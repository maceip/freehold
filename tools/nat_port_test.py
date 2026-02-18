#!/usr/bin/env python3
"""NAT Port Allocation Pattern Test

Creates N UDP sockets bound to the same local port, each sending to a
different STUN server. Reports the external port allocated for each flow.
Shows whether ports are sequential, random, or clustered.

Run on a device behind carrier NAT to characterize allocation patterns
before deploying port spray.

Usage:
    python3 nat_port_test.py [--count N] [--local-port PORT]
"""

import argparse
import os
import socket
import struct
import sys
import time

# Public STUN servers (UDP port 3478)
STUN_SERVERS = [
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.ekiga.net",
    "stun.ideasip.com",
    "stun.schlund.de",
    "stun.voiparound.com",
    "stun.voipbuster.com",
]

STUN_PORT = 3478

# STUN Binding Request (RFC 5389)
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def make_stun_request():
    """Build a STUN Binding Request."""
    txn_id = os.urandom(12)
    header = struct.pack("!HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE)
    return header + txn_id, txn_id


def parse_stun_response(data, txn_id):
    """Parse STUN Binding Response, return (ip, port) or None."""
    if len(data) < 20:
        return None

    msg_type, msg_len, magic = struct.unpack("!HHI", data[:8])
    if msg_type != STUN_BINDING_RESPONSE:
        return None
    if magic != STUN_MAGIC_COOKIE:
        return None
    if data[8:20] != txn_id:
        return None

    offset = 20
    while offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        attr_data = data[offset + 4 : offset + 4 + attr_len]

        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS and attr_len >= 8:
            family = attr_data[1]
            if family == 0x01:  # IPv4
                xor_port = struct.unpack("!H", attr_data[2:4])[0]
                xor_ip = struct.unpack("!I", attr_data[4:8])[0]
                port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
                ip_int = xor_ip ^ STUN_MAGIC_COOKIE
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                return ip, port

        if attr_type == STUN_ATTR_MAPPED_ADDRESS and attr_len >= 8:
            family = attr_data[1]
            if family == 0x01:  # IPv4
                port = struct.unpack("!H", attr_data[2:4])[0]
                ip = socket.inet_ntoa(attr_data[4:8])
                return ip, port

        # Attributes are padded to 4-byte boundaries
        offset += 4 + ((attr_len + 3) & ~3)

    return None


def test_port_allocation(count, local_port):
    """Send STUN requests to multiple servers, report external ports."""
    results = []
    servers = []

    # Resolve STUN servers
    for name in STUN_SERVERS[:count]:
        try:
            ip = socket.gethostbyname(name)
            servers.append((name, ip))
        except socket.gaierror:
            print(f"  Could not resolve {name}, skipping", file=sys.stderr)

    if not servers:
        print("No STUN servers reachable", file=sys.stderr)
        return []

    print(f"Testing with {len(servers)} STUN servers, local port {local_port}\n")

    for i, (name, ip) in enumerate(servers):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("0.0.0.0", local_port))
        sock.settimeout(2.0)

        req, txn_id = make_stun_request()
        try:
            sock.sendto(req, (ip, STUN_PORT))
            data, _ = sock.recvfrom(1024)
            result = parse_stun_response(data, txn_id)
            if result:
                ext_ip, ext_port = result
                results.append((name, ext_ip, ext_port))
                print(f"  [{i+1}/{len(servers)}] {name:30s} -> {ext_ip}:{ext_port}")
            else:
                print(f"  [{i+1}/{len(servers)}] {name:30s} -> (no mapped addr)")
        except socket.timeout:
            print(f"  [{i+1}/{len(servers)}] {name:30s} -> (timeout)")
        except OSError as e:
            print(f"  [{i+1}/{len(servers)}] {name:30s} -> (error: {e})")
        finally:
            sock.close()

        # Small delay to see sequential allocation
        time.sleep(0.05)

    return results


def analyze_results(results):
    """Analyze port allocation pattern."""
    if len(results) < 2:
        print("\nNot enough results to analyze pattern")
        return

    ports = [r[2] for r in results]
    ips = set(r[1] for r in results)

    print(f"\n{'='*60}")
    print(f"External IP(s): {', '.join(sorted(ips))}")
    print(f"Ports: {ports}")

    # Check if all same port (endpoint-independent mapping)
    if len(set(ports)) == 1:
        print(f"\nPattern: ENDPOINT-INDEPENDENT (all same port: {ports[0]})")
        print("  Port spray NOT needed - single poke works fine.")
        return

    # Check for sequential allocation
    deltas = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
    avg_delta = sum(deltas) / len(deltas)
    min_delta = min(deltas)
    max_delta = max(deltas)

    print(f"\nPort deltas: {deltas}")
    print(f"  min={min_delta}, max={max_delta}, avg={avg_delta:.1f}")

    port_range = max(ports) - min(ports)
    print(f"  Total range: {port_range} (from {min(ports)} to {max(ports)})")

    if all(0 < d <= 5 for d in deltas):
        print(f"\nPattern: SEQUENTIAL (stride ~{avg_delta:.0f})")
        print(f"  Port spray of {port_range * 2} should work well.")
    elif port_range < 1000:
        print(f"\nPattern: CLUSTERED (range {port_range})")
        print(f"  Port spray of {max(port_range * 3, 5000)} should work.")
    else:
        print(f"\nPattern: RANDOM or WIDE (range {port_range})")
        print("  Port spray unlikely to help. Use bidirectional XDP relay.")


def main():
    parser = argparse.ArgumentParser(description="Test NAT port allocation patterns")
    parser.add_argument(
        "--count",
        "-n",
        type=int,
        default=10,
        help="Number of STUN servers to test (max 10)",
    )
    parser.add_argument(
        "--local-port",
        "-p",
        type=int,
        default=0,
        help="Local port to bind (0 = ephemeral)",
    )
    args = parser.parse_args()

    count = min(args.count, len(STUN_SERVERS))
    local_port = args.local_port

    # If no specific port requested, pick a random ephemeral port
    if local_port == 0:
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.bind(("0.0.0.0", 0))
        local_port = tmp.getsockname()[1]
        tmp.close()

    results = test_port_allocation(count, local_port)
    analyze_results(results)


if __name__ == "__main__":
    main()
