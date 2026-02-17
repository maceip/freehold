# Freehold

[![CI](https://github.com/maceip/freehold/actions/workflows/ci.yml/badge.svg)](https://github.com/maceip/freehold/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**Public IPs for all your devices.**

Give any device a real public IP address. Host services that browsers trust — not tunnel URLs. Works from behind CGNAT, double-NAT, or corporate firewalls.

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Platforms](#platforms)
- [Server Setup](#server-setup)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

Test the public relay without installing anything:

```bash
# Test H3 (if curl supports it)
curl --http3 https://freehold.lit.app/

# Test HTTPS
curl https://freehold.lit.app/
```

Expose a local service to the internet:

```bash
# Expose localhost:3000 to the internet
freehold --relay freehold.lit.app:9999 --port 8080 --backend 127.0.0.1:3000
```

Your service is now reachable at `freehold.lit.app:8080`.

## How It Works

```
Browser (Alice)                 Freehold Relay                  You (Bob, behind NAT)
     |                              |                                |
     |                              |    <--- UDP Register ----------|
     |                              |    --- HMAC Challenge -------->|
     |                              |    <--- Confirm --------------|
     |                              |       [eBPF map updated]       |
     |                              |                                |
     |--- QUIC/H3 request -------->|                                |
     |                              |--- XDP rewrites dst --------->| (NAT may drop)
     |                              |--- Punch(alice:port) -------->| (control channel)
     |                              |                                |
     |                              |              Bob sends UDP --->| to Alice (opens NAT)
     |                              |                                |
     |--- QUIC retransmit -------->|--- XDP rewrites dst --------->| (NAT allows now)
     |                              |                                |--- H3 Proxy → backend
     |<--------- QUIC response directly from Bob -------------------|
```

1. **Bob registers** — sends UDP to the relay, completes HMAC challenge, gets added to the eBPF map. The relay assigns a stable subdomain (`<hash>.freehold.lit.app`) and sets DNS A + HTTPS records
2. **Alice connects** — sends QUIC to `relay:port`. The XDP program rewrites the destination IP to Bob's address but **leaves Alice's source IP unchanged**
3. **NAT hole-punch** — if Bob is behind endpoint-dependent NAT, the relay detects the new source and sends a Punch message telling Bob to send a UDP packet to Alice, opening the NAT mapping. QUIC retransmission handles the 1-2s initial latency
4. **Bob responds directly** — Bob sees Alice's real IP as the packet source and sends the QUIC response straight back to her, bypassing the relay entirely
5. **Alice's NAT accepts it** — she initiated the outbound UDP, so her NAT allows the reply even though it comes from Bob's IP (QUIC uses connection IDs, not IP tuples)
6. **TLS via DNS-01** — Bob can request a real TLS certificate by sending an ACME challenge token in the Confirm message. The relay sets `_acme-challenge.<subdomain>.freehold.lit.app` TXT records via Knot DNS

The relay is only in the **inbound** path. Alice doesn't install anything — she just uses a browser.

## Features

- **Wire-speed forwarding** — eBPF/XDP processes packets in kernel space
- **Stateless verification** — HMAC cookies prevent spoofing without storing state
- **Anycast routing** — BGP announces your prefix globally
- **NAT hole-punching** — Relay-assisted UDP punch opens endpoint-dependent NATs for arbitrary sources
- **H3/QUIC proxy** — Optional HTTP/3 reverse proxy with automatic TLS
- **WebSocket over H3** — RFC 9220 Extended CONNECT for WebSocket through QUIC relay
- **DemuxSocket** — Engine and Quinn share one UDP socket; zero mux code needed
- **DNS ACME API** — Clients request TLS certificates via DNS-01 challenges through the relay
- **Multi-platform** — Desktop, mobile, and web clients

## Installation

### From Source

```bash
git clone https://github.com/maceip/freehold
cd freehold
cargo build --release

# Client binary
./target/release/freehold --help

# Server binary (requires root for eBPF)
./target/release/freehold-server --help
```

### Platform Apps

See [Platforms](#platforms) for native apps on macOS, Windows, Linux, Android, iOS, and Web.

## Usage

### Basic Registration

```bash
# Register port, receive raw UDP
freehold --relay freehold.lit.app:9999 --port 8080
```

### With HTTP Backend (DemuxSocket)

```bash
# Expose HTTP backend via QUIC — single shared socket, zero mux code
freehold --relay freehold.lit.app:9999 --port 443 \
  --backend 127.0.0.1:3000 \
  --domain myapp.example.com
```

Engine registration and Quinn H3/QUIC share one UDP socket via `DemuxSocket`. Packets with magic byte `0x46` go to Engine; everything else (QUIC) goes to Quinn. No socket conflicts, no configuration needed.

### Headless Mode

```bash
# No tray icon, just registration
freehold --relay freehold.lit.app:9999 --port 8080 --headless
```

### Try With Tools You Already Have

```bash
# Terminal 1: Start any HTTP server
python3 -m http.server 8000

# Terminal 2: Expose it
freehold --relay freehold.lit.app:9999 --port 8080 --backend 127.0.0.1:8000 --headless
```

Works with anything: nginx, caddy, node, flask, rails — if it binds to a port, Freehold can expose it.

## Platforms

| Platform | Type | Status |
|----------|------|--------|
| **macOS** | Menu bar app (Swift/SwiftUI) | ✅ |
| **Windows** | System tray (C#) | ✅ |
| **Linux** | GTK4 indicator | ✅ |
| **Android** | VPN service (Kotlin) | ✅ |
| **iOS** | VPN app (Swift) | ✅ |
| **Web** | Isolated Web App (WASM) | ✅ |

Platform-specific documentation:
- [Android](platforms/android/README.md)
- [iOS](platforms/ios/README.md)
- [Web](platforms/web/isolated-web-app/README.md)

## Server Setup

The relay server requires:
- Linux with eBPF support (kernel 5.15+)
- A public IP or anycast prefix
- Root privileges (for XDP attachment)

```bash
# Generate example config
freehold-server example-config > /etc/freehold/server.toml

# Edit config with your settings
vim /etc/freehold/server.toml

# Build eBPF (requires clang)
cargo xtask build-ebpf --release

# Run server
sudo freehold-server -c /etc/freehold/server.toml
```

### Public Relay

A public relay is available at:

```
freehold.lit.app:9999
```

This relay announces the `142.248.222.0/24` anycast prefix.

## Examples

End-to-end examples in [`examples/`](examples/):

- **[`heartbeat-ws`](examples/heartbeat-ws/)** — Rust WebSocket server that sends `{"ts", "seq"}` heartbeats every second. Runs behind Freehold's H3 proxy using `Service` (DemuxSocket under the hood).
- **[`android-ws-client`](examples/android-ws-client/)** — Android Compose app using Cronet HTTP/3 to connect to the heartbeat server through Freehold.

```bash
# Run the heartbeat server locally
cargo run -p heartbeat-ws -- --port 8443

# Or with relay registration
cargo run -p heartbeat-ws -- --relay freehold.lit.app:9999 --relay-port 55126
```

## Architecture

```
freehold/
├── crates/
│   ├── freehold-api/           # Wire protocol (Register, Challenge, Confirm, Punch, DNS ACME)
│   ├── freehold-common/        # Shared types (eBPF maps, events)
│   ├── freehold-ebpf/          # XDP packet forwarder
│   ├── freehold-server/        # Relay server (+ Knot DNS integration)
│   ├── freehold-client-core/   # Headless client engine (+ DemuxSocket)
│   ├── freehold-client/        # CLI with platform UI
│   ├── freehold-h3-proxy/      # HTTP/3 reverse proxy (+ WebSocket RFC 9220)
│   ├── freehold-android-bridge/# Android FFI bindings
│   └── freehold-e2e-tests/     # Integration tests
├── examples/
│   ├── heartbeat-ws/           # WebSocket heartbeat server
│   └── android-ws-client/      # Android Cronet H3 client
├── platforms/
│   ├── macos/                  # Swift menu bar app
│   ├── windows/                # C# system tray
│   ├── linux/                  # GTK4 indicator
│   ├── android/                # Kotlin VPN service
│   ├── ios/                    # Swift VPN app
│   └── web/                    # Isolated Web App
└── tests/
    └── e2e/                    # Network namespace E2E tests
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

For security issues, see [SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0

## Links

- **GitHub:** https://github.com/maceip/freehold
- **Website:** https://freehold.lit.app
