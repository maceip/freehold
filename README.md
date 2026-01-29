# Freehold

**Public IPs for all your devices.**

Give any device a real public IP address. Host services that browsers trust — not tunnel URLs. Works from behind CGNAT, double-NAT, or corporate firewalls.

## Getting to Freehold

Test the public relay without installing anything:

```bash
# Test H3 (if curl supports it)
curl --http3 https://freehold.lit.app/

# Test HTTPS
curl https://freehold.lit.app/

# Check DNS HTTPS record (H3 discovery)
dig freehold.lit.app HTTPS +short
```

## Quick Start

```bash
# Expose localhost:3000 to the internet
freehold --relay freehold.lit.app:9999 --port 8080 --backend 127.0.0.1:3000
```

Your service is now reachable at `freehold.lit.app:8080`.

## Try It With Tools You Already Have

No need to install anything special for the backend. Freehold forwards traffic to whatever is listening.

```bash
# Terminal 1: Start a simple HTTP server
python3 -m http.server 8000

# Terminal 2: Expose it through Freehold
freehold --relay freehold.lit.app:9999 --port 8080 --backend 127.0.0.1:8000 --headless
```

Or use netcat to see raw traffic:

```bash
# Terminal 1: Listen for connections
nc -l -p 9000

# Terminal 2: Register the port
freehold --relay freehold.lit.app:9999 --port 8080 --backend 127.0.0.1:9000 --headless

# From anywhere: connect and send data
echo "hello from the internet" | nc freehold.lit.app 8080
```

Works with anything: nginx, caddy, node, flask, rails — if it binds to a port, Freehold can expose it.

## How It Works

```
You (behind NAT)                    Freehold Relay                    Browser
     |                                   |                               |
     |------- UDP Register ------------->|                               |
     |<------ Challenge -----------------|                               |
     |------- Confirm ------------------>|                               |
     |                                   |                               |
     |        [Registration active]      |                               |
     |                                   |                               |
     |                                   |<----- HTTPS request ----------|
     |<---- XDP forwards packet ---------|                               |
     |------- Response ----------------->|-----> Response -------------->|
```

1. Client sends UDP registration to relay (opens NAT hole)
2. Relay responds with HMAC challenge (stateless verification)
3. Client confirms, relay adds to eBPF map
4. Incoming traffic is forwarded at wire-speed via XDP

## Features

- **Wire-speed forwarding** — eBPF/XDP processes packets in kernel space
- **Stateless verification** — HMAC cookies prevent spoofing without storing state
- **Anycast routing** — BGP announces your prefix globally
- **NAT hole-punching** — UDP-based registration works through restrictive NATs
- **H3/QUIC proxy** — Optional HTTP/3 reverse proxy with automatic TLS

## Installation

```bash
# Clone and build
git clone https://git.sr.ht/~rpm/freehold
cd freehold
cargo build --release

# Client binary
./target/release/freehold --help

# Server binary (requires root for eBPF)
./target/release/freehold-server --help
```

## Server Setup

The relay server requires:
- Linux with eBPF support
- A public IP or anycast prefix
- Root privileges (for XDP attachment)

```bash
# Generate example config
freehold-server example-config > /etc/freehold/server.toml

# Edit config with your settings
vim /etc/freehold/server.toml

# Build eBPF (requires clang)
cd crates/freehold-ebpf
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu -I/usr/include \
  -c src/main.bpf.c -o /opt/freehold/freehold.bpf.o

# Run server
freehold-server -c /etc/freehold/server.toml
```

## Client Usage

```bash
# Basic: register port, receive raw UDP
freehold --relay freehold.lit.app:9999 --port 8080

# With H3 proxy: expose HTTP backend via QUIC
freehold --relay freehold.lit.app:9999 --port 443 \
  --backend 127.0.0.1:3000 \
  --domain myapp.example.com

# Headless mode (no tray icon)
freehold --relay freehold.lit.app:9999 --port 8080 --headless

# Auto-discover neighbor relays
freehold --relay freehold.lit.app:9999 --port 8080 --discover
```

## Public Relay

A public relay is available at:

```
freehold.lit.app:9999
```

This relay announces the `142.248.222.0/24` anycast prefix.

## Architecture

```
freehold-network/
├── crates/
│   ├── freehold-api/        # Wire protocol
│   ├── freehold-common/     # Shared types (eBPF maps, events)
│   ├── freehold-client-core/# Headless client engine
│   ├── freehold-client/     # CLI with platform UI
│   ├── freehold-server/     # Relay server
│   ├── freehold-ebpf/       # XDP packet forwarder
│   └── freehold-h3-proxy/   # HTTP/3 reverse proxy
├── platforms/
│   ├── macos/               # Menu bar app
│   ├── windows/             # System tray
│   └── linux/               # GTK4 indicator
└── www/                     # Landing page (hosted through Freehold)
```

## License

MIT

## Links

- **Source:** https://git.sr.ht/~rpm/freehold
- **Website:** https://freehold.lit.app (hosted through Freehold)
