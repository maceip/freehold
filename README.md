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
- **WebSocket over H3** — RFC 9220 Extended CONNECT for WebSocket through QUIC relay
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

### With HTTP Backend

```bash
# Expose HTTP backend via QUIC
freehold --relay freehold.lit.app:9999 --port 443 \
  --backend 127.0.0.1:3000 \
  --domain myapp.example.com
```

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

## Architecture

```
freehold-network/
├── crates/
│   ├── freehold-api/           # Wire protocol
│   ├── freehold-common/        # Shared types (eBPF maps, events)
│   ├── freehold-ebpf/          # XDP packet forwarder
│   ├── freehold-server/        # Relay server
│   ├── freehold-client-core/   # Headless client engine
│   ├── freehold-client/        # CLI with platform UI
│   ├── freehold-h3-proxy/      # HTTP/3 reverse proxy (+ WebSocket)
│   ├── freehold-android-bridge/# Android FFI bindings
│   └── freehold-e2e-tests/     # Integration tests
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
