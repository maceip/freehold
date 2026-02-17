# iOS WebSocket Client (Rust + SwiftUI)

An iOS app that connects to a Freehold heartbeat server using **QUIC/HTTP3**,
powered by Rust (quinn + h3) with a SwiftUI frontend.

## Architecture

```
SwiftUI <--C FFI--> Rust (quinn + h3)
   |                       |
WSClient.swift      QUIC / HTTP/3 Extended CONNECT
   |                       |
ContentView.swift   Freehold Relay (XDP fwd)
                           |
                    heartbeat-ws :3000
```

All networking lives in Rust — QUIC handshake, HTTP/3 negotiation, WebSocket
upgrade via Extended CONNECT (RFC 9220). Swift just calls `ws_client_connect()`,
polls `ws_client_poll_message()`, and renders with SwiftUI.

## Project layout

```
ios-ws-client/
├── FreeholdWSClient/          # Rust crate (staticlib + C FFI)
│   ├── Cargo.toml
│   ├── cbindgen.toml          # Generates C header for Swift
│   ├── build.rs
│   ├── src/lib.rs             # QUIC/H3 client + FFI exports
│   └── include/
│       ├── freehold_ws_client.h   # Auto-generated
│       └── module.modulemap
│
├── App/                       # SwiftUI app
│   ├── FreeholdWSClientApp.swift
│   ├── ContentView.swift      # UI: host/port, connect, message log
│   ├── WSClient.swift         # Swift wrapper over C FFI
│   └── Info.plist
│
├── Package.swift              # SPM (links Rust xcframework)
└── build-rust.sh              # Cross-compile for iOS targets
```

## Build

```bash
# 1. Build Rust for iOS (requires Xcode + iOS targets)
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./build-rust.sh

# 2. Open in Xcode (add App/ sources to an iOS app target,
#    link FreeholdWSClient.xcframework)
```

## FFI surface

The Rust crate exports these C functions (auto-generated header):

| Function | Purpose |
|----------|---------|
| `ws_client_init()` | Initialize tracing |
| `ws_client_connect(host, port)` | Open QUIC/H3 + WebSocket |
| `ws_client_disconnect()` | Tear down connection |
| `ws_client_state()` | Poll connection state |
| `ws_client_poll_message()` | Non-blocking message receive |
| `ws_client_send(text)` | Send text over WebSocket |
| `ws_client_last_error()` | Get last error string |
| `ws_client_free_message()` | Free received message |
| `ws_client_free_string()` | Free error string |

## Dual-path DNS

The app includes a **path selector** (Auto / Relay / Direct) that
demonstrates Freehold's dual-path DNS:

| Path | FQDN | Behavior |
|------|------|----------|
| Auto (SVCB) | `<hash>.freehold.lit.app` | Races relay + direct, picks fastest |
| Relay | `<hash>.relay.freehold.lit.app` | Always via relay (works behind any NAT) |
| Direct | `<hash>.home.freehold.lit.app` | Direct to server (permissive NAT only) |

Enter just the subdomain hash (e.g. `a7xk2m`) and the app constructs
the full FQDN based on the selected path. Use "Auto" for production —
it races both paths and picks whichever responds first.

## Why Rust for the network layer?

iOS's URLSession supports HTTP/3, but does not expose Extended CONNECT
(RFC 9220) for WebSocket-over-H3. By using quinn + h3 in Rust, we get
full control over the QUIC connection — including the WebSocket upgrade
that Freehold's H3 proxy expects.
