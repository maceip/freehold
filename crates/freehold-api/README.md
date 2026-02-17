# freehold-api

[![Crates.io](https://img.shields.io/crates/v/freehold-api.svg)](https://crates.io/crates/freehold-api)
[![Documentation](https://docs.rs/freehold-api/badge.svg)](https://docs.rs/freehold-api)
[![License](https://img.shields.io/crates/l/freehold-api.svg)](LICENSE)

Wire protocol for the Freehold anycast relay network.

This crate defines the message format for client-server communication, including registration, challenge-response authentication, and neighbor discovery.

## Usage

```rust
use freehold_api::{Message, COOKIE_SIZE};

// Parse incoming UDP packet
let data: &[u8] = &[0x46, 0x01, 0x1F, 0x90]; // REGISTER port 8080
let msg = Message::parse(data)?;

match msg {
    Message::Register { port } => {
        println!("Client wants to register port {}", port);

        // Generate challenge response
        let cookie = [0u8; COOKIE_SIZE]; // Your HMAC here
        let response = Message::Challenge { port, cookie };
        let bytes = response.to_bytes();
        // Send bytes back to client
    }
    Message::Confirm { port, cookie, action } => {
        // Verify cookie and complete registration
        // action is ConfirmAction::None, SetTxt, ClearTxt, or CreateRecords
    }
    Message::Heartbeat { port } => {
        // Refresh registration TTL
    }
    _ => {}
}
```

## Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `Register` | Client → Server | Request port registration |
| `Challenge` | Server → Client | HMAC cookie challenge |
| `Confirm` | Client → Server | Echo cookie to confirm |
| `Heartbeat` | Client → Server | Keep registration alive |
| `Neighbors` | Server → Client | List of other relays + subdomain |
| `Punch` | Server → Client | NAT hole-punch request |
| `Error` | Server → Client | Registration rejected |

## Wire Format

All messages start with magic byte `0x46` ('F') followed by message type:

```
Register:   [0x46, 0x01, port_be16]
Challenge:  [0x46, 0x02, port_be16, cookie[16]]
Confirm:    [0x46, 0x03, port_be16, cookie[16], action?, ...]
Heartbeat:  [0x46, 0x04, port_be16]
Neighbors:  [0x46, 0x05, count, ip1[4], ..., subdomain_len?, subdomain?]
Punch:      [0x46, 0x06, ip[4], port_be16]
Error:      [0x46, 0xFF, port_be16]
```

## Confirm Actions

The Confirm message supports optional trailing action bytes for DNS/ACME operations:

| Action | Byte | Payload | Purpose |
|--------|------|---------|---------|
| `None` | (omitted) | — | Standard registration |
| `SetTxt` | `0x01` | `[len, data...]` | Set ACME DNS-01 TXT record |
| `ClearTxt` | `0x02` | `[0x00]` | Clear ACME TXT record |
| `CreateRecords` | `0x03` | `[0x00]` | Request DNS A + HTTPS records |

`CreateRecords` requires the client to already be registered in the eBPF map (proving reachability). DNS records are not created during initial registration.

## Timing Constants

```rust
use freehold_api::timing;

// Cookie time buckets (30 seconds)
let bucket = timing::TIME_BUCKET;

// Registration expires after 60 seconds without heartbeat
let ttl = timing::REGISTRATION_TTL;

// Send heartbeat every 25 seconds
let interval = timing::HEARTBEAT_INTERVAL;
```

## License

MIT OR Apache-2.0
