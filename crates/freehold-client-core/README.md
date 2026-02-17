# freehold-client-core

[![Crates.io](https://img.shields.io/crates/v/freehold-client-core.svg)](https://crates.io/crates/freehold-client-core)
[![Documentation](https://docs.rs/freehold-client-core/badge.svg)](https://docs.rs/freehold-client-core)
[![License](https://img.shields.io/crates/l/freehold-client-core.svg)](LICENSE)

Headless client engine for the Freehold anycast relay network.

Handles UDP registration, heartbeat maintenance, neighbor discovery, and optional H3/QUIC proxy. Platform-specific UIs (desktop tray, mobile apps) build on top of this.

## Usage

```rust
use freehold_client_core::{Engine, StatusUpdate, RelayState};
use tokio::sync::mpsc;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let relay: SocketAddr = "relay.example.com:9999".parse()?;
    let port = 8080; // Port to claim on the relay

    // Create channel for status updates
    let (status_tx, mut status_rx) = mpsc::channel(32);

    // Create engine
    let mut engine = Engine::new(relay, port, true, status_tx)?;

    // Handle status updates in separate task
    tokio::spawn(async move {
        while let Some(update) = status_rx.recv().await {
            match update {
                StatusUpdate::RelayState { addr, state } => {
                    println!("Relay {}: {:?}", addr, state);
                }
                StatusUpdate::NeighborDiscovered(ip) => {
                    println!("Found neighbor relay: {}", ip);
                }
                StatusUpdate::SubdomainAssigned(sub) => {
                    println!("Subdomain: {}", sub);
                }
                StatusUpdate::AcmeCertReady => {
                    println!("ACME cert installed");
                }
                StatusUpdate::Error(msg) => {
                    eprintln!("Error: {}", msg);
                }
                _ => {}
            }
        }
    });

    // Run the engine (blocks)
    engine.run().await?;

    Ok(())
}
```

## With H3 Proxy

Enable the `h3-proxy` feature to expose HTTP backends:

```toml
[dependencies]
freehold-client-core = { version = "1.0", features = ["h3-proxy"] }
```

```rust
use freehold_client_core::{Service, ServiceConfig, generate_self_signed_cert};

let (certs, key) = generate_self_signed_cert(&["myapp.example.com"])?;

let service = Service::new(ServiceConfig {
    relay: "relay.example.com:9999".parse()?,
    relay_port: 443,
    h3_bind: "0.0.0.0:443".parse()?,
    backend: "127.0.0.1:3000".parse()?,
    certs,
    key,
    auto_discover: true,
    acme_cache_dir: None,  // Some(path) to enable automatic ACME certs
    dns_zone: None,        // Some("freehold.lit.app") for ACME multi-SAN certs
}, status_tx)?;

service.run(shutdown_rx).await?;
```

## State Machine

For custom integrations, use the pure state machine directly:

```rust
use freehold_client_core::state::{StateMachine, Action, RelayState};
use freehold_api::Message;
use std::time::Instant;

let mut sm = StateMachine::new(relay_addr, port, auto_discover);

// On each tick, get actions to perform
let actions = sm.tick(Instant::now());
for action in actions {
    match action {
        Action::SendRegister { relay_idx } => {
            // Send UDP REGISTER message
        }
        Action::SendHeartbeat { relay_idx } => {
            // Send UDP HEARTBEAT message
        }
        // ... handle other actions
    }
}

// When receiving messages, update state
let actions = sm.handle_message(message, from_addr, Instant::now());
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `h3-proxy` | Yes | Include H3/QUIC proxy support |
| `acme` | No | Automatic Let's Encrypt certs via DNS-01 (requires `h3-proxy`) |

## Automatic ACME Certificates

Enable the `acme` feature and set `acme_cache_dir` to automatically obtain
and renew Let's Encrypt certificates:

```toml
[dependencies]
freehold-client-core = { version = "1.0", features = ["h3-proxy", "acme"] }
```

Set both `acme_cache_dir` and `dns_zone` to enable. The ACME task runs in the background:
1. Waits for subdomain hash assignment from the relay
2. Constructs three FQDNs: `{hash}.{zone}`, `{hash}.relay.{zone}`, `{hash}.home.{zone}`
3. Checks disk cache for a valid cert — if found, hot-swaps immediately
4. Sends `CreateRecords` to create dual-path DNS records (SVCB for relay + home)
5. Runs DNS-01 flow sequentially per authorization (each domain has its own challenge token)
6. Hot-swaps the multi-SAN cert into the running QUIC endpoint (zero downtime)

The three FQDNs enable dual-path connectivity:

| FQDN | A record points to | Purpose |
|------|--------------------|---------|
| `{hash}.{zone}` | relay IP | Primary — two SVCB records let browsers race relay + direct |
| `{hash}.relay.{zone}` | relay IP | Guaranteed relay path for SDK clients |
| `{hash}.home.{zone}` | **server's real public IP** | Direct path — bypasses relay entirely |

The `.home` A record contains the server's real public IP (the UDP source address
from registration). This is how SDK clients discover the server's actual address
and can probe it to open their NAT for direct responses.

Monitor via `StatusUpdate::SubdomainAssigned` and `StatusUpdate::AcmeCertReady`.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  Platform UI    │     │   H3 Proxy      │
│  (tray, mobile) │     │   (optional)    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
              ┌──────┴──────┐
              │   Engine    │
              │  (this lib) │
              └──────┬──────┘
                     │
              ┌──────┴──────┐
              │  UDP Socket │
              └──────┬──────┘
                     │
                  Relay
```

## License

MIT OR Apache-2.0
