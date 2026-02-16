# freehold-h3-proxy

[![Crates.io](https://img.shields.io/crates/v/freehold-h3-proxy.svg)](https://crates.io/crates/freehold-h3-proxy)
[![Documentation](https://docs.rs/freehold-h3-proxy/badge.svg)](https://docs.rs/freehold-h3-proxy)
[![License](https://img.shields.io/crates/l/freehold-h3-proxy.svg)](LICENSE)

HTTP/3 (QUIC) to HTTP/1.1 reverse proxy with WebSocket support.

Accepts incoming QUIC/H3 connections and forwards requests to a local HTTP backend. Supports standard HTTP request proxying and WebSocket tunneling via RFC 9220 Extended CONNECT.

## Usage

```rust
use freehold_h3_proxy::{H3Proxy, H3ProxyConfig, generate_self_signed_cert};
use std::net::SocketAddr;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate self-signed certificate (or load your own)
    let (certs, key) = generate_self_signed_cert(&["localhost"])?;

    // Configure proxy
    let config = H3ProxyConfig {
        bind_addr: "0.0.0.0:443".parse()?,
        backend: "127.0.0.1:8080".parse()?,
        certs,
        key,
    };

    let proxy = H3Proxy::new(config);

    // Run with shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    proxy.run(shutdown_rx).await?;

    Ok(())
}
```

## Features

- **HTTP/3 over QUIC** - Modern protocol with multiplexing and 0-RTT
- **WebSocket over HTTP/3** - RFC 9220 Extended CONNECT for WebSocket tunneling
- **Automatic TLS** - Built-in certificate generation or bring your own
- **Simple forwarding** - Proxies to any HTTP/1.1 backend
- **Graceful shutdown** - Clean connection draining

## How It Works

### HTTP Requests

```
Browser --QUIC/H3--> H3Proxy --HTTP/1.1--> Your Backend
         (port 443)           (port 8080)
```

1. Browser connects via QUIC to the proxy
2. Proxy terminates TLS and parses HTTP/3 requests
3. Requests are forwarded to your backend over HTTP/1.1
4. Responses flow back through the same path

### WebSocket Connections (RFC 9220)

```
Browser                          H3 Proxy                     Backend
   |                                |                            |
   |-- CONNECT :protocol=websocket ->|                            |
   |                                |-- GET / Upgrade: websocket ->|
   |                                |<-- 101 Switching Protocols --|
   |<------------ 200 OK ----------|                            |
   |                                |                            |
   |<===== bidirectional data =====>|<===== TCP byte stream ====>|
```

When a browser sends an HTTP/3 Extended CONNECT request with `:protocol: websocket`:

1. The proxy opens a TCP connection to the backend
2. Sends an HTTP/1.1 WebSocket upgrade request (with `Upgrade: websocket` headers)
3. Receives the `101 Switching Protocols` response from the backend
4. Responds with `200 OK` on the H3 stream (per RFC 9220)
5. Bidirectionally pipes data between the H3 stream and the TCP connection

This allows WebSocket connections to traverse Freehold's UDP-based QUIC relay, since all traffic flows over QUIC (UDP) rather than TCP.

## Certificate Generation

```rust
use freehold_h3_proxy::generate_self_signed_cert;

// Single domain
let (certs, key) = generate_self_signed_cert(&["example.com"])?;

// Multiple domains (SANs)
let (certs, key) = generate_self_signed_cert(&[
    "example.com",
    "www.example.com",
    "api.example.com",
])?;
```

## License

MIT OR Apache-2.0
