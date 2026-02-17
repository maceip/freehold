//! Heartbeat WebSocket Server
//!
//! A minimal backend that accepts WebSocket connections and:
//! - Sends `{"ts": <unix_ms>, "seq": <n>}` every second
//! - Echoes any received text message back to the sender
//!
//! Designed to run behind Freehold's H3 proxy (Service), which converts
//! HTTP/3 Extended CONNECT (RFC 9220) into a plain HTTP/1.1 WebSocket
//! upgrade to this server.
//!
//! # Quick start (local, no relay)
//!
//! ```sh
//! # Terminal 1 — start heartbeat server + H3 proxy (local mode)
//! cargo run -p heartbeat-ws -- --port 8443
//!
//! # Terminal 2 — connect via H3 (needs curl with HTTP/3)
//! curl --http3-only -k -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
//!   https://127.0.0.1:8443/ws
//! ```
//!
//! # With relay registration
//!
//! ```sh
//! cargo run -p heartbeat-ws -- --relay freehold.lit.app:9999 --relay-port 55126
//! ```

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "heartbeat-ws",
    about = "WebSocket heartbeat server for Freehold"
)]
struct Args {
    /// Relay server address (skip for local-only mode)
    #[clap(long)]
    relay: Option<String>,

    /// Port to claim on the relay
    #[clap(long)]
    relay_port: Option<u16>,

    /// Local port for H3/QUIC (also used for local-mode HTTPS)
    #[clap(long, default_value = "8443")]
    port: u16,

    /// Heartbeat interval in milliseconds
    #[clap(long, default_value = "1000")]
    interval_ms: u64,

    /// Domain for self-signed cert
    #[clap(long, default_value = "localhost")]
    domain: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("heartbeat_ws=info,freehold_client_core=debug,freehold_h3_proxy=debug")
        .init();

    let args = Args::parse();

    // Bind WebSocket backend on localhost (H3 proxy connects here)
    let ws_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ws_addr = ws_listener.local_addr()?;
    info!("WebSocket backend on {}", ws_addr);

    let interval_ms = args.interval_ms;

    // Spawn the WebSocket accept loop
    tokio::spawn(async move {
        loop {
            match ws_listener.accept().await {
                Ok((stream, addr)) => {
                    info!("WS connection from {}", addr);
                    tokio::spawn(handle_ws(stream, interval_ms));
                }
                Err(e) => warn!("Accept error: {}", e),
            }
        }
    });

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx.send(true);
    });

    // Start Freehold service (relay + H3 proxy) or local-only H3 proxy
    if let (Some(relay_str), Some(relay_port)) = (&args.relay, args.relay_port) {
        // Full mode: register with relay + H3 proxy
        let relay_addr: SocketAddr = tokio::net::lookup_host(relay_str)
            .await
            .context(format!("resolve relay: {}", relay_str))?
            .next()
            .context("no addresses for relay")?;

        let h3_bind: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
        info!(
            "Freehold service: relay {}:{} | H3 {} -> backend {}",
            relay_str, relay_port, h3_bind, ws_addr
        );

        let (status_tx, mut status_rx) = tokio::sync::mpsc::channel(32);

        // Log status updates
        tokio::spawn(async move {
            while let Some(update) = status_rx.recv().await {
                info!("status: {:?}", update);
            }
        });

        let service = freehold_client_core::create_service_with_self_signed_cert(
            relay_addr,
            relay_port,
            h3_bind,
            ws_addr,
            &args.domain,
            true,
            status_tx,
        )?;

        service.run(shutdown_rx).await
    } else {
        // Local-only mode: H3 proxy without relay
        use freehold_client_core::{generate_self_signed_cert, H3Proxy, H3ProxyConfig};

        let h3_bind: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
        let (certs, key) = generate_self_signed_cert(&[&args.domain])?;

        info!("Local mode: H3 {} -> backend {}", h3_bind, ws_addr);

        let proxy = H3Proxy::new(H3ProxyConfig {
            bind_addr: h3_bind,
            backend: ws_addr,
            certs,
            key,
        });

        proxy.run(shutdown_rx).await
    }
}

async fn handle_ws(stream: TcpStream, interval_ms: u64) {
    let ws = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("WebSocket handshake failed: {}", e);
            return;
        }
    };

    let (mut write, mut read) = ws.split();
    let mut seq: u64 = 0;
    let mut heartbeat = time::interval(time::Duration::from_millis(interval_ms));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let msg = serde_json::json!({ "ts": ts, "seq": seq });
                seq += 1;

                if write.send(Message::Text(msg.to_string().into())).await.is_err() {
                    break;
                }
            }
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(ref text))) => {
                        info!("echo: {}", text);
                        if write.send(Message::Text(text.clone())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = write.send(Message::Pong(data)).await;
                    }
                    Some(Err(e)) => {
                        warn!("WS error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    info!("WS session ended (sent {} heartbeats)", seq);
}
