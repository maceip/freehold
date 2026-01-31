//! Freehold Windows Client Entry Point

use anyhow::Result;
use freehold_client_core::Engine;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Create status channel
    let (status_tx, status_rx) = mpsc::channel(100);

    // Default relay address (TODO: make configurable)
    let default_relay: SocketAddr = "127.0.0.1:7878".parse()?;
    let default_port = 8080;
    let auto_discover = true;

    // Create engine with default config
    let engine = Engine::new(default_relay, default_port, auto_discover, status_tx)?;

    // Run the Windows tray app
    freehold_platform_windows::run(engine, status_rx).await
}
