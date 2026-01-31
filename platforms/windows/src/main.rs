//! Freehold Windows Client Entry Point

use anyhow::Result;
use freehold_client_core::Engine;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Create status channel
    let (status_tx, status_rx) = mpsc::channel(100);

    // Create engine with default config
    let engine = Engine::new(status_tx)?;

    // Run the Windows tray app
    freehold_platform_windows::run(engine, status_rx).await
}
