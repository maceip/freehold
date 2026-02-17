//! Scute service binary — JSON-over-stdio bridge to freehold-client-core.
//!
//! Usage:
//!   scute-service '{"port": 3000}'
//!   scute-service '{"port": 3000, "relay": "freehold.lit.app:9999"}'
//!
//! Reads config from first CLI argument (JSON string).
//! Writes JSON events to stdout, one per line.
//! Reads commands from stdin (JSON lines). Supports: {"cmd": "stop"}
//! Exits on stdin EOF or SIGTERM.

use anyhow::{Context, Result};
use freehold_scute::{ScuteConfig, ScuteEvent};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, watch};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("freehold=info,freehold_client_core=info,freehold_h3_proxy=info")
        .with_writer(std::io::stderr)
        .init();

    let config_json = std::env::args()
        .nth(1)
        .context("usage: scute-service '<json config>'")?;

    let config: ScuteConfig =
        serde_json::from_str(&config_json).context("invalid config JSON")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ScuteEvent>();

    // Stdout writer — serialize events as JSON lines
    let stdout_task = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&event) {
                // Use println! which is line-buffered
                println!("{}", json);
            }
        }
    });

    // Stdin reader — watch for stop command or EOF
    let shutdown_tx2 = shutdown_tx.clone();
    let stdin_task = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            // Parse command
            if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&line) {
                if cmd.get("cmd").and_then(|v| v.as_str()) == Some("stop") {
                    let _ = shutdown_tx2.send(true);
                    break;
                }
            }
        }
        // stdin closed — shutdown
        let _ = shutdown_tx2.send(true);
    });

    // Handle SIGTERM/SIGINT
    let shutdown_tx3 = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx3.send(true);
    });

    // Run the service
    let service_result = freehold_scute::run_service(config, event_tx, shutdown_rx).await;

    // Clean up
    let _ = shutdown_tx.send(true);
    stdin_task.abort();
    stdout_task.abort();

    service_result
}
