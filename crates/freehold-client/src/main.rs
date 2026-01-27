//! Freehold Client - Desktop tray application
//!
//! This is the "Shell" that dispatches to platform-specific UI implementations.

use anyhow::{Context, Result};
use clap::Parser;
use freehold_client_core::{Engine, StatusUpdate};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Parser)]
#[command(name = "freehold", about = "Expose your service through Freehold")]
struct Args {
    /// Relay server address
    #[clap(short, long)]
    relay: SocketAddr,

    /// Port to claim on the relay
    #[clap(short, long)]
    port: u16,

    /// Auto-discover and register with neighbors
    #[clap(long, default_value = "true")]
    discover: bool,

    /// Run headless (no tray UI)
    #[clap(long)]
    headless: bool,

    // --- H3 Proxy Options ---
    /// Local HTTP backend to proxy to (enables H3 proxy mode)
    #[clap(long)]
    backend: Option<SocketAddr>,

    /// Address to bind H3/QUIC server (default: 0.0.0.0:<port>)
    #[clap(long)]
    h3_bind: Option<SocketAddr>,

    /// Path to TLS certificate (PEM). If not provided, generates self-signed.
    #[clap(long)]
    cert: Option<PathBuf>,

    /// Path to TLS private key (PEM). Required if --cert is provided.
    #[clap(long)]
    key: Option<PathBuf>,

    /// Domain name for self-signed certificate
    #[clap(long, default_value = "localhost")]
    domain: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("freehold=info,freehold_client_core=debug,freehold_h3_proxy=debug")
        .init();

    let args = Args::parse();
    let (status_tx, status_rx) = mpsc::channel(32);

    info!("Starting Freehold - claiming port {} via {}", args.port, args.relay);

    // Determine if we're in H3 proxy mode
    if let Some(backend) = args.backend {
        run_with_h3_proxy(args, backend, status_tx, status_rx).await
    } else {
        // Registration-only mode
        let engine = Engine::new(args.relay, args.port, args.discover, status_tx)?;

        if args.headless {
            run_headless(engine, status_rx).await
        } else {
            run_with_tray(engine, status_rx).await
        }
    }
}

/// Run with H3 proxy (full service mode)
async fn run_with_h3_proxy(
    args: Args,
    backend: SocketAddr,
    status_tx: mpsc::Sender<StatusUpdate>,
    mut status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    use freehold_client_core::{
        create_service_with_self_signed_cert, Service, ServiceConfig,
        CertificateDer,
    };

    // Determine H3 bind address
    let h3_bind = args.h3_bind.unwrap_or_else(|| {
        format!("0.0.0.0:{}", args.port).parse().unwrap()
    });

    info!(
        "H3 proxy mode: {} -> backend {}",
        h3_bind, backend
    );

    // Create service - use provided certs or generate self-signed
    let service = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        info!("Loading TLS cert from {:?}", cert_path);

        // Load certificate chain
        let cert_pem = std::fs::read(cert_path)
            .context("read certificate file")?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parse certificates")?;

        // Load private key
        let key_pem = std::fs::read(key_path)
            .context("read key file")?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parse private key")?
            .context("no private key found")?;

        Service::new(
            ServiceConfig {
                relay: args.relay,
                relay_port: args.port,
                h3_bind,
                backend,
                certs,
                key,
                auto_discover: args.discover,
            },
            status_tx,
        ).context("create service with provided certs")?
    } else {
        create_service_with_self_signed_cert(
            args.relay,
            args.port,
            h3_bind,
            backend,
            &args.domain,
            args.discover,
            status_tx,
        ).context("create service with self-signed cert")?
    };

    // Spawn status printer
    tokio::spawn(async move {
        while let Some(update) = status_rx.recv().await {
            match &update {
                StatusUpdate::RelayState { addr, state } => {
                    info!("Relay {} -> {:?}", addr, state);
                }
                StatusUpdate::NeighborDiscovered(ip) => {
                    info!("Discovered neighbor: {}", ip);
                }
                StatusUpdate::Error(e) => {
                    info!("Error: {}", e);
                }
            }
        }
    });

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx_clone.send(true);
    });

    service.run(shutdown_rx).await
}

async fn run_headless(
    mut engine: Engine,
    mut status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    // Spawn status printer
    tokio::spawn(async move {
        while let Some(update) = status_rx.recv().await {
            info!("Status: {:?}", update);
        }
    });

    engine.run().await
}

#[cfg(target_os = "macos")]
async fn run_with_tray(
    engine: Engine,
    status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    freehold_platform_macos::run(engine, status_rx).await
}

#[cfg(target_os = "windows")]
async fn run_with_tray(
    engine: Engine,
    status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    freehold_platform_windows::run(engine, status_rx).await
}

#[cfg(target_os = "linux")]
async fn run_with_tray(
    engine: Engine,
    status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    freehold_platform_linux::run(engine, status_rx).await
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
async fn run_with_tray(
    engine: Engine,
    status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    tracing::warn!("No tray support for this platform, running headless");
    run_headless(engine, status_rx).await
}
