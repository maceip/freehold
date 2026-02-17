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

mod service;
mod update;

#[derive(Parser)]
#[command(
    name = "freehold",
    version,
    about = "Expose your service through Freehold"
)]
struct Args {
    /// Relay server address (hostname:port or ip:port)
    #[clap(short, long, default_value = "freehold.lit.app:9999")]
    relay: String,

    /// Port to claim on the relay (random if not specified)
    #[clap(short, long)]
    port: Option<u16>,

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

    /// Run in local mode (H3 proxy only, no relay registration)
    #[clap(long)]
    local: bool,

    // --- Service Options ---
    /// Install Freehold as a startup service
    #[clap(long)]
    install: bool,

    /// Uninstall Freehold startup service
    #[clap(long)]
    uninstall: bool,

    /// Disable automatic update check on startup
    #[clap(long)]
    no_update: bool,

    /// Check for and install updates
    #[clap(long)]
    update: bool,

    /// Show service installation status
    #[clap(long)]
    status: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("freehold=info,freehold_client_core=debug,freehold_h3_proxy=debug")
        .init();

    let args = Args::parse();

    // Handle service commands
    if args.install {
        service::install()?;
        println!("Freehold installed as startup service");
        return Ok(());
    }

    if args.uninstall {
        service::uninstall()?;
        println!("Freehold uninstalled from startup");
        return Ok(());
    }

    if args.status {
        if service::is_installed() {
            println!("Freehold is installed as a startup service");
        } else {
            println!("Freehold is not installed as a startup service");
        }
        return Ok(());
    }

    // Handle update command
    if args.update {
        update::self_update().await?;
        return Ok(());
    }

    // Check for updates in background (unless disabled)
    if !args.no_update {
        update::check_update_background();
    }

    let (status_tx, status_rx) = mpsc::channel(32);

    // Local mode: H3 proxy only, no relay registration
    if args.local {
        let backend = args
            .backend
            .ok_or_else(|| anyhow::anyhow!("--backend is required in --local mode"))?;
        let port = args
            .port
            .ok_or_else(|| anyhow::anyhow!("--port is required in --local mode"))?;
        info!("Starting Freehold in local mode (H3 proxy only)");
        return run_local_h3_proxy(args, port, backend).await;
    }

    // Resolve relay address (supports both hostname:port and ip:port)
    let relay_addr = tokio::net::lookup_host(&args.relay)
        .await
        .context(format!("Failed to resolve relay address: {}", args.relay))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("No addresses found for relay: {}", args.relay))?;

    // Determine port - if not specified, start demo HTTP server on random port
    let (port, _demo_server) = if let Some(p) = args.port {
        (p, None)
    } else {
        // Demo mode: start embedded HTTP server on random port
        let (server, port) = start_demo_http_server().await?;
        info!("Demo mode: started HTTP server on port {}", port);
        (port, Some(server))
    };

    info!(
        "Starting Freehold - claiming port {} via {} ({})",
        port, args.relay, relay_addr
    );

    // Determine if we're in H3 proxy mode
    if let Some(backend) = args.backend {
        run_with_h3_proxy(args, relay_addr, port, backend, status_tx, status_rx).await
    } else {
        // Registration-only mode
        let engine = Engine::new(relay_addr, port, args.discover, status_tx)?;

        if args.headless {
            run_headless(engine, status_rx).await
        } else {
            run_with_tray(engine, status_rx).await
        }
    }
}

/// Start a simple demo HTTP server on a random port
async fn start_demo_http_server() -> Result<(tokio::task::JoinHandle<()>, u16)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, addr)) = listener.accept().await {
                info!("Demo server: connection from {}", addr);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;

                    let response = "HTTP/1.1 200 OK\r\n\
                        Content-Type: text/html\r\n\
                        Content-Length: 147\r\n\
                        \r\n\
                        <html><body style=\"font-family:system-ui;text-align:center;padding:50px\">\
                        <h1>Freehold Demo</h1>\
                        <p>Your service is reachable!</p>\
                        </body></html>";

                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    Ok((handle, port))
}

/// Run in local mode (H3 proxy only, no relay registration)
async fn run_local_h3_proxy(args: Args, port: u16, backend: SocketAddr) -> Result<()> {
    use freehold_client_core::{generate_self_signed_cert, CertificateDer, H3Proxy, H3ProxyConfig};

    let h3_bind = args
        .h3_bind
        .unwrap_or_else(|| format!("0.0.0.0:{}", port).parse().unwrap());

    info!("H3 proxy (local): {} -> backend {}", h3_bind, backend);

    // Load or generate certs
    let (certs, key) = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        info!("Loading TLS cert from {:?}", cert_path);

        let cert_pem = std::fs::read(cert_path).context("read certificate file")?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parse certificates")?;

        let key_pem = std::fs::read(key_path).context("read key file")?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parse private key")?
            .context("no private key found")?;

        (certs, key)
    } else {
        info!("Generating self-signed cert for {}", args.domain);
        generate_self_signed_cert(&[&args.domain])?
    };

    // Clone certs for TCP Alt-Svc announcer
    let tcp_certs = certs.clone();
    let tcp_key = key.clone_key();
    let tcp_port = port;

    let proxy = H3Proxy::new(H3ProxyConfig {
        bind_addr: h3_bind,
        backend,
        certs,
        key,
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn TCP Alt-Svc announcer
    let tcp_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = run_tcp_alt_svc_announcer(tcp_certs, tcp_key, tcp_port, tcp_shutdown).await
        {
            tracing::error!("TCP Alt-Svc announcer error: {}", e);
        }
    });

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx.send(true);
    });

    proxy.run(shutdown_rx).await
}

/// TCP listener that does TLS handshake and sends Alt-Svc header pointing to H3
async fn run_tcp_alt_svc_announcer(
    certs: Vec<freehold_client_core::CertificateDer<'static>>,
    key: freehold_client_core::PrivateKeyDer<'static>,
    port: u16,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use rustls::ServerConfig;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build TLS config")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .context("bind TCP listener")?;

    info!("TCP Alt-Svc announcer listening on 0.0.0.0:{}", port);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("TCP Alt-Svc announcer shutting down");
                    break;
                }
            }
            result = listener.accept() => {
                let (stream, addr) = result.context("accept TCP connection")?;
                let acceptor = acceptor.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(mut tls_stream) => {
                            info!("TCP connection from {} - sending Alt-Svc", addr);

                            // Read request (just consume it)
                            let mut buf = [0u8; 4096];
                            let _ = tls_stream.read(&mut buf).await;

                            // Send response with Alt-Svc header
                            let response = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Alt-Svc: h3=\":{}\" ; ma=86400\r\n\
                                 Content-Length: 0\r\n\
                                 Connection: close\r\n\
                                 \r\n",
                                port
                            );

                            let _ = tls_stream.write_all(response.as_bytes()).await;
                            let _ = tls_stream.shutdown().await;
                        }
                        Err(e) => {
                            tracing::debug!("TLS handshake failed from {}: {}", addr, e);
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

/// Run with H3 proxy (full service mode with relay registration)
async fn run_with_h3_proxy(
    args: Args,
    relay_addr: SocketAddr,
    port: u16,
    backend: SocketAddr,
    status_tx: mpsc::Sender<StatusUpdate>,
    mut status_rx: mpsc::Receiver<StatusUpdate>,
) -> Result<()> {
    use freehold_client_core::{
        create_service_with_self_signed_cert, CertificateDer, Service, ServiceConfig,
    };

    // Determine H3 bind address
    let h3_bind = args
        .h3_bind
        .unwrap_or_else(|| format!("0.0.0.0:{}", port).parse().unwrap());

    info!("H3 proxy mode: {} -> backend {}", h3_bind, backend);

    // Create service - use provided certs or generate self-signed
    let service = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
        info!("Loading TLS cert from {:?}", cert_path);

        // Load certificate chain
        let cert_pem = std::fs::read(cert_path).context("read certificate file")?;
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parse certificates")?;

        // Load private key
        let key_pem = std::fs::read(key_path).context("read key file")?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("parse private key")?
            .context("no private key found")?;

        Service::new(
            ServiceConfig {
                relay: relay_addr,
                relay_port: port,
                h3_bind,
                backend,
                certs,
                key,
                auto_discover: args.discover,
                acme_cache_dir: None,
                dns_zone: None,
            },
            status_tx,
        )
        .context("create service with provided certs")?
    } else {
        create_service_with_self_signed_cert(
            relay_addr,
            port,
            h3_bind,
            backend,
            &args.domain,
            args.discover,
            status_tx,
        )
        .context("create service with self-signed cert")?
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
                StatusUpdate::Traffic { sent, received } => {
                    tracing::debug!("Traffic: sent {} received {}", sent, received);
                }
                StatusUpdate::PortChanged { port } => {
                    info!("Port changed to {}", port);
                }
                StatusUpdate::SubdomainAssigned(sub) => {
                    info!("Subdomain assigned: {}", sub);
                }
                StatusUpdate::AcmeCertReady => {
                    info!("ACME certificate ready");
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
async fn run_with_tray(engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    freehold_platform_macos::run(engine, status_rx).await
}

#[cfg(target_os = "windows")]
async fn run_with_tray(engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    freehold_platform_windows::run(engine, status_rx).await
}

#[cfg(target_os = "linux")]
async fn run_with_tray(engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    freehold_platform_linux::run(engine, status_rx).await
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
async fn run_with_tray(engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    tracing::warn!("No tray support for this platform, running headless");
    run_headless(engine, status_rx).await
}
