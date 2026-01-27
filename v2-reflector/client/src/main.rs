//! Specular Sovereign Proxy
//!
//! Exposes local services to the internet via the Specular relay network.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use quinn::crypto::rustls::QuicServerConfig;
use specular_common::*;
use tokio::sync::watch;
use tracing::{debug, info, warn};

mod proxy;
mod registration;
mod tls;

use proxy::SovereignProxy;
use registration::RegistrationClient;

#[derive(Parser)]
#[command(name = "specular")]
#[command(about = "Specular Sovereign Proxy - expose local services")]
struct Args {
    /// Domain name for TLS certificate
    #[arg(short, long)]
    domain: String,

    /// Local target to proxy to (e.g., 127.0.0.1:8080)
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    target: String,

    /// Relay address (ip:port)
    #[arg(short, long)]
    relay: String,

    /// Requested port on relay (0 = auto-assign)
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    /// Local bind address for H3 server
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    bind: String,

    /// Data directory for keys and certs
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,specular=debug")
        .init();

    let args = Args::parse();

    info!("Specular Sovereign Proxy starting");
    info!("  Domain: {}", args.domain);
    info!("  Target: {}", args.target);
    info!("  Relay: {}", args.relay);

    // Set up data directory
    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("specular")
    });
    std::fs::create_dir_all(&data_dir)?;

    // Load or generate signing key
    let signing_key = load_or_generate_key(&data_dir)?;
    info!("Public key: {:?}", signing_key.verifying_key().as_bytes());

    // Load or generate TLS cert
    let (certs, key) = tls::load_or_generate_cert(&data_dir, &args.domain)?;

    // Parse addresses
    let relay_addr: SocketAddr = args.relay.parse().context("Invalid relay address")?;
    let bind_addr: SocketAddr = args.bind.parse().context("Invalid bind address")?;
    let target_addr: SocketAddr = args.target.parse().context("Invalid target address")?;

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Register with relay
    let mut reg_client = RegistrationClient::new(relay_addr, signing_key.clone());
    let assigned_port = reg_client.register(args.port).await?;
    info!("Registered on relay port {}", assigned_port);

    // Spawn heartbeat loop
    let reg_client = Arc::new(tokio::sync::Mutex::new(reg_client));
    let reg_client_clone = reg_client.clone();
    let shutdown_rx_hb = shutdown_rx.clone();
    tokio::spawn(async move {
        heartbeat_loop(reg_client_clone, assigned_port, shutdown_rx_hb).await;
    });

    // Start H3 server
    let proxy = Arc::new(SovereignProxy::new(target_addr));
    run_h3_server(bind_addr, certs, key, proxy, shutdown_rx).await?;

    // Cleanup
    let _ = shutdown_tx.send(true);

    Ok(())
}

fn load_or_generate_key(data_dir: &PathBuf) -> Result<SigningKey> {
    let key_path = data_dir.join("identity.key");

    if key_path.exists() {
        let key_bytes = std::fs::read(&key_path)?;
        if key_bytes.len() == 32 {
            let key_array: [u8; 32] = key_bytes.try_into().unwrap();
            info!("Loaded existing identity key");
            return Ok(SigningKey::from_bytes(&key_array));
        }
    }

    // Generate new key
    info!("Generating new identity key");
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    std::fs::write(&key_path, signing_key.to_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(signing_key)
}

async fn heartbeat_loop(
    reg_client: Arc<tokio::sync::Mutex<RegistrationClient>>,
    port: u16,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(HEARTBEAT_INTERVAL as u64);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Heartbeat loop shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                let mut client = reg_client.lock().await;
                match client.heartbeat(port).await {
                    Ok(ttl) => debug!("Heartbeat OK, TTL: {}s", ttl),
                    Err(e) => warn!("Heartbeat failed: {}", e),
                }
            }
        }
    }
}

async fn run_h3_server(
    bind_addr: SocketAddr,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    proxy: Arc<SovereignProxy>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Create TLS config
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.max_early_data_size = u32::MAX;

    let quic_config = QuicServerConfig::try_from(tls_config)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    info!("H3 server listening on {}", bind_addr);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("H3 server shutting down");
                    break;
                }
            }
            incoming = endpoint.accept() => {
                match incoming {
                    Some(conn) => {
                        let proxy = proxy.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, proxy).await {
                                debug!("Connection error: {:?}", e);
                            }
                        });
                    }
                    None => break,
                }
            }
        }
    }

    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    proxy: Arc<SovereignProxy>,
) -> Result<()> {
    let connection = incoming.await?;
    let remote = connection.remote_address();
    info!("New H3 connection from {}", remote);

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let proxy = proxy.clone();
                let remote = remote;
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = proxy.handle_request(request, stream, remote).await {
                                warn!("Request error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to resolve request: {:?}", e);
                        }
                    }
                });
            }
            Ok(None) => {
                debug!("Connection closed gracefully");
                break;
            }
            Err(e) => {
                debug!("Connection ended: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}
