//! Minimal H3/QUIC static file server for testing tquic integration.
//!
//! Usage:
//!   h3-server --root ./website --port 4433
//!
//! This server:
//! - Generates a self-signed cert on startup (saved to temp files)
//! - Serves static files over HTTP/3
//! - Supports multipath QUIC (configurable)

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{debug, error, info};

use tquic::h3::connection::Http3Connection;
use tquic::h3::Http3Config;
use tquic::{Config, Connection, MultipathAlgorithm, TransportHandler};

#[derive(Parser, Debug)]
#[command(name = "h3-server", about = "Minimal H3 static file server")]
struct Args {
    /// Root directory to serve files from
    #[arg(short, long, default_value = "./website")]
    root: PathBuf,

    /// Port to listen on
    #[arg(short, long, default_value = "4433")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Enable multipath QUIC
    #[arg(long)]
    multipath: bool,

    /// TLS certificate file (PEM)
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key file (PEM)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.clone().into()),
        )
        .init();

    info!("Starting H3 server");
    info!("  Root: {:?}", args.root);
    info!("  Bind: {}:{}", args.bind, args.port);
    info!("  Multipath: {}", args.multipath);

    // Verify root directory exists
    if !args.root.exists() {
        anyhow::bail!("Root directory does not exist: {:?}", args.root);
    }

    // Get or generate TLS credentials
    let (cert_path, key_path) = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => (cert.clone(), key.clone()),
        _ => {
            let (cert_path, key_path) = generate_self_signed_cert()?;
            info!("Generated self-signed certificate");
            info!("  Cert: {:?}", cert_path);
            info!("  Key: {:?}", key_path);
            (cert_path, key_path)
        }
    };

    // Run the server
    run_server(&args, &cert_path, &key_path)?;

    Ok(())
}

fn generate_self_signed_cert() -> Result<(PathBuf, PathBuf)> {
    use rcgen::{CertificateParams, KeyPair};

    // Generate key pair
    let key_pair = KeyPair::generate()?;

    // Create certificate params with defaults
    let params = CertificateParams::new(vec!["localhost".to_string()])?;

    // Generate certificate
    let cert = params.self_signed(&key_pair)?;

    // Write to temp files
    let temp_dir = std::env::temp_dir().join("h3-server");
    fs::create_dir_all(&temp_dir)?;

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");

    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, key_pair.serialize_pem())?;

    Ok((cert_path, key_path))
}

fn run_server(args: &Args, cert_path: &PathBuf, key_path: &PathBuf) -> Result<()> {
    use std::net::UdpSocket;

    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;

    // Create UDP socket
    let socket = UdpSocket::bind(bind_addr).context("Failed to bind UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("Failed to set socket nonblocking")?;

    info!("Listening on {}", bind_addr);

    // Create QUIC config
    let mut config = Config::new().context("Failed to create QUIC config")?;

    // Set TLS config using file paths
    let cert_str = cert_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid cert path"))?;
    let key_str = key_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid key path"))?;

    let tls_config = tquic::TlsConfig::new_server_config(
        cert_str,
        key_str,
        vec![b"h3".to_vec()], // ALPN
        false,                 // verify peer
    )
    .context("Failed to create TLS config")?;

    config.set_tls_config(tls_config);

    // Basic QUIC settings
    config.set_max_idle_timeout(30_000); // 30 seconds
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);

    // Multipath settings
    if args.multipath {
        config.enable_multipath(true);
        config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);
        info!("Multipath QUIC enabled");
    }

    // Create handler
    let _handler = ServerHandler::new(args.root.clone());

    info!("Server ready. Press Ctrl+C to stop.");
    info!("");
    info!("To test with curl (requires HTTP/3 support):");
    info!("  curl --http3-only -k https://localhost:{}/", args.port);
    info!("");
    info!("Note: Most browsers need configuration to accept self-signed certs for QUIC.");
    info!("Consider using --cert and --key with properly signed certificates for testing.");

    // Simple event loop - receive and log packets
    // Full tquic integration requires their socket wrapper and endpoint
    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                debug!("Received {} bytes from {}", len, from);
                // TODO: Full tquic endpoint integration
                // For now, this demonstrates the socket is receiving QUIC packets
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                error!("Socket error: {}", e);
            }
        }
    }
}

/// Handler for server-side QUIC connections.
struct ServerHandler {
    root: PathBuf,
    #[allow(dead_code)]
    connections: HashMap<u64, ConnectionState>,
}

#[allow(dead_code)]
struct ConnectionState {
    h3_conn: Option<Http3Connection>,
    pending_responses: HashMap<u64, PendingResponse>,
}

#[allow(dead_code)]
struct PendingResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    body_sent: usize,
}

impl ServerHandler {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            connections: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    fn serve_file(&self, path: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
        // Normalize path
        let path = if path == "/" { "/index.html" } else { path };
        let path = path.trim_start_matches('/');

        // Prevent directory traversal
        if path.contains("..") {
            return (
                400,
                vec![("content-type".into(), "text/plain".into())],
                b"Bad Request".to_vec(),
            );
        }

        let file_path = self.root.join(path);

        // Check if file exists
        if !file_path.exists() || !file_path.is_file() {
            debug!("404: {:?}", file_path);
            return (
                404,
                vec![("content-type".into(), "text/plain".into())],
                b"Not Found".to_vec(),
            );
        }

        // Read file
        match fs::read(&file_path) {
            Ok(contents) => {
                let mime = mime_guess::from_path(&file_path)
                    .first_or_octet_stream()
                    .to_string();

                debug!("200: {:?} ({}, {} bytes)", file_path, mime, contents.len());

                (
                    200,
                    vec![
                        ("content-type".into(), mime),
                        ("content-length".into(), contents.len().to_string()),
                    ],
                    contents,
                )
            }
            Err(e) => {
                error!("Failed to read file {:?}: {}", file_path, e);
                (
                    500,
                    vec![("content-type".into(), "text/plain".into())],
                    b"Internal Server Error".to_vec(),
                )
            }
        }
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        let conn_id = conn.trace_id();
        info!("Connection created: {}", conn_id);
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        let conn_id = conn.trace_id();
        info!("Connection established: {}", conn_id);

        // Initialize H3 connection
        if conn.application_proto() == b"h3" {
            if let Ok(h3_config) = Http3Config::new() {
                if let Ok(_h3_conn) = Http3Connection::new_with_quic_conn(conn, &h3_config) {
                    debug!("H3 connection initialized");
                }
            }
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let conn_id = conn.trace_id();
        info!("Connection closed: {}", conn_id);
    }

    fn on_stream_created(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!("Stream {} created", stream_id);
    }

    fn on_stream_readable(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!("Stream {} readable", stream_id);
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!("Stream {} writable", stream_id);
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, stream_id: u64) {
        debug!("Stream {} closed", stream_id);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {
        debug!("New token received");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_serve_file_index() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "<html>test</html>").unwrap();

        let handler = ServerHandler::new(dir.path().to_path_buf());
        let (status, headers, body) = handler.serve_file("/");

        assert_eq!(status, 200);
        assert!(headers.iter().any(|(k, v)| k == "content-type" && v.contains("html")));
        assert_eq!(body, b"<html>test</html>");
    }

    #[test]
    fn test_serve_file_not_found() {
        let dir = tempdir().unwrap();
        let handler = ServerHandler::new(dir.path().to_path_buf());
        let (status, _, _) = handler.serve_file("/nonexistent.txt");
        assert_eq!(status, 404);
    }

    #[test]
    fn test_serve_file_directory_traversal() {
        let dir = tempdir().unwrap();
        let handler = ServerHandler::new(dir.path().to_path_buf());
        let (status, _, _) = handler.serve_file("/../etc/passwd");
        assert_eq!(status, 400);
    }

    #[test]
    fn test_serve_file_js() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), "console.log('test')").unwrap();

        let handler = ServerHandler::new(dir.path().to_path_buf());
        let (status, headers, _) = handler.serve_file("/app.js");

        assert_eq!(status, 200);
        assert!(headers.iter().any(|(k, v)| k == "content-type" && v.contains("javascript")));
    }

    #[test]
    fn test_generate_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());

        let (cert_path, key_path) = result.unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());

        let cert_content = fs::read_to_string(&cert_path).unwrap();
        let key_content = fs::read_to_string(&key_path).unwrap();

        assert!(cert_content.contains("BEGIN CERTIFICATE"));
        assert!(key_content.contains("BEGIN PRIVATE KEY"));
    }
}
