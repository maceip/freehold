//! H3/QUIC static file server using quinn.
//!
//! Usage:
//!   h3-server --root ./website --port 4433
//!
//! This is a working HTTP/3 server that:
//! - Generates a self-signed cert on startup (or uses provided certs)
//! - Serves static files over HTTP/3
//! - Can be tested with: curl --http3-only -k https://localhost:4433/

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use http::{Request, Response, StatusCode};
use tracing::{debug, error, info, warn};

use h3::quic::BidiStream;
use h3::server::RequestStream;
use quinn::crypto::rustls::QuicServerConfig;

#[derive(Parser, Debug)]
#[command(name = "h3-server", about = "H3/QUIC static file server")]
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Install ring as the default crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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

    // Verify root directory exists
    if !args.root.exists() {
        anyhow::bail!("Root directory does not exist: {:?}", args.root);
    }

    // Get or generate TLS credentials
    let (certs, key) = match (&args.cert, &args.key) {
        (Some(cert_path), Some(key_path)) => load_certs_from_files(cert_path, key_path)?,
        _ => {
            info!("Generating self-signed certificate...");
            generate_self_signed_cert()?
        }
    };

    // Run the server
    run_server(&args, certs, key).await?;

    Ok(())
}

fn load_certs_from_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    let cert_pem = fs::read(cert_path).context("Failed to read certificate file")?;
    let key_pem = fs::read(key_path).context("Failed to read key file")?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("Failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in file"))?;

    Ok((certs, key))
}

fn generate_self_signed_cert() -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate()?;
    let params = CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("Failed to convert key: {:?}", e))?;

    info!("Self-signed certificate generated for localhost");

    Ok((vec![cert_der], key_der))
}

async fn run_server(
    args: &Args,
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<()> {
    // Create rustls config
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS config")?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.max_early_data_size = u32::MAX;

    // Create QUIC server config
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config).context("Failed to create QUIC server config")?,
    ));

    // Bind endpoint
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .context("Failed to bind QUIC endpoint")?;

    info!("Listening on https://{}", bind_addr);
    info!("");
    info!("Test with:");
    info!("  curl --http3-only -k https://localhost:{}/", args.port);
    info!("");

    let root = args.root.clone();

    // Accept connections
    while let Some(incoming) = endpoint.accept().await {
        let root = root.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, root).await {
                warn!("Connection error: {:?}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming, root: PathBuf) -> Result<()> {
    let connection = incoming.await.context("Failed to accept connection")?;

    info!(
        "New connection from {}",
        connection.remote_address()
    );

    // Create H3 connection
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .context("Failed to create H3 connection")?;

    // Handle requests
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let root = root.clone();

                tokio::spawn(async move {
                    // Resolve the request to get headers and stream
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = handle_request(request, stream, root).await {
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
                // Connection closed with NO_ERROR is normal (client done)
                debug!("Connection ended: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request<S>(
    request: Request<()>,
    mut stream: RequestStream<S, Bytes>,
    root: PathBuf,
) -> Result<()>
where
    S: BidiStream<Bytes>,
{
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    info!("{} {}", method, path);

    // Only handle GET requests
    if method != http::Method::GET {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .unwrap();

        stream.send_response(response).await?;
        stream.send_data(Bytes::from("Method Not Allowed")).await?;
        stream.finish().await?;
        return Ok(());
    }

    // Serve file
    let (status, content_type, body) = serve_file(&root, &path);

    let response = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();

    stream.send_response(response).await?;

    // Send body in chunks
    const CHUNK_SIZE: usize = 16384;
    for chunk in body.chunks(CHUNK_SIZE) {
        stream.send_data(Bytes::copy_from_slice(chunk)).await?;
    }

    // Finish the stream - ignore errors if client already closed
    // (client may close after receiving all data, which is normal)
    if let Err(e) = stream.finish().await {
        debug!("Stream finish: {} (client may have closed)", e);
    }

    debug!("{} {} -> {} ({} bytes)", method, path, status.as_u16(), body.len());

    Ok(())
}

fn serve_file(root: &PathBuf, path: &str) -> (StatusCode, &'static str, Vec<u8>) {
    // Normalize path
    let path = if path == "/" { "/index.html" } else { path };
    let path = path.trim_start_matches('/');

    // Prevent directory traversal
    if path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            "text/plain",
            b"Bad Request".to_vec(),
        );
    }

    let file_path = root.join(path);

    // Check if file exists
    if !file_path.exists() || !file_path.is_file() {
        debug!("404: {:?}", file_path);
        return (
            StatusCode::NOT_FOUND,
            "text/plain",
            b"Not Found".to_vec(),
        );
    }

    // Read file
    match fs::read(&file_path) {
        Ok(contents) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream();

            let content_type = match mime.type_().as_str() {
                "text" => match mime.subtype().as_str() {
                    "html" => "text/html; charset=utf-8",
                    "css" => "text/css; charset=utf-8",
                    "javascript" => "text/javascript; charset=utf-8",
                    "plain" => "text/plain; charset=utf-8",
                    _ => "text/plain; charset=utf-8",
                },
                "application" => match mime.subtype().as_str() {
                    "javascript" => "application/javascript; charset=utf-8",
                    "json" => "application/json; charset=utf-8",
                    _ => "application/octet-stream",
                },
                "image" => match mime.subtype().as_str() {
                    "png" => "image/png",
                    "jpeg" => "image/jpeg",
                    "gif" => "image/gif",
                    "svg+xml" => "image/svg+xml",
                    "webp" => "image/webp",
                    _ => "application/octet-stream",
                },
                _ => "application/octet-stream",
            };

            (StatusCode::OK, content_type, contents)
        }
        Err(e) => {
            error!("Failed to read file {:?}: {}", file_path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                b"Internal Server Error".to_vec(),
            )
        }
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

        let (status, content_type, body) = serve_file(&dir.path().to_path_buf(), "/");

        assert_eq!(status, StatusCode::OK);
        assert!(content_type.contains("html"));
        assert_eq!(body, b"<html>test</html>");
    }

    #[test]
    fn test_serve_file_not_found() {
        let dir = tempdir().unwrap();
        let (status, _, _) = serve_file(&dir.path().to_path_buf(), "/nonexistent.txt");
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_serve_file_directory_traversal() {
        let dir = tempdir().unwrap();
        let (status, _, _) = serve_file(&dir.path().to_path_buf(), "/../etc/passwd");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_serve_file_js() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("app.js"), "console.log('test')").unwrap();

        let (status, content_type, _) = serve_file(&dir.path().to_path_buf(), "/app.js");

        assert_eq!(status, StatusCode::OK);
        assert!(content_type.contains("javascript"));
    }

    #[test]
    fn test_serve_file_css() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("style.css"), "body { color: red; }").unwrap();

        let (status, content_type, _) = serve_file(&dir.path().to_path_buf(), "/style.css");

        assert_eq!(status, StatusCode::OK);
        assert!(content_type.contains("css"));
    }

    #[test]
    fn test_generate_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }
}
