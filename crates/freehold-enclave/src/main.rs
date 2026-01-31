//! Freehold Enclave Binary
//!
//! This binary runs inside a Gramine SGX enclave and communicates with
//! the untrusted freehold-server via a Unix socket.
//!
//! Protocol:
//! - Request/Response over Unix socket
//! - JSON-encoded messages
//! - Server sends requests, enclave responds

use freehold_api::{ATTESTATION_NONCE_SIZE, COOKIE_SIZE};
use freehold_enclave::{Enclave, EnclaveError};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

/// Socket path for enclave communication
const SOCKET_PATH: &str = "/tmp/freehold-enclave.sock";

/// Request from untrusted server to enclave
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Request {
    /// Initialize enclave with secret
    Init { secret_hex: String },
    /// Generate cookie for registration
    GenerateCookie {
        ip: String,
        port: u16,
        time_bucket: u64,
    },
    /// Verify cookie
    VerifyCookie {
        ip: String,
        port: u16,
        cookie_hex: String,
        current_bucket: u64,
    },
    /// Generate attestation quote
    GenerateQuote { nonce_hex: String },
    /// Shutdown enclave
    Shutdown,
}

/// Response from enclave to untrusted server
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Response {
    /// Initialization success
    InitOk,
    /// Cookie generated
    Cookie { cookie_hex: String },
    /// Cookie verification result
    Verified { valid: bool },
    /// Attestation quote
    Quote {
        quote_hex: String,
        collateral_hex: String,
    },
    /// Error response
    Error { message: String },
    /// Shutdown acknowledgment
    ShutdownOk,
}

fn main() {
    eprintln!("[enclave] Freehold enclave starting...");

    // Remove stale socket
    let _ = std::fs::remove_file(SOCKET_PATH);

    // Create socket directory if needed
    if let Some(parent) = PathBuf::from(SOCKET_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Listen for connections
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[enclave] Failed to bind socket: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("[enclave] Listening on {}", SOCKET_PATH);

    // Enclave state (initialized on first Init request)
    let mut enclave: Option<Enclave> = None;

    // Accept connections (single-threaded for simplicity)
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_connection(stream, &mut enclave) {
                    eprintln!("[enclave] Connection error: {}", e);
                }
                // Check if we should shutdown
                if enclave.is_none() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("[enclave] Accept error: {}", e);
            }
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(SOCKET_PATH);
    eprintln!("[enclave] Shutdown complete");
}

fn handle_connection(
    stream: UnixStream,
    enclave: &mut Option<Enclave>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            // Connection closed
            break;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                send_response(
                    &mut writer,
                    &Response::Error {
                        message: format!("parse error: {}", e),
                    },
                )?;
                continue;
            }
        };

        let response = handle_request(request, enclave);
        send_response(&mut writer, &response)?;

        // Check for shutdown
        if matches!(response, Response::ShutdownOk) {
            *enclave = None;
            break;
        }
    }

    Ok(())
}

fn handle_request(request: Request, enclave: &mut Option<Enclave>) -> Response {
    match request {
        Request::Init { secret_hex } => {
            let secret = match hex::decode(&secret_hex) {
                Ok(s) => s,
                Err(e) => {
                    return Response::Error {
                        message: format!("invalid secret hex: {}", e),
                    }
                }
            };

            match Enclave::new(&secret) {
                Ok(e) => {
                    *enclave = Some(e);
                    eprintln!("[enclave] Initialized with secret");
                    Response::InitOk
                }
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }

        Request::GenerateCookie {
            ip,
            port,
            time_bucket,
        } => {
            let enc = match enclave.as_ref() {
                Some(e) => e,
                None => {
                    return Response::Error {
                        message: "enclave not initialized".to_string(),
                    }
                }
            };

            let ip: Ipv4Addr = match ip.parse() {
                Ok(i) => i,
                Err(e) => {
                    return Response::Error {
                        message: format!("invalid IP: {}", e),
                    }
                }
            };

            let cookie = enc.generate_cookie(ip, port, time_bucket);
            Response::Cookie {
                cookie_hex: hex::encode(cookie.bytes),
            }
        }

        Request::VerifyCookie {
            ip,
            port,
            cookie_hex,
            current_bucket,
        } => {
            let enc = match enclave.as_ref() {
                Some(e) => e,
                None => {
                    return Response::Error {
                        message: "enclave not initialized".to_string(),
                    }
                }
            };

            let ip: Ipv4Addr = match ip.parse() {
                Ok(i) => i,
                Err(e) => {
                    return Response::Error {
                        message: format!("invalid IP: {}", e),
                    }
                }
            };

            let cookie_bytes = match hex::decode(&cookie_hex) {
                Ok(b) if b.len() == COOKIE_SIZE => {
                    let mut arr = [0u8; COOKIE_SIZE];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return Response::Error {
                        message: format!("invalid cookie length: {}", b.len()),
                    }
                }
                Err(e) => {
                    return Response::Error {
                        message: format!("invalid cookie hex: {}", e),
                    }
                }
            };

            let valid = enc.verify_cookie(ip, port, &cookie_bytes, current_bucket);
            Response::Verified { valid }
        }

        Request::GenerateQuote { nonce_hex } => {
            let enc = match enclave.as_ref() {
                Some(e) => e,
                None => {
                    return Response::Error {
                        message: "enclave not initialized".to_string(),
                    }
                }
            };

            let nonce_bytes = match hex::decode(&nonce_hex) {
                Ok(b) if b.len() == ATTESTATION_NONCE_SIZE => {
                    let mut arr = [0u8; ATTESTATION_NONCE_SIZE];
                    arr.copy_from_slice(&b);
                    arr
                }
                Ok(b) => {
                    return Response::Error {
                        message: format!("invalid nonce length: {}", b.len()),
                    }
                }
                Err(e) => {
                    return Response::Error {
                        message: format!("invalid nonce hex: {}", e),
                    }
                }
            };

            match enc.generate_quote(&nonce_bytes) {
                Ok(attestation) => Response::Quote {
                    quote_hex: hex::encode(&attestation.quote),
                    collateral_hex: hex::encode(&attestation.collateral),
                },
                Err(EnclaveError::AttestationNotAvailable) => Response::Error {
                    message: "attestation not available (SGX not enabled)".to_string(),
                },
                Err(e) => Response::Error {
                    message: e.to_string(),
                },
            }
        }

        Request::Shutdown => {
            eprintln!("[enclave] Shutdown requested");
            Response::ShutdownOk
        }
    }
}

fn send_response(
    writer: &mut UnixStream,
    response: &Response,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(response)?;
    writeln!(writer, "{}", json)?;
    writer.flush()?;
    Ok(())
}
