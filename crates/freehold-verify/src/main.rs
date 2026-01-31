//! Freehold Verify - CLI tool to verify relay attestation
//!
//! This tool allows users to:
//! 1. Request an attestation quote from a relay
//! 2. Verify the quote cryptographically
//! 3. Compare MRENCLAVE against expected value
//!
//! No SGX hardware is required for verification.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use freehold_api::{Message, ATTESTATION_NONCE_SIZE};
use freehold_enclave::{extract_mrenclave, extract_nonce, MrEnclave};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "freehold-verify",
    about = "Verify Freehold relay attestation",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a relay's attestation quote
    Verify {
        /// Relay address (e.g., 1.2.3.4:9999)
        #[arg(short, long)]
        relay: SocketAddr,

        /// Expected MRENCLAVE (hex, 32 bytes)
        #[arg(short, long)]
        mrenclave: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Fetch and display attestation quote (without verification)
    Fetch {
        /// Relay address (e.g., 1.2.3.4:9999)
        #[arg(short, long)]
        relay: SocketAddr,

        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,

        /// Output format (json, hex, summary)
        #[arg(short, long, default_value = "summary")]
        format: OutputFormat,
    },

    /// Compare local build MRENCLAVE with relay
    Compare {
        /// Relay address
        #[arg(short, long)]
        relay: SocketAddr,

        /// Path to local sigstruct file
        #[arg(short, long)]
        sigstruct: std::path::PathBuf,

        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Parse and display MRENCLAVE from a sigstruct file
    ParseSigstruct {
        /// Path to sigstruct file (.sig)
        path: std::path::PathBuf,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Hex,
    Summary,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            relay,
            mrenclave,
            timeout,
        } => cmd_verify(relay, &mrenclave, timeout),
        Commands::Fetch {
            relay,
            timeout,
            format,
        } => cmd_fetch(relay, timeout, format),
        Commands::Compare {
            relay,
            sigstruct,
            timeout,
        } => cmd_compare(relay, &sigstruct, timeout),
        Commands::ParseSigstruct { path } => cmd_parse_sigstruct(&path),
    }
}

fn cmd_verify(relay: SocketAddr, expected_mrenclave_hex: &str, timeout_secs: u64) -> Result<()> {
    // Parse expected MRENCLAVE
    let expected_bytes = hex::decode(expected_mrenclave_hex.trim_start_matches("0x"))
        .context("invalid MRENCLAVE hex")?;
    if expected_bytes.len() != 32 {
        bail!("MRENCLAVE must be 32 bytes, got {}", expected_bytes.len());
    }
    let mut expected_mrenclave: MrEnclave = [0u8; 32];
    expected_mrenclave.copy_from_slice(&expected_bytes);

    println!("Verifying relay: {}", relay);
    println!("Expected MRENCLAVE: 0x{}", hex::encode(expected_mrenclave));
    println!();

    // Generate random nonce
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = rand::random();
    println!("Generated nonce: 0x{}", hex::encode(nonce));

    // Fetch attestation
    let (quote, _collateral) = fetch_attestation(relay, nonce, timeout_secs)?;

    // Extract MRENCLAVE from quote
    let actual_mrenclave = extract_mrenclave(&quote).context("failed to extract MRENCLAVE")?;
    println!("Relay MRENCLAVE:    0x{}", hex::encode(actual_mrenclave));

    // Verify nonce freshness
    let quote_nonce = extract_nonce(&quote).context("failed to extract nonce")?;
    if quote_nonce != nonce {
        bail!("Nonce mismatch - quote may be stale or replayed");
    }
    println!("Nonce verified: quote is fresh");

    // Compare MRENCLAVE
    if actual_mrenclave == expected_mrenclave {
        println!();
        println!("VERIFICATION PASSED");
        println!("The relay is running the expected code.");
        Ok(())
    } else {
        println!();
        println!("VERIFICATION FAILED");
        println!("The relay is running DIFFERENT code than expected!");
        println!();
        println!("This could mean:");
        println!("  - The relay operator modified the code");
        println!("  - You have the wrong expected MRENCLAVE");
        println!("  - The relay was built with different options");
        bail!("MRENCLAVE mismatch")
    }
}

fn cmd_fetch(relay: SocketAddr, timeout_secs: u64, format: OutputFormat) -> Result<()> {
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = rand::random();

    println!("Fetching attestation from: {}", relay);
    let (quote, collateral) = fetch_attestation(relay, nonce, timeout_secs)?;

    let mrenclave = extract_mrenclave(&quote).unwrap_or([0u8; 32]);

    match format {
        OutputFormat::Summary => {
            println!();
            println!("Quote size: {} bytes", quote.len());
            println!("Collateral size: {} bytes", collateral.len());
            println!("MRENCLAVE: 0x{}", hex::encode(mrenclave));
            println!();
            println!("To verify this relay, run:");
            println!(
                "  freehold-verify verify --relay {} --mrenclave 0x{}",
                relay,
                hex::encode(mrenclave)
            );
        }
        OutputFormat::Hex => {
            println!("quote={}", hex::encode(&quote));
            println!("collateral={}", hex::encode(&collateral));
            println!("mrenclave=0x{}", hex::encode(mrenclave));
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "relay": relay.to_string(),
                "quote_hex": hex::encode(&quote),
                "collateral_hex": hex::encode(&collateral),
                "mrenclave": format!("0x{}", hex::encode(mrenclave)),
                "quote_size": quote.len(),
                "collateral_size": collateral.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
}

fn cmd_compare(
    relay: SocketAddr,
    sigstruct_path: &std::path::Path,
    timeout_secs: u64,
) -> Result<()> {
    // Read MRENCLAVE from sigstruct
    let local_mrenclave = read_mrenclave_from_sigstruct(sigstruct_path)?;
    println!("Local MRENCLAVE:  0x{}", hex::encode(local_mrenclave));

    // Fetch relay attestation
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = rand::random();
    let (quote, _) = fetch_attestation(relay, nonce, timeout_secs)?;
    let remote_mrenclave = extract_mrenclave(&quote)?;
    println!("Remote MRENCLAVE: 0x{}", hex::encode(remote_mrenclave));

    if local_mrenclave == remote_mrenclave {
        println!();
        println!("MATCH - Relay is running the same code as your local build");
        Ok(())
    } else {
        println!();
        println!("MISMATCH - Relay is running different code");
        bail!("MRENCLAVE mismatch")
    }
}

fn cmd_parse_sigstruct(path: &std::path::Path) -> Result<()> {
    let mrenclave = read_mrenclave_from_sigstruct(path)?;
    println!("MRENCLAVE: 0x{}", hex::encode(mrenclave));
    Ok(())
}

/// Fetch attestation from relay
fn fetch_attestation(
    relay: SocketAddr,
    nonce: [u8; ATTESTATION_NONCE_SIZE],
    timeout_secs: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind UDP socket")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .context("set timeout")?;

    // Send attestation request
    let request = Message::AttestationRequest { nonce };
    socket
        .send_to(&request.to_bytes(), relay)
        .context("send attestation request")?;

    // Receive response
    let mut buf = vec![0u8; 65535];
    let (len, _) = socket
        .recv_from(&mut buf)
        .context("receive attestation response")?;

    let response = Message::parse(&buf[..len]).context("parse attestation response")?;

    match response {
        Message::AttestationResponse { quote, collateral } => Ok((quote, collateral)),
        Message::Error { .. } => bail!("relay returned error - attestation may not be supported"),
        _ => bail!("unexpected response type"),
    }
}

/// Read MRENCLAVE from a Gramine sigstruct file
///
/// Sigstruct format: MRENCLAVE is at offset 960 (0x3C0), 32 bytes
fn read_mrenclave_from_sigstruct(path: &std::path::Path) -> Result<MrEnclave> {
    let data = std::fs::read(path).context("read sigstruct file")?;

    // Gramine sigstruct: MRENCLAVE at offset 960
    const MRENCLAVE_OFFSET: usize = 960;

    if data.len() < MRENCLAVE_OFFSET + 32 {
        bail!(
            "sigstruct file too small: {} bytes (need at least {})",
            data.len(),
            MRENCLAVE_OFFSET + 32
        );
    }

    let mut mrenclave: MrEnclave = [0u8; 32];
    mrenclave.copy_from_slice(&data[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + 32]);
    Ok(mrenclave)
}
