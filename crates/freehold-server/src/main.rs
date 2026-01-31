//! Freehold Server - Relay daemon with stateless cookie verification
//!
//! Supports SGX attestation for verifiable relay operation.

mod config;

use anyhow::{Context, Result};
use aya::maps::{Array, AsyncPerfEventArray, HashMap};
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use config::Config;
use freehold_api::{timing, Message, ATTESTATION_NONCE_SIZE, COOKIE_SIZE};
use freehold_common::{maps, EventType, Registration, XdpEvent, XDP_PROGRAM};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Get monotonic kernel time in nanoseconds.
/// This matches what XDP uses (bpf_ktime_get_ns).
fn ktime_get_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Get time bucket for cookie generation (30-second windows).
fn time_bucket() -> u64 {
    ktime_get_ns() / timing::TIME_BUCKET.as_nanos() as u64
}

#[derive(Parser)]
#[command(name = "freehold-server", about = "Freehold anycast relay server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to config file
    #[clap(short, long, default_value = "/etc/freehold/server.toml")]
    config: PathBuf,

    /// Override interface from config
    #[clap(short, long)]
    interface: Option<String>,

    /// Override port from config
    #[clap(short, long)]
    port: Option<u16>,

    /// Override eBPF path from config
    #[clap(short, long)]
    ebpf: Option<PathBuf>,

    /// Enable verbose XDP event logging
    #[clap(long)]
    verbose_events: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Print example configuration file
    ExampleConfig,
    /// Validate configuration file
    ValidateConfig {
        /// Path to config file (overrides --config)
        path: Option<PathBuf>,
    },
}

/// Tracks which ports an IP has registered (for quota cleanup)
#[derive(Default)]
struct QuotaTracker {
    ports_by_ip: StdHashMap<Ipv4Addr, Vec<u16>>,
    ip_by_port: StdHashMap<u16, Ipv4Addr>,
}

impl QuotaTracker {
    fn register(&mut self, ip: Ipv4Addr, port: u16) {
        if let Some(old_ip) = self.ip_by_port.remove(&port) {
            if let Some(ports) = self.ports_by_ip.get_mut(&old_ip) {
                ports.retain(|&p| p != port);
                if ports.is_empty() {
                    self.ports_by_ip.remove(&old_ip);
                }
            }
        }
        self.ip_by_port.insert(port, ip);
        self.ports_by_ip.entry(ip).or_default().push(port);
    }

    fn unregister(&mut self, port: u16) {
        if let Some(ip) = self.ip_by_port.remove(&port) {
            if let Some(ports) = self.ports_by_ip.get_mut(&ip) {
                ports.retain(|&p| p != port);
                if ports.is_empty() {
                    self.ports_by_ip.remove(&ip);
                }
            }
        }
    }

    fn count(&self, ip: &Ipv4Addr) -> u32 {
        self.ports_by_ip
            .get(ip)
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }

    fn ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.ip_by_port.keys().copied()
    }
}

/// Cached attestation data (quote + collateral)
/// Generated once and cached since MRENCLAVE doesn't change at runtime
struct AttestationCache {
    /// Pre-generated quote (without nonce - will be refreshed on request)
    enabled: bool,
    /// Cached collateral (PCK certs, TCB info) - valid for ~24h
    collateral: Vec<u8>,
}

struct Server {
    secret: [u8; 32],
    neighbors: Vec<Ipv4Addr>,
    max_ports_per_ip: u32,
    registrations: HashMap<aya::maps::MapData, u16, Registration>,
    quotas: Arc<RwLock<QuotaTracker>>,
    attestation: AttestationCache,
}

impl Server {
    fn cookie(&self, ip: Ipv4Addr, port: u16, bucket: u64) -> [u8; COOKIE_SIZE] {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&ip.octets());
        mac.update(&port.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&mac.finalize().into_bytes()[..COOKIE_SIZE]);
        cookie
    }

    fn verify(&self, ip: Ipv4Addr, port: u16, cookie: &[u8; COOKIE_SIZE]) -> bool {
        let bucket = time_bucket();
        [bucket, bucket.saturating_sub(1)]
            .iter()
            .any(|&b| &self.cookie(ip, port, b) == cookie)
    }

    async fn handle(&mut self, socket: &UdpSocket, data: &[u8], from: SocketAddr) -> Result<()> {
        let msg = match Message::parse(data) {
            Ok(m) => m,
            Err(e) => {
                debug!("Parse error from {}: {}", from, e);
                return Ok(());
            }
        };

        let ip = match from {
            SocketAddr::V4(a) => *a.ip(),
            _ => return Ok(()),
        };

        match msg {
            Message::Register { port } => {
                let count = self.quotas.read().await.count(&ip);
                if count >= self.max_ports_per_ip {
                    debug!("Quota exceeded for {} (has {} ports)", ip, count);
                    socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                    return Ok(());
                }

                let bucket = time_bucket();
                let cookie = self.cookie(ip, port, bucket);
                socket.send_to(&Message::Challenge { port, cookie }.to_bytes(), from)?;
                debug!("REGISTER {} port {} -> CHALLENGE", ip, port);
            }

            Message::Confirm { port, cookie } => {
                if !self.verify(ip, port, &cookie) {
                    warn!("Invalid cookie from {} for port {}", ip, port);
                    socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                    return Ok(());
                }

                let now = ktime_get_ns();
                let reg = Registration {
                    tokens: freehold_common::rate_limit::MAX_BURST,
                    last_refill: now,
                    home_ip: u32::from(ip).to_be(),
                    home_port: from.port(),
                    _pad1: 0,
                    expiry: now + timing::REGISTRATION_TTL.as_nanos() as u64,
                };
                self.registrations
                    .insert(port, reg, 0)
                    .context("insert registration")?;

                self.quotas.write().await.register(ip, port);
                info!("CONFIRMED {} port {} -> {}:{}", ip, port, ip, from.port());

                socket.send_to(
                    &Message::Neighbors {
                        addrs: self.neighbors.clone(),
                    }
                    .to_bytes(),
                    from,
                )?;
            }

            Message::Heartbeat { port } => {
                if let Ok(mut reg) = self.registrations.get(&port, 0) {
                    let reg_ip = Ipv4Addr::from(u32::from_be(reg.home_ip));
                    if reg_ip != ip {
                        debug!("Heartbeat IP mismatch: {} != {}", ip, reg_ip);
                        return Ok(());
                    }
                    reg.expiry = ktime_get_ns() + timing::REGISTRATION_TTL.as_nanos() as u64;
                    self.registrations
                        .insert(port, reg, 0)
                        .context("update registration")?;
                    debug!("HEARTBEAT {} port {}", ip, port);
                }
                socket.send_to(
                    &Message::Neighbors {
                        addrs: self.neighbors.clone(),
                    }
                    .to_bytes(),
                    from,
                )?;
            }

            Message::AttestationRequest { nonce } => {
                debug!("ATTESTATION request from {}", from);
                if !self.attestation.enabled {
                    // Attestation not available - return error
                    // In production with SGX, this would generate a real quote
                    warn!("Attestation requested but not enabled");
                    socket.send_to(&Message::Error { port: 0 }.to_bytes(), from)?;
                    return Ok(());
                }

                // Generate quote with nonce for freshness
                // In real SGX deployment, this calls into the enclave
                let quote = self.generate_attestation_quote(&nonce);
                let response = Message::AttestationResponse {
                    quote,
                    collateral: self.attestation.collateral.clone(),
                };
                socket.send_to(&response.to_bytes(), from)?;
                info!("ATTESTATION sent to {}", from);
            }

            _ => {}
        }
        Ok(())
    }

    async fn cleanup_expired(&mut self) -> Result<usize> {
        let now = ktime_get_ns();
        let mut expired = Vec::new();

        let ports: Vec<u16> = self.quotas.read().await.ports().collect();

        for port in ports {
            match self.registrations.get(&port, 0) {
                Ok(reg) => {
                    if now > reg.expiry {
                        expired.push(port);
                    }
                }
                Err(_) => {
                    expired.push(port);
                }
            }
        }

        let mut quotas = self.quotas.write().await;
        for port in &expired {
            let _ = self.registrations.remove(port);
            quotas.unregister(*port);
            debug!("Cleaned up expired registration for port {}", port);
        }

        Ok(expired.len())
    }

    /// Generate attestation quote with nonce
    ///
    /// In SGX mode, this generates a real DCAP quote via the enclave.
    /// Without SGX, returns a mock quote for testing.
    fn generate_attestation_quote(&self, nonce: &[u8; ATTESTATION_NONCE_SIZE]) -> Vec<u8> {
        // Mock quote structure for testing without SGX
        // Real implementation would call into SGX enclave
        //
        // Quote format (simplified mock):
        // - Header (48 bytes): version, attestation type, etc.
        // - Report body (384 bytes): MRENCLAVE at offset 112, report_data at offset 320
        // - Signature (variable)
        let mut quote = vec![0u8; 432]; // Minimal mock quote

        // Version (2 bytes)
        quote[0] = 3; // DCAP quote version 3

        // Attestation key type (2 bytes)
        quote[2] = 2; // ECDSA-256

        // MRENCLAVE at offset 160 (48 header + 112 into report body)
        // Use a deterministic mock value based on build
        let mock_mrenclave = self.compute_mock_mrenclave();
        quote[160..192].copy_from_slice(&mock_mrenclave);

        // Report data at offset 368 (48 header + 320 into report body)
        // First 32 bytes contain the nonce
        quote[368..368 + ATTESTATION_NONCE_SIZE].copy_from_slice(nonce);

        quote
    }

    /// Compute a mock MRENCLAVE for testing
    ///
    /// In production, this would be the actual enclave measurement.
    /// For testing, we derive it from the binary hash.
    fn compute_mock_mrenclave(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Hash something deterministic for testing
        let mut hasher = Sha256::new();
        hasher.update(b"freehold-mock-enclave-v1");
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());

        let result = hasher.finalize();
        let mut mrenclave = [0u8; 32];
        mrenclave.copy_from_slice(&result);
        mrenclave
    }
}

/// Process XDP events from perf buffer
async fn process_xdp_events(
    mut perf_array: AsyncPerfEventArray<aya::maps::MapData>,
    verbose: bool,
) {
    let cpus = online_cpus().expect("get online CPUs");

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .expect("open perf buffer for CPU");

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await;
                match events {
                    Ok(events) => {
                        for buf in buffers.iter().take(events.read) {
                            if buf.len() >= XdpEvent::SIZE {
                                let event: XdpEvent = unsafe {
                                    std::ptr::read_unaligned(buf.as_ptr() as *const XdpEvent)
                                };

                                let src_ip = Ipv4Addr::from(event.src_ip.to_be());
                                let dst_ip = Ipv4Addr::from(event.dst_ip.to_be());

                                match event.event_type() {
                                    Some(EventType::DropRateLimit) => {
                                        warn!(
                                            "XDP DROP rate-limit: {}:{} -> {}:{} ({} bytes)",
                                            src_ip,
                                            event.src_port,
                                            dst_ip,
                                            event.dst_port,
                                            event.pkt_len
                                        );
                                    }
                                    Some(EventType::DropExpired) => {
                                        if verbose {
                                            debug!(
                                                "XDP DROP expired: {}:{} -> {}:{} ({} bytes)",
                                                src_ip,
                                                event.src_port,
                                                dst_ip,
                                                event.dst_port,
                                                event.pkt_len
                                            );
                                        }
                                    }
                                    Some(EventType::DropNoReg) => {
                                        if verbose {
                                            debug!(
                                                "XDP DROP no-reg: {}:{} -> {}:{} ({} bytes)",
                                                src_ip,
                                                event.src_port,
                                                dst_ip,
                                                event.dst_port,
                                                event.pkt_len
                                            );
                                        }
                                    }
                                    Some(EventType::Forward) => {
                                        if verbose {
                                            debug!(
                                                "XDP FWD: {}:{} -> {}:{} ({} bytes)",
                                                src_ip,
                                                event.src_port,
                                                dst_ip,
                                                event.dst_port,
                                                event.pkt_len
                                            );
                                        }
                                    }
                                    None => {
                                        warn!("Unknown XDP event type: {}", event.event_type);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading perf events: {}", e);
                    }
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    match cli.command {
        Some(Commands::ExampleConfig) => {
            println!("{}", Config::example());
            return Ok(());
        }
        Some(Commands::ValidateConfig { path }) => {
            let config_path = path.as_ref().unwrap_or(&cli.config);
            let config = Config::from_file(config_path)?;
            println!("Configuration valid:");
            println!("  Interface: {}", config.interface);
            println!("  Port: {}", config.port);
            println!("  eBPF: {}", config.ebpf_path);
            if let Some(ref prefix) = config.anycast.prefix {
                println!("  Anycast prefix: {}", prefix);
            }
            println!("  Neighbors: {:?}", config.neighbors);
            return Ok(());
        }
        None => {}
    }

    // Load config
    let config = if cli.config.exists() {
        Config::from_file(&cli.config)?
    } else {
        eprintln!(
            "Config file not found: {}\n\nGenerate an example with: freehold-server example-config > /etc/freehold/server.toml",
            cli.config.display()
        );
        std::process::exit(1);
    };

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&config.logging.filter)
        .init();

    // Apply CLI overrides
    let interface = cli.interface.unwrap_or(config.interface.clone());
    let port = cli.port.unwrap_or(config.port);
    let ebpf_path = cli.ebpf.unwrap_or_else(|| PathBuf::from(&config.ebpf_path));
    let verbose_events = cli.verbose_events || config.limits.verbose_events;

    let secret = config.get_secret()?;

    info!("Freehold Relay Server starting");
    info!("  Interface: {}", interface);
    info!("  Port: {}", port);
    info!("  eBPF: {}", ebpf_path.display());
    if let Some(ref prefix) = config.anycast.prefix {
        info!("  Anycast prefix: {}", prefix);
    }

    // Load eBPF
    let mut bpf = Ebpf::load_file(&ebpf_path).context("load eBPF program")?;
    let _ = aya_log::EbpfLogger::init(&mut bpf);

    let mut ctrl: Array<_, u16> = Array::try_from(
        bpf.take_map(maps::CONTROL_PORT)
            .context("get control_port map")?,
    )
    .context("create control_port array")?;
    ctrl.set(0, port, 0).context("set control port")?;

    let regs: HashMap<_, u16, Registration> = HashMap::try_from(
        bpf.take_map(maps::REGISTRATIONS)
            .context("get registrations map")?,
    )
    .context("create registrations hashmap")?;

    let perf_array: AsyncPerfEventArray<_> =
        AsyncPerfEventArray::try_from(bpf.take_map(maps::EVENTS).context("get events map")?)
            .context("create perf event array")?;

    process_xdp_events(perf_array, verbose_events).await;

    let prog: &mut Xdp = bpf
        .program_mut(XDP_PROGRAM)
        .context("get XDP program")?
        .try_into()
        .context("cast to XDP")?;
    prog.load().context("load XDP program")?;
    prog.attach(&interface, XdpFlags::default())
        .context("attach XDP to interface")?;
    info!("XDP attached to {}", interface);

    // Bind to anycast IP so responses come from the same IP clients contacted
    // This is critical for NAT hole-punching to work
    let bind_addr = config
        .anycast
        .primary_ip
        .map(|ip| format!("{}:{}", ip, port))
        .unwrap_or_else(|| format!("0.0.0.0:{}", port));

    let socket = UdpSocket::bind(&bind_addr).context("bind UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("set socket nonblocking")?;
    info!("Listening on {}", bind_addr);

    let quotas = Arc::new(RwLock::new(QuotaTracker::default()));

    // Initialize attestation (mock for now, real SGX in production)
    let attestation = AttestationCache {
        enabled: true, // Enable mock attestation for testing
        collateral: serde_json::to_vec(&serde_json::json!({
            "type": "mock",
            "note": "This is mock collateral for testing. Real deployment uses DCAP.",
            "pck_cert_chain": "mock-pck-cert",
            "tcb_info": "mock-tcb-info",
            "qe_identity": "mock-qe-identity"
        }))
        .unwrap_or_default(),
    };

    let mut server = Server {
        secret,
        neighbors: config.neighbors.clone(),
        max_ports_per_ip: config.limits.max_ports_per_ip,
        registrations: regs,
        quotas: quotas.clone(),
        attestation,
    };

    info!("Attestation: enabled (mock mode)");

    let cleanup_interval = Duration::from_secs(config.limits.cleanup_interval_secs);
    let mut last_cleanup = std::time::Instant::now();

    let mut buf = [0u8; 1500];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                if let Err(e) = server.handle(&socket, &buf[..len], from).await {
                    error!("Handle error from {}: {}", from, e);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(e) => error!("Socket error: {}", e),
        }

        if last_cleanup.elapsed() >= cleanup_interval {
            match server.cleanup_expired().await {
                Ok(count) if count > 0 => {
                    info!("Cleaned up {} expired registrations", count);
                }
                Err(e) => {
                    warn!("Cleanup error: {}", e);
                }
                _ => {}
            }
            last_cleanup = std::time::Instant::now();
        }
    }
}
