//! Freehold Server - Relay daemon with stateless cookie verification

use anyhow::{Context, Result};
use aya::maps::{Array, AsyncPerfEventArray, HashMap};
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use clap::{Parser, Subcommand};
use freehold_api::{timing, Message};
use freehold_common::{maps, EventType, Registration, XdpEvent, XDP_PROGRAM};
use freehold_server::config::Config;
use freehold_server::cookie::CookieAuth;
use freehold_server::quota::QuotaTracker;
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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

struct Server {
    cookie_auth: CookieAuth,
    neighbors: Vec<Ipv4Addr>,
    max_ports_per_ip: u32,
    registrations: Arc<RwLock<HashMap<aya::maps::MapData, u16, Registration>>>,
    quotas: Arc<RwLock<QuotaTracker>>,
}

impl Server {
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
                let cookie = self.cookie_auth.generate(ip, port, bucket);
                socket.send_to(&Message::Challenge { port, cookie }.to_bytes(), from)?;
                debug!("REGISTER {} port {} -> CHALLENGE", ip, port);
            }

            Message::Confirm { port, cookie } => {
                let current_bucket = time_bucket();
                if !self
                    .cookie_auth
                    .verify_with_grace(ip, port, &cookie, current_bucket)
                {
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
                    .write()
                    .await
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
                let mut regs = self.registrations.write().await;
                if let Ok(mut reg) = regs.get(&port, 0) {
                    let reg_ip = Ipv4Addr::from(u32::from_be(reg.home_ip));
                    if reg_ip != ip {
                        debug!("Heartbeat IP mismatch: {} != {}", ip, reg_ip);
                        return Ok(());
                    }
                    reg.expiry = ktime_get_ns() + timing::REGISTRATION_TTL.as_nanos() as u64;
                    regs.insert(port, reg, 0)
                        .context("update registration")?;
                    debug!("HEARTBEAT {} port {}", ip, port);
                }
                drop(regs);
                socket.send_to(
                    &Message::Neighbors {
                        addrs: self.neighbors.clone(),
                    }
                    .to_bytes(),
                    from,
                )?;
            }

            _ => {}
        }
        Ok(())
    }

    async fn cleanup_expired(&mut self) -> Result<usize> {
        let now = ktime_get_ns();
        let mut expired = Vec::new();

        let ports: Vec<u16> = self.quotas.read().await.ports().collect();

        let mut regs = self.registrations.write().await;
        for port in ports {
            match regs.get(&port, 0) {
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
            let _ = regs.remove(port);
            quotas.unregister(*port);
            debug!("Cleaned up expired registration for port {}", port);
        }

        Ok(expired.len())
    }
}

/// Shared state for NAT hole-punch tracking
struct PunchTracker {
    /// Recently seen (src_ip, src_port, dst_port) tuples with timestamps
    seen: StdHashMap<(Ipv4Addr, u16, u16), Instant>,
}

/// TTL for seen-sources entries
const PUNCH_SEEN_TTL: Duration = Duration::from_secs(60);

/// Process XDP events from perf buffer
async fn process_xdp_events(
    mut perf_array: AsyncPerfEventArray<aya::maps::MapData>,
    verbose: bool,
    punch_socket: Arc<UdpSocket>,
) {
    let cpus = online_cpus().expect("get online CPUs");

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .expect("open perf buffer for CPU");

        let punch_socket = punch_socket.clone();

        tokio::spawn(async move {
            let mut punch_tracker = PunchTracker {
                seen: StdHashMap::new(),
            };
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            let mut last_prune = Instant::now();

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

                                        // NAT hole-punch: send Punch to Bob for new sources
                                        let key = (src_ip, event.src_port, event.dst_port);
                                        let now = Instant::now();

                                        let is_new = match punch_tracker.seen.get(&key) {
                                            None => true,
                                            Some(t) => now.duration_since(*t) >= PUNCH_SEEN_TTL,
                                        };

                                        if is_new {
                                            punch_tracker.seen.insert(key, now);

                                            // XDP already rewrote dst to home_ip:home_port,
                                            // so the event contains Bob's address directly
                                            let home_addr = SocketAddr::new(dst_ip.into(), event.dst_port);
                                            let punch_msg = Message::Punch {
                                                addr: SocketAddr::new(src_ip.into(), event.src_port),
                                            };
                                            if let Err(e) = punch_socket.send_to(&punch_msg.to_bytes(), home_addr) {
                                                warn!("Failed to send Punch to {}: {}", home_addr, e);
                                            } else {
                                                debug!("Punch: sent {}:{} -> {}", src_ip, event.src_port, home_addr);
                                            }
                                        }

                                        // Periodic prune of stale entries
                                        if now.duration_since(last_prune) >= PUNCH_SEEN_TTL {
                                            punch_tracker.seen.retain(|_, t| now.duration_since(*t) < PUNCH_SEEN_TTL);
                                            last_prune = now;
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

    let registrations = Arc::new(RwLock::new(regs));

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

    let punch_socket = Arc::new(socket.try_clone().context("clone socket for punch")?);

    process_xdp_events(perf_array, verbose_events, punch_socket).await;

    let mut server = Server {
        cookie_auth: CookieAuth::new(secret),
        neighbors: config.neighbors.clone(),
        max_ports_per_ip: config.limits.max_ports_per_ip,
        registrations: registrations.clone(),
        quotas: quotas.clone(),
    };

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
