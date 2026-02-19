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
use freehold_server::dns::{DnsManager, TxtRateLimiter};
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
    dns_manager: Option<DnsManager>,
    txt_rate: TxtRateLimiter,
    primary_ip: Option<Ipv4Addr>,
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

            Message::Confirm {
                port,
                cookie,
                action,
            } => {
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
                let relay_ip_be = self
                    .primary_ip
                    .map(|ip| u32::from(ip).to_be())
                    .unwrap_or(0);

                // Preserve XDP-learned fields (nat_port, client_ip/port)
                // from existing registration so re-confirms don't wipe them.
                let (prev_nat_port, prev_client_ip, prev_client_port) =
                    match self.registrations.read().await.get(&port, 0) {
                        Ok(existing) => {
                            let same_ip = existing.home_ip == u32::from(ip).to_be();
                            if same_ip {
                                (existing.nat_port, existing.client_ip, existing.client_port)
                            } else {
                                (0, 0, 0)
                            }
                        }
                        Err(_) => (0, 0, 0),
                    };

                let reg = Registration {
                    tokens: freehold_common::rate_limit::MAX_BURST,
                    last_refill: now,
                    home_ip: u32::from(ip).to_be(),
                    home_port: from.port(),
                    nat_port: prev_nat_port,
                    expiry: now + timing::REGISTRATION_TTL.as_nanos() as u64,
                    relay_ip: relay_ip_be,
                    client_ip: prev_client_ip,
                    client_port: prev_client_port,
                    _pad2: 0,
                    _pad3: 0,
                };
                self.registrations
                    .write()
                    .await
                    .insert(port, reg, 0)
                    .context("insert registration")?;

                self.quotas.write().await.register(ip, port);
                info!("CONFIRMED {} port {} -> {}:{}", ip, port, ip, from.port());

                // Compute subdomain and handle DNS / ACME actions
                let subdomain = self.cookie_auth.subdomain(ip, port);

                match action {
                    freehold_api::ConfirmAction::CreateRecords => {
                        // Reachability check: port must already exist in eBPF map
                        let reg_data = match self.registrations.read().await.get(&port, 0) {
                            Ok(reg) => {
                                let reg_ip = Ipv4Addr::from(u32::from_be(reg.home_ip));
                                if reg_ip == ip {
                                    Some(reg)
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        };
                        let reg_data = match reg_data {
                            Some(r) => r,
                            None => {
                                warn!(
                                    "CreateRecords rejected for {}:{} — not registered",
                                    ip, port
                                );
                                socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                                return Ok(());
                            }
                        };
                        if let Some(ref dns) = self.dns_manager {
                            if let Some(primary_ip) = self.primary_ip {
                                let home_ip = Ipv4Addr::from(u32::from_be(reg_data.home_ip));
                                let home_port = reg_data.home_port;
                                if let Err(e) = dns.set_registration(
                                    &subdomain, primary_ip, port, home_ip, home_port,
                                ) {
                                    warn!("DNS registration failed for {}: {}", subdomain, e);
                                    socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                                    return Ok(());
                                }
                            }
                        }
                    }
                    freehold_api::ConfirmAction::SetTxt(data) => {
                        if let Some(ref dns) = self.dns_manager {
                            if !self.txt_rate.check(port) {
                                debug!("TXT rate limited for port {}", port);
                                socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                                return Ok(());
                            }
                            match String::from_utf8(data) {
                                Ok(token) => {
                                    if let Err(e) = dns.set_txt(&subdomain, &token) {
                                        warn!("DNS SetTxt failed for {}: {}", subdomain, e);
                                        socket
                                            .send_to(&Message::Error { port }.to_bytes(), from)?;
                                        return Ok(());
                                    }
                                    self.txt_rate.record(port);
                                }
                                Err(_) => {
                                    warn!("Invalid UTF-8 in TXT data for port {}", port);
                                    socket.send_to(&Message::Error { port }.to_bytes(), from)?;
                                    return Ok(());
                                }
                            }
                        }
                    }
                    freehold_api::ConfirmAction::ClearTxt => {
                        if let Some(ref dns) = self.dns_manager {
                            if let Err(e) = dns.clear_txt(&subdomain) {
                                warn!("DNS ClearTxt failed for {}: {}", subdomain, e);
                            }
                        }
                    }
                    freehold_api::ConfirmAction::None => {}
                }

                let has_dns = self.dns_manager.is_some();
                socket.send_to(
                    &Message::Neighbors {
                        addrs: self.neighbors.clone(),
                        subdomain: if has_dns { Some(subdomain) } else { None },
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
                    regs.insert(port, reg, 0).context("update registration")?;
                    debug!("HEARTBEAT {} port {}", ip, port);
                }
                drop(regs);
                socket.send_to(
                    &Message::Neighbors {
                        addrs: self.neighbors.clone(),
                        subdomain: None,
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
            // Clean up DNS records for expired ports
            if let Some(ref dns) = self.dns_manager {
                if let Some(owner_ip) = quotas.get_owner(*port) {
                    let subdomain = self.cookie_auth.subdomain(owner_ip, *port);
                    if let Err(e) = dns.clear_all(&subdomain) {
                        warn!(
                            "DNS cleanup failed for {} (port {}): {}",
                            subdomain, port, e
                        );
                    }
                    self.txt_rate.remove(*port);
                }
            }

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
    registrations: Arc<RwLock<HashMap<aya::maps::MapData, u16, Registration>>>,
) {
    let cpus = online_cpus().expect("get online CPUs");

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .expect("open perf buffer for CPU");

        let punch_socket = punch_socket.clone();
        let registrations = registrations.clone();

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

                                        // Event is now pre-rewrite: dst_port is the relay port,
                                        // src_ip:src_port is Alice's address.
                                        // Look up registration to get Bob's home address.
                                        let relay_port = event.dst_port;

                                        // Update client address in registration for reverse path
                                        let home_addr = {
                                            let mut regs = registrations.write().await;
                                            match regs.get(&relay_port, 0) {
                                                Ok(mut reg) => {
                                                    let home_addr = SocketAddr::new(
                                                        Ipv4Addr::from(
                                                            u32::from_be(reg.home_ip),
                                                        )
                                                        .into(),
                                                        reg.home_port,
                                                    );
                                                    let client_ip_be =
                                                        u32::from(src_ip).to_be();
                                                    if reg.client_ip != client_ip_be
                                                        || reg.client_port != event.src_port
                                                    {
                                                        reg.client_ip = client_ip_be;
                                                        reg.client_port = event.src_port;
                                                        let _ = regs.insert(
                                                            relay_port, reg, 0,
                                                        );
                                                    }
                                                    Some(home_addr)
                                                }
                                                Err(_) => None,
                                            }
                                        };

                                        // NAT hole-punch: send Punch to Bob for new sources
                                        if let Some(home_addr) = home_addr {
                                            let key =
                                                (src_ip, event.src_port, relay_port);
                                            let now = Instant::now();

                                            let is_new =
                                                match punch_tracker.seen.get(&key) {
                                                    None => true,
                                                    Some(t) => {
                                                        now.duration_since(*t)
                                                            >= PUNCH_SEEN_TTL
                                                    }
                                                };

                                            if is_new {
                                                punch_tracker.seen.insert(key, now);

                                                let punch_msg = Message::Punch {
                                                    addr: SocketAddr::new(
                                                        src_ip.into(),
                                                        event.src_port,
                                                    ),
                                                    spray_range: 10_000,
                                                };
                                                if let Err(e) = punch_socket
                                                    .send_to(
                                                        &punch_msg.to_bytes(),
                                                        home_addr,
                                                    )
                                                {
                                                    warn!(
                                                        "Failed to send Punch to {}: {}",
                                                        home_addr, e
                                                    );
                                                } else {
                                                    debug!(
                                                        "Punch: sent {}:{} -> {}",
                                                        src_ip,
                                                        event.src_port,
                                                        home_addr
                                                    );
                                                }
                                            }

                                            // Periodic prune of stale entries
                                            if now.duration_since(last_prune)
                                                >= PUNCH_SEEN_TTL
                                            {
                                                punch_tracker.seen.retain(|_, t| {
                                                    now.duration_since(*t)
                                                        < PUNCH_SEEN_TTL
                                                });
                                                last_prune = now;
                                            }
                                        }
                                    }
                                    Some(EventType::ForwardPost) => {
                                        if verbose {
                                            debug!(
                                                "XDP FWD-POST: {}:{} -> {}:{} ({} bytes)",
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

    process_xdp_events(perf_array, verbose_events, punch_socket, registrations.clone()).await;

    // Initialize DNS manager if enabled
    let dns_manager = if config.dns.enabled {
        info!("DNS management enabled for zone {}", config.dns.zone);
        Some(DnsManager::new(&config.dns))
    } else {
        None
    };

    let mut server = Server {
        cookie_auth: CookieAuth::new(secret),
        neighbors: config.neighbors.clone(),
        max_ports_per_ip: config.limits.max_ports_per_ip,
        registrations: registrations.clone(),
        quotas: quotas.clone(),
        dns_manager,
        txt_rate: TxtRateLimiter::new(config.dns.txt_rate_limit_secs),
        primary_ip: config.anycast.primary_ip,
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
