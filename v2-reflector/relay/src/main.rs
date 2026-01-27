//! Specular Relay Daemon
//!
//! Manages the eBPF reflector and handles the registration protocol.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
use specular_common::*;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "specular-relay")]
#[command(about = "Specular relay daemon")]
struct Args {
    /// Network interface to attach XDP program
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Control port for registration protocol
    #[arg(short, long, default_value_t = CONTROL_PORT)]
    port: u16,

    /// Port range start for allocations
    #[arg(long, default_value_t = 10000)]
    port_start: u16,

    /// Port range end for allocations
    #[arg(long, default_value_t = 60000)]
    port_end: u16,
}

/// Pending registration waiting for challenge response
struct PendingRegistration {
    client_addr: SocketAddr,
    pubkey: VerifyingKey,
    port: u16,
    nonce: [u8; 32],
    created: SystemTime,
}

/// Relay state
struct RelayState {
    /// Pending registrations (port -> pending)
    pending: DashMap<u16, PendingRegistration>,
    /// Confirmed registrations (port -> pubkey)
    confirmed: DashMap<u16, VerifyingKey>,
    /// IP quota tracking
    quota: DashMap<Ipv4Addr, u32>,
    /// Next available port
    next_port: RwLock<u16>,
    /// Port range
    port_start: u16,
    port_end: u16,
}

impl RelayState {
    fn new(port_start: u16, port_end: u16) -> Self {
        Self {
            pending: DashMap::new(),
            confirmed: DashMap::new(),
            quota: DashMap::new(),
            next_port: RwLock::new(port_start),
            port_start,
            port_end,
        }
    }

    async fn allocate_port(&self) -> Option<u16> {
        let mut next = self.next_port.write().await;
        let start = *next;

        loop {
            let port = *next;
            *next = if *next >= self.port_end {
                self.port_start
            } else {
                *next + 1
            };

            // Check if port is free
            if !self.pending.contains_key(&port) && !self.confirmed.contains_key(&port) {
                return Some(port);
            }

            // Wrapped around - no free ports
            if *next == start {
                return None;
            }
        }
    }

    fn check_quota(&self, ip: Ipv4Addr) -> bool {
        let count = self.quota.get(&ip).map(|c| *c).unwrap_or(0);
        count < MAX_PORTS_PER_IP
    }

    fn increment_quota(&self, ip: Ipv4Addr) {
        self.quota
            .entry(ip)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    fn decrement_quota(&self, ip: Ipv4Addr) {
        if let Some(mut entry) = self.quota.get_mut(&ip) {
            if *entry > 0 {
                *entry -= 1;
            }
        }
    }
}

/// eBPF registration entry (must match C struct)
#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfRegistration {
    state: u8,
    _pad1: [u8; 3],
    client_ip: u32,
    client_port: u16,
    _pad2: [u8; 2],
    tokens: u64,
    last_refill: u64,
    expiry: u64,
    nonce: [u8; 32],
    pubkey: [u8; 32],
}

unsafe impl aya::Pod for EbpfRegistration {}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info,specular_relay=debug")
        .init();

    let args = Args::parse();

    info!("Specular Relay starting");
    info!("  Interface: {}", args.interface);
    info!("  Control port: {}", args.port);
    info!("  Port range: {}-{}", args.port_start, args.port_end);

    // Load eBPF program - Box::leak for 'static lifetime
    let bpf: &'static mut Ebpf = Box::leak(Box::new(load_ebpf(&args.interface)?));

    // Get map reference
    let registrations: AyaHashMap<_, u16, EbpfRegistration> =
        AyaHashMap::try_from(bpf.map_mut("registrations").context("map not found")?)?;

    let registrations = Arc::new(RwLock::new(registrations));

    // Create state
    let state = Arc::new(RelayState::new(args.port_start, args.port_end));

    // Bind control socket
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.port)).await?;
    info!("Control socket bound to 0.0.0.0:{}", args.port);

    // Spawn cleanup task
    let state_clone = state.clone();
    let regs_clone = registrations.clone();
    tokio::spawn(async move {
        cleanup_loop(state_clone, regs_clone).await;
    });

    // Main loop
    let mut buf = vec![0u8; 2048];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let data = &buf[..len];

        if let Err(e) = handle_packet(&socket, addr, data, &state, &registrations).await {
            warn!("Error handling packet from {}: {}", addr, e);
        }
    }
}

fn load_ebpf(interface: &str) -> Result<Ebpf> {
    info!("Loading eBPF program...");

    // Load eBPF object at runtime
    let ebpf_path = std::env::var("SPECULAR_EBPF_PATH")
        .unwrap_or_else(|_| "/opt/specular/specular-ebpf.bpf.o".to_string());

    let ebpf_bytes = std::fs::read(&ebpf_path)
        .with_context(|| format!("Failed to read eBPF object from {}", ebpf_path))?;

    let mut bpf = Ebpf::load(&ebpf_bytes)
        .with_context(|| "Failed to load eBPF program")?;

    // Attach XDP program
    let program: &mut Xdp = bpf.program_mut("specular_ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(interface, XdpFlags::default())?;

    info!("XDP program attached to {}", interface);
    Ok(bpf)
}

async fn handle_packet(
    socket: &UdpSocket,
    addr: SocketAddr,
    data: &[u8],
    state: &Arc<RelayState>,
    registrations: &Arc<RwLock<AyaHashMap<&mut aya::maps::MapData, u16, EbpfRegistration>>>,
) -> Result<()> {
    // Parse header (simplified - in production use proper parsing)
    if data.len() < 12 {
        return Ok(()); // Too short
    }

    if &data[0..4] != &MAGIC {
        debug!("Invalid magic from {}", addr);
        return Ok(());
    }

    let version = data[4];
    if version != VERSION {
        warn!("Unsupported version {} from {}", version, addr);
        return Ok(());
    }

    let msg_type = MessageType::try_from(data[5])?;
    let _length = u16::from_le_bytes([data[6], data[7]]);
    let sequence = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let payload = &data[12..];

    match msg_type {
        MessageType::Register => {
            handle_register(socket, addr, payload, sequence, state, registrations).await
        }
        MessageType::Response => {
            handle_response(socket, addr, payload, sequence, state, registrations).await
        }
        MessageType::Heartbeat => {
            handle_heartbeat(socket, addr, payload, sequence, state, registrations).await
        }
        _ => {
            debug!("Unexpected message type {:?} from {}", msg_type, addr);
            Ok(())
        }
    }
}

async fn handle_register(
    socket: &UdpSocket,
    addr: SocketAddr,
    payload: &[u8],
    sequence: u32,
    state: &Arc<RelayState>,
    registrations: &Arc<RwLock<AyaHashMap<&mut aya::maps::MapData, u16, EbpfRegistration>>>,
) -> Result<()> {
    let msg: RegisterMessage = bincode::deserialize(payload)?;

    info!("REGISTER from {} for port {}", addr, msg.port);

    // Verify signature
    let pubkey = msg.verify()?;
    debug!("Signature valid for pubkey {:?}", pubkey.as_bytes());

    // Extract client IP
    let client_ip = match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => {
            warn!("IPv6 not supported yet");
            return Ok(());
        }
    };

    // Check quota
    if !state.check_quota(client_ip) {
        warn!("Quota exceeded for {}", client_ip);
        send_error(socket, addr, sequence, error_codes::QUOTA_EXCEEDED, "Quota exceeded").await?;
        return Ok(());
    }

    // Allocate or use requested port
    let port = if msg.port == 0 {
        state.allocate_port().await.ok_or_else(|| {
            anyhow::anyhow!("No ports available")
        })?
    } else {
        // Check if requested port is available
        if state.pending.contains_key(&msg.port) || state.confirmed.contains_key(&msg.port) {
            send_error(socket, addr, sequence, error_codes::PORT_IN_USE, "Port in use").await?;
            return Ok(());
        }
        msg.port
    };

    // Generate challenge
    let challenge = ChallengeMessage::new(port);

    // Store pending registration
    state.pending.insert(port, PendingRegistration {
        client_addr: addr,
        pubkey,
        port,
        nonce: challenge.nonce,
        created: SystemTime::now(),
    });

    // Insert pending state into eBPF map
    {
        let mut regs = registrations.write().await;
        let entry = EbpfRegistration {
            state: 0, // PENDING
            _pad1: [0; 3],
            client_ip: u32::from(client_ip),
            client_port: addr.port(),
            _pad2: [0; 2],
            tokens: BURST_SIZE,
            last_refill: 0, // Will be set on first packet
            expiry: 0, // Not confirmed yet
            nonce: challenge.nonce,
            pubkey: *pubkey.as_bytes(),
        };
        regs.insert(port, entry, 0)?;
    }

    // Send challenge
    info!("Sending CHALLENGE to {} for port {}", addr, port);
    send_challenge(socket, addr, sequence, &challenge).await?;

    Ok(())
}

async fn handle_response(
    socket: &UdpSocket,
    addr: SocketAddr,
    payload: &[u8],
    sequence: u32,
    state: &Arc<RelayState>,
    registrations: &Arc<RwLock<AyaHashMap<&mut aya::maps::MapData, u16, EbpfRegistration>>>,
) -> Result<()> {
    let msg: ResponseMessage = bincode::deserialize(payload)?;

    info!("RESPONSE from {} for port {}", addr, msg.port);

    // Find pending registration
    let pending = state.pending.remove(&msg.port);
    let (_, pending) = match pending {
        Some(p) => p,
        None => {
            warn!("No pending registration for port {}", msg.port);
            send_error(socket, addr, sequence, error_codes::NOT_FOUND, "Not found").await?;
            return Ok(());
        }
    };

    // Verify response
    if let Err(e) = msg.verify(&pending.pubkey, &pending.nonce) {
        warn!("Challenge verification failed: {}", e);
        send_error(socket, addr, sequence, error_codes::INVALID_SIGNATURE, "Invalid response").await?;
        return Ok(());
    }

    // Get client IP
    let client_ip = match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => return Ok(()),
    };

    // Calculate expiry
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let expiry = now_ns + (DEFAULT_TTL as u64 * 1_000_000_000);

    // Update eBPF map to CONFIRMED
    {
        let mut regs = registrations.write().await;
        let entry = EbpfRegistration {
            state: 1, // CONFIRMED
            _pad1: [0; 3],
            client_ip: u32::from(client_ip),
            client_port: addr.port(),
            _pad2: [0; 2],
            tokens: BURST_SIZE,
            last_refill: now_ns,
            expiry,
            nonce: [0; 32], // Clear nonce
            pubkey: *pending.pubkey.as_bytes(),
        };
        regs.insert(msg.port, entry, 0)?;
    }

    // Update state
    state.confirmed.insert(msg.port, pending.pubkey);
    state.increment_quota(client_ip);

    // Send ACK
    info!("Registration CONFIRMED for {} port {}", addr, msg.port);

    let ack = AckMessage {
        port: msg.port,
        ttl: DEFAULT_TTL,
        relay_ip: [0, 0, 0, 0], // TODO: get actual relay IP
    };
    send_ack(socket, addr, sequence, &ack).await?;

    Ok(())
}

async fn handle_heartbeat(
    socket: &UdpSocket,
    addr: SocketAddr,
    payload: &[u8],
    sequence: u32,
    state: &Arc<RelayState>,
    registrations: &Arc<RwLock<AyaHashMap<&mut aya::maps::MapData, u16, EbpfRegistration>>>,
) -> Result<()> {
    let msg: HeartbeatMessage = bincode::deserialize(payload)?;

    debug!("HEARTBEAT from {} for port {}", addr, msg.port);

    // Find confirmed registration
    let _pubkey = match state.confirmed.get(&msg.port) {
        Some(pk) => *pk,
        None => {
            debug!("No confirmed registration for port {}", msg.port);
            return Ok(());
        }
    };

    // TODO: Verify heartbeat signature

    // Refresh expiry in eBPF
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let new_expiry = now_ns + (DEFAULT_TTL as u64 * 1_000_000_000);

    {
        let mut regs = registrations.write().await;
        if let Ok(mut entry) = regs.get(&msg.port, 0) {
            entry.expiry = new_expiry;
            regs.insert(msg.port, entry, 0)?;
        }
    }

    // Send heartbeat ACK
    let ack = HeartbeatAckMessage {
        port: msg.port,
        ttl: DEFAULT_TTL,
    };
    send_heartbeat_ack(socket, addr, sequence, &ack).await?;

    Ok(())
}

async fn send_challenge(
    socket: &UdpSocket,
    addr: SocketAddr,
    sequence: u32,
    msg: &ChallengeMessage,
) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let header = Header::new(MessageType::Challenge, payload.len() as u16, sequence);
    let header_bytes = bincode::serialize(&header)?;

    let mut packet = header_bytes;
    packet.extend_from_slice(&payload);

    socket.send_to(&packet, addr).await?;
    Ok(())
}

async fn send_ack(
    socket: &UdpSocket,
    addr: SocketAddr,
    sequence: u32,
    msg: &AckMessage,
) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let header = Header::new(MessageType::Ack, payload.len() as u16, sequence);
    let header_bytes = bincode::serialize(&header)?;

    let mut packet = header_bytes;
    packet.extend_from_slice(&payload);

    socket.send_to(&packet, addr).await?;
    Ok(())
}

async fn send_heartbeat_ack(
    socket: &UdpSocket,
    addr: SocketAddr,
    sequence: u32,
    msg: &HeartbeatAckMessage,
) -> Result<()> {
    let payload = bincode::serialize(msg)?;
    let header = Header::new(MessageType::HeartbeatAck, payload.len() as u16, sequence);
    let header_bytes = bincode::serialize(&header)?;

    let mut packet = header_bytes;
    packet.extend_from_slice(&payload);

    socket.send_to(&packet, addr).await?;
    Ok(())
}

async fn send_error(
    socket: &UdpSocket,
    addr: SocketAddr,
    sequence: u32,
    code: u16,
    message: &str,
) -> Result<()> {
    let msg = ErrorMessage {
        code,
        message: message.to_string(),
    };
    let payload = bincode::serialize(&msg)?;
    let header = Header::new(MessageType::ErrorResponse, payload.len() as u16, sequence);
    let header_bytes = bincode::serialize(&header)?;

    let mut packet = header_bytes;
    packet.extend_from_slice(&payload);

    socket.send_to(&packet, addr).await?;
    Ok(())
}

async fn cleanup_loop(
    state: Arc<RelayState>,
    _registrations: Arc<RwLock<AyaHashMap<&mut aya::maps::MapData, u16, EbpfRegistration>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        let now = SystemTime::now();

        // Clean up expired pending registrations (30 second timeout)
        let pending_timeout = Duration::from_secs(30);
        state.pending.retain(|port, pending| {
            let age = now.duration_since(pending.created).unwrap_or_default();
            if age > pending_timeout {
                info!("Cleaning up expired pending registration for port {}", port);
                false
            } else {
                true
            }
        });

        // TODO: Clean up expired confirmed registrations from eBPF map
    }
}
