//! Server configuration from file or CLI

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network interface to attach XDP to
    pub interface: String,

    /// Control port for registration protocol
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to compiled eBPF object file
    pub ebpf_path: String,

    /// HMAC secret for cookie generation (hex encoded, 32 bytes)
    /// Can be overridden by FREEHOLD_SECRET env var
    #[serde(default)]
    pub secret: Option<String>,

    /// Anycast IP configuration
    #[serde(default)]
    pub anycast: AnycastConfig,

    /// Neighbor relay servers for discovery
    #[serde(default)]
    pub neighbors: Vec<Ipv4Addr>,

    /// Rate limiting and quotas
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Anycast IP block configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnycastConfig {
    /// The anycast prefix being announced (e.g., "198.51.100.0/24")
    /// Clients connect to IPs in this range
    pub prefix: Option<Ipv4Net>,

    /// Primary IP for this relay within the anycast block
    /// This is the IP that gets advertised to neighbors
    pub primary_ip: Option<Ipv4Addr>,

    /// Bind all IPs in the prefix to loopback/dummy interface
    /// If false, assumes IPs are already configured
    #[serde(default)]
    pub bind_ips: bool,

    /// Interface to bind anycast IPs to (default: "lo")
    #[serde(default = "default_anycast_interface")]
    pub bind_interface: String,
}

/// Rate limiting and quota configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum ports per IP (default: 3)
    #[serde(default = "default_max_ports")]
    pub max_ports_per_ip: u32,

    /// Cleanup interval in seconds (default: 30)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Enable verbose XDP event logging
    #[serde(default)]
    pub verbose_events: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (default: "freehold_server=debug")
    #[serde(default = "default_log_filter")]
    pub filter: String,

    /// Log format: "pretty", "json", or "compact"
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_port() -> u16 {
    9999
}

fn default_anycast_interface() -> String {
    "lo".to_string()
}

fn default_max_ports() -> u32 {
    3
}

fn default_cleanup_interval() -> u64 {
    30
}

fn default_log_filter() -> String {
    "freehold_server=debug".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_ports_per_ip: default_max_ports(),
            cleanup_interval_secs: default_cleanup_interval(),
            verbose_events: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter: default_log_filter(),
            format: default_log_format(),
        }
    }
}

impl Config {
    /// Load config from a TOML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Get the secret, preferring env var over config file
    pub fn get_secret(&self) -> Result<[u8; 32]> {
        let secret_hex = std::env::var("FREEHOLD_SECRET")
            .ok()
            .or_else(|| self.secret.clone())
            .context("secret must be provided via FREEHOLD_SECRET env or config file")?;

        let bytes = hex::decode(&secret_hex).context("decode secret hex")?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret must be 32 bytes (64 hex chars)"))
    }

    /// Generate an example config file
    pub fn example() -> String {
        r#"# Freehold Relay Server Configuration

# Network interface to attach XDP program to
# This should be your physical NIC that receives traffic
interface = "eth0"

# Control port for the registration protocol
# Clients send Register/Confirm/Heartbeat messages here
port = 9999

# Path to the compiled eBPF object file
ebpf_path = "/opt/freehold/freehold.bpf.o"

# HMAC secret for cookie generation (64 hex chars = 32 bytes)
# IMPORTANT: Generate with: openssl rand -hex 32
# Can also be set via FREEHOLD_SECRET environment variable
# secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[anycast]
# Your announced anycast prefix (e.g., from Vultr BGP)
# Clients connect to IPs in this range
prefix = "198.51.100.0/24"

# Primary IP for this relay (used in neighbor announcements)
# Should be an IP within your prefix
primary_ip = "198.51.100.1"

# Whether to automatically bind IPs to an interface
# Set to true if IPs aren't already configured on the system
bind_ips = false

# Interface to bind anycast IPs to (if bind_ips = true)
bind_interface = "lo"

# Neighbor relay servers for mesh discovery
# Clients learn about these and can register with them too
neighbors = [
    "198.51.100.2",
    "198.51.100.3",
]

[limits]
# Maximum ports a single IP can register
max_ports_per_ip = 3

# How often to clean up expired registrations (seconds)
cleanup_interval_secs = 30

# Log all XDP events (verbose, useful for debugging)
verbose_events = false

[logging]
# Tracing filter string
filter = "freehold_server=debug"

# Log format: "pretty", "json", or "compact"
format = "pretty"
"#
        .to_string()
    }
}
