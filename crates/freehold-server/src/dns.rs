//! DNS record management via knotc CLI
//!
//! Manages A, HTTPS, and TXT records for backend subdomains
//! using the Knot DNS `knotc` control utility.

use crate::config::DnsConfig;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Instant;
use tracing::{debug, warn};

/// Manages DNS records via knotc CLI
pub struct DnsManager {
    zone: String,
    knotc_path: String,
}

impl DnsManager {
    /// Create a new DnsManager from config
    pub fn new(config: &DnsConfig) -> Self {
        Self {
            zone: config.zone.clone(),
            knotc_path: config.knotc_path.clone(),
        }
    }

    /// Run a knotc command, returning stdout on success
    fn knotc(&self, args: &[&str]) -> Result<String> {
        let output = Command::new(&self.knotc_path)
            .args(args)
            .output()
            .with_context(|| format!("run knotc {:?}", args))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("knotc {:?} failed: {}", args, stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Execute a DNS transaction (begin, operations, commit)
    fn transaction(&self, ops: impl FnOnce(&DnsManager) -> Result<()>) -> Result<()> {
        self.knotc(&["zone-begin", &self.zone])?;
        match ops(self) {
            Ok(()) => {
                self.knotc(&["zone-commit", &self.zone])?;
                Ok(())
            }
            Err(e) => {
                let _ = self.knotc(&["zone-abort", &self.zone]);
                Err(e)
            }
        }
    }

    /// Set A record for a subdomain pointing to relay IP
    pub fn set_a(&self, subdomain: &str, ip: Ipv4Addr) -> Result<()> {
        let fqdn = format!("{}.{}", subdomain, self.zone);
        self.transaction(|mgr| {
            mgr.knotc(&["zone-set", &mgr.zone, &fqdn, "A", &ip.to_string()])?;
            debug!("DNS: set {} A {}", fqdn, ip);
            Ok(())
        })
    }

    /// Set HTTPS record for a subdomain with h3 ALPN and port
    pub fn set_https(&self, subdomain: &str, port: u16) -> Result<()> {
        let fqdn = format!("{}.{}", subdomain, self.zone);
        let svcb_params = format!("1 . alpn=h3 port={}", port);
        self.transaction(|mgr| {
            mgr.knotc(&["zone-set", &mgr.zone, &fqdn, "HTTPS", &svcb_params])?;
            debug!("DNS: set {} HTTPS {}", fqdn, svcb_params);
            Ok(())
        })
    }

    /// Set TXT record for ACME DNS-01 challenge
    pub fn set_txt(&self, subdomain: &str, token: &str) -> Result<()> {
        let fqdn = format!("_acme-challenge.{}.{}", subdomain, self.zone);
        self.transaction(|mgr| {
            mgr.knotc(&["zone-set", &mgr.zone, &fqdn, "TXT", token])?;
            debug!("DNS: set {} TXT {}", fqdn, token);
            Ok(())
        })
    }

    /// Clear TXT record for ACME challenge
    pub fn clear_txt(&self, subdomain: &str) -> Result<()> {
        let fqdn = format!("_acme-challenge.{}.{}", subdomain, self.zone);
        self.transaction(|mgr| {
            mgr.knotc(&["zone-unset", &mgr.zone, &fqdn, "TXT"])?;
            debug!("DNS: cleared {} TXT", fqdn);
            Ok(())
        })
    }

    /// Clear all DNS records for a subdomain (A, HTTPS, TXT)
    pub fn clear_all(&self, subdomain: &str) -> Result<()> {
        let fqdn = format!("{}.{}", subdomain, self.zone);
        let acme_fqdn = format!("_acme-challenge.{}.{}", subdomain, self.zone);
        self.transaction(|mgr| {
            // Best-effort removal - ignore errors for records that don't exist
            let _ = mgr.knotc(&["zone-unset", &mgr.zone, &fqdn, "A"]);
            let _ = mgr.knotc(&["zone-unset", &mgr.zone, &fqdn, "HTTPS"]);
            let _ = mgr.knotc(&["zone-unset", &mgr.zone, &acme_fqdn, "TXT"]);
            debug!("DNS: cleared all records for {}", subdomain);
            Ok(())
        })
    }

    /// Set up registration records (A + HTTPS) in a single transaction
    pub fn set_registration(&self, subdomain: &str, ip: Ipv4Addr, port: u16) -> Result<()> {
        let fqdn = format!("{}.{}", subdomain, self.zone);
        let svcb_params = format!("1 . alpn=h3 port={}", port);
        self.transaction(|mgr| {
            mgr.knotc(&["zone-set", &mgr.zone, &fqdn, "A", &ip.to_string()])?;
            mgr.knotc(&["zone-set", &mgr.zone, &fqdn, "HTTPS", &svcb_params])?;
            debug!("DNS: registered {} A {} HTTPS {}", fqdn, ip, svcb_params);
            Ok(())
        })
    }
}

/// Rate limiter for TXT record updates (per port)
pub struct TxtRateLimiter {
    last_update: HashMap<u16, Instant>,
    min_interval_secs: u64,
}

impl TxtRateLimiter {
    /// Create a new rate limiter with the given minimum interval
    pub fn new(min_interval_secs: u64) -> Self {
        Self {
            last_update: HashMap::new(),
            min_interval_secs,
        }
    }

    /// Check if a TXT update is allowed for this port
    pub fn check(&self, port: u16) -> bool {
        match self.last_update.get(&port) {
            None => true,
            Some(last) => last.elapsed().as_secs() >= self.min_interval_secs,
        }
    }

    /// Record that a TXT update was performed for this port
    pub fn record(&mut self, port: u16) {
        self.last_update.insert(port, Instant::now());
    }

    /// Remove tracking for a port (on expiry cleanup)
    pub fn remove(&mut self, port: u16) {
        self.last_update.remove(&port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_limiter_allows_first_request() {
        let limiter = TxtRateLimiter::new(300);
        assert!(limiter.check(8080));
    }

    #[test]
    fn rate_limiter_blocks_immediate_second_request() {
        let mut limiter = TxtRateLimiter::new(300);
        limiter.record(8080);
        assert!(!limiter.check(8080));
    }

    #[test]
    fn rate_limiter_different_ports_independent() {
        let mut limiter = TxtRateLimiter::new(300);
        limiter.record(8080);
        assert!(limiter.check(8081)); // Different port should be allowed
    }

    #[test]
    fn rate_limiter_remove_allows_next_request() {
        let mut limiter = TxtRateLimiter::new(300);
        limiter.record(8080);
        limiter.remove(8080);
        assert!(limiter.check(8080));
    }
}
