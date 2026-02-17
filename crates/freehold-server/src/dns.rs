//! DNS record management via knotc CLI
//!
//! Manages dual-path DNS records for backend subdomains using the
//! Knot DNS `knotc` control utility.
//!
//! ## Dual-path DNS
//!
//! Each registration creates records for three names:
//!
//! | Name | Records | Purpose |
//! |------|---------|---------|
//! | `{hash}` | A (relay) + 2x HTTPS (relay, home) | SVCB-racing for browsers |
//! | `{hash}.relay` | A + HTTPS (relay only) | Explicit relay path for SDK clients |
//! | `{hash}.home` | A + HTTPS (home only) | Explicit direct path for SDK clients |
//!
//! SVCB-aware browsers (Chrome, Edge) race both HTTPS endpoints on the
//! primary domain automatically. SDK clients can use `.relay` or `.home`
//! for explicit control. Legacy clients fall back to the A record (relay).
//!
//! ACME TXT records are set on all three `_acme-challenge.*` names to
//! support multi-SAN certificate issuance.

use crate::config::DnsConfig;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Instant;
use tracing::debug;

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
        self.transaction(|mgr| {
            mgr.knotc(&[
                "zone-set",
                &mgr.zone,
                subdomain,
                "300",
                "A",
                &ip.to_string(),
            ])?;
            debug!("DNS: set {}.{} A {}", subdomain, mgr.zone, ip);
            Ok(())
        })
    }

    /// Set HTTPS record for a subdomain with h3 ALPN and port
    pub fn set_https(&self, subdomain: &str, port: u16) -> Result<()> {
        let svcb_params = format!("1 . alpn=h3 port={}", port);
        self.transaction(|mgr| {
            mgr.knotc(&[
                "zone-set",
                &mgr.zone,
                subdomain,
                "300",
                "HTTPS",
                &svcb_params,
            ])?;
            debug!("DNS: set {}.{} HTTPS {}", subdomain, mgr.zone, svcb_params);
            Ok(())
        })
    }

    /// Set TXT record for ACME DNS-01 challenge on all three names
    pub fn set_txt(&self, subdomain: &str, token: &str) -> Result<()> {
        let names = [
            format!("_acme-challenge.{}", subdomain),
            format!("_acme-challenge.{}.relay", subdomain),
            format!("_acme-challenge.{}.home", subdomain),
        ];
        self.transaction(|mgr| {
            for name in &names {
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "TXT"]);
                mgr.knotc(&["zone-set", &mgr.zone, name, "60", "TXT", token])?;
                debug!("DNS: set {}.{} TXT {}", name, mgr.zone, token);
            }
            Ok(())
        })
    }

    /// Clear TXT records for ACME challenge on all three names
    pub fn clear_txt(&self, subdomain: &str) -> Result<()> {
        let names = [
            format!("_acme-challenge.{}", subdomain),
            format!("_acme-challenge.{}.relay", subdomain),
            format!("_acme-challenge.{}.home", subdomain),
        ];
        self.transaction(|mgr| {
            for name in &names {
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "TXT"]);
                debug!("DNS: cleared {}.{} TXT", name, mgr.zone);
            }
            Ok(())
        })
    }

    /// Clear all DNS records for a subdomain and its relay/home variants
    pub fn clear_all(&self, subdomain: &str) -> Result<()> {
        let relay_name = format!("{}.relay", subdomain);
        let home_name = format!("{}.home", subdomain);
        let acme_names = [
            format!("_acme-challenge.{}", subdomain),
            format!("_acme-challenge.{}", relay_name),
            format!("_acme-challenge.{}", home_name),
        ];
        self.transaction(|mgr| {
            // Best-effort removal - ignore errors for records that don't exist
            for name in &[subdomain.to_string(), relay_name.clone(), home_name.clone()] {
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "A"]);
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "HTTPS"]);
            }
            for name in &acme_names {
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "TXT"]);
            }
            debug!("DNS: cleared all records for {}.{}", subdomain, mgr.zone);
            Ok(())
        })
    }

    /// Set up dual-path registration records in a single transaction.
    ///
    /// Creates:
    /// - `{sub}` A → relay_ip (fallback for legacy clients)
    /// - `{sub}` HTTPS priority 1 → relay (port=relay_port, ipv4hint=relay_ip)
    /// - `{sub}` HTTPS priority 1 → direct (port=home_port, ipv4hint=home_ip)
    /// - `{sub}.relay` A → relay_ip + HTTPS
    /// - `{sub}.home` A → home_ip + HTTPS
    pub fn set_registration(
        &self,
        subdomain: &str,
        relay_ip: Ipv4Addr,
        relay_port: u16,
        home_ip: Ipv4Addr,
        home_port: u16,
    ) -> Result<()> {
        let relay_name = format!("{}.relay", subdomain);
        let home_name = format!("{}.home", subdomain);
        let relay_svcb = format!("1 . alpn=h3 port={} ipv4hint={}", relay_port, relay_ip);
        let direct_svcb = format!("1 . alpn=h3 port={} ipv4hint={}", home_port, home_ip);
        let relay_only_svcb = format!("1 . alpn=h3 port={}", relay_port);
        let home_only_svcb = format!("1 . alpn=h3 port={}", home_port);

        self.transaction(|mgr| {
            // Clear existing records for all three names
            for name in &[subdomain.to_string(), relay_name.clone(), home_name.clone()] {
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "A"]);
                let _ = mgr.knotc(&["zone-unset", &mgr.zone, name, "HTTPS"]);
            }

            // Primary domain: A fallback + two HTTPS records for SVCB racing
            mgr.knotc(&[
                "zone-set", &mgr.zone, subdomain, "300", "A", &relay_ip.to_string(),
            ])?;
            mgr.knotc(&[
                "zone-set", &mgr.zone, subdomain, "300", "HTTPS", &relay_svcb,
            ])?;
            mgr.knotc(&[
                "zone-set", &mgr.zone, subdomain, "300", "HTTPS", &direct_svcb,
            ])?;

            // Relay subdomain: A + HTTPS
            mgr.knotc(&[
                "zone-set", &mgr.zone, &relay_name, "300", "A", &relay_ip.to_string(),
            ])?;
            mgr.knotc(&[
                "zone-set", &mgr.zone, &relay_name, "300", "HTTPS", &relay_only_svcb,
            ])?;

            // Home subdomain: A + HTTPS
            mgr.knotc(&[
                "zone-set", &mgr.zone, &home_name, "300", "A", &home_ip.to_string(),
            ])?;
            mgr.knotc(&[
                "zone-set", &mgr.zone, &home_name, "300", "HTTPS", &home_only_svcb,
            ])?;

            debug!(
                "DNS: registered {}.{} relay={}:{} home={}:{}",
                subdomain, mgr.zone, relay_ip, relay_port, home_ip, home_port
            );
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
