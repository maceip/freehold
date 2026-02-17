//! Quota tracking for port registrations
//!
//! This module manages the mapping between IP addresses and registered ports,
//! enforcing per-IP quota limits.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Tracks which ports an IP has registered (for quota enforcement)
#[derive(Default, Debug)]
pub struct QuotaTracker {
    /// Maps IP -> list of registered ports
    ports_by_ip: HashMap<Ipv4Addr, Vec<u16>>,
    /// Maps port -> owning IP (for efficient unregistration)
    ip_by_port: HashMap<u16, Ipv4Addr>,
}

impl QuotaTracker {
    /// Create a new empty QuotaTracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a port for an IP address.
    ///
    /// If the port was previously registered by another IP, it is reassigned.
    /// If the same IP re-registers the same port, this is a no-op (no duplicate).
    pub fn register(&mut self, ip: Ipv4Addr, port: u16) {
        // Remove any existing registration for this port
        if let Some(old_ip) = self.ip_by_port.remove(&port) {
            if let Some(ports) = self.ports_by_ip.get_mut(&old_ip) {
                ports.retain(|&p| p != port);
                if ports.is_empty() {
                    self.ports_by_ip.remove(&old_ip);
                }
            }
        }
        // Register the new assignment
        self.ip_by_port.insert(port, ip);
        let ports = self.ports_by_ip.entry(ip).or_default();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }

    /// Unregister a port, removing its IP association.
    pub fn unregister(&mut self, port: u16) {
        if let Some(ip) = self.ip_by_port.remove(&port) {
            if let Some(ports) = self.ports_by_ip.get_mut(&ip) {
                ports.retain(|&p| p != port);
                if ports.is_empty() {
                    self.ports_by_ip.remove(&ip);
                }
            }
        }
    }

    /// Get the number of ports registered by an IP.
    pub fn count(&self, ip: &Ipv4Addr) -> u32 {
        self.ports_by_ip
            .get(ip)
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }

    /// Check if an IP has reached a quota limit.
    pub fn is_at_limit(&self, ip: &Ipv4Addr, max_ports: u32) -> bool {
        self.count(ip) >= max_ports
    }

    /// Get all registered ports.
    pub fn ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.ip_by_port.keys().copied()
    }

    /// Get the IP that owns a port, if any.
    pub fn get_owner(&self, port: u16) -> Option<Ipv4Addr> {
        self.ip_by_port.get(&port).copied()
    }

    /// Get all ports registered by an IP.
    pub fn get_ports(&self, ip: &Ipv4Addr) -> Option<&[u16]> {
        self.ports_by_ip.get(ip).map(|v| v.as_slice())
    }

    /// Get the total number of registered ports.
    pub fn total_ports(&self) -> usize {
        self.ip_by_port.len()
    }

    /// Get the number of unique IPs with registrations.
    pub fn total_ips(&self) -> usize {
        self.ports_by_ip.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn new_tracker_is_empty() {
        let tracker = QuotaTracker::new();
        assert_eq!(tracker.total_ports(), 0);
        assert_eq!(tracker.total_ips(), 0);
    }

    #[test]
    fn register_single_port() {
        let mut tracker = QuotaTracker::new();
        tracker.register(ip(10, 0, 0, 1), 8080);

        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 1);
        assert_eq!(tracker.get_owner(8080), Some(ip(10, 0, 0, 1)));
        assert_eq!(tracker.total_ports(), 1);
        assert_eq!(tracker.total_ips(), 1);
    }

    #[test]
    fn register_multiple_ports_same_ip() {
        let mut tracker = QuotaTracker::new();
        let addr = ip(10, 0, 0, 1);

        tracker.register(addr, 8080);
        tracker.register(addr, 8081);
        tracker.register(addr, 8082);

        assert_eq!(tracker.count(&addr), 3);
        assert_eq!(
            tracker.get_ports(&addr),
            Some([8080, 8081, 8082].as_slice())
        );
        assert_eq!(tracker.total_ports(), 3);
        assert_eq!(tracker.total_ips(), 1);
    }

    #[test]
    fn register_ports_different_ips() {
        let mut tracker = QuotaTracker::new();

        tracker.register(ip(10, 0, 0, 1), 8080);
        tracker.register(ip(10, 0, 0, 2), 8081);
        tracker.register(ip(10, 0, 0, 3), 8082);

        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 1);
        assert_eq!(tracker.count(&ip(10, 0, 0, 2)), 1);
        assert_eq!(tracker.count(&ip(10, 0, 0, 3)), 1);
        assert_eq!(tracker.total_ips(), 3);
    }

    #[test]
    fn unregister_port() {
        let mut tracker = QuotaTracker::new();
        tracker.register(ip(10, 0, 0, 1), 8080);
        tracker.register(ip(10, 0, 0, 1), 8081);

        tracker.unregister(8080);

        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 1);
        assert_eq!(tracker.get_owner(8080), None);
        assert_eq!(tracker.get_owner(8081), Some(ip(10, 0, 0, 1)));
    }

    #[test]
    fn unregister_last_port_removes_ip() {
        let mut tracker = QuotaTracker::new();
        tracker.register(ip(10, 0, 0, 1), 8080);

        tracker.unregister(8080);

        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 0);
        assert_eq!(tracker.total_ips(), 0);
        assert_eq!(tracker.get_ports(&ip(10, 0, 0, 1)), None);
    }

    #[test]
    fn unregister_nonexistent_port_is_noop() {
        let mut tracker = QuotaTracker::new();
        tracker.register(ip(10, 0, 0, 1), 8080);

        tracker.unregister(9999); // Doesn't exist

        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 1);
        assert_eq!(tracker.total_ports(), 1);
    }

    #[test]
    fn port_reassignment() {
        let mut tracker = QuotaTracker::new();

        // First IP registers port 8080
        tracker.register(ip(10, 0, 0, 1), 8080);
        assert_eq!(tracker.get_owner(8080), Some(ip(10, 0, 0, 1)));
        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 1);

        // Second IP takes over port 8080
        tracker.register(ip(10, 0, 0, 2), 8080);

        // Port should now belong to second IP
        assert_eq!(tracker.get_owner(8080), Some(ip(10, 0, 0, 2)));
        assert_eq!(tracker.count(&ip(10, 0, 0, 2)), 1);

        // First IP should have no ports now
        assert_eq!(tracker.count(&ip(10, 0, 0, 1)), 0);
        assert_eq!(tracker.get_ports(&ip(10, 0, 0, 1)), None);
    }

    #[test]
    fn quota_limit_check() {
        let mut tracker = QuotaTracker::new();
        let addr = ip(10, 0, 0, 1);

        assert!(!tracker.is_at_limit(&addr, 3));

        tracker.register(addr, 8080);
        assert!(!tracker.is_at_limit(&addr, 3));

        tracker.register(addr, 8081);
        assert!(!tracker.is_at_limit(&addr, 3));

        tracker.register(addr, 8082);
        assert!(tracker.is_at_limit(&addr, 3));
    }

    #[test]
    fn ports_iterator() {
        let mut tracker = QuotaTracker::new();
        tracker.register(ip(10, 0, 0, 1), 8080);
        tracker.register(ip(10, 0, 0, 2), 8081);
        tracker.register(ip(10, 0, 0, 1), 8082);

        let mut ports: Vec<u16> = tracker.ports().collect();
        ports.sort();
        assert_eq!(ports, vec![8080, 8081, 8082]);
    }

    #[test]
    fn count_unknown_ip_is_zero() {
        let tracker = QuotaTracker::new();
        assert_eq!(tracker.count(&ip(192, 168, 1, 1)), 0);
    }

    #[test]
    fn register_same_port_twice_same_ip() {
        let mut tracker = QuotaTracker::new();
        let addr = ip(10, 0, 0, 1);

        tracker.register(addr, 8080);
        tracker.register(addr, 8080); // Same IP, same port

        // Must count as 1, not 2 — no duplicates allowed
        assert_eq!(tracker.count(&addr), 1);
        assert_eq!(tracker.get_owner(8080), Some(addr));
        assert_eq!(tracker.total_ports(), 1);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    proptest! {
        /// After registering, the IP should own the port
        #[test]
        fn prop_register_establishes_ownership(
            ip in ipv4_strategy(),
            port in any::<u16>()
        ) {
            let mut tracker = QuotaTracker::new();
            tracker.register(ip, port);
            prop_assert_eq!(tracker.get_owner(port), Some(ip));
        }

        /// After unregistering, the port should have no owner
        #[test]
        fn prop_unregister_removes_ownership(
            ip in ipv4_strategy(),
            port in any::<u16>()
        ) {
            let mut tracker = QuotaTracker::new();
            tracker.register(ip, port);
            tracker.unregister(port);
            prop_assert_eq!(tracker.get_owner(port), None);
        }

        /// Count should match the number of registered ports
        #[test]
        fn prop_count_matches_registrations(
            ip in ipv4_strategy(),
            ports in prop::collection::vec(any::<u16>(), 0..10)
        ) {
            let mut tracker = QuotaTracker::new();
            let unique_ports: std::collections::HashSet<_> = ports.iter().copied().collect();

            for port in &ports {
                tracker.register(ip, *port);
            }

            // Count should equal unique ports (duplicates overwrite)
            prop_assert_eq!(tracker.count(&ip), unique_ports.len() as u32);
        }

        /// Reassigning a port should update ownership
        #[test]
        fn prop_reassignment_updates_owner(
            ip1 in ipv4_strategy(),
            ip2 in ipv4_strategy(),
            port in any::<u16>()
        ) {
            let mut tracker = QuotaTracker::new();
            tracker.register(ip1, port);
            tracker.register(ip2, port);

            prop_assert_eq!(tracker.get_owner(port), Some(ip2));
            // If IPs are different, ip1 should lose the port
            if ip1 != ip2 {
                prop_assert!(!tracker.get_ports(&ip1).is_some_and(|p| p.contains(&port)));
            }
        }

        /// Total ports should equal sum of all IP counts
        #[test]
        fn prop_total_ports_consistent(
            registrations in prop::collection::vec(
                (ipv4_strategy(), any::<u16>()),
                0..20
            )
        ) {
            let mut tracker = QuotaTracker::new();
            for (ip, port) in registrations {
                tracker.register(ip, port);
            }

            // Each port should be counted exactly once
            let total_from_iterator = tracker.ports().count();
            prop_assert_eq!(tracker.total_ports(), total_from_iterator);
        }
    }
}
