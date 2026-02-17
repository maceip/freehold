//! State machine logic extracted for testability
//!
//! This module contains the pure state transition logic, separated from I/O.
//!
//! # Thread Safety
//! This type is NOT thread-safe. All calls must be from the same thread.
//! Use a channel to send events from network thread to engine thread.

use freehold_api::{timing, ConfirmAction, Message, COOKIE_SIZE};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Maximum number of neighbors to track (prevents memory exhaustion from malicious server)
pub const MAX_NEIGHBORS: usize = 256;

/// Maximum exponent for exponential backoff (2^6 = 64x base interval)
const MAX_BACKOFF_EXPONENT: u32 = 6;

/// Maximum backoff delay cap (prevents unreasonably long waits)
const MAX_BACKOFF_DELAY: Duration = Duration::from_secs(60);

/// Maximum messages per relay per second (rate limiting)
const MAX_MESSAGES_PER_SECOND: u32 = 100;

/// Rate limit window duration
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);

/// Relay connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    /// Not connected, ready to send REGISTER
    Disconnected,
    /// REGISTER sent, waiting for CHALLENGE
    Pending,
    /// Registered and receiving NEIGHBORS
    Connected,
}

/// Typed error for client operations (#30)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Server explicitly rejected registration
    RegistrationRejected { relay: SocketAddr },
    /// Timed out waiting for response
    Timeout {
        relay: SocketAddr,
        phase: &'static str,
    },
    /// Rate limited (too many messages)
    RateLimited { relay: SocketAddr },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::RegistrationRejected { relay } => {
                write!(f, "Relay {} rejected registration", relay)
            }
            ClientError::Timeout { relay, phase } => {
                write!(f, "Timeout waiting for {} from {}", phase, relay)
            }
            ClientError::RateLimited { relay } => {
                write!(f, "Rate limited by relay {}", relay)
            }
        }
    }
}

impl std::error::Error for ClientError {}

/// Action the engine should take
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a REGISTER message to this relay
    SendRegister { relay_idx: usize },
    /// Send a CONFIRM message to this relay
    SendConfirm { relay_idx: usize },
    /// Send a CONFIRM with an ACME action to this relay
    SendConfirmWithAction { relay_idx: usize, action: ConfirmAction },
    /// Send a HEARTBEAT message to this relay
    SendHeartbeat { relay_idx: usize },
    /// Notify UI of state change
    NotifyStateChange { addr: SocketAddr, state: RelayState },
    /// Notify UI of new neighbor
    NotifyNeighbor { ip: Ipv4Addr },
    /// Notify UI of error (typed for programmatic handling)
    NotifyError { error: ClientError },
    /// Add a new relay to track
    AddRelay { addr: SocketAddr },
}

/// Relay state tracking
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub addr: SocketAddr,
    pub state: RelayState,
    pub cookie: Option<[u8; COOKIE_SIZE]>,
    /// Assigned subdomain from relay (e.g. "xxx.freehold.lit.app")
    pub subdomain: Option<String>,
    /// Last activity time, or None if never contacted.
    /// Using Option explicitly represents "never" rather than a magic past value.
    pub last_activity: Option<Instant>,
    /// Number of consecutive failed connection attempts (for exponential backoff)
    pub retry_count: u32,
    /// Messages received in current rate limit window
    messages_in_window: u32,
    /// Start of current rate limit window
    rate_limit_window_start: Instant,
}

impl RelayInfo {
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            state: RelayState::Disconnected,
            cookie: None,
            subdomain: None,
            // None means never contacted - will trigger immediate REGISTER
            last_activity: None,
            retry_count: 0,
            messages_in_window: 0,
            rate_limit_window_start: now,
        }
    }

    /// Time since last activity, or Duration::MAX if never contacted.
    /// Duration::MAX ensures immediate triggering of retry logic.
    pub fn time_since_activity(&self, now: Instant) -> Duration {
        self.last_activity
            .map(|t| now.duration_since(t))
            .unwrap_or(Duration::MAX)
    }

    /// Calculate next retry delay with exponential backoff and jitter.
    ///
    /// Uses 2^retry_count multiplier capped at 64x, plus random jitter
    /// of up to 25% to prevent thundering herd.
    pub fn next_retry_delay(&self) -> Duration {
        let base = timing::REGISTER_RETRY_INTERVAL;
        let exponent = self.retry_count.min(MAX_BACKOFF_EXPONENT);
        let multiplier = 2u32.saturating_pow(exponent);
        let backoff = base.saturating_mul(multiplier);

        // Cap at maximum delay
        let capped = if backoff > MAX_BACKOFF_DELAY {
            MAX_BACKOFF_DELAY
        } else {
            backoff
        };

        // Add jitter: random 0-25% of the delay to prevent thundering herd
        // Use a simple deterministic jitter based on retry_count and addr
        // to keep the function pure (no RNG dependency)
        let jitter_factor = (self.retry_count as u64 * 17 + self.addr.port() as u64 * 31) % 25;
        let jitter = capped.as_millis() as u64 * jitter_factor / 100;

        capped + Duration::from_millis(jitter)
    }

    /// Reset retry count after successful connection
    pub fn reset_retry_count(&mut self) {
        self.retry_count = 0;
    }

    /// Increment retry count after failed attempt
    pub fn increment_retry_count(&mut self) {
        self.retry_count = self.retry_count.saturating_add(1);
    }

    /// Check if a message should be accepted under rate limiting.
    ///
    /// Returns true if within rate limit, false if rate limited.
    /// Updates internal counters.
    pub fn check_rate_limit(&mut self, now: Instant) -> bool {
        // Check if we need to start a new window
        if now.duration_since(self.rate_limit_window_start) >= RATE_LIMIT_WINDOW {
            self.rate_limit_window_start = now;
            self.messages_in_window = 0;
        }

        // Check if within limit
        if self.messages_in_window >= MAX_MESSAGES_PER_SECOND {
            return false;
        }

        self.messages_in_window += 1;
        true
    }

    /// Get current message count in rate limit window (for testing)
    #[cfg(test)]
    pub fn messages_in_window(&self) -> u32 {
        self.messages_in_window
    }
}

/// Pure state machine for the client engine
#[derive(Debug)]
pub struct StateMachine {
    pub port: u16,
    pub relays: Vec<RelayInfo>,
    pub neighbors: HashSet<Ipv4Addr>,
    pub auto_discover: bool,
}

impl StateMachine {
    pub fn new(initial_relay: SocketAddr, port: u16, auto_discover: bool) -> Self {
        Self {
            port,
            relays: vec![RelayInfo::new(initial_relay)],
            neighbors: HashSet::new(),
            auto_discover,
        }
    }

    /// Get the actions needed for the current time
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();

        for i in 0..self.relays.len() {
            let elapsed = self.relays[i].time_since_activity(now);
            let retry_delay = self.relays[i].next_retry_delay();

            match self.relays[i].state {
                RelayState::Disconnected if elapsed >= retry_delay => {
                    // Only send REGISTER if enough time has passed (with exponential backoff)
                    // Transition to Pending immediately to prevent duplicate sends
                    self.relays[i].state = RelayState::Pending;
                    self.relays[i].last_activity = Some(now);
                    actions.push(Action::SendRegister { relay_idx: i });
                }
                RelayState::Pending if elapsed > timing::REGISTER_TIMEOUT => {
                    // Timeout - transition back to Disconnected and increment retry count
                    let addr = self.relays[i].addr;
                    self.relays[i].state = RelayState::Disconnected;
                    self.relays[i].increment_retry_count();
                    actions.push(Action::NotifyStateChange {
                        addr,
                        state: RelayState::Disconnected,
                    });
                }
                RelayState::Connected if elapsed >= timing::HEARTBEAT_INTERVAL => {
                    // Update last_activity to prevent duplicate heartbeats if response is slow
                    self.relays[i].last_activity = Some(now);
                    actions.push(Action::SendHeartbeat { relay_idx: i });
                }
                _ => {}
            }
        }

        actions
    }

    /// Handle an incoming message, return actions to take
    pub fn handle_message(&mut self, msg: Message, from: SocketAddr, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();

        // Find relay by full address first, then fallback to port (for anycast IP changes)
        let idx = match self.relays.iter().position(|r| r.addr == from).or_else(|| {
            self.relays
                .iter()
                .position(|r| r.addr.port() == from.port())
        }) {
            Some(i) => i,
            None => return actions,
        };

        // Check rate limit - drop message if exceeded
        if !self.relays[idx].check_rate_limit(now) {
            return actions;
        }

        // Update relay address if it changed (anycast scenario)
        if self.relays[idx].addr != from {
            self.relays[idx].addr = from;
        }

        match msg {
            Message::Challenge { port, cookie } if port == self.port => {
                self.relays[idx].cookie = Some(cookie);
                self.relays[idx].state = RelayState::Pending;
                actions.push(Action::SendConfirm { relay_idx: idx });
            }

            Message::Neighbors { addrs, subdomain } => {
                if self.relays[idx].state == RelayState::Pending {
                    self.relays[idx].state = RelayState::Connected;
                    // Reset retry count on successful connection
                    self.relays[idx].reset_retry_count();
                    actions.push(Action::NotifyStateChange {
                        addr: from,
                        state: RelayState::Connected,
                    });
                }
                // Store subdomain if relay provided one
                if subdomain.is_some() {
                    self.relays[idx].subdomain = subdomain;
                }
                self.relays[idx].last_activity = Some(now);

                if self.auto_discover {
                    for ip in addrs {
                        // Prevent memory exhaustion from malicious server
                        if self.neighbors.len() >= MAX_NEIGHBORS {
                            break;
                        }
                        if self.neighbors.insert(ip) {
                            let new_addr = SocketAddr::new(ip.into(), from.port());
                            if !self.relays.iter().any(|r| r.addr == new_addr) {
                                actions.push(Action::NotifyNeighbor { ip });
                                actions.push(Action::AddRelay { addr: new_addr });
                            }
                        }
                    }
                }
            }

            Message::Error { port } if port == self.port => {
                self.relays[idx].state = RelayState::Disconnected;
                self.relays[idx].cookie = None;
                actions.push(Action::NotifyError {
                    error: ClientError::RegistrationRejected { relay: from },
                });
            }

            _ => {}
        }

        actions
    }

    /// Mark a relay as having sent a message
    pub fn mark_activity(&mut self, relay_idx: usize, now: Instant) {
        if relay_idx < self.relays.len() {
            self.relays[relay_idx].last_activity = Some(now);
        }
    }

    /// Add a new relay
    pub fn add_relay(&mut self, addr: SocketAddr) {
        self.relays.push(RelayInfo::new(addr));
    }

    /// Get relay info
    pub fn get_relay(&self, idx: usize) -> Option<&RelayInfo> {
        self.relays.get(idx)
    }

    /// Get relay states for UI
    pub fn relay_states(&self) -> Vec<(SocketAddr, RelayState)> {
        self.relays.iter().map(|r| (r.addr, r.state)).collect()
    }

    /// Change port (request new endpoint)
    pub fn change_port(&mut self, new_port: u16, _now: Instant) -> Vec<Action> {
        self.port = new_port;
        let mut actions = Vec::new();

        for relay in &mut self.relays {
            relay.state = RelayState::Disconnected;
            relay.cookie = None;
            relay.last_activity = None; // Reset to trigger immediate REGISTER
            actions.push(Action::NotifyStateChange {
                addr: relay.addr,
                state: RelayState::Disconnected,
            });
        }

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn relay_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    #[test]
    fn new_state_machine() {
        let sm = StateMachine::new(relay_addr(9999), 8080, true);
        assert_eq!(sm.port, 8080);
        assert_eq!(sm.relays.len(), 1);
        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert!(sm.auto_discover);
    }

    #[test]
    fn tick_sends_register_when_disconnected() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();

        let actions = sm.tick(now);
        assert!(actions.contains(&Action::SendRegister { relay_idx: 0 }));
    }

    #[test]
    fn handle_challenge_transitions_to_pending() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();
        let cookie = [0xAB; COOKIE_SIZE];

        let actions = sm.handle_message(
            Message::Challenge { port: 8080, cookie },
            relay_addr(9999),
            now,
        );

        assert_eq!(sm.relays[0].state, RelayState::Pending);
        assert_eq!(sm.relays[0].cookie, Some(cookie));
        assert!(actions.contains(&Action::SendConfirm { relay_idx: 0 }));
    }

    #[test]
    fn handle_challenge_wrong_port_ignored() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();
        let cookie = [0xAB; COOKIE_SIZE];

        let actions = sm.handle_message(
            Message::Challenge {
                port: 9999, // Wrong port
                cookie,
            },
            relay_addr(9999),
            now,
        );

        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert!(actions.is_empty());
    }

    #[test]
    fn handle_neighbors_transitions_to_connected() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();

        // First get to Pending state
        sm.relays[0].state = RelayState::Pending;

        let actions =
            sm.handle_message(Message::Neighbors { addrs: vec![], subdomain: None }, relay_addr(9999), now);

        assert_eq!(sm.relays[0].state, RelayState::Connected);
        assert!(actions.contains(&Action::NotifyStateChange {
            addr: relay_addr(9999),
            state: RelayState::Connected,
        }));
    }

    #[test]
    fn handle_neighbors_with_discovery() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, true);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Pending;

        let neighbor_ip = Ipv4Addr::new(10, 0, 0, 2);
        let actions = sm.handle_message(
            Message::Neighbors {
                addrs: vec![neighbor_ip],
                subdomain: None,
            },
            relay_addr(9999),
            now,
        );

        assert!(sm.neighbors.contains(&neighbor_ip));
        assert!(actions.contains(&Action::NotifyNeighbor { ip: neighbor_ip }));
        assert!(actions.contains(&Action::AddRelay {
            addr: SocketAddr::new(neighbor_ip.into(), 9999),
        }));
    }

    #[test]
    fn handle_neighbors_no_duplicate_discovery() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, true);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Connected;

        let neighbor_ip = Ipv4Addr::new(10, 0, 0, 2);
        sm.neighbors.insert(neighbor_ip); // Already known

        let actions = sm.handle_message(
            Message::Neighbors {
                addrs: vec![neighbor_ip],
                subdomain: None,
            },
            relay_addr(9999),
            now,
        );

        // Should not add duplicate
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::NotifyNeighbor { .. })));
    }

    #[test]
    fn handle_error_transitions_to_disconnected() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Connected;

        let actions = sm.handle_message(Message::Error { port: 8080 }, relay_addr(9999), now);

        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::NotifyError {
                error: ClientError::RegistrationRejected { .. }
            }
        )));
    }

    #[test]
    fn tick_timeout_in_pending_state() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);

        // Set to pending with old activity time
        sm.relays[0].state = RelayState::Pending;
        sm.relays[0].last_activity =
            Some(Instant::now() - timing::REGISTER_TIMEOUT - Duration::from_secs(1));

        let actions = sm.tick(Instant::now());

        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert!(actions.contains(&Action::NotifyStateChange {
            addr: relay_addr(9999),
            state: RelayState::Disconnected,
        }));
    }

    #[test]
    fn tick_sends_heartbeat_when_connected() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        sm.relays[0].state = RelayState::Connected;
        sm.relays[0].last_activity =
            Some(Instant::now() - timing::HEARTBEAT_INTERVAL - Duration::from_secs(1));

        let actions = sm.tick(Instant::now());

        assert!(actions.contains(&Action::SendHeartbeat { relay_idx: 0 }));
    }

    #[test]
    fn no_heartbeat_spam_on_rapid_ticks() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        sm.relays[0].state = RelayState::Connected;
        sm.relays[0].last_activity =
            Some(Instant::now() - timing::HEARTBEAT_INTERVAL - Duration::from_secs(1));

        let now = Instant::now();

        // First tick should send heartbeat
        let actions1 = sm.tick(now);
        assert!(actions1.contains(&Action::SendHeartbeat { relay_idx: 0 }));

        // Immediate second tick should NOT send another heartbeat
        // (last_activity was updated by first tick)
        let actions2 = sm.tick(now);
        assert!(!actions2
            .iter()
            .any(|a| matches!(a, Action::SendHeartbeat { .. })));

        // Even 1 second later, still no heartbeat (interval is 25 seconds)
        let actions3 = sm.tick(now + Duration::from_secs(1));
        assert!(!actions3
            .iter()
            .any(|a| matches!(a, Action::SendHeartbeat { .. })));
    }

    #[test]
    fn change_port_resets_all_relays() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        sm.relays[0].state = RelayState::Connected;
        sm.add_relay(relay_addr(9998));
        sm.relays[1].state = RelayState::Pending;

        let now = Instant::now();
        let actions = sm.change_port(9000, now);

        assert_eq!(sm.port, 9000);
        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert_eq!(sm.relays[1].state, RelayState::Disconnected);
        assert_eq!(actions.len(), 2); // Two state change notifications
    }

    #[test]
    fn unknown_relay_port_ignored() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();

        // Message from unknown relay
        let actions = sm.handle_message(
            Message::Neighbors { addrs: vec![], subdomain: None },
            relay_addr(8888), // Unknown port
            now,
        );

        assert!(actions.is_empty());
    }

    #[test]
    fn multiple_relays_independent_state() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        sm.add_relay(relay_addr(9998));

        sm.relays[0].state = RelayState::Connected;
        sm.relays[1].state = RelayState::Pending;

        assert_eq!(
            sm.relay_states(),
            vec![
                (relay_addr(9999), RelayState::Connected),
                (relay_addr(9998), RelayState::Pending),
            ]
        );
    }

    // ==================== Security Tests ====================

    #[test]
    fn neighbors_bounded_prevents_memory_exhaustion() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, true);
        sm.relays[0].state = RelayState::Connected;

        // Send messages with batches of IPs across multiple time windows
        // to avoid rate limiting while testing the neighbor cap
        let mut time_offset = Duration::ZERO;
        for batch in 0..10 {
            let now = Instant::now() + time_offset;
            // Each batch has 50 unique IPs
            let addrs: Vec<Ipv4Addr> = (0..50)
                .map(|i| {
                    let idx = batch * 50 + i;
                    Ipv4Addr::new(
                        ((idx >> 24) & 0xFF) as u8,
                        ((idx >> 16) & 0xFF) as u8,
                        ((idx >> 8) & 0xFF) as u8,
                        (idx & 0xFF) as u8,
                    )
                })
                .collect();
            sm.handle_message(Message::Neighbors { addrs, subdomain: None }, relay_addr(9999), now);
            // Advance time to next rate limit window
            time_offset += RATE_LIMIT_WINDOW;
        }

        // Should be capped at MAX_NEIGHBORS (256), not 500
        assert_eq!(sm.neighbors.len(), MAX_NEIGHBORS);
    }

    #[test]
    fn neighbors_flood_single_message() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, true);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Connected;

        // Send one message with 1000 unique IPs
        let addrs: Vec<Ipv4Addr> = (0..1000)
            .map(|i| Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xFF) as u8))
            .collect();

        sm.handle_message(Message::Neighbors { addrs, subdomain: None }, relay_addr(9999), now);

        // Should be capped at MAX_NEIGHBORS
        assert!(sm.neighbors.len() <= MAX_NEIGHBORS);
    }

    // ==================== Exponential Backoff Tests ====================

    #[test]
    fn backoff_increases_with_retries() {
        let addr = relay_addr(9999);
        let mut relay = RelayInfo::new(addr);

        let delay0 = relay.next_retry_delay();
        relay.increment_retry_count();
        let delay1 = relay.next_retry_delay();
        relay.increment_retry_count();
        let delay2 = relay.next_retry_delay();
        relay.increment_retry_count();
        let delay3 = relay.next_retry_delay();

        // Each delay should be roughly 2x the previous (with jitter)
        // Base is 100ms, so: 100ms, 200ms, 400ms, 800ms
        assert!(delay1 > delay0, "delay1 should be > delay0");
        assert!(delay2 > delay1, "delay2 should be > delay1");
        assert!(delay3 > delay2, "delay3 should be > delay2");

        // Check approximate values (allowing for jitter)
        assert!(delay0.as_millis() >= 100 && delay0.as_millis() < 150);
        assert!(delay1.as_millis() >= 200 && delay1.as_millis() < 300);
        assert!(delay2.as_millis() >= 400 && delay2.as_millis() < 600);
    }

    #[test]
    fn backoff_caps_at_maximum() {
        let addr = relay_addr(9999);
        let mut relay = RelayInfo::new(addr);

        // Increment many times past the cap
        for _ in 0..20 {
            relay.increment_retry_count();
        }

        let delay = relay.next_retry_delay();

        // Should be capped at MAX_BACKOFF_DELAY (60 seconds) + jitter
        assert!(
            delay.as_secs() <= 75,
            "delay should be capped near 60 seconds"
        );
    }

    #[test]
    fn backoff_reset_on_connection() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();

        // Simulate several failed attempts
        for _ in 0..5 {
            sm.relays[0].increment_retry_count();
        }
        assert_eq!(sm.relays[0].retry_count, 5);

        // Receive NEIGHBORS (successful connection)
        sm.relays[0].state = RelayState::Pending;
        sm.handle_message(Message::Neighbors { addrs: vec![], subdomain: None }, relay_addr(9999), now);

        // Retry count should be reset
        assert_eq!(sm.relays[0].retry_count, 0);
    }

    #[test]
    fn backoff_increment_on_timeout() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);

        // Set to Pending with activity in the past (will timeout)
        sm.relays[0].state = RelayState::Pending;
        sm.relays[0].last_activity =
            Some(Instant::now() - timing::REGISTER_TIMEOUT - Duration::from_secs(1));
        sm.relays[0].retry_count = 0;

        // Tick should timeout and increment retry count
        sm.tick(Instant::now());

        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert_eq!(sm.relays[0].retry_count, 1);
    }

    #[test]
    fn backoff_delays_next_register() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();

        // Initial tick sends register immediately
        let actions1 = sm.tick(now);
        assert!(actions1
            .iter()
            .any(|a| matches!(a, Action::SendRegister { .. })));

        // Simulate timeout - goes back to Disconnected with retry_count=1
        sm.relays[0].state = RelayState::Disconnected;
        sm.relays[0].retry_count = 1;
        sm.relays[0].last_activity = Some(now);

        // Tick immediately after should NOT send register (backoff is ~200ms)
        let actions2 = sm.tick(now + Duration::from_millis(50));
        assert!(!actions2
            .iter()
            .any(|a| matches!(a, Action::SendRegister { .. })));

        // After backoff period, should send register
        let actions3 = sm.tick(now + Duration::from_millis(250));
        assert!(actions3
            .iter()
            .any(|a| matches!(a, Action::SendRegister { .. })));
    }

    // ==================== Rate Limiting Tests ====================

    #[test]
    fn rate_limit_allows_normal_traffic() {
        let addr = relay_addr(9999);
        let mut relay = RelayInfo::new(addr);
        let now = Instant::now();

        // Should allow up to MAX_MESSAGES_PER_SECOND messages
        for _ in 0..50 {
            assert!(
                relay.check_rate_limit(now),
                "normal traffic should be allowed"
            );
        }
    }

    #[test]
    fn rate_limit_blocks_flood() {
        let addr = relay_addr(9999);
        let mut relay = RelayInfo::new(addr);
        let now = Instant::now();

        // Send MAX_MESSAGES_PER_SECOND messages
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            assert!(relay.check_rate_limit(now));
        }

        // Next message should be blocked
        assert!(!relay.check_rate_limit(now), "flood should be blocked");
        assert!(
            !relay.check_rate_limit(now),
            "continued flood should be blocked"
        );
    }

    #[test]
    fn rate_limit_resets_after_window() {
        let addr = relay_addr(9999);
        let mut relay = RelayInfo::new(addr);
        let now = Instant::now();

        // Exhaust the rate limit
        for _ in 0..MAX_MESSAGES_PER_SECOND {
            relay.check_rate_limit(now);
        }
        assert!(!relay.check_rate_limit(now), "should be rate limited");

        // After window expires, should allow again
        let later = now + RATE_LIMIT_WINDOW + Duration::from_millis(1);
        assert!(
            relay.check_rate_limit(later),
            "should allow after window reset"
        );
    }

    #[test]
    fn rate_limit_drops_messages_in_state_machine() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, true);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Connected;

        // Send many messages rapidly
        let mut accepted = 0;
        for i in 0..150 {
            let ip = Ipv4Addr::new(10, 0, 0, i as u8);
            let actions = sm.handle_message(
                Message::Neighbors { addrs: vec![ip], subdomain: None },
                relay_addr(9999),
                now,
            );
            if !actions.is_empty() {
                accepted += 1;
            }
        }

        // Should have accepted about MAX_MESSAGES_PER_SECOND
        assert!(
            accepted <= MAX_MESSAGES_PER_SECOND as usize,
            "should not accept more than rate limit"
        );
        assert!(accepted >= 90, "should accept most messages up to limit");
    }

    // ==================== Relay Matching Tests ====================

    #[test]
    fn two_relays_same_port_different_ips() {
        // Two relays on different IPs but same port
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 9999);

        let mut sm = StateMachine::new(addr1, 8080, false);
        sm.add_relay(addr2);
        sm.relays[0].state = RelayState::Connected;
        sm.relays[1].state = RelayState::Pending;

        let now = Instant::now();

        // Message from addr2 should match relay 1, not relay 0
        let actions = sm.handle_message(Message::Neighbors { addrs: vec![], subdomain: None }, addr2, now);

        // Relay 1 should transition to Connected (it was Pending)
        assert_eq!(sm.relays[1].state, RelayState::Connected);
        // Relay 0 should still be Connected (unchanged)
        assert_eq!(sm.relays[0].state, RelayState::Connected);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::NotifyStateChange { addr, state: RelayState::Connected } if *addr == addr2
        )));
    }

    #[test]
    fn anycast_ip_change_updates_relay() {
        // Start with one IP
        let original_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 9999);

        let mut sm = StateMachine::new(original_addr, 8080, false);
        sm.relays[0].state = RelayState::Connected;

        let now = Instant::now();

        // Receive message from new IP (same port - anycast scenario)
        sm.handle_message(Message::Neighbors { addrs: vec![], subdomain: None }, new_addr, now);

        // Relay address should be updated to new IP
        assert_eq!(sm.relays[0].addr, new_addr);
    }

    #[test]
    fn exact_match_preferred_over_port_match() {
        // Two relays: one exact match, one same port different IP
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 9999);

        let mut sm = StateMachine::new(addr1, 8080, false);
        sm.add_relay(addr2);

        // Both in Pending state
        sm.relays[0].state = RelayState::Pending;
        sm.relays[1].state = RelayState::Pending;

        let now = Instant::now();

        // Message from addr1 should match relay 0 exactly
        sm.handle_message(Message::Neighbors { addrs: vec![], subdomain: None }, addr1, now);

        // Only relay 0 should transition
        assert_eq!(sm.relays[0].state, RelayState::Connected);
        assert_eq!(sm.relays[1].state, RelayState::Pending);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::net::IpAddr;

    fn socket_addr_strategy() -> impl Strategy<Value = SocketAddr> {
        (
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
            1024u16..65535,
        )
            .prop_map(|(a, b, c, d, port)| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
            })
    }

    proptest! {
        /// State machine always starts Disconnected
        #[test]
        fn prop_starts_disconnected(
            addr in socket_addr_strategy(),
            port in any::<u16>()
        ) {
            let sm = StateMachine::new(addr, port, false);
            prop_assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        }

        /// tick() always returns SendRegister for Disconnected relays
        #[test]
        fn prop_tick_register_when_disconnected(
            addr in socket_addr_strategy(),
            port in any::<u16>()
        ) {
            let mut sm = StateMachine::new(addr, port, false);
            let actions = sm.tick(Instant::now());
            let expected = Action::SendRegister { relay_idx: 0 };
            prop_assert!(actions.contains(&expected));
        }

        /// Challenge with correct port transitions to Pending
        #[test]
        fn prop_challenge_sets_pending(
            addr in socket_addr_strategy(),
            port in any::<u16>(),
            cookie in prop::array::uniform16(any::<u8>())
        ) {
            let mut sm = StateMachine::new(addr, port, false);
            sm.handle_message(
                Message::Challenge { port, cookie },
                addr,
                Instant::now(),
            );
            prop_assert_eq!(sm.relays[0].state, RelayState::Pending);
            prop_assert_eq!(sm.relays[0].cookie, Some(cookie));
        }

        /// Neighbors after Challenge transitions to Connected
        #[test]
        fn prop_neighbors_after_challenge_connects(
            addr in socket_addr_strategy(),
            port in any::<u16>()
        ) {
            let mut sm = StateMachine::new(addr, port, false);
            sm.relays[0].state = RelayState::Pending;

            sm.handle_message(
                Message::Neighbors { addrs: vec![], subdomain: None },
                addr,
                Instant::now(),
            );

            prop_assert_eq!(sm.relays[0].state, RelayState::Connected);
        }
    }
}
