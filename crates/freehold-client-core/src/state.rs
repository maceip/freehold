//! State machine logic extracted for testability
//!
//! This module contains the pure state transition logic, separated from I/O.

use freehold_api::{timing, Message, COOKIE_SIZE};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

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

/// Action the engine should take
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a REGISTER message to this relay
    SendRegister { relay_idx: usize },
    /// Send a CONFIRM message to this relay
    SendConfirm { relay_idx: usize },
    /// Send a HEARTBEAT message to this relay
    SendHeartbeat { relay_idx: usize },
    /// Notify UI of state change
    NotifyStateChange { addr: SocketAddr, state: RelayState },
    /// Notify UI of new neighbor
    NotifyNeighbor { ip: Ipv4Addr },
    /// Notify UI of error
    NotifyError { message: String },
    /// Add a new relay to track
    AddRelay { addr: SocketAddr },
}

/// Relay state tracking
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub addr: SocketAddr,
    pub state: RelayState,
    pub cookie: Option<[u8; COOKIE_SIZE]>,
    pub last_activity: Instant,
}

impl RelayInfo {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            state: RelayState::Disconnected,
            cookie: None,
            // Start in the past so we immediately send REGISTER
            last_activity: Instant::now() - timing::HEARTBEAT_INTERVAL,
        }
    }

    pub fn time_since_activity(&self, now: Instant) -> Duration {
        now.duration_since(self.last_activity)
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

            match self.relays[i].state {
                RelayState::Disconnected if elapsed >= timing::REGISTER_RETRY_INTERVAL => {
                    // Only send REGISTER if enough time has passed since last attempt
                    // Transition to Pending immediately to prevent duplicate sends
                    self.relays[i].state = RelayState::Pending;
                    self.relays[i].last_activity = now;
                    actions.push(Action::SendRegister { relay_idx: i });
                }
                RelayState::Pending if elapsed > timing::REGISTER_TIMEOUT => {
                    // Timeout - transition back to Disconnected
                    let addr = self.relays[i].addr;
                    self.relays[i].state = RelayState::Disconnected;
                    actions.push(Action::NotifyStateChange {
                        addr,
                        state: RelayState::Disconnected,
                    });
                }
                RelayState::Connected if elapsed >= timing::HEARTBEAT_INTERVAL => {
                    actions.push(Action::SendHeartbeat { relay_idx: i });
                }
                _ => {}
            }
        }

        actions
    }

    /// Handle an incoming message, return actions to take
    pub fn handle_message(
        &mut self,
        msg: Message,
        from: SocketAddr,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Find relay by port (anycast may change IP)
        let idx = match self.relays.iter().position(|r| r.addr.port() == from.port()) {
            Some(i) => i,
            None => return actions,
        };

        match msg {
            Message::Challenge { port, cookie } if port == self.port => {
                self.relays[idx].cookie = Some(cookie);
                self.relays[idx].state = RelayState::Pending;
                actions.push(Action::SendConfirm { relay_idx: idx });
            }

            Message::Neighbors { addrs } => {
                if self.relays[idx].state == RelayState::Pending {
                    self.relays[idx].state = RelayState::Connected;
                    actions.push(Action::NotifyStateChange {
                        addr: from,
                        state: RelayState::Connected,
                    });
                }
                self.relays[idx].last_activity = now;

                if self.auto_discover {
                    for ip in addrs {
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
                    message: format!("Relay {} rejected", from),
                });
            }

            _ => {}
        }

        actions
    }

    /// Mark a relay as having sent a message
    pub fn mark_activity(&mut self, relay_idx: usize, now: Instant) {
        if relay_idx < self.relays.len() {
            self.relays[relay_idx].last_activity = now;
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
    pub fn change_port(&mut self, new_port: u16, now: Instant) -> Vec<Action> {
        self.port = new_port;
        let mut actions = Vec::new();

        for relay in &mut self.relays {
            relay.state = RelayState::Disconnected;
            relay.cookie = None;
            relay.last_activity = now - timing::HEARTBEAT_INTERVAL;
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
            Message::Challenge {
                port: 8080,
                cookie,
            },
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

        let actions = sm.handle_message(
            Message::Neighbors { addrs: vec![] },
            relay_addr(9999),
            now,
        );

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
            },
            relay_addr(9999),
            now,
        );

        // Should not add duplicate
        assert!(!actions.iter().any(|a| matches!(a, Action::NotifyNeighbor { .. })));
    }

    #[test]
    fn handle_error_transitions_to_disconnected() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);
        let now = Instant::now();
        sm.relays[0].state = RelayState::Connected;

        let actions = sm.handle_message(Message::Error { port: 8080 }, relay_addr(9999), now);

        assert_eq!(sm.relays[0].state, RelayState::Disconnected);
        assert!(actions.iter().any(|a| matches!(a, Action::NotifyError { .. })));
    }

    #[test]
    fn tick_timeout_in_pending_state() {
        let mut sm = StateMachine::new(relay_addr(9999), 8080, false);

        // Set to pending with old activity time
        sm.relays[0].state = RelayState::Pending;
        sm.relays[0].last_activity = Instant::now() - timing::REGISTER_TIMEOUT - Duration::from_secs(1);

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
        sm.relays[0].last_activity = Instant::now() - timing::HEARTBEAT_INTERVAL - Duration::from_secs(1);

        let actions = sm.tick(Instant::now());

        assert!(actions.contains(&Action::SendHeartbeat { relay_idx: 0 }));
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
            Message::Neighbors { addrs: vec![] },
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

        assert_eq!(sm.relay_states(), vec![
            (relay_addr(9999), RelayState::Connected),
            (relay_addr(9998), RelayState::Pending),
        ]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::net::IpAddr;

    fn socket_addr_strategy() -> impl Strategy<Value = SocketAddr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), 1024u16..65535)
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
                Message::Neighbors { addrs: vec![] },
                addr,
                Instant::now(),
            );

            prop_assert_eq!(sm.relays[0].state, RelayState::Connected);
        }
    }
}
