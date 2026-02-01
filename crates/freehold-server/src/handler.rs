//! Message handler trait for protocol logic extraction
//!
//! This module defines the `MessageHandler` trait that abstracts the core
//! message handling logic from I/O and storage concerns. This allows:
//!
//! - Tests to use a mock implementation without eBPF
//! - The real server to implement the same trait
//! - Shared protocol logic without code duplication
//!
//! # Example
//!
//! ```rust,ignore
//! use freehold_server::handler::{MessageHandler, HandlerContext};
//!
//! struct MyHandler {
//!     context: HandlerContext,
//! }
//!
//! impl MessageHandler for MyHandler {
//!     fn context(&self) -> &HandlerContext { &self.context }
//!     fn context_mut(&mut self) -> &mut HandlerContext { &mut self.context }
//!     fn is_registered(&self, ip: Ipv4Addr, port: u16) -> bool { /* ... */ }
//!     fn register(&mut self, ip: Ipv4Addr, port: u16) { /* ... */ }
//! }
//! ```

use crate::cookie::CookieAuth;
use crate::quota::QuotaTracker;
use freehold_api::Message;
use std::net::Ipv4Addr;

/// Context shared by all message handler implementations
pub struct HandlerContext {
    /// Cookie authentication for stateless verification
    pub cookie_auth: CookieAuth,
    /// Per-IP port quota tracking
    pub quotas: QuotaTracker,
    /// Maximum ports allowed per IP
    pub max_ports_per_ip: u32,
    /// Neighbor list to send in NEIGHBORS messages
    pub neighbors: Vec<Ipv4Addr>,
}

impl HandlerContext {
    /// Create a new handler context
    pub fn new(secret: [u8; 32], max_ports_per_ip: u32, neighbors: Vec<Ipv4Addr>) -> Self {
        Self {
            cookie_auth: CookieAuth::new(secret),
            quotas: QuotaTracker::default(),
            max_ports_per_ip,
            neighbors,
        }
    }
}

/// Result of handling a message
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleResult {
    /// Send this message as a response
    Reply(Message),
    /// No response needed
    NoReply,
}

impl HandleResult {
    /// Convert to Option<Message> for convenience
    pub fn into_option(self) -> Option<Message> {
        match self {
            HandleResult::Reply(msg) => Some(msg),
            HandleResult::NoReply => None,
        }
    }
}

impl From<Message> for HandleResult {
    fn from(msg: Message) -> Self {
        HandleResult::Reply(msg)
    }
}

/// Trait for message handlers implementing the Freehold protocol.
///
/// This trait separates the protocol logic from I/O and storage concerns.
/// Implementors provide the storage backend (eBPF maps, in-memory, etc.)
/// while the protocol logic is handled by the default `handle` method.
pub trait MessageHandler {
    /// Get the handler context (shared state)
    fn context(&self) -> &HandlerContext;

    /// Get mutable handler context
    fn context_mut(&mut self) -> &mut HandlerContext;

    /// Get current time bucket for cookie generation.
    /// Override to use a fixed bucket in tests.
    fn time_bucket(&self) -> u64 {
        // Default: use system time
        use freehold_api::timing;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        let ktime_ns = (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64);
        ktime_ns / timing::TIME_BUCKET.as_nanos() as u64
    }

    /// Get valid time buckets for cookie verification (current and previous).
    /// Override to use fixed buckets in tests.
    fn valid_buckets(&self) -> Vec<u64> {
        let current = self.time_bucket();
        vec![current, current.saturating_sub(1)]
    }

    /// Check if a port is registered for the given IP.
    /// Storage-specific implementation required.
    fn is_registered(&self, ip: Ipv4Addr, port: u16) -> bool;

    /// Register a port for the given IP.
    /// Called after successful cookie verification.
    /// Storage-specific implementation required.
    fn register(&mut self, ip: Ipv4Addr, port: u16);

    /// Handle a message and return the response.
    ///
    /// This is the core protocol logic, shared by all implementations.
    fn handle(&mut self, msg: Message, from_ip: Ipv4Addr) -> HandleResult {
        match msg {
            Message::Register { port } => self.handle_register(from_ip, port),
            Message::Confirm { port, cookie } => self.handle_confirm(from_ip, port, cookie),
            Message::Heartbeat { port } => self.handle_heartbeat(from_ip, port),
            _ => HandleResult::NoReply,
        }
    }

    /// Handle REGISTER message
    fn handle_register(&mut self, from_ip: Ipv4Addr, port: u16) -> HandleResult {
        let ctx = self.context();

        // Check quota
        let count = ctx.quotas.count(&from_ip);
        if count >= ctx.max_ports_per_ip {
            return Message::Error { port }.into();
        }

        // Generate challenge cookie
        let bucket = self.time_bucket();
        let cookie = ctx.cookie_auth.generate(from_ip, port, bucket);
        Message::Challenge { port, cookie }.into()
    }

    /// Handle CONFIRM message
    fn handle_confirm(
        &mut self,
        from_ip: Ipv4Addr,
        port: u16,
        cookie: [u8; freehold_api::COOKIE_SIZE],
    ) -> HandleResult {
        let valid_buckets = self.valid_buckets();

        // Verify cookie
        if !self
            .context()
            .cookie_auth
            .verify(from_ip, port, &cookie, &valid_buckets)
        {
            return Message::Error { port }.into();
        }

        // Register the port
        self.register(from_ip, port);
        self.context_mut().quotas.register(from_ip, port);

        // Send neighbors
        Message::Neighbors {
            addrs: self.context().neighbors.clone(),
        }
        .into()
    }

    /// Handle HEARTBEAT message
    fn handle_heartbeat(&mut self, from_ip: Ipv4Addr, port: u16) -> HandleResult {
        // Only respond if registered for this IP
        if self.is_registered(from_ip, port) {
            Message::Neighbors {
                addrs: self.context().neighbors.clone(),
            }
            .into()
        } else {
            HandleResult::NoReply
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Simple in-memory implementation for testing
    struct TestHandler {
        context: HandlerContext,
        registered: HashSet<(Ipv4Addr, u16)>,
        fixed_bucket: u64,
    }

    impl TestHandler {
        fn new(secret: [u8; 32]) -> Self {
            Self {
                context: HandlerContext::new(
                    secret,
                    8,
                    vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
                ),
                registered: HashSet::new(),
                fixed_bucket: 0,
            }
        }
    }

    impl MessageHandler for TestHandler {
        fn context(&self) -> &HandlerContext {
            &self.context
        }

        fn context_mut(&mut self) -> &mut HandlerContext {
            &mut self.context
        }

        fn time_bucket(&self) -> u64 {
            self.fixed_bucket
        }

        fn valid_buckets(&self) -> Vec<u64> {
            vec![self.fixed_bucket, self.fixed_bucket.saturating_sub(1)]
        }

        fn is_registered(&self, ip: Ipv4Addr, port: u16) -> bool {
            self.registered.contains(&(ip, port))
        }

        fn register(&mut self, ip: Ipv4Addr, port: u16) {
            self.registered.insert((ip, port));
        }
    }

    #[test]
    fn test_full_registration_flow() {
        let secret = [0xAB; 32];
        let mut handler = TestHandler::new(secret);
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let port = 8080;

        // Step 1: REGISTER
        let result = handler.handle(Message::Register { port }, client_ip);
        let cookie = match result {
            HandleResult::Reply(Message::Challenge { port: p, cookie }) => {
                assert_eq!(p, port);
                cookie
            }
            _ => panic!("Expected CHALLENGE"),
        };

        // Step 2: CONFIRM
        let result = handler.handle(Message::Confirm { port, cookie }, client_ip);
        match result {
            HandleResult::Reply(Message::Neighbors { addrs }) => {
                assert_eq!(addrs.len(), 2);
            }
            _ => panic!("Expected NEIGHBORS"),
        }

        // Verify registered
        assert!(handler.is_registered(client_ip, port));
    }

    #[test]
    fn test_invalid_cookie_rejected() {
        let secret = [0xAB; 32];
        let mut handler = TestHandler::new(secret);
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let port = 8080;

        // Send CONFIRM with bogus cookie
        let bogus_cookie = [0xFF; freehold_api::COOKIE_SIZE];
        let result = handler.handle(
            Message::Confirm {
                port,
                cookie: bogus_cookie,
            },
            client_ip,
        );

        match result {
            HandleResult::Reply(Message::Error { port: p }) => {
                assert_eq!(p, port);
            }
            _ => panic!("Expected ERROR"),
        }

        // Verify not registered
        assert!(!handler.is_registered(client_ip, port));
    }

    #[test]
    fn test_heartbeat_only_for_registered() {
        let secret = [0xAB; 32];
        let mut handler = TestHandler::new(secret);
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Heartbeat for unregistered port
        let result = handler.handle(Message::Heartbeat { port: 9999 }, client_ip);
        assert_eq!(result, HandleResult::NoReply);

        // Register a port
        handler.registered.insert((client_ip, 8080));

        // Heartbeat for registered port
        let result = handler.handle(Message::Heartbeat { port: 8080 }, client_ip);
        match result {
            HandleResult::Reply(Message::Neighbors { .. }) => {}
            _ => panic!("Expected NEIGHBORS"),
        }
    }

    #[test]
    fn test_quota_exceeded() {
        let secret = [0xAB; 32];
        let mut handler = TestHandler::new(secret);
        handler.context.max_ports_per_ip = 2;
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Register two ports
        for port in [8080, 8081] {
            let result = handler.handle(Message::Register { port }, client_ip);
            let cookie = match result {
                HandleResult::Reply(Message::Challenge { cookie, .. }) => cookie,
                _ => panic!("Expected CHALLENGE"),
            };
            let result = handler.handle(Message::Confirm { port, cookie }, client_ip);
            assert!(matches!(
                result,
                HandleResult::Reply(Message::Neighbors { .. })
            ));
        }

        // Third registration should fail
        let result = handler.handle(Message::Register { port: 8082 }, client_ip);
        match result {
            HandleResult::Reply(Message::Error { port }) => {
                assert_eq!(port, 8082);
            }
            _ => panic!("Expected ERROR"),
        }
    }

    #[test]
    fn test_different_ips_can_register_same_port() {
        let secret = [0xAB; 32];
        let mut handler = TestHandler::new(secret);
        let port = 8080;

        let clients = [
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 2),
            Ipv4Addr::new(10, 0, 1, 3),
        ];

        for client_ip in clients {
            let result = handler.handle(Message::Register { port }, client_ip);
            let cookie = match result {
                HandleResult::Reply(Message::Challenge { cookie, .. }) => cookie,
                _ => panic!("Expected CHALLENGE"),
            };
            let result = handler.handle(Message::Confirm { port, cookie }, client_ip);
            assert!(
                matches!(result, HandleResult::Reply(Message::Neighbors { .. })),
                "Client {} should be able to register port {}",
                client_ip,
                port
            );
        }
    }
}
