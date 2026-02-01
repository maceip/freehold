//! Freehold Server Library
//!
//! This library contains the core logic for the Freehold relay server,
//! separated from the binary for testability.
//!
//! # Architecture
//!
//! The server is split into several components:
//!
//! - `cookie`: Stateless HMAC-based cookie authentication
//! - `quota`: Per-IP port quota tracking
//! - `handler`: Message handler trait for protocol logic
//! - `config`: Configuration parsing
//!
//! # Message Handler Trait
//!
//! The `handler::MessageHandler` trait defines the protocol logic and can be
//! implemented by different backends:
//!
//! - The real server uses eBPF maps for registration storage
//! - Tests use an in-memory implementation
//!
//! This separation allows testing the protocol logic without eBPF.

pub mod config;
pub mod cookie;
pub mod handler;
pub mod quota;
