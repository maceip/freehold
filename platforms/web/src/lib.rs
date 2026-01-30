//! Freehold Web Platform - WASM client with Direct Sockets API
//!
//! This module provides the Freehold client engine compiled to WebAssembly,
//! designed to run in Isolated Web Apps with Direct Sockets API access.
//!
//! # Architecture
//!
//! ```text
//! Browser IWA
//! ┌─────────────────────────────────────────┐
//! │  JavaScript UI                          │
//! │     ↓ (wasm-bindgen)                    │
//! │  freehold-platform-web (WASM)           │
//! │     ↓ (Direct Sockets API)              │
//! │  UDPSocket → Relay Server               │
//! └─────────────────────────────────────────┘
//! ```

use freehold_api::{timing, Message, COOKIE_SIZE};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_time::Instant;

// Re-export for convenience
pub use freehold_api::{MessageType, ProtocolError};

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_writer(tracing_web::MakeConsoleWriter)
        .without_time()
        .init();

    tracing::info!("freehold-platform-web initialized");
}

// =============================================================================
// Direct Sockets API Bindings
// =============================================================================

#[wasm_bindgen]
extern "C" {
    /// UDPSocket from Direct Sockets API
    #[wasm_bindgen(js_name = "UDPSocket")]
    pub type UdpSocket;

    #[wasm_bindgen(constructor, js_class = "UDPSocket")]
    fn new(options: &JsValue) -> UdpSocket;

    #[wasm_bindgen(method, getter)]
    fn opened(this: &UdpSocket) -> js_sys::Promise;

    #[wasm_bindgen(method)]
    fn close(this: &UdpSocket);

    /// TCPSocket from Direct Sockets API
    #[wasm_bindgen(js_name = "TCPSocket")]
    pub type TcpSocket;

    #[wasm_bindgen(constructor, js_class = "TCPSocket")]
    fn new_tcp(remote_address: &str, remote_port: u16, options: &JsValue) -> TcpSocket;

    #[wasm_bindgen(method, getter)]
    fn opened_tcp(this: &TcpSocket) -> js_sys::Promise;

    /// TCPServerSocket from Direct Sockets API
    #[wasm_bindgen(js_name = "TCPServerSocket")]
    pub type TcpServerSocket;

    #[wasm_bindgen(constructor, js_class = "TCPServerSocket")]
    fn new_server(local_address: &str, options: &JsValue) -> TcpServerSocket;
}

// =============================================================================
// Status Updates (mirrors client-core)
// =============================================================================

/// Relay connection state
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayState {
    Disconnected = 0,
    Pending = 1,
    Connected = 2,
}

/// Status update sent to UI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StatusUpdate {
    #[serde(rename = "relay_state")]
    RelayState { addr: String, state: RelayState },
    #[serde(rename = "neighbor_discovered")]
    NeighborDiscovered { ip: String },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "port_registered")]
    PortRegistered { port: u16 },
}

impl StatusUpdate {
    /// Convert to JsValue for JavaScript consumption
    pub fn to_js(&self) -> JsValue {
        serde_wasm_bindgen::to_value(self).unwrap_or(JsValue::NULL)
    }
}

// =============================================================================
// Relay Tracking
// =============================================================================

/// Internal relay state tracking
struct Relay {
    addr: String,
    ip: String,
    port: u16,
    state: RelayState,
    cookie: Option<[u8; COOKIE_SIZE]>,
    last_activity: Instant,
}

// =============================================================================
// Web Engine
// =============================================================================

/// Callback type for status updates
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "(update: StatusUpdate) => void")]
    pub type StatusCallback;
}

/// The Freehold web client engine
#[wasm_bindgen]
pub struct WebEngine {
    port: u16,
    relays: Rc<RefCell<Vec<Relay>>>,
    neighbors: Rc<RefCell<HashSet<String>>>,
    status_callback: Option<js_sys::Function>,
    auto_discover: bool,
    running: Rc<RefCell<bool>>,
}

#[wasm_bindgen]
impl WebEngine {
    /// Create a new web engine
    #[wasm_bindgen(constructor)]
    pub fn new(
        initial_relay_ip: &str,
        initial_relay_port: u16,
        port: u16,
        auto_discover: bool,
    ) -> Self {
        let relay_addr = format!("{}:{}", initial_relay_ip, initial_relay_port);

        Self {
            port,
            relays: Rc::new(RefCell::new(vec![Relay {
                addr: relay_addr,
                ip: initial_relay_ip.to_string(),
                port: initial_relay_port,
                state: RelayState::Disconnected,
                cookie: None,
                last_activity: Instant::now(),
            }])),
            neighbors: Rc::new(RefCell::new(HashSet::new())),
            status_callback: None,
            auto_discover,
            running: Rc::new(RefCell::new(false)),
        }
    }

    /// Set the status update callback
    #[wasm_bindgen(js_name = "setStatusCallback")]
    pub fn set_status_callback(&mut self, callback: js_sys::Function) {
        self.status_callback = Some(callback);
    }

    /// Get the claimed port
    #[wasm_bindgen(getter)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if Direct Sockets API is available
    #[wasm_bindgen(js_name = "checkDirectSocketsApi")]
    pub fn check_direct_sockets_api() -> bool {
        let window = match web_sys::window() {
            Some(w) => w,
            None => return false,
        };

        let udp = js_sys::Reflect::has(&window, &"UDPSocket".into()).unwrap_or(false);
        let tcp = js_sys::Reflect::has(&window, &"TCPSocket".into()).unwrap_or(false);
        let tcp_server = js_sys::Reflect::has(&window, &"TCPServerSocket".into()).unwrap_or(false);

        tracing::info!(
            "Direct Sockets API: UDP={}, TCP={}, TCPServer={}",
            udp,
            tcp,
            tcp_server
        );

        udp && tcp
    }

    /// Get current relay states as JSON
    #[wasm_bindgen(js_name = "getRelayStates")]
    pub fn get_relay_states(&self) -> JsValue {
        let relays = self.relays.borrow();
        let array = js_sys::Array::new();

        for r in relays.iter() {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(&obj, &"addr".into(), &r.addr.clone().into()).ok();
            js_sys::Reflect::set(
                &obj,
                &"state".into(),
                &match r.state {
                    RelayState::Disconnected => "disconnected",
                    RelayState::Pending => "pending",
                    RelayState::Connected => "connected",
                }
                .into(),
            )
            .ok();
            array.push(&obj);
        }

        array.into()
    }

    /// Send status update to JavaScript
    fn emit_status(&self, update: StatusUpdate) {
        if let Some(ref callback) = self.status_callback {
            let js_update = update.to_js();
            let _ = callback.call1(&JsValue::NULL, &js_update);
        }
    }

    /// Start the engine (async)
    #[wasm_bindgen]
    pub async fn start(&self) -> Result<(), JsValue> {
        if *self.running.borrow() {
            return Err(JsValue::from_str("Engine already running"));
        }

        *self.running.borrow_mut() = true;
        tracing::info!("Starting web engine for port {}", self.port);

        // Check Direct Sockets API
        if !Self::check_direct_sockets_api() {
            self.emit_status(StatusUpdate::Error {
                message: "Direct Sockets API not available".to_string(),
            });
            *self.running.borrow_mut() = false;
            return Err(JsValue::from_str("Direct Sockets API not available"));
        }

        // Create UDP socket for relay communication
        let socket = self.create_udp_socket().await?;

        // Main loop
        self.run_loop(socket).await
    }

    /// Stop the engine
    #[wasm_bindgen]
    pub fn stop(&self) {
        *self.running.borrow_mut() = false;
        tracing::info!("Stopping web engine");
    }

    /// Create UDP socket via Direct Sockets API
    async fn create_udp_socket(&self) -> Result<UdpSocket, JsValue> {
        let options = js_sys::Object::new();

        // Bind to any local port
        js_sys::Reflect::set(&options, &"localAddress".into(), &"0.0.0.0".into())?;
        js_sys::Reflect::set(&options, &"localPort".into(), &0.into())?;

        let socket = UdpSocket::new(&options.into());

        // Wait for socket to open
        let opened = JsFuture::from(socket.opened()).await?;
        tracing::info!("UDP socket opened: {:?}", opened);

        Ok(socket)
    }

    /// Main engine loop
    async fn run_loop(&self, _socket: UdpSocket) -> Result<(), JsValue> {
        let heartbeat_ms = timing::HEARTBEAT_INTERVAL.as_millis() as i32;
        let register_timeout_ms = timing::REGISTER_TIMEOUT.as_millis() as u128;

        while *self.running.borrow() {
            let now = Instant::now();

            // Process each relay
            let relay_count = self.relays.borrow().len();
            for i in 0..relay_count {
                let (state, elapsed_ms, addr) = {
                    let relays = self.relays.borrow();
                    let relay = &relays[i];
                    (
                        relay.state,
                        now.duration_since(relay.last_activity).as_millis(),
                        relay.addr.clone(),
                    )
                };

                match state {
                    RelayState::Disconnected => {
                        self.send_register(i).await?;
                    }
                    RelayState::Pending if elapsed_ms > register_timeout_ms => {
                        tracing::warn!("Timeout for {}, retrying", addr);
                        self.relays.borrow_mut()[i].state = RelayState::Disconnected;
                        self.emit_status(StatusUpdate::RelayState {
                            addr,
                            state: RelayState::Disconnected,
                        });
                    }
                    RelayState::Connected
                        if elapsed_ms >= timing::HEARTBEAT_INTERVAL.as_millis() =>
                    {
                        self.send_heartbeat(i).await?;
                    }
                    _ => {}
                }
            }

            // Sleep before next iteration
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                let window = web_sys::window().unwrap();
                window
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, heartbeat_ms)
                    .unwrap();
            });
            JsFuture::from(promise).await?;
        }

        Ok(())
    }

    /// Send REGISTER message
    async fn send_register(&self, idx: usize) -> Result<(), JsValue> {
        let (addr, port) = {
            let relays = self.relays.borrow();
            (relays[idx].addr.clone(), self.port)
        };

        let msg = Message::Register { port };
        let data = msg.to_bytes();

        tracing::debug!("REGISTER -> {}", addr);

        // TODO: Actually send via UDPSocket writable stream
        // For now, update state to simulate the flow
        {
            let mut relays = self.relays.borrow_mut();
            relays[idx].state = RelayState::Pending;
            relays[idx].last_activity = Instant::now();
        }

        self.emit_status(StatusUpdate::RelayState {
            addr,
            state: RelayState::Pending,
        });

        Ok(())
    }

    /// Send HEARTBEAT message
    async fn send_heartbeat(&self, idx: usize) -> Result<(), JsValue> {
        let addr = self.relays.borrow()[idx].addr.clone();

        let msg = Message::Heartbeat { port: self.port };
        let _data = msg.to_bytes();

        tracing::debug!("HEARTBEAT -> {}", addr);

        // Update last activity
        self.relays.borrow_mut()[idx].last_activity = Instant::now();

        Ok(())
    }

    /// Send CONFIRM message
    async fn send_confirm(&self, idx: usize) -> Result<(), JsValue> {
        let (addr, cookie) = {
            let relays = self.relays.borrow();
            (relays[idx].addr.clone(), relays[idx].cookie)
        };

        if let Some(cookie) = cookie {
            let msg = Message::Confirm {
                port: self.port,
                cookie,
            };
            let _data = msg.to_bytes();

            tracing::debug!("CONFIRM -> {}", addr);
        }

        Ok(())
    }

    /// Process incoming message
    #[wasm_bindgen(js_name = "processMessage")]
    pub fn process_message(&self, data: &[u8], from_addr: &str) -> Result<(), JsValue> {
        let msg =
            Message::parse(data).map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

        // Find relay by address
        let idx = {
            let relays = self.relays.borrow();
            relays.iter().position(|r| r.addr == from_addr)
        };

        let idx = match idx {
            Some(i) => i,
            None => return Ok(()), // Unknown sender
        };

        match msg {
            Message::Challenge { port, cookie } if port == self.port => {
                tracing::info!("CHALLENGE from {}", from_addr);

                {
                    let mut relays = self.relays.borrow_mut();
                    relays[idx].cookie = Some(cookie);
                    relays[idx].state = RelayState::Pending;
                }

                // Send confirm (would be async in real impl)
                // self.send_confirm(idx).await?;
            }

            Message::Neighbors { addrs } => {
                let was_pending = self.relays.borrow()[idx].state == RelayState::Pending;

                if was_pending {
                    {
                        let mut relays = self.relays.borrow_mut();
                        relays[idx].state = RelayState::Connected;
                        relays[idx].last_activity = Instant::now();
                    }

                    tracing::info!("CONNECTED to {} for port {}", from_addr, self.port);

                    self.emit_status(StatusUpdate::RelayState {
                        addr: from_addr.to_string(),
                        state: RelayState::Connected,
                    });

                    self.emit_status(StatusUpdate::PortRegistered { port: self.port });
                }

                // Process neighbors if auto-discover enabled
                if self.auto_discover {
                    for ip in addrs {
                        let ip_str = ip.to_string();
                        let mut neighbors = self.neighbors.borrow_mut();

                        if neighbors.insert(ip_str.clone()) {
                            tracing::info!("Discovered neighbor {}", ip);

                            self.emit_status(StatusUpdate::NeighborDiscovered { ip: ip_str });
                        }
                    }
                }
            }

            Message::Error { port } if port == self.port => {
                tracing::warn!("ERROR from {}", from_addr);

                {
                    let mut relays = self.relays.borrow_mut();
                    relays[idx].state = RelayState::Disconnected;
                    relays[idx].cookie = None;
                }

                self.emit_status(StatusUpdate::Error {
                    message: format!("Relay {} rejected registration", from_addr),
                });
            }

            _ => {}
        }

        Ok(())
    }
}

// =============================================================================
// Protocol Helpers (exposed to JS)
// =============================================================================

/// Create a REGISTER message
#[wasm_bindgen(js_name = "createRegisterMessage")]
pub fn create_register_message(port: u16) -> Vec<u8> {
    Message::Register { port }.to_bytes()
}

/// Create a HEARTBEAT message
#[wasm_bindgen(js_name = "createHeartbeatMessage")]
pub fn create_heartbeat_message(port: u16) -> Vec<u8> {
    Message::Heartbeat { port }.to_bytes()
}

/// Create a CONFIRM message
#[wasm_bindgen(js_name = "createConfirmMessage")]
pub fn create_confirm_message(port: u16, cookie: &[u8]) -> Result<Vec<u8>, JsValue> {
    if cookie.len() != COOKIE_SIZE {
        return Err(JsValue::from_str(&format!(
            "Cookie must be {} bytes",
            COOKIE_SIZE
        )));
    }

    let mut cookie_arr = [0u8; COOKIE_SIZE];
    cookie_arr.copy_from_slice(cookie);

    Ok(Message::Confirm {
        port,
        cookie: cookie_arr,
    }
    .to_bytes())
}

/// Parse a message and return type + data as JSON
#[wasm_bindgen(js_name = "parseMessage")]
pub fn parse_message(data: &[u8]) -> Result<JsValue, JsValue> {
    let msg =
        Message::parse(data).map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;

    let result = match msg {
        Message::Register { port } => serde_json::json!({
            "type": "register",
            "port": port
        }),
        Message::Challenge { port, cookie } => serde_json::json!({
            "type": "challenge",
            "port": port,
            "cookie": cookie.to_vec()
        }),
        Message::Confirm { port, cookie } => serde_json::json!({
            "type": "confirm",
            "port": port,
            "cookie": cookie.to_vec()
        }),
        Message::Heartbeat { port } => serde_json::json!({
            "type": "heartbeat",
            "port": port
        }),
        Message::Neighbors { addrs } => serde_json::json!({
            "type": "neighbors",
            "addrs": addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>()
        }),
        Message::Error { port } => serde_json::json!({
            "type": "error",
            "port": port
        }),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Get protocol constants
#[wasm_bindgen(js_name = "getProtocolConstants")]
pub fn get_protocol_constants() -> JsValue {
    let constants = serde_json::json!({
        "magic": freehold_api::MAGIC,
        "cookieSize": COOKIE_SIZE,
        "maxNeighbors": freehold_api::MAX_NEIGHBORS,
        "timeBucketSecs": timing::TIME_BUCKET.as_secs(),
        "registrationTtlSecs": timing::REGISTRATION_TTL.as_secs(),
        "heartbeatIntervalSecs": timing::HEARTBEAT_INTERVAL.as_secs(),
        "registerTimeoutSecs": timing::REGISTER_TIMEOUT.as_secs(),
        "maxPortsPerIp": freehold_api::quota::MAX_PORTS_PER_IP
    });

    serde_wasm_bindgen::to_value(&constants).unwrap_or(JsValue::NULL)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_create_register_message() {
        let msg = create_register_message(443);
        assert_eq!(msg[0], freehold_api::MAGIC);
        assert_eq!(msg[1], 0x01); // Register type
    }

    #[wasm_bindgen_test]
    fn test_parse_message() {
        let data = create_register_message(8080);
        let parsed = parse_message(&data).unwrap();

        let obj: serde_json::Value = serde_wasm_bindgen::from_value(parsed).unwrap();
        assert_eq!(obj["type"], "register");
        assert_eq!(obj["port"], 8080);
    }

    #[wasm_bindgen_test]
    fn test_protocol_constants() {
        let constants = get_protocol_constants();
        let obj: serde_json::Value = serde_wasm_bindgen::from_value(constants).unwrap();

        assert_eq!(obj["magic"], 0x46);
        assert_eq!(obj["cookieSize"], 16);
    }
}
