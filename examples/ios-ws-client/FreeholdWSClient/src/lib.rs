//! Freehold WebSocket Client — Rust/QUIC networking for iOS
//!
//! This crate provides a QUIC/H3 WebSocket client exposed through C FFI
//! for integration with Swift/SwiftUI on iOS.
//!
//! ```text
//! SwiftUI <--C FFI--> freehold_ws_client (Rust)
//!    |                       |
//! @MainActor           quinn + h3
//!    |                       |
//! poll_message()      QUIC/H3 Extended CONNECT
//!                            |
//!                    Freehold Relay (XDP fwd)
//!                            |
//!                    heartbeat-ws backend
//! ```

use std::ffi::{c_char, CStr, CString};
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

// ============================================================================
// FFI Types
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Error = 3,
}

#[repr(C)]
pub struct FFIWSMessage {
    /// Null-terminated UTF-8 text (caller must free with ws_client_free_message)
    pub text: *mut c_char,
}

// ============================================================================
// Internal State
// ============================================================================

struct ClientContext {
    runtime: Runtime,
    shutdown_tx: Option<watch::Sender<bool>>,
    send_tx: Option<mpsc::UnboundedSender<String>>,
    recv_rx: Arc<Mutex<mpsc::UnboundedReceiver<String>>>,
    state: Arc<std::sync::atomic::AtomicU8>,
    last_error: Arc<Mutex<Option<String>>>,
}

static CLIENT: std::sync::OnceLock<Mutex<Option<ClientContext>>> = std::sync::OnceLock::new();

fn get_client() -> &'static Mutex<Option<ClientContext>> {
    CLIENT.get_or_init(|| Mutex::new(None))
}

fn set_state(ctx: &ClientContext, state: FFIConnectionState) {
    ctx.state.store(state as u8, Ordering::SeqCst);
}

// ============================================================================
// FFI Functions
// ============================================================================

/// Initialize tracing (call once at app launch).
#[no_mangle]
pub extern "C" fn ws_client_init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("freehold_ws_client=debug,quinn=warn,h3=debug")
        .try_init();
    info!("ws_client_init");
}

/// Connect to a Freehold relay via QUIC/H3 WebSocket.
///
/// # Safety
/// `host` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn ws_client_connect(host: *const c_char, port: u16) -> i32 {
    if host.is_null() {
        return -1;
    }

    let host_str = match CStr::from_ptr(host).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };

    // Tear down any existing connection
    ws_client_disconnect();

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("runtime: {}", e);
            return -1;
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (send_tx, send_rx) = mpsc::unbounded_channel::<String>();
    let (recv_tx, recv_rx) = mpsc::unbounded_channel::<String>();

    let state = Arc::new(std::sync::atomic::AtomicU8::new(
        FFIConnectionState::Connecting as u8,
    ));
    let last_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let state2 = state.clone();
    let last_error2 = last_error.clone();

    runtime.spawn(async move {
        if let Err(e) = run_ws_client(&host_str, port, shutdown_rx, send_rx, recv_tx, state2.clone()).await {
            warn!("ws session ended: {}", e);
            *last_error2.lock().unwrap() = Some(e.to_string());
            state2.store(FFIConnectionState::Error as u8, Ordering::SeqCst);
        }
    });

    let ctx = ClientContext {
        runtime,
        shutdown_tx: Some(shutdown_tx),
        send_tx: Some(send_tx),
        recv_rx: Arc::new(Mutex::new(recv_rx)),
        state,
        last_error,
    };

    *get_client().lock().unwrap() = Some(ctx);
    0
}

/// Disconnect.
#[no_mangle]
pub extern "C" fn ws_client_disconnect() {
    let mut guard = get_client().lock().unwrap();
    if let Some(ctx) = guard.take() {
        if let Some(tx) = ctx.shutdown_tx {
            let _ = tx.send(true);
        }
        // runtime drops here, cancelling spawned tasks
    }
}

/// Get the current connection state.
#[no_mangle]
pub extern "C" fn ws_client_state() -> FFIConnectionState {
    let guard = get_client().lock().unwrap();
    match &*guard {
        Some(ctx) => match ctx.state.load(Ordering::SeqCst) {
            0 => FFIConnectionState::Disconnected,
            1 => FFIConnectionState::Connecting,
            2 => FFIConnectionState::Connected,
            _ => FFIConnectionState::Error,
        },
        None => FFIConnectionState::Disconnected,
    }
}

/// Get the last error message. Returns NULL if no error.
/// Caller must free with `ws_client_free_string`.
#[no_mangle]
pub extern "C" fn ws_client_last_error() -> *mut c_char {
    let guard = get_client().lock().unwrap();
    match &*guard {
        Some(ctx) => {
            let err = ctx.last_error.lock().unwrap();
            match &*err {
                Some(msg) => CString::new(msg.as_str())
                    .map(|s| s.into_raw())
                    .unwrap_or(ptr::null_mut()),
                None => ptr::null_mut(),
            }
        }
        None => ptr::null_mut(),
    }
}

/// Poll for the next received WebSocket message (non-blocking).
/// Returns NULL if no message available.
/// Caller must free with `ws_client_free_message`.
#[no_mangle]
pub extern "C" fn ws_client_poll_message() -> *mut FFIWSMessage {
    let guard = get_client().lock().unwrap();
    if let Some(ctx) = &*guard {
        let mut rx = ctx.recv_rx.lock().unwrap();
        if let Ok(text) = rx.try_recv() {
            let c_text = CString::new(text)
                .map(|s| s.into_raw())
                .unwrap_or(ptr::null_mut());
            return Box::into_raw(Box::new(FFIWSMessage { text: c_text }));
        }
    }
    ptr::null_mut()
}

/// Send a text message over the WebSocket.
///
/// # Safety
/// `text` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn ws_client_send(text: *const c_char) -> i32 {
    if text.is_null() {
        return -1;
    }

    let msg = match CStr::from_ptr(text).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return -1,
    };

    let guard = get_client().lock().unwrap();
    if let Some(ctx) = &*guard {
        if let Some(tx) = &ctx.send_tx {
            let _ = tx.send(msg);
            return 0;
        }
    }
    -1
}

/// Free a message returned by `ws_client_poll_message`.
///
/// # Safety
/// Must have been returned by `ws_client_poll_message`.
#[no_mangle]
pub unsafe extern "C" fn ws_client_free_message(msg: *mut FFIWSMessage) {
    if msg.is_null() {
        return;
    }
    let msg = Box::from_raw(msg);
    if !msg.text.is_null() {
        let _ = CString::from_raw(msg.text);
    }
}

/// Free a string returned by `ws_client_last_error`.
///
/// # Safety
/// Must have been allocated by this crate.
#[no_mangle]
pub unsafe extern "C" fn ws_client_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ============================================================================
// QUIC/H3 WebSocket Client
// ============================================================================

/// Opens a QUIC connection, negotiates HTTP/3, sends Extended CONNECT
/// to upgrade to WebSocket, then loops reading/writing frames.
async fn run_ws_client(
    host: &str,
    port: u16,
    mut shutdown: watch::Receiver<bool>,
    mut send_rx: mpsc::UnboundedReceiver<String>,
    recv_tx: mpsc::UnboundedSender<String>,
    state: Arc<std::sync::atomic::AtomicU8>,
) -> anyhow::Result<()> {
    // ---- TLS config (trust self-signed for dev) ----
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(Arc::new(transport));

    // ---- QUIC connection ----
    let addr: SocketAddr = format!("{}:{}", host, port).parse()
        .or_else(|_| {
            // Try resolving hostname (blocking ok here, runs once)
            use std::net::ToSocketAddrs;
            format!("{}:{}", host, port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addrs"))
        })?;

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    info!("QUIC connecting to {}", addr);
    let conn = endpoint.connect(addr, host)?.await?;
    info!("QUIC connected");

    // ---- H3 connection ----
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    // Spawn H3 driver
    let driver_done = Arc::new(AtomicBool::new(false));
    let driver_done2 = driver_done.clone();
    tokio::spawn(async move {
        if let Err(e) = futures::future::poll_fn(|cx| driver.poll_close(cx)).await {
            warn!("H3 driver: {}", e);
        }
        driver_done2.store(true, Ordering::SeqCst);
    });

    // ---- Extended CONNECT (WebSocket upgrade) ----
    let req = http::Request::builder()
        .method("CONNECT")
        .uri(format!("https://{}:{}/ws", host, port))
        .header(":protocol", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", "websocket")
        .body(())?;

    let mut stream = send_request.send_request(req).await?;
    let resp = stream.recv_response().await?;

    if resp.status() != http::StatusCode::OK {
        anyhow::bail!("WebSocket upgrade failed: {}", resp.status());
    }

    info!("WebSocket connected (HTTP/3 Extended CONNECT)");
    state.store(FFIConnectionState::Connected as u8, Ordering::SeqCst);

    // ---- Read/write loop ----
    // H3 streams use DATA frames. For WebSocket-over-H3, each DATA frame
    // carries one or more WebSocket payload bytes (no WS framing needed —
    // the H3 layer handles message boundaries).

    loop {
        tokio::select! {
            // Shutdown signal
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("shutdown requested");
                    break;
                }
            }

            // Receive from server
            data = stream.recv_data() => {
                match data {
                    Ok(Some(mut buf)) => {
                        // h3 returns impl Buf, copy to bytes
                        use bytes::Buf;
                        let mut dst = vec![0u8; buf.remaining()];
                        buf.copy_to_slice(&mut dst);

                        if let Ok(text) = String::from_utf8(dst) {
                            let _ = recv_tx.send(text);
                        }
                    }
                    Ok(None) => {
                        info!("stream closed by server");
                        break;
                    }
                    Err(e) => {
                        warn!("recv error: {}", e);
                        break;
                    }
                }
            }

            // Send user messages
            msg = send_rx.recv() => {
                match msg {
                    Some(text) => {
                        stream.send_data(Bytes::from(text)).await?;
                    }
                    None => break,
                }
            }
        }
    }

    state.store(FFIConnectionState::Disconnected as u8, Ordering::SeqCst);
    Ok(())
}

// ============================================================================
// TLS: skip verification for self-signed certs (dev only)
// ============================================================================

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
