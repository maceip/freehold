//! Scute bridge library — JSON protocol for controlling freehold-client-core.
//!
//! Used as:
//! - Binary (`scute-service`): reads JSON config from CLI args, writes JSON events to stdout
//! - cdylib: loaded via FFI on Android/iOS

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use freehold_client_core::{Service, ServiceConfig, StatusUpdate};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

/// JSON config accepted from the SDK
#[derive(Debug, Deserialize)]
pub struct ScuteConfig {
    /// Local port to expose (backend HTTP server)
    pub port: u16,
    /// Relay server address (default: freehold.lit.app:9999)
    pub relay: Option<String>,
    /// Address to bind the QUIC socket (default: 0.0.0.0:0)
    pub bind: Option<String>,
    /// Auto-discover neighbor relays
    pub discover: Option<bool>,
    /// ACME cache directory (default: ~/.scute/acme)
    pub acme_cache: Option<String>,
}

/// JSON events emitted to stdout
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum ScuteEvent {
    #[serde(rename = "ready")]
    Ready { url: String, subdomain: String },
    #[serde(rename = "relay_state")]
    RelayState { addr: String, state: String },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "traffic")]
    Traffic { sent: u64, received: u64 },
    #[serde(rename = "acme_ready")]
    AcmeReady,
    #[serde(rename = "started")]
    Started { bind_addr: String },
}

/// Run the scute service, writing JSON events to the provided callback.
pub async fn run_service(
    config: ScuteConfig,
    event_tx: mpsc::UnboundedSender<ScuteEvent>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let relay_str = config.relay.as_deref().unwrap_or("freehold.lit.app:9999");
    let relay_addr: SocketAddr = tokio::net::lookup_host(relay_str)
        .await
        .context(format!("resolve relay: {}", relay_str))?
        .next()
        .context(format!("no addresses for relay: {}", relay_str))?;

    let bind_str = config.bind.as_deref().unwrap_or("0.0.0.0:0");
    let h3_bind: SocketAddr = bind_str.parse().context("parse bind address")?;

    let backend: SocketAddr = format!("127.0.0.1:{}", config.port)
        .parse()
        .context("parse backend address")?;

    let discover = config.discover.unwrap_or(true);

    let acme_cache_dir = config
        .acme_cache
        .map(PathBuf::from)
        .or_else(dirs_default_acme_cache);

    let domain = "localhost";

    let (status_tx, mut status_rx) = mpsc::channel::<StatusUpdate>(64);

    // Generate self-signed cert for initial startup (ACME will hot-swap later)
    let (certs, key) =
        freehold_client_core::generate_self_signed_cert(&[domain]).context("generate cert")?;

    let service = Service::new(
        ServiceConfig {
            relay: relay_addr,
            relay_port: 0, // Let relay assign
            h3_bind,
            backend,
            certs,
            key,
            auto_discover: discover,
            acme_cache_dir,
        },
        status_tx,
    )?;

    let _ = event_tx.send(ScuteEvent::Started {
        bind_addr: h3_bind.to_string(),
    });

    // Forward status updates as JSON events
    let event_tx2 = event_tx.clone();
    tokio::spawn(async move {
        while let Some(update) = status_rx.recv().await {
            let event = match update {
                StatusUpdate::RelayState { addr, state } => ScuteEvent::RelayState {
                    addr: addr.to_string(),
                    state: format!("{:?}", state),
                },
                StatusUpdate::SubdomainAssigned(sub) => {
                    let url = format!("https://{}", sub);
                    ScuteEvent::Ready {
                        url,
                        subdomain: sub,
                    }
                }
                StatusUpdate::Error(msg) => ScuteEvent::Error { message: msg },
                StatusUpdate::Traffic { sent, received } => ScuteEvent::Traffic { sent, received },
                StatusUpdate::AcmeCertReady => ScuteEvent::AcmeReady,
                StatusUpdate::NeighborDiscovered(_) | StatusUpdate::PortChanged { .. } => continue,
            };
            if event_tx2.send(event).is_err() {
                break;
            }
        }
    });

    service.run(shutdown).await
}

fn dirs_default_acme_cache() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("scute").join("acme"))
}

// ---------------------------------------------------------------------------
// C FFI for mobile (Android/iOS)
// ---------------------------------------------------------------------------

/// Opaque handle for FFI
pub struct ScuteHandle {
    shutdown_tx: watch::Sender<bool>,
    event_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<ScuteEvent>>>,
}

/// Start the scute service. Returns a handle pointer.
/// `config_json` must be a valid JSON string (ScuteConfig).
///
/// # Safety
/// `config_json` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn scute_start(config_json: *const std::os::raw::c_char) -> *mut ScuteHandle {
    use std::ffi::CStr;

    let c_str = unsafe { CStr::from_ptr(config_json) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let config: ScuteConfig = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::unbounded_channel();

    // Spawn tokio runtime on a background thread
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            if let Err(e) = run_service(config, event_tx, shutdown_rx).await {
                tracing::error!("scute service error: {:?}", e);
            }
        });
    });

    Box::into_raw(Box::new(ScuteHandle {
        shutdown_tx,
        event_rx: std::sync::Mutex::new(Some(event_rx)),
    }))
}

/// Stop the scute service and free the handle.
///
/// # Safety
/// `handle` must be a valid pointer from `scute_start`.
#[no_mangle]
pub unsafe extern "C" fn scute_stop(handle: *mut ScuteHandle) {
    if handle.is_null() {
        return;
    }
    let handle = unsafe { Box::from_raw(handle) };
    let _ = handle.shutdown_tx.send(true);
}

/// Poll for the next event. Returns a JSON string (caller must free with `scute_free_string`).
/// Returns null if no event is available.
///
/// # Safety
/// `handle` must be a valid pointer from `scute_start`.
#[no_mangle]
pub unsafe extern "C" fn scute_poll_event(handle: *mut ScuteHandle) -> *mut std::os::raw::c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let handle = unsafe { &*handle };
    let mut guard = handle.event_rx.lock().unwrap();
    if let Some(ref mut rx) = *guard {
        if let Ok(event) = rx.try_recv() {
            if let Ok(json) = serde_json::to_string(&event) {
                return std::ffi::CString::new(json)
                    .map(|c| c.into_raw())
                    .unwrap_or(std::ptr::null_mut());
            }
        }
    }
    std::ptr::null_mut()
}

/// Free a string returned by `scute_poll_event`.
///
/// # Safety
/// `ptr` must be a valid pointer from `scute_poll_event` or null.
#[no_mangle]
pub unsafe extern "C" fn scute_free_string(ptr: *mut std::os::raw::c_char) {
    if !ptr.is_null() {
        let _ = unsafe { std::ffi::CString::from_raw(ptr) };
    }
}
