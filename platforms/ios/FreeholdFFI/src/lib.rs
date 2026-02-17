//! Freehold iOS FFI - C-compatible bindings for Swift integration
//!
//! This crate provides a C FFI layer over freehold-client-core for use
//! in iOS applications via Swift.
//!
//! # Architecture
//!
//! ```text
//! Swift App <--FFI--> freehold_ffi <--> freehold-client-core
//!     |                    |                    |
//!     |                    v                    v
//!     |              Tokio Runtime         Engine + H3Proxy
//!     |                    |
//!     v                    v
//! NEPacketTunnelProvider (VPN)
//! ```

use std::ffi::{c_char, c_void, CStr, CString};
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use freehold_client_core::{
    create_service_with_self_signed_cert, Engine, RelayState, Service, StatusUpdate,
};
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

// ============================================================================
// Types
// ============================================================================

/// Opaque handle to the Freehold engine context
pub struct FreeholdContext {
    runtime: Runtime,
    service: Option<Service>,
    shutdown_tx: Option<watch::Sender<bool>>,
    status_rx: Arc<Mutex<mpsc::Receiver<StatusUpdate>>>,
    is_running: AtomicBool,
}

/// FFI-safe relay state enum
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIRelayState {
    Disconnected = 0,
    Pending = 1,
    Connected = 2,
}

/// FFI-safe status update structure
#[repr(C)]
pub struct FFIStatusUpdate {
    pub update_type: FFIStatusType,
    pub relay_addr: *mut c_char, // null-terminated string or NULL
    pub relay_state: FFIRelayState,
    pub neighbor_ip: *mut c_char, // null-terminated string or NULL
    pub error_message: *mut c_char, // null-terminated string or NULL
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIStatusType {
    RelayState = 0,
    NeighborDiscovered = 1,
    Error = 2,
    None = 3,
}

/// FFI-safe configuration structure
#[repr(C)]
pub struct FFIConfig {
    pub relay_host: *const c_char,
    pub relay_port: u16,
    pub claim_port: u16,
    pub h3_bind_port: u16,
    pub backend_host: *const c_char,
    pub backend_port: u16,
    pub domain: *const c_char,
    pub auto_discover: bool,
}

// ============================================================================
// Global State
// ============================================================================

static CONTEXT: OnceCell<Mutex<Option<FreeholdContext>>> = OnceCell::new();

fn get_context() -> &'static Mutex<Option<FreeholdContext>> {
    CONTEXT.get_or_init(|| Mutex::new(None))
}

// ============================================================================
// FFI Functions
// ============================================================================

/// Initialize the Freehold FFI layer. Call this once at app startup.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn freehold_init() -> i32 {
    // Initialize tracing for debug builds
    #[cfg(debug_assertions)]
    {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }

    info!("Freehold FFI initialized");
    0
}

/// Create and start the Freehold service.
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 strings.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn freehold_start(config: *const FFIConfig) -> i32 {
    if config.is_null() {
        error!("freehold_start: config is null");
        return -1;
    }

    let config = &*config;

    // Parse configuration
    let relay_host = match CStr::from_ptr(config.relay_host).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("Invalid relay_host");
            return -1;
        }
    };

    let backend_host = match CStr::from_ptr(config.backend_host).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("Invalid backend_host");
            return -1;
        }
    };

    let domain = match CStr::from_ptr(config.domain).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("Invalid domain");
            return -1;
        }
    };

    let relay_addr: SocketAddr = match format!("{}:{}", relay_host, config.relay_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid relay address: {}", e);
            return -1;
        }
    };

    let h3_bind: SocketAddr = match format!("0.0.0.0:{}", config.h3_bind_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid h3_bind address: {}", e);
            return -1;
        }
    };

    let backend: SocketAddr = match format!("{}:{}", backend_host, config.backend_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid backend address: {}", e);
            return -1;
        }
    };

    // Create runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return -1;
        }
    };

    // Create status channel
    let (status_tx, status_rx) = mpsc::channel(100);

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create service
    let service = match create_service_with_self_signed_cert(
        relay_addr,
        config.claim_port,
        h3_bind,
        backend,
        domain,
        config.auto_discover,
        status_tx,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create service: {}", e);
            return -1;
        }
    };

    // Store context
    let ctx = FreeholdContext {
        runtime,
        service: Some(service),
        shutdown_tx: Some(shutdown_tx),
        status_rx: Arc::new(Mutex::new(status_rx)),
        is_running: AtomicBool::new(false),
    };

    let mut guard = get_context().lock().unwrap();
    *guard = Some(ctx);

    // Start service in background
    if let Some(ref mut ctx) = *guard {
        let service = ctx.service.take().unwrap();
        let shutdown_rx = shutdown_rx;

        ctx.is_running.store(true, Ordering::SeqCst);

        ctx.runtime.spawn(async move {
            info!("Freehold service starting");
            if let Err(e) = service.run(shutdown_rx).await {
                error!("Service error: {}", e);
            }
            info!("Freehold service stopped");
        });
    }

    info!("Freehold started successfully");
    0
}

/// Stop the Freehold service.
///
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn freehold_stop() -> i32 {
    let mut guard = get_context().lock().unwrap();

    if let Some(ref mut ctx) = *guard {
        if ctx.is_running.load(Ordering::SeqCst) {
            // Send shutdown signal
            if let Some(ref shutdown_tx) = ctx.shutdown_tx {
                let _ = shutdown_tx.send(true);
            }
            ctx.is_running.store(false, Ordering::SeqCst);
            info!("Freehold stop requested");
        }
    }

    *guard = None;
    info!("Freehold stopped");
    0
}

/// Check if the service is running.
///
/// Returns 1 if running, 0 if not running.
#[no_mangle]
pub extern "C" fn freehold_is_running() -> i32 {
    let guard = get_context().lock().unwrap();

    if let Some(ref ctx) = *guard {
        if ctx.is_running.load(Ordering::SeqCst) {
            return 1;
        }
    }
    0
}

/// Poll for the next status update (non-blocking).
///
/// Returns a pointer to FFIStatusUpdate if available, NULL if no update.
/// The caller must free the returned pointer with freehold_free_status_update.
#[no_mangle]
pub extern "C" fn freehold_poll_status() -> *mut FFIStatusUpdate {
    let guard = get_context().lock().unwrap();

    if let Some(ref ctx) = *guard {
        let mut rx_guard = ctx.status_rx.lock().unwrap();
        match rx_guard.try_recv() {
            Ok(update) => {
                let ffi_update = Box::new(convert_status_update(update));
                return Box::into_raw(ffi_update);
            }
            Err(_) => return ptr::null_mut(),
        }
    }
    ptr::null_mut()
}

/// Free a status update returned by freehold_poll_status.
///
/// # Safety
/// The pointer must have been returned by freehold_poll_status.
#[no_mangle]
pub unsafe extern "C" fn freehold_free_status_update(update: *mut FFIStatusUpdate) {
    if update.is_null() {
        return;
    }

    let update = Box::from_raw(update);

    // Free string fields
    if !update.relay_addr.is_null() {
        let _ = CString::from_raw(update.relay_addr);
    }
    if !update.neighbor_ip.is_null() {
        let _ = CString::from_raw(update.neighbor_ip);
    }
    if !update.error_message.is_null() {
        let _ = CString::from_raw(update.error_message);
    }
}

/// Free a string allocated by the FFI layer.
///
/// # Safety
/// The pointer must have been allocated by the FFI layer.
#[no_mangle]
pub unsafe extern "C" fn freehold_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

/// Get the library version.
///
/// Returns a pointer to a null-terminated string. Do not free this pointer.
#[no_mangle]
pub extern "C" fn freehold_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

// ============================================================================
// Helper Functions
// ============================================================================

fn convert_status_update(update: StatusUpdate) -> FFIStatusUpdate {
    match update {
        StatusUpdate::RelayState { addr, state } => FFIStatusUpdate {
            update_type: FFIStatusType::RelayState,
            relay_addr: CString::new(addr.to_string())
                .map(|s| s.into_raw())
                .unwrap_or(ptr::null_mut()),
            relay_state: match state {
                RelayState::Disconnected => FFIRelayState::Disconnected,
                RelayState::Pending => FFIRelayState::Pending,
                RelayState::Connected => FFIRelayState::Connected,
            },
            neighbor_ip: ptr::null_mut(),
            error_message: ptr::null_mut(),
        },
        StatusUpdate::NeighborDiscovered(ip) => FFIStatusUpdate {
            update_type: FFIStatusType::NeighborDiscovered,
            relay_addr: ptr::null_mut(),
            relay_state: FFIRelayState::Disconnected,
            neighbor_ip: CString::new(ip.to_string())
                .map(|s| s.into_raw())
                .unwrap_or(ptr::null_mut()),
            error_message: ptr::null_mut(),
        },
        StatusUpdate::Error(msg) => FFIStatusUpdate {
            update_type: FFIStatusType::Error,
            relay_addr: ptr::null_mut(),
            relay_state: FFIRelayState::Disconnected,
            neighbor_ip: ptr::null_mut(),
            error_message: CString::new(msg)
                .map(|s| s.into_raw())
                .unwrap_or(ptr::null_mut()),
        },
        StatusUpdate::Traffic { .. }
        | StatusUpdate::PortChanged { .. }
        | StatusUpdate::SubdomainAssigned(_)
        | StatusUpdate::AcmeCertReady => FFIStatusUpdate {
            update_type: FFIStatusType::Error,
            relay_addr: ptr::null_mut(),
            relay_state: FFIRelayState::Disconnected,
            neighbor_ip: ptr::null_mut(),
            error_message: ptr::null_mut(),
        },
    }
}

// ============================================================================
// VPN / Network Extension Support
// ============================================================================

/// Callback type for packet handling in VPN mode
pub type PacketCallback = extern "C" fn(data: *const u8, len: usize, context: *mut c_void);

/// VPN context for Network Extension integration
pub struct VPNContext {
    packet_callback: Option<PacketCallback>,
    callback_context: *mut c_void,
}

unsafe impl Send for VPNContext {}
unsafe impl Sync for VPNContext {}

static VPN_CONTEXT: OnceCell<Mutex<Option<VPNContext>>> = OnceCell::new();

fn get_vpn_context() -> &'static Mutex<Option<VPNContext>> {
    VPN_CONTEXT.get_or_init(|| Mutex::new(None))
}

/// Initialize VPN mode for use with NEPacketTunnelProvider.
///
/// The callback will be invoked when packets need to be written to the tunnel.
///
/// # Safety
/// The callback must remain valid for the lifetime of the VPN session.
/// The context pointer will be passed to the callback.
#[no_mangle]
pub unsafe extern "C" fn freehold_vpn_init(
    callback: PacketCallback,
    context: *mut c_void,
) -> i32 {
    let vpn_ctx = VPNContext {
        packet_callback: Some(callback),
        callback_context: context,
    };

    let mut guard = get_vpn_context().lock().unwrap();
    *guard = Some(vpn_ctx);

    info!("Freehold VPN mode initialized");
    0
}

/// Process an incoming packet from the tunnel (device -> network).
///
/// # Safety
/// data must point to a valid buffer of at least len bytes.
#[no_mangle]
pub unsafe extern "C" fn freehold_vpn_process_packet(
    data: *const u8,
    len: usize,
) -> i32 {
    if data.is_null() || len == 0 {
        return -1;
    }

    let _packet = std::slice::from_raw_parts(data, len);

    // TODO: Implement packet processing for VPN mode
    // This would typically:
    // 1. Parse the IP packet
    // 2. If destined for a freehold service, route through QUIC
    // 3. Otherwise, pass through or drop based on policy

    0
}

/// Stop VPN mode.
#[no_mangle]
pub extern "C" fn freehold_vpn_stop() -> i32 {
    let mut guard = get_vpn_context().lock().unwrap();
    *guard = None;
    info!("Freehold VPN mode stopped");
    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert_eq!(freehold_init(), 0);
    }

    #[test]
    fn test_version() {
        let version = freehold_version();
        assert!(!version.is_null());
        unsafe {
            let s = CStr::from_ptr(version);
            assert_eq!(s.to_str().unwrap(), "0.1.0");
        }
    }

    #[test]
    fn test_is_running_when_not_started() {
        assert_eq!(freehold_is_running(), 0);
    }
}
