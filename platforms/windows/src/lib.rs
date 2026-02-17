//! Freehold Windows Platform - Win32 tray implementation

#[cfg(not(target_os = "windows"))]
compile_error!("freehold-platform-windows can only be compiled for Windows");

use anyhow::Result;
use freehold_client_core::{Engine, EngineCommand, StatusUpdate};
use tokio::sync::mpsc;

#[cfg(target_os = "windows")]
mod windows_impl {
    use anyhow::{anyhow, Result};
    use freehold_client_core::{EngineCommand, RelayState, StatusUpdate};
    use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
    use std::sync::Mutex;
    use tokio::sync::mpsc;
    use tracing::info;
    use windows::{
        core::*,
        Win32::{
            Foundation::*,
            Graphics::Gdi::*,
            System::LibraryLoader::GetModuleHandleW,
            UI::{Shell::*, WindowsAndMessaging::*},
        },
    };

    const WM_TRAYICON: u32 = WM_USER + 1;
    const WM_UPDATE_TRAY: u32 = WM_USER + 2;
    const ID_TRAY_ICON: u32 = 1;
    const IDM_STATUS: u32 = 99;
    const IDM_PORT: u32 = 100;
    const IDM_TRAFFIC: u32 = 101;
    const IDM_NEW_ENDPOINT: u32 = 103;
    const IDM_EXIT: u32 = 104;

    // Wrapper for HICON to implement Send/Sync (safe because icons are only accessed from the Windows message thread)
    #[derive(Clone, Copy)]
    struct SendableIcon(HICON);
    unsafe impl Send for SendableIcon {}
    unsafe impl Sync for SendableIcon {}

    static CURRENT_STATE: Mutex<RelayState> = Mutex::new(RelayState::Disconnected);
    static CURRENT_PORT: AtomicU16 = AtomicU16::new(0);
    static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
    static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);
    static MAIN_HWND: Mutex<Option<isize>> = Mutex::new(None);
    static COMMAND_TX: Mutex<Option<mpsc::Sender<EngineCommand>>> = Mutex::new(None);

    // Custom icon state
    static ICON_CONNECTED: Mutex<Option<SendableIcon>> = Mutex::new(None);
    static ICON_DISCONNECTED: Mutex<Option<SendableIcon>> = Mutex::new(None);
    static ICON_PENDING: Mutex<Option<SendableIcon>> = Mutex::new(None);

    /// Create a simple colored circle icon
    unsafe fn create_status_icon(color: COLORREF) -> Result<HICON> {
        let size = 16i32;

        // Create device context
        let screen_dc = GetDC(None);
        let mem_dc = CreateCompatibleDC(Some(screen_dc));

        // Create bitmap
        let bitmap = CreateCompatibleBitmap(screen_dc, size, size);
        let old_bitmap = SelectObject(mem_dc, bitmap.into());

        // Fill with transparent color (magenta = transparent in icons)
        let brush = CreateSolidBrush(COLORREF(0x00FF00FF)); // Magenta
        let rect = RECT {
            left: 0,
            top: 0,
            right: size,
            bottom: size,
        };
        FillRect(mem_dc, &rect, brush);
        let _ = DeleteObject(brush.into());

        // Draw filled circle
        let brush = CreateSolidBrush(color);
        let pen = CreatePen(PS_SOLID, 1, color);
        let old_brush = SelectObject(mem_dc, brush.into());
        let old_pen = SelectObject(mem_dc, pen.into());

        Ellipse(mem_dc, 1, 1, size - 1, size - 1);

        SelectObject(mem_dc, old_brush);
        SelectObject(mem_dc, old_pen);
        let _ = DeleteObject(brush.into());
        let _ = DeleteObject(pen.into());

        // Create mask bitmap (1-bit)
        let mask_bitmap = CreateBitmap(size, size, 1, 1, None);
        let mask_dc = CreateCompatibleDC(Some(screen_dc));
        let old_mask = SelectObject(mask_dc, mask_bitmap.into());

        // Fill mask with white (transparent)
        let white_brush = CreateSolidBrush(COLORREF(0x00FFFFFF));
        FillRect(mask_dc, &rect, white_brush);
        let _ = DeleteObject(white_brush.into());

        // Draw black circle on mask (opaque area)
        let black_brush = CreateSolidBrush(COLORREF(0x00000000));
        let black_pen = CreatePen(PS_SOLID, 1, COLORREF(0x00000000));
        let old_mask_brush = SelectObject(mask_dc, black_brush.into());
        let old_mask_pen = SelectObject(mask_dc, black_pen.into());

        Ellipse(mask_dc, 1, 1, size - 1, size - 1);

        SelectObject(mask_dc, old_mask_brush);
        SelectObject(mask_dc, old_mask_pen);
        let _ = DeleteObject(black_brush.into());
        let _ = DeleteObject(black_pen.into());

        SelectObject(mem_dc, old_bitmap);
        SelectObject(mask_dc, old_mask);

        // Create icon
        let icon_info = ICONINFO {
            fIcon: BOOL::from(true),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask_bitmap,
            hbmColor: bitmap,
        };

        let icon = CreateIconIndirect(&icon_info)?;

        // Cleanup
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteObject(mask_bitmap.into());
        DeleteDC(mem_dc);
        DeleteDC(mask_dc);
        ReleaseDC(None, screen_dc);

        Ok(icon)
    }

    /// Initialize status icons
    unsafe fn init_icons() -> Result<()> {
        // Green for connected
        let connected = create_status_icon(COLORREF(0x0000FF00))?; // Green (BGR)
        *ICON_CONNECTED.lock().unwrap() = Some(SendableIcon(connected));

        // Red for disconnected
        let disconnected = create_status_icon(COLORREF(0x000000FF))?; // Red (BGR)
        *ICON_DISCONNECTED.lock().unwrap() = Some(SendableIcon(disconnected));

        // Yellow/Orange for pending
        let pending = create_status_icon(COLORREF(0x0000A5FF))?; // Orange (BGR)
        *ICON_PENDING.lock().unwrap() = Some(SendableIcon(pending));

        Ok(())
    }

    /// Get icon for current state
    unsafe fn get_state_icon(state: RelayState) -> HICON {
        match state {
            RelayState::Connected => ICON_CONNECTED
                .lock()
                .unwrap()
                .map(|s| s.0)
                .unwrap_or(HICON::default()),
            RelayState::Pending => ICON_PENDING
                .lock()
                .unwrap()
                .map(|s| s.0)
                .unwrap_or(HICON::default()),
            RelayState::Disconnected => ICON_DISCONNECTED
                .lock()
                .unwrap()
                .map(|s| s.0)
                .unwrap_or(HICON::default()),
        }
    }

    /// Format bytes to human readable string
    fn format_bytes(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    pub fn run_ui(
        mut status_rx: mpsc::Receiver<StatusUpdate>,
        command_tx: mpsc::Sender<EngineCommand>,
        port: u16,
    ) -> Result<()> {
        CURRENT_PORT.store(port, Ordering::Relaxed);
        *COMMAND_TX.lock().unwrap() = Some(command_tx);

        unsafe {
            // Initialize icons
            init_icons()?;

            let instance = GetModuleHandleW(None)?;

            let class_name = w!("FreeholdWindowClass");

            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(window_proc),
                hInstance: instance.into(),
                hCursor: LoadCursorW(None, IDC_ARROW)?,
                hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as _),
                lpszClassName: class_name,
                ..Default::default()
            };

            RegisterClassExW(&wc);

            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                w!("Freehold"),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                400,
                300,
                None,
                None,
                Some(instance.into()),
                None,
            )?;

            *MAIN_HWND.lock().unwrap() = Some(hwnd.0 as isize);

            add_tray_icon(hwnd)?;
            info!("Freehold Windows tray started");

            // Spawn status receiver that posts to window
            let hwnd_raw = hwnd.0 as isize;
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    while let Some(update) = status_rx.recv().await {
                        match update {
                            StatusUpdate::RelayState { addr, state } => {
                                *CURRENT_STATE.lock().unwrap() = state;
                                info!("Relay {} -> {:?}", addr, state);
                                // Post message to update tray
                                let hwnd = HWND(hwnd_raw as *mut _);
                                let _ =
                                    PostMessageW(Some(hwnd), WM_UPDATE_TRAY, WPARAM(0), LPARAM(0));
                            }
                            StatusUpdate::NeighborDiscovered(ip) => {
                                info!("Discovered neighbor: {}", ip);
                            }
                            StatusUpdate::Error(e) => {
                                info!("Error: {}", e);
                            }
                            StatusUpdate::Traffic { sent, received } => {
                                BYTES_SENT.store(sent, Ordering::Relaxed);
                                BYTES_RECEIVED.store(received, Ordering::Relaxed);
                            }
                            StatusUpdate::PortChanged { port } => {
                                info!("Port changed to {}", port);
                                CURRENT_PORT.store(port, Ordering::Relaxed);
                                // Update tray icon
                                let hwnd = HWND(hwnd_raw as *mut _);
                                let _ =
                                    PostMessageW(Some(hwnd), WM_UPDATE_TRAY, WPARAM(0), LPARAM(0));
                            }
                            StatusUpdate::SubdomainAssigned(sub) => {
                                info!("Subdomain assigned: {}", sub);
                            }
                            StatusUpdate::AcmeCertReady => {
                                info!("ACME certificate ready");
                            }
                        }
                    }
                });
            });

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            remove_tray_icon(hwnd)?;
            Ok(())
        }
    }

    unsafe fn add_tray_icon(hwnd: HWND) -> Result<()> {
        let state = *CURRENT_STATE.lock().unwrap();
        let port = CURRENT_PORT.load(Ordering::Relaxed);

        let tip = format!(
            "Freehold - {} (Port {})",
            match state {
                RelayState::Connected => "Connected",
                RelayState::Pending => "Connecting...",
                RelayState::Disconnected => "Disconnected",
            },
            port
        );

        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_ICON,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
            uCallbackMessage: WM_TRAYICON,
            hIcon: get_state_icon(state),
            ..Default::default()
        };

        let tip_wide: Vec<u16> = tip.encode_utf16().chain(std::iter::once(0)).collect();
        nid.szTip[..tip_wide.len().min(128)].copy_from_slice(&tip_wide[..tip_wide.len().min(128)]);

        if !Shell_NotifyIconW(NIM_ADD, &nid).as_bool() {
            return Err(anyhow!("Failed to add tray icon"));
        }
        Ok(())
    }

    unsafe fn update_tray_icon(hwnd: HWND) -> Result<()> {
        let state = *CURRENT_STATE.lock().unwrap();
        let port = CURRENT_PORT.load(Ordering::Relaxed);

        let tip = format!(
            "Freehold - {} (Port {})",
            match state {
                RelayState::Connected => "Connected",
                RelayState::Pending => "Connecting...",
                RelayState::Disconnected => "Disconnected",
            },
            port
        );

        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_ICON,
            uFlags: NIF_TIP | NIF_ICON,
            hIcon: get_state_icon(state),
            ..Default::default()
        };

        let tip_wide: Vec<u16> = tip.encode_utf16().chain(std::iter::once(0)).collect();
        nid.szTip[..tip_wide.len().min(128)].copy_from_slice(&tip_wide[..tip_wide.len().min(128)]);

        if !Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool() {
            return Err(anyhow!("Failed to update tray icon"));
        }
        Ok(())
    }

    unsafe fn remove_tray_icon(hwnd: HWND) -> Result<()> {
        let nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_ICON,
            ..Default::default()
        };
        if !Shell_NotifyIconW(NIM_DELETE, &nid).as_bool() {
            return Err(anyhow!("Failed to remove tray icon"));
        }
        Ok(())
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let state = *CURRENT_STATE.lock().unwrap();
        let port = CURRENT_PORT.load(Ordering::Relaxed);
        let sent = BYTES_SENT.load(Ordering::Relaxed);
        let received = BYTES_RECEIVED.load(Ordering::Relaxed);

        let menu = CreatePopupMenu().unwrap();

        let status_text = match state {
            RelayState::Connected => w!("● Connected"),
            RelayState::Pending => w!("◐ Connecting..."),
            RelayState::Disconnected => w!("○ Disconnected"),
        };

        AppendMenuW(
            menu,
            MF_STRING | MF_GRAYED,
            IDM_STATUS as usize,
            status_text,
        )
        .unwrap();

        let port_str: Vec<u16> = format!("Port: {}\0", port).encode_utf16().collect();
        AppendMenuW(
            menu,
            MF_STRING | MF_GRAYED,
            IDM_PORT as usize,
            PCWSTR(port_str.as_ptr()),
        )
        .unwrap();

        let traffic_str: Vec<u16> =
            format!("↑ {}  ↓ {}\0", format_bytes(sent), format_bytes(received))
                .encode_utf16()
                .collect();
        AppendMenuW(
            menu,
            MF_STRING | MF_GRAYED,
            IDM_TRAFFIC as usize,
            PCWSTR(traffic_str.as_ptr()),
        )
        .unwrap();

        AppendMenuW(menu, MF_SEPARATOR, 0, None).unwrap();
        AppendMenuW(
            menu,
            MF_STRING,
            IDM_NEW_ENDPOINT as usize,
            w!("Get New Endpoint"),
        )
        .unwrap();
        AppendMenuW(menu, MF_SEPARATOR, 0, None).unwrap();
        AppendMenuW(menu, MF_STRING, IDM_EXIT as usize, w!("Exit")).unwrap();

        let mut pt = POINT::default();
        GetCursorPos(&mut pt).unwrap();

        SetForegroundWindow(hwnd).unwrap();
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, None, hwnd, None).unwrap();
        DestroyMenu(menu).unwrap();
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_TRAYICON => {
                if lparam.0 as u32 == WM_RBUTTONUP || lparam.0 as u32 == WM_LBUTTONUP {
                    show_context_menu(hwnd);
                }
                LRESULT(0)
            }
            WM_UPDATE_TRAY => {
                update_tray_icon(hwnd).ok();
                LRESULT(0)
            }
            WM_COMMAND => {
                let cmd = (wparam.0 & 0xFFFF) as u32;
                match cmd {
                    IDM_NEW_ENDPOINT => {
                        if let Some(ref tx) = *COMMAND_TX.lock().unwrap() {
                            let _ = tx.blocking_send(EngineCommand::NewEndpoint);
                        }
                    }
                    IDM_EXIT => {
                        if let Some(ref tx) = *COMMAND_TX.lock().unwrap() {
                            let _ = tx.blocking_send(EngineCommand::Shutdown);
                        }
                        PostQuitMessage(0);
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Run the engine with Windows tray UI
pub async fn run(mut engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    let port = engine.port();

    // Create command channel
    let (cmd_tx, cmd_rx) = mpsc::channel::<EngineCommand>(32);

    // Set command receiver on engine
    engine.set_command_rx(cmd_rx);

    // Spawn engine
    let engine_handle = tokio::spawn(async move { engine.run().await });

    #[cfg(target_os = "windows")]
    {
        // Run Windows UI on separate thread (blocking)
        let ui_handle = std::thread::spawn(move || windows_impl::run_ui(status_rx, cmd_tx, port));

        ui_handle
            .join()
            .map_err(|_| anyhow::anyhow!("UI thread panicked"))??;
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Fallback for non-Windows
        let mut status_rx = status_rx;
        while let Some(update) = status_rx.recv().await {
            tracing::info!("Status: {:?}", update);
        }
    }

    engine_handle.abort();
    Ok(())
}
