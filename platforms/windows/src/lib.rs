//! Freehold Windows Platform - Win32 tray implementation

#[cfg(not(target_os = "windows"))]
compile_error!("freehold-platform-windows can only be compiled for Windows");

use anyhow::Result;
use freehold_client_core::{Engine, RelayState, StatusUpdate};
use tokio::sync::mpsc;
use tracing::info;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Mutex;
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
    const IDM_EXIT: u32 = 102;

    static CURRENT_STATE: Mutex<RelayState> = Mutex::new(RelayState::Disconnected);
    static CURRENT_PORT: AtomicU16 = AtomicU16::new(0);
    static MAIN_HWND: Mutex<Option<isize>> = Mutex::new(None);

    pub fn run_ui(mut status_rx: mpsc::Receiver<StatusUpdate>, port: u16) -> Result<()> {
        CURRENT_PORT.store(port, Ordering::Relaxed);

        unsafe {
            let instance = GetModuleHandleW(None)?;

            let class_name = w!("FreeholdWindowClass");

            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
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
                instance,
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
                                PostMessageW(hwnd, WM_UPDATE_TRAY, WPARAM(0), LPARAM(0)).ok();
                            }
                            StatusUpdate::NeighborDiscovered(ip) => {
                                info!("Discovered neighbor: {}", ip);
                            }
                            StatusUpdate::Error(e) => {
                                info!("Error: {}", e);
                            }
                        }
                    }
                });
            });

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                TranslateMessage(&msg);
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
            hIcon: LoadIconW(None, IDI_APPLICATION)?,
            ..Default::default()
        };

        let tip_wide: Vec<u16> = tip.encode_utf16().chain(std::iter::once(0)).collect();
        nid.szTip[..tip_wide.len().min(128)].copy_from_slice(&tip_wide[..tip_wide.len().min(128)]);

        Shell_NotifyIconW(NIM_ADD, &nid)?;
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
            uFlags: NIF_TIP,
            ..Default::default()
        };

        let tip_wide: Vec<u16> = tip.encode_utf16().chain(std::iter::once(0)).collect();
        nid.szTip[..tip_wide.len().min(128)].copy_from_slice(&tip_wide[..tip_wide.len().min(128)]);

        Shell_NotifyIconW(NIM_MODIFY, &nid)?;
        Ok(())
    }

    unsafe fn remove_tray_icon(hwnd: HWND) -> Result<()> {
        let nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_ICON,
            ..Default::default()
        };
        Shell_NotifyIconW(NIM_DELETE, &nid)?;
        Ok(())
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let state = *CURRENT_STATE.lock().unwrap();
        let port = CURRENT_PORT.load(Ordering::Relaxed);

        let menu = CreatePopupMenu().unwrap();

        let status_text = match state {
            RelayState::Connected => w!("Status: Connected"),
            RelayState::Pending => w!("Status: Connecting..."),
            RelayState::Disconnected => w!("Status: Disconnected"),
        };

        AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_STATUS as usize, status_text).unwrap();

        let port_str: Vec<u16> = format!("Port: {}\0", port).encode_utf16().collect();
        AppendMenuW(
            menu,
            MF_STRING | MF_GRAYED,
            IDM_PORT as usize,
            PCWSTR(port_str.as_ptr()),
        )
        .unwrap();

        AppendMenuW(menu, MF_SEPARATOR, 0, None).unwrap();
        AppendMenuW(menu, MF_STRING, IDM_EXIT as usize, w!("Exit")).unwrap();

        let mut pt = POINT::default();
        GetCursorPos(&mut pt).unwrap();

        SetForegroundWindow(hwnd).unwrap();
        TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, None).unwrap();
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
                if cmd == IDM_EXIT {
                    PostQuitMessage(0);
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

    // Spawn engine
    let engine_handle = tokio::spawn(async move {
        engine.run().await
    });

    #[cfg(target_os = "windows")]
    {
        // Run Windows UI on separate thread (blocking)
        let ui_handle = std::thread::spawn(move || {
            windows_impl::run_ui(status_rx, port)
        });

        ui_handle.join().map_err(|_| anyhow::anyhow!("UI thread panicked"))??;
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Fallback for non-Windows
        let mut status_rx = status_rx;
        while let Some(update) = status_rx.recv().await {
            info!("Status: {:?}", update);
        }
    }

    engine_handle.abort();
    Ok(())
}
