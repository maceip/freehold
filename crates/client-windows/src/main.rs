//! Windows native client using windows-rs.

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::sync::OnceLock;
    use tracing::info;
    use windows::{
        core::*,
        Win32::{
            Foundation::*,
            Graphics::Gdi::*,
            System::LibraryLoader::GetModuleHandleW,
            UI::{
                Shell::*,
                WindowsAndMessaging::*,
            },
        },
    };

    use client_core::{ConnectionState, ProxyClient};

    const WM_TRAYICON: u32 = WM_USER + 1;
    const ID_TRAY_ICON: u32 = 1;
    const IDM_CONNECT: u32 = 100;
    const IDM_DISCONNECT: u32 = 101;
    const IDM_EXIT: u32 = 102;

    static INSTANCE: OnceLock<HINSTANCE> = OnceLock::new();

    pub fn run() -> Result<()> {
        unsafe {
            let instance = GetModuleHandleW(None)?;
            INSTANCE.set(instance).unwrap();

            // Register window class
            let class_name = w!("ReflectWindowClass");

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

            // Create hidden window for tray icon messages
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                w!("Reflect"),
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

            // Add tray icon
            add_tray_icon(hwnd)?;

            info!("Windows client started");

            // Message loop
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).into() {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Cleanup
            remove_tray_icon(hwnd)?;

            Ok(())
        }
    }

    unsafe fn add_tray_icon(hwnd: HWND) -> Result<()> {
        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ID_TRAY_ICON,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
            uCallbackMessage: WM_TRAYICON,
            hIcon: LoadIconW(None, IDI_APPLICATION)?,
            ..Default::default()
        };

        let tip = "Reflect";
        let tip_wide: Vec<u16> = tip.encode_utf16().chain(std::iter::once(0)).collect();
        nid.szTip[..tip_wide.len().min(128)].copy_from_slice(&tip_wide[..tip_wide.len().min(128)]);

        Shell_NotifyIconW(NIM_ADD, &nid)?;
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
        let menu = CreatePopupMenu().unwrap();

        AppendMenuW(menu, MF_STRING, IDM_CONNECT as usize, w!("Connect")).unwrap();
        AppendMenuW(menu, MF_STRING | MF_GRAYED, IDM_DISCONNECT as usize, w!("Disconnect")).unwrap();
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
            WM_COMMAND => {
                let cmd = (wparam.0 & 0xFFFF) as u32;
                match cmd {
                    IDM_CONNECT => {
                        info!("Connect clicked");
                    }
                    IDM_DISCONNECT => {
                        info!("Disconnect clicked");
                    }
                    IDM_EXIT => {
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

fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting Reflect Windows client");

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = windows_impl::run() {
            tracing::error!("Error: {:?}", e);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        tracing::error!("This binary is Windows-only");
    }
}
