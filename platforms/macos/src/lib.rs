//! Freehold macOS Platform - AppKit/Cocoa tray implementation

#[cfg(not(target_os = "macos"))]
compile_error!("freehold-platform-macos can only be compiled for macOS");

use anyhow::Result;
use freehold_client_core::{Engine, RelayState, StatusUpdate};
use tokio::sync::mpsc;
use tracing::info;

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::{define_class, msg_send_id, ClassType, DeclaredClass};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate, NSMenu, NSMenuItem,
        NSStatusBar, NSStatusItem,
    };
    use objc2_foundation::{ns_string, MainThreadMarker, NSObject, NSObjectProtocol, NSString};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Mutex;

    // Global state for cross-thread communication
    static CURRENT_STATE: Mutex<RelayState> = Mutex::new(RelayState::Disconnected);
    static CURRENT_PORT: AtomicU16 = AtomicU16::new(0);

    struct AppDelegateIvars {
        status_item: Cell<Option<Retained<NSStatusItem>>>,
        status_menu_item: Cell<Option<Retained<NSMenuItem>>>,
        port_menu_item: Cell<Option<Retained<NSMenuItem>>>,
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "FreeholdAppDelegate"]
        #[ivars = AppDelegateIvars]
        struct AppDelegate;

        unsafe impl NSObjectProtocol for AppDelegate {}

        unsafe impl NSApplicationDelegate for AppDelegate {
            #[method(applicationDidFinishLaunching:)]
            unsafe fn application_did_finish_launching(&self, _notification: &NSObject) {
                info!("Freehold launched");
                self.setup_status_item();
                self.start_ui_update_timer();
            }

            #[method(applicationShouldTerminateAfterLastWindowClosed:)]
            unsafe fn application_should_terminate_after_last_window_closed(
                &self,
                _sender: &NSApplication,
            ) -> bool {
                false
            }
        }
    );

    impl DeclaredClass for AppDelegate {
        type Ivars = AppDelegateIvars;
    }

    impl AppDelegate {
        fn new(mtm: MainThreadMarker) -> Retained<Self> {
            let this = mtm.alloc::<Self>();
            let this = this.set_ivars(AppDelegateIvars {
                status_item: Cell::new(None),
                status_menu_item: Cell::new(None),
                port_menu_item: Cell::new(None),
            });
            unsafe { msg_send_id![super(this), init] }
        }

        fn setup_status_item(&self) {
            let mtm = MainThreadMarker::new().unwrap();

            unsafe {
                let status_bar = NSStatusBar::systemStatusBar();
                let status_item = status_bar.statusItemWithLength(-1.0);

                if let Some(button) = status_item.button() {
                    button.setTitle(ns_string!("⬡"));
                }

                let menu = NSMenu::new(mtm);
                menu.setAutoenablesItems(false);

                let status_menu_item = NSMenuItem::initWithTitle_action_keyEquivalent(
                    mtm.alloc(),
                    ns_string!("Disconnected"),
                    None,
                    ns_string!(""),
                );
                status_menu_item.setEnabled(false);

                let port_menu_item = NSMenuItem::initWithTitle_action_keyEquivalent(
                    mtm.alloc(),
                    ns_string!("No port claimed"),
                    None,
                    ns_string!(""),
                );
                port_menu_item.setEnabled(false);

                let separator = NSMenuItem::separatorItem(mtm);

                let quit_item = NSMenuItem::initWithTitle_action_keyEquivalent(
                    mtm.alloc(),
                    ns_string!("Quit Freehold"),
                    Some(objc2::sel!(terminate:)),
                    ns_string!("q"),
                );

                menu.addItem(&status_menu_item);
                menu.addItem(&port_menu_item);
                menu.addItem(&separator);
                menu.addItem(&quit_item);

                status_item.setMenu(Some(&menu));

                self.ivars().status_item.set(Some(status_item));
                self.ivars().status_menu_item.set(Some(status_menu_item));
                self.ivars().port_menu_item.set(Some(port_menu_item));
            }
        }

        fn start_ui_update_timer(&self) {
            // Use a GCD timer to periodically update the UI
            let status_item = self.ivars().status_item.take();
            let status_menu_item = self.ivars().status_menu_item.take();
            let port_menu_item = self.ivars().port_menu_item.take();

            self.ivars().status_item.set(status_item.clone());
            self.ivars().status_menu_item.set(status_menu_item.clone());
            self.ivars().port_menu_item.set(port_menu_item.clone());

            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(250));

                    let state = *CURRENT_STATE.lock().unwrap();
                    let port = CURRENT_PORT.load(Ordering::Relaxed);

                    // Dispatch to main thread for UI updates
                    if let Some(mtm) = MainThreadMarker::new() {
                        unsafe {
                            if let Some(ref status_item) = status_item {
                                if let Some(button) = status_item.button() {
                                    let icon = match state {
                                        RelayState::Connected => ns_string!("⬢"),
                                        RelayState::Pending => ns_string!("◎"),
                                        RelayState::Disconnected => ns_string!("⬡"),
                                    };
                                    button.setTitle(icon);
                                }
                            }

                            if let Some(ref item) = status_menu_item {
                                let text = match state {
                                    RelayState::Connected => NSString::from_str("Connected"),
                                    RelayState::Pending => NSString::from_str("Connecting..."),
                                    RelayState::Disconnected => NSString::from_str("Disconnected"),
                                };
                                item.setTitle(&text);
                            }

                            if let Some(ref item) = port_menu_item {
                                let text = if port > 0 {
                                    NSString::from_str(&format!("Port: {}", port))
                                } else {
                                    NSString::from_str("No port claimed")
                                };
                                item.setTitle(&text);
                            }
                        }
                    }
                }
            });
        }
    }

    pub fn run_ui(mut status_rx: mpsc::Receiver<StatusUpdate>, port: u16) -> Result<()> {
        let mtm = MainThreadMarker::new().expect("Must run on main thread");

        // Store the port
        CURRENT_PORT.store(port, Ordering::Relaxed);

        let app = NSApplication::sharedApplication(mtm);
        unsafe {
            app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        }

        let delegate = AppDelegate::new(mtm);
        let delegate_obj = ProtocolObject::from_ref(&*delegate);
        app.setDelegate(Some(delegate_obj));

        // Process status updates in background thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                while let Some(update) = status_rx.recv().await {
                    match update {
                        StatusUpdate::RelayState { addr, state } => {
                            *CURRENT_STATE.lock().unwrap() = state;
                            info!("Relay {} -> {:?}", addr, state);
                        }
                        StatusUpdate::NeighborDiscovered(ip) => {
                            info!("Discovered neighbor: {}", ip);
                        }
                        StatusUpdate::Error(e) => {
                            info!("Error: {}", e);
                        }
                        StatusUpdate::Traffic { sent, received } => {
                            // TODO: Display traffic stats in menu
                            let _ = (sent, received);
                        }
                        StatusUpdate::PortChanged { port } => {
                            info!("Port changed to {}", port);
                            CURRENT_PORT.store(port, Ordering::Relaxed);
                        }
                    }
                }
            });
        });

        unsafe {
            app.run();
        }

        Ok(())
    }
}

/// Run the engine with macOS tray UI
pub async fn run(mut engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    let port = engine.port();

    let engine_handle = tokio::spawn(async move { engine.run().await });

    #[cfg(target_os = "macos")]
    {
        macos_impl::run_ui(status_rx, port)?;
    }

    #[cfg(not(target_os = "macos"))]
    {
        let mut status_rx = status_rx;
        while let Some(update) = status_rx.recv().await {
            info!("Status: {:?}", update);
        }
    }

    engine_handle.abort();
    Ok(())
}
