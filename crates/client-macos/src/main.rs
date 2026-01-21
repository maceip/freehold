//! macOS native client using AppKit via objc2.

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send_id, ClassType, DeclaredClass};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate, NSBackingStoreType,
    NSColor, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{
    ns_string, MainThreadMarker, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString,
};
use std::cell::Cell;
use tracing::info;

use client_core::{ConnectionState, ProxyClient};

// Application delegate
struct AppDelegateIvars {
    window: Cell<Option<Retained<NSWindow>>>,
    status_item: Cell<Option<Retained<NSStatusItem>>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "AppDelegate"]
    #[ivars = AppDelegateIvars]
    struct AppDelegate;

    unsafe impl NSObjectProtocol for AppDelegate {}

    unsafe impl NSApplicationDelegate for AppDelegate {
        #[method(applicationDidFinishLaunching:)]
        unsafe fn application_did_finish_launching(&self, _notification: &NSObject) {
            info!("Application launched");
            self.setup_window();
            self.setup_status_item();
        }

        #[method(applicationShouldTerminateAfterLastWindowClosed:)]
        unsafe fn application_should_terminate_after_last_window_closed(
            &self,
            _sender: &NSApplication,
        ) -> bool {
            false // Keep running in menu bar
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
            window: Cell::new(None),
            status_item: Cell::new(None),
        });
        unsafe { msg_send_id![super(this), init] }
    }

    fn setup_window(&self) {
        let mtm = MainThreadMarker::new().unwrap();

        let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(400.0, 300.0));

        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable;

        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc(),
                frame,
                style,
                NSBackingStoreType::NSBackingStoreBuffered,
                false,
            )
        };

        unsafe {
            window.setTitle(ns_string!("Reflect"));
            window.center();

            // Set background color
            if let Some(bg) = NSColor::windowBackgroundColor() {
                window.setBackgroundColor(Some(&bg));
            }
        }

        self.ivars().window.set(Some(window));
    }

    fn setup_status_item(&self) {
        let mtm = MainThreadMarker::new().unwrap();

        unsafe {
            let status_bar = NSStatusBar::systemStatusBar();
            let status_item = status_bar.statusItemWithLength(-1.0); // Variable width

            if let Some(button) = status_item.button() {
                button.setTitle(ns_string!("⬡"));
            }

            // Create menu
            let menu = NSMenu::new(mtm);
            menu.setAutoenablesItems(false);

            let connect_item =
                NSMenuItem::initWithTitle_action_keyEquivalent(mtm.alloc(), ns_string!("Connect"), None, ns_string!(""));

            let disconnect_item = NSMenuItem::initWithTitle_action_keyEquivalent(
                mtm.alloc(),
                ns_string!("Disconnect"),
                None,
                ns_string!(""),
            );
            disconnect_item.setEnabled(false);

            let separator = NSMenuItem::separatorItem(mtm);

            let quit_item = NSMenuItem::initWithTitle_action_keyEquivalent(
                mtm.alloc(),
                ns_string!("Quit"),
                Some(objc2::sel!(terminate:)),
                ns_string!("q"),
            );

            menu.addItem(&connect_item);
            menu.addItem(&disconnect_item);
            menu.addItem(&separator);
            menu.addItem(&quit_item);

            status_item.setMenu(Some(&menu));

            self.ivars().status_item.set(Some(status_item));
        }
    }

    fn show_window(&self) {
        if let Some(window) = self.ivars().window.take() {
            unsafe {
                window.makeKeyAndOrderFront(None);
            }
            self.ivars().window.set(Some(window));
        }
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting Reflect macOS client");

    let mtm = MainThreadMarker::new().expect("Must run on main thread");

    let app = NSApplication::sharedApplication(mtm);
    unsafe {
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    }

    let delegate = AppDelegate::new(mtm);
    let delegate_obj = ProtocolObject::from_ref(&*delegate);
    app.setDelegate(Some(delegate_obj));

    unsafe {
        app.run();
    }
}
