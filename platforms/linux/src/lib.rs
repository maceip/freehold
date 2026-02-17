//! Freehold Linux Platform - GTK4 tray implementation

#[cfg(not(target_os = "linux"))]
compile_error!("freehold-platform-linux can only be compiled for Linux");

use anyhow::Result;
use freehold_client_core::{Engine, RelayState, StatusUpdate};
use tokio::sync::mpsc;
use tracing::info;

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use gtk4::prelude::*;
    use gtk4::{
        gio, Application, ApplicationWindow, Box as GtkBox, Label, MenuButton, Orientation,
    };
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU16, Ordering};

    const APP_ID: &str = "com.freehold.client";

    // Store port globally for access from UI thread
    static STORED_PORT: AtomicU16 = AtomicU16::new(0);

    pub fn run_ui(mut status_rx: mpsc::Receiver<StatusUpdate>, port: u16) -> Result<()> {
        STORED_PORT.store(port, Ordering::Relaxed);

        let app = Application::builder().application_id(APP_ID).build();

        let state = Rc::new(RefCell::new(RelayState::Disconnected));
        let state_clone = state.clone();

        app.connect_activate(move |app| {
            build_ui(app, state_clone.clone(), port);
        });

        // Status updates processed via GTK main context
        let state_for_updates = state.clone();
        gtk4::glib::spawn_future_local(async move {
            while let Some(update) = status_rx.recv().await {
                match update {
                    StatusUpdate::RelayState { addr, state } => {
                        *state_for_updates.borrow_mut() = state;
                        info!("Relay {} -> {:?}", addr, state);
                    }
                    StatusUpdate::NeighborDiscovered(ip) => {
                        info!("Discovered neighbor: {}", ip);
                    }
                    StatusUpdate::Error(e) => {
                        info!("Error: {}", e);
                    }
                    StatusUpdate::Traffic { sent, received } => {
                        // TODO: Display traffic stats in UI
                        let _ = (sent, received);
                    }
                    StatusUpdate::PortChanged { port } => {
                        info!("Port changed to {}", port);
                        STORED_PORT.store(port, Ordering::Relaxed);
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

        app.run();
        Ok(())
    }

    fn build_ui(app: &Application, state: Rc<RefCell<RelayState>>, port: u16) {
        // Menu model
        let menu = gio::Menu::new();

        let section = gio::Menu::new();
        section.append(Some("Quit"), Some("app.quit"));
        menu.append_section(None, &section);

        // Actions
        let quit_action = gio::SimpleAction::new("quit", None);
        let app_clone = app.clone();
        quit_action.connect_activate(move |_, _| {
            app_clone.quit();
        });
        app.add_action(&quit_action);

        // Status display
        let status_label = Label::builder()
            .label("Disconnected")
            .css_classes(["title-2"])
            .build();

        let port_label = Label::builder()
            .label(&format!("Port: {}", port))
            .css_classes(["dim-label"])
            .build();

        let status_icon = Label::builder().label("⬡").css_classes(["title-1"]).build();

        // Update status periodically
        let status_label_clone = status_label.clone();
        let status_icon_clone = status_icon.clone();
        let state_clone = state.clone();
        gtk4::glib::timeout_add_local(std::time::Duration::from_millis(250), move || {
            let current = *state_clone.borrow();
            let (text, icon) = match current {
                RelayState::Connected => ("Connected", "⬢"),
                RelayState::Pending => ("Connecting...", "◎"),
                RelayState::Disconnected => ("Disconnected", "⬡"),
            };
            status_label_clone.set_label(text);
            status_icon_clone.set_label(icon);
            gtk4::glib::ControlFlow::Continue
        });

        // Layout
        let content = GtkBox::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();

        content.append(&status_icon);
        content.append(&status_label);
        content.append(&port_label);

        // Header with menu
        let menu_button = MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .build();

        let header = gtk4::HeaderBar::builder().build();
        header.pack_end(&menu_button);

        let window = ApplicationWindow::builder()
            .application(app)
            .title("Freehold")
            .default_width(400)
            .default_height(300)
            .child(&content)
            .build();

        window.set_titlebar(Some(&header));
        window.present();

        info!("Freehold GTK4 client started on port {}", port);
    }
}

/// Run the engine with Linux GTK4 UI
pub async fn run(mut engine: Engine, status_rx: mpsc::Receiver<StatusUpdate>) -> Result<()> {
    let port = engine.port();

    // Spawn engine
    let engine_handle = tokio::spawn(async move { engine.run().await });

    #[cfg(target_os = "linux")]
    {
        // GTK4 needs to run on main thread
        linux_impl::run_ui(status_rx, port)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut status_rx = status_rx;
        while let Some(update) = status_rx.recv().await {
            info!("Status: {:?}", update);
        }
    }

    engine_handle.abort();
    Ok(())
}
