//! Linux native client using GTK4.

#[cfg(target_os = "linux")]
mod linux_impl {
    use gtk4::prelude::*;
    use gtk4::{
        glib, Application, ApplicationWindow, Box as GtkBox, Button, Label, Orientation,
        MenuButton, gio,
    };
    use tracing::info;

    const APP_ID: &str = "com.reflect.client";

    pub fn run() -> glib::ExitCode {
        let app = Application::builder().application_id(APP_ID).build();

        app.connect_activate(build_ui);

        app.run()
    }

    fn build_ui(app: &Application) {
        // Create menu model
        let menu = gio::Menu::new();
        menu.append(Some("Connect"), Some("app.connect"));
        menu.append(Some("Disconnect"), Some("app.disconnect"));

        let section = gio::Menu::new();
        section.append(Some("Quit"), Some("app.quit"));
        menu.append_section(None, &section);

        // Create actions
        let connect_action = gio::SimpleAction::new("connect", None);
        connect_action.connect_activate(|_, _| {
            info!("Connect clicked");
        });
        app.add_action(&connect_action);

        let disconnect_action = gio::SimpleAction::new("disconnect", None);
        disconnect_action.set_enabled(false);
        disconnect_action.connect_activate(|_, _| {
            info!("Disconnect clicked");
        });
        app.add_action(&disconnect_action);

        let quit_action = gio::SimpleAction::new("quit", None);
        let app_clone = app.clone();
        quit_action.connect_activate(move |_, _| {
            app_clone.quit();
        });
        app.add_action(&quit_action);

        // Build UI
        let status_label = Label::builder()
            .label("Disconnected")
            .css_classes(["title-2"])
            .build();

        let server_label = Label::builder()
            .label("No server")
            .css_classes(["dim-label"])
            .build();

        let connect_btn = Button::builder()
            .label("Connect")
            .css_classes(["suggested-action", "pill"])
            .build();

        connect_btn.connect_clicked(|_| {
            info!("Connect button clicked");
        });

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

        content.append(&status_label);
        content.append(&server_label);
        content.append(&connect_btn);

        // Header bar with menu
        let menu_button = MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .build();

        let header = gtk4::HeaderBar::builder().build();
        header.pack_end(&menu_button);

        let window = ApplicationWindow::builder()
            .application(app)
            .title("Reflect")
            .default_width(400)
            .default_height(300)
            .child(&content)
            .build();

        window.set_titlebar(Some(&header));
        window.present();
        info!("Linux GTK4 client started");
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting Reflect Linux client");

    #[cfg(target_os = "linux")]
    {
        linux_impl::run();
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::error!("This binary is Linux-only");
    }
}
