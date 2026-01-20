//! System tray icon management with carebear icons.
//!
//! Tracks:
//! - Heartbeat status to reflector anycast network
//! - Domain registration and key status
//! - Connection quality and relay health

use anyhow::Result;
use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{
    menu::MenuId,
    Icon, TrayIcon, TrayIconBuilder, TrayIconEvent,
};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Different carebear states for the tray icon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarebearState {
    /// Happy bear - everything is working, heartbeat OK
    Happy,
    /// Sleepy bear - service is idle/starting up
    Sleepy,
    /// Grumpy bear - error state / heartbeat failed
    Grumpy,
    /// Love bear - connected and actively transferring
    Love,
    /// Bedtime bear - shutting down
    Bedtime,
}

impl CarebearState {
    /// Get the icon bytes for this state
    pub fn icon_bytes(&self) -> &'static [u8] {
        // TODO: Replace with actual carebear PNG/SVG icons
        // For now, use the same placeholder for all states
        // The icons should be ~32x32 or ~64x64 PNG with transparency
        match self {
            CarebearState::Happy => include_bytes!("../assets/bear_happy.png"),
            CarebearState::Sleepy => include_bytes!("../assets/bear_sleepy.png"),
            CarebearState::Grumpy => include_bytes!("../assets/bear_grumpy.png"),
            CarebearState::Love => include_bytes!("../assets/bear_love.png"),
            CarebearState::Bedtime => include_bytes!("../assets/bear_bedtime.png"),
        }
    }

    /// Get tooltip text for this state
    pub fn tooltip(&self) -> &'static str {
        match self {
            CarebearState::Happy => "Carebears - Connected ✓",
            CarebearState::Sleepy => "Carebears - Starting...",
            CarebearState::Grumpy => "Carebears - Connection Lost!",
            CarebearState::Love => "Carebears - Transferring ♥",
            CarebearState::Bedtime => "Carebears - Shutting down...",
        }
    }

    /// Determine state from network status
    pub fn from_status(status: &NetworkStatus) -> Self {
        if status.is_shutting_down {
            return CarebearState::Bedtime;
        }

        if !status.heartbeat_ok {
            return CarebearState::Grumpy;
        }

        if !status.registered {
            return CarebearState::Sleepy;
        }

        if status.active_connections > 0 {
            return CarebearState::Love;
        }

        CarebearState::Happy
    }
}

/// Network/registration status tracked by the tray
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// Domain registered with the reflector network
    pub domain: Option<String>,

    /// Whether we have valid keys
    pub has_keys: bool,

    /// Last successful heartbeat timestamp
    pub last_heartbeat: Option<Instant>,

    /// Heartbeat interval
    pub heartbeat_interval: Duration,

    /// Whether heartbeat is currently OK
    pub heartbeat_ok: bool,

    /// Whether domain is registered with reflector network
    pub registered: bool,

    /// Number of active relay connections
    pub relay_count: usize,

    /// Number of active client connections
    pub active_connections: usize,

    /// Bytes transferred this session
    pub bytes_transferred: u64,

    /// Current anycast IP (if assigned)
    pub anycast_ip: Option<String>,

    /// Is the service shutting down
    pub is_shutting_down: bool,

    /// Last error message (if any)
    pub last_error: Option<String>,
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self {
            domain: None,
            has_keys: false,
            last_heartbeat: None,
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_ok: false,
            registered: false,
            relay_count: 0,
            active_connections: 0,
            bytes_transferred: 0,
            anycast_ip: None,
            is_shutting_down: false,
            last_error: None,
        }
    }
}

impl NetworkStatus {
    /// Check if heartbeat is stale
    pub fn is_heartbeat_stale(&self) -> bool {
        match self.last_heartbeat {
            Some(last) => last.elapsed() > self.heartbeat_interval * 2,
            None => true,
        }
    }

    /// Format status for display
    pub fn format_tooltip(&self) -> String {
        let state = CarebearState::from_status(self);
        let mut lines = vec![state.tooltip().to_string()];

        if let Some(domain) = &self.domain {
            lines.push(format!("Domain: {}", domain));
        }

        if let Some(ip) = &self.anycast_ip {
            lines.push(format!("Anycast: {}", ip));
        }

        if self.relay_count > 0 {
            lines.push(format!("Relays: {}", self.relay_count));
        }

        if self.active_connections > 0 {
            lines.push(format!("Connections: {}", self.active_connections));
        }

        if let Some(err) = &self.last_error {
            lines.push(format!("Error: {}", err));
        }

        lines.join("\n")
    }
}

/// Menu item IDs
pub mod menu_ids {
    pub const STATUS_HEADER: &str = "status_header";
    pub const STATUS_DOMAIN: &str = "status_domain";
    pub const STATUS_HEARTBEAT: &str = "status_heartbeat";
    pub const STATUS_RELAYS: &str = "status_relays";
    pub const OPEN_DASHBOARD: &str = "open_dashboard";
    pub const COPY_ADDRESS: &str = "copy_address";
    pub const RECONNECT: &str = "reconnect";
    pub const VIEW_LOGS: &str = "view_logs";
    pub const QUIT: &str = "quit";
}

/// Commands that can be triggered from the tray menu
#[derive(Debug, Clone)]
pub enum TrayCommand {
    OpenDashboard,
    CopyAddress,
    Reconnect,
    ViewLogs,
    Quit,
}

/// System tray manager with status tracking
pub struct TrayManager {
    tray_icon: TrayIcon,
    current_state: CarebearState,
    status: Arc<RwLock<NetworkStatus>>,
    menu_receiver: mpsc::Receiver<TrayCommand>,
}

impl TrayManager {
    /// Create a new tray manager
    pub fn new(domain: Option<String>) -> Result<(Self, mpsc::Sender<TrayCommand>)> {
        let mut status = NetworkStatus::default();
        status.domain = domain;

        Self::with_status(status)
    }

    /// Create a new tray manager with initial status
    pub fn with_status(initial_status: NetworkStatus) -> Result<(Self, mpsc::Sender<TrayCommand>)> {
        let initial_state = CarebearState::from_status(&initial_status);

        // Create menu
        let menu = Self::build_menu(&initial_status)?;

        // Load initial icon
        let icon = Self::load_icon(initial_state)?;

        // Build tray icon
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(initial_status.format_tooltip())
            .with_icon(icon)
            .build()?;

        // Set up command channel
        let (cmd_tx, cmd_rx) = mpsc::channel();

        // Spawn menu event handler
        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            loop {
                if let Ok(event) = MenuEvent::receiver().recv() {
                    let cmd = match event.id.0.as_str() {
                        menu_ids::OPEN_DASHBOARD => Some(TrayCommand::OpenDashboard),
                        menu_ids::COPY_ADDRESS => Some(TrayCommand::CopyAddress),
                        menu_ids::RECONNECT => Some(TrayCommand::Reconnect),
                        menu_ids::VIEW_LOGS => Some(TrayCommand::ViewLogs),
                        menu_ids::QUIT => Some(TrayCommand::Quit),
                        _ => None,
                    };

                    if let Some(cmd) = cmd {
                        if cmd_tx_clone.send(cmd).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        info!("System tray initialized with {:?} state", initial_state);

        Ok((
            Self {
                tray_icon,
                current_state: initial_state,
                status: Arc::new(RwLock::new(initial_status)),
                menu_receiver: cmd_rx,
            },
            cmd_tx,
        ))
    }

    /// Build the tray menu
    fn build_menu(status: &NetworkStatus) -> Result<Menu> {
        let menu = Menu::new();

        // Status header (disabled, just for display)
        let header = MenuItem::with_id(
            MenuId::new(menu_ids::STATUS_HEADER),
            "🐻 Carebears Proxy",
            false,
            None,
        );
        menu.append(&header)?;

        // Domain status
        let domain_text = match &status.domain {
            Some(d) => format!("Domain: {}", d),
            None => "Domain: Not configured".to_string(),
        };
        let domain_item = MenuItem::with_id(
            MenuId::new(menu_ids::STATUS_DOMAIN),
            &domain_text,
            false,
            None,
        );
        menu.append(&domain_item)?;

        // Heartbeat status
        let heartbeat_text = if status.heartbeat_ok {
            "Heartbeat: ✓ OK"
        } else {
            "Heartbeat: ✗ Disconnected"
        };
        let heartbeat_item = MenuItem::with_id(
            MenuId::new(menu_ids::STATUS_HEARTBEAT),
            heartbeat_text,
            false,
            None,
        );
        menu.append(&heartbeat_item)?;

        // Relay count
        let relay_text = format!("Relays: {}", status.relay_count);
        let relay_item = MenuItem::with_id(
            MenuId::new(menu_ids::STATUS_RELAYS),
            &relay_text,
            false,
            None,
        );
        menu.append(&relay_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Open dashboard
        let dashboard_item = MenuItem::with_id(
            MenuId::new(menu_ids::OPEN_DASHBOARD),
            "Open Dashboard",
            true,
            None,
        );
        menu.append(&dashboard_item)?;

        // Copy address
        let copy_item = MenuItem::with_id(
            MenuId::new(menu_ids::COPY_ADDRESS),
            "Copy Proxy Address",
            true,
            None,
        );
        menu.append(&copy_item)?;

        // Reconnect
        let reconnect_item = MenuItem::with_id(
            MenuId::new(menu_ids::RECONNECT),
            "Reconnect",
            true,
            None,
        );
        menu.append(&reconnect_item)?;

        // View logs
        let logs_item = MenuItem::with_id(
            MenuId::new(menu_ids::VIEW_LOGS),
            "View Logs",
            true,
            None,
        );
        menu.append(&logs_item)?;

        menu.append(&PredefinedMenuItem::separator())?;

        // Quit
        let quit_item = MenuItem::with_id(
            MenuId::new(menu_ids::QUIT),
            "Quit",
            true,
            None,
        );
        menu.append(&quit_item)?;

        Ok(menu)
    }

    /// Load an icon for a given state
    fn load_icon(state: CarebearState) -> Result<Icon> {
        let icon_bytes = state.icon_bytes();

        // Decode PNG image
        let img = image::load_from_memory(icon_bytes)?;
        let rgba = img.to_rgba8();
        let (width, height) = rgba.dimensions();

        Icon::from_rgba(rgba.into_raw(), width, height)
            .map_err(|e| anyhow::anyhow!("Failed to create icon: {}", e))
    }

    /// Update network status and refresh tray
    pub fn update_status<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut NetworkStatus),
    {
        let new_state = {
            let mut status = self.status.write().unwrap();
            updater(&mut status);
            CarebearState::from_status(&status)
        };

        self.set_state(new_state)?;
        self.refresh_tooltip()?;

        Ok(())
    }

    /// Record a successful heartbeat
    pub fn record_heartbeat(&mut self) -> Result<()> {
        self.update_status(|s| {
            s.last_heartbeat = Some(Instant::now());
            s.heartbeat_ok = true;
        })
    }

    /// Record a failed heartbeat
    pub fn record_heartbeat_failure(&mut self, error: &str) -> Result<()> {
        self.update_status(|s| {
            s.heartbeat_ok = false;
            s.last_error = Some(error.to_string());
        })
    }

    /// Update registration status
    pub fn set_registered(&mut self, registered: bool, anycast_ip: Option<String>) -> Result<()> {
        self.update_status(|s| {
            s.registered = registered;
            s.anycast_ip = anycast_ip;
            if registered {
                s.has_keys = true;
            }
        })
    }

    /// Update relay count
    pub fn set_relay_count(&mut self, count: usize) -> Result<()> {
        self.update_status(|s| {
            s.relay_count = count;
        })
    }

    /// Update active connections
    pub fn set_active_connections(&mut self, count: usize) -> Result<()> {
        self.update_status(|s| {
            s.active_connections = count;
        })
    }

    /// Set shutting down state
    pub fn set_shutting_down(&mut self) -> Result<()> {
        self.update_status(|s| {
            s.is_shutting_down = true;
        })
    }

    /// Update the tray icon state
    fn set_state(&mut self, new_state: CarebearState) -> Result<()> {
        if self.current_state == new_state {
            return Ok(());
        }

        let icon = Self::load_icon(new_state)?;
        self.tray_icon.set_icon(Some(icon))?;

        debug!("Tray state changed: {:?} -> {:?}", self.current_state, new_state);
        self.current_state = new_state;

        Ok(())
    }

    /// Refresh tooltip from current status
    fn refresh_tooltip(&self) -> Result<()> {
        let status = self.status.read().unwrap();
        self.tray_icon.set_tooltip(Some(status.format_tooltip()))?;
        Ok(())
    }

    /// Get the current state
    pub fn state(&self) -> CarebearState {
        self.current_state
    }

    /// Get current status (cloned)
    pub fn status(&self) -> NetworkStatus {
        self.status.read().unwrap().clone()
    }

    /// Try to receive a command (non-blocking)
    pub fn try_recv_command(&self) -> Option<TrayCommand> {
        self.menu_receiver.try_recv().ok()
    }

    /// Receive a command (blocking)
    pub fn recv_command(&self) -> Option<TrayCommand> {
        self.menu_receiver.recv().ok()
    }
}

/// Run the tray icon event loop (call from main thread on macOS)
pub fn run_tray_event_loop<F>(mut callback: F)
where
    F: FnMut(TrayIconEvent) + 'static,
{
    std::thread::spawn(move || {
        loop {
            if let Ok(event) = TrayIconEvent::receiver().recv() {
                callback(event);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_from_status() {
        let mut status = NetworkStatus::default();

        // Default = sleepy (not registered)
        assert_eq!(CarebearState::from_status(&status), CarebearState::Grumpy);

        // With heartbeat OK but not registered
        status.heartbeat_ok = true;
        assert_eq!(CarebearState::from_status(&status), CarebearState::Sleepy);

        // Registered = happy
        status.registered = true;
        assert_eq!(CarebearState::from_status(&status), CarebearState::Happy);

        // With active connections = love
        status.active_connections = 5;
        assert_eq!(CarebearState::from_status(&status), CarebearState::Love);

        // Shutting down overrides all
        status.is_shutting_down = true;
        assert_eq!(CarebearState::from_status(&status), CarebearState::Bedtime);
    }
}
