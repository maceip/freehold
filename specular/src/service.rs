//! Cross-platform service management for Specular.
//!
//! Supports:
//! - Linux: systemd user/system services
//! - macOS: launchd agents/daemons
//! - Windows: Windows Service API

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{info, warn};

const SERVICE_NAME: &str = "specular";
const SERVICE_DESCRIPTION: &str = "Specular Sovereign Proxy";

/// Get the path to the current executable
fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to get current executable path")
}

/// Manage the Specular service (install/uninstall)
pub fn manage_service(action: &str, domain: &str, target: &str) -> Result<()> {
    match action {
        "install" => install_service(domain, target),
        "uninstall" => uninstall_service(),
        _ => Err(anyhow::anyhow!("Unknown action: {}", action)),
    }
}

fn install_service(domain: &str, target: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_systemd_service(domain, target)
    }

    #[cfg(target_os = "macos")]
    {
        install_launchd_service(domain, target)
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_service(domain, target)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Service installation not supported on this platform"))
    }
}

fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        uninstall_systemd_service()
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_launchd_service()
    }

    #[cfg(target_os = "windows")]
    {
        uninstall_windows_service()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Service uninstallation not supported on this platform"))
    }
}

// ============================================================================
// Linux (systemd)
// ============================================================================

#[cfg(target_os = "linux")]
fn systemd_user_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("systemd/user")
}

#[cfg(target_os = "linux")]
fn systemd_service_path() -> PathBuf {
    systemd_user_dir().join(format!("{}.service", SERVICE_NAME))
}

#[cfg(target_os = "linux")]
fn install_systemd_service(domain: &str, target: &str) -> Result<()> {
    let exe = current_exe()?;
    let service_dir = systemd_user_dir();
    std::fs::create_dir_all(&service_dir)?;

    let unit = format!(
        r#"[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} run --domain {domain} --target {target}
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#,
        description = SERVICE_DESCRIPTION,
        exe = exe.display(),
        domain = domain,
        target = target,
    );

    let service_path = systemd_service_path();
    std::fs::write(&service_path, unit)?;
    info!("Created systemd service: {}", service_path.display());

    // Reload and enable
    let status = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()?;
    if !status.success() {
        warn!("Failed to reload systemd daemon");
    }

    let status = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", SERVICE_NAME])
        .status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to enable service"));
    }

    info!("Service installed and started successfully");
    info!("Check status with: systemctl --user status {}", SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd_service() -> Result<()> {
    // Stop and disable
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", SERVICE_NAME])
        .status();

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", SERVICE_NAME])
        .status();

    // Remove service file
    let service_path = systemd_service_path();
    if service_path.exists() {
        std::fs::remove_file(&service_path)?;
        info!("Removed service file: {}", service_path.display());
    }

    // Reload
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    info!("Service uninstalled successfully");
    Ok(())
}

// ============================================================================
// macOS (launchd)
// ============================================================================

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join("Library/LaunchAgents")
        .join(format!("com.specular.{}.plist", SERVICE_NAME))
}

#[cfg(target_os = "macos")]
fn install_launchd_service(domain: &str, target: &str) -> Result<()> {
    let exe = current_exe()?;
    let plist_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join("Library/LaunchAgents");
    std::fs::create_dir_all(&plist_dir)?;

    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join("Library/Logs/Specular");
    std::fs::create_dir_all(&log_dir)?;

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.specular.{service}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
        <string>--domain</string>
        <string>{domain}</string>
        <string>--target</string>
        <string>{target}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/specular.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/specular.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
"#,
        service = SERVICE_NAME,
        exe = exe.display(),
        domain = domain,
        target = target,
        log_dir = log_dir.display(),
    );

    let plist_path = launchd_plist_path();
    std::fs::write(&plist_path, plist)?;
    info!("Created launchd plist: {}", plist_path.display());

    // Load the service
    let status = std::process::Command::new("launchctl")
        .args(["load", "-w", plist_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("Failed to load launchd service"));
    }

    info!("Service installed and started successfully");
    info!("Check status with: launchctl list | grep specular");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd_service() -> Result<()> {
    let plist_path = launchd_plist_path();

    // Unload the service
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w", plist_path.to_str().unwrap()])
            .status();

        std::fs::remove_file(&plist_path)?;
        info!("Removed plist: {}", plist_path.display());
    }

    info!("Service uninstalled successfully");
    Ok(())
}

// ============================================================================
// Windows
// ============================================================================

#[cfg(target_os = "windows")]
fn install_windows_service(domain: &str, target: &str) -> Result<()> {
    use std::ffi::OsString;
    use windows_service::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let exe = current_exe()?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_binary_path = format!(
        "{} run --domain {} --target {}",
        exe.display(),
        domain,
        target
    );

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DESCRIPTION),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("run"),
            OsString::from("--domain"),
            OsString::from(domain),
            OsString::from("--target"),
            OsString::from(target),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::START)?;
    service.start(&[OsString::new()])?;

    info!("Windows service installed and started successfully");
    info!("Check status with: sc query {}", SERVICE_NAME);
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows_service() -> Result<()> {
    use std::ffi::OsString;
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;

    // Stop the service
    let _ = service.stop();

    // Delete the service
    service.delete()?;

    info!("Windows service uninstalled successfully");
    Ok(())
}

/// Check if the service is running
pub fn check_service_status() -> Result<ServiceStatus> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("systemctl")
            .args(["--user", "is-active", SERVICE_NAME])
            .output()?;

        let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(match status.as_str() {
            "active" => ServiceStatus::Running,
            "inactive" => ServiceStatus::Stopped,
            _ => ServiceStatus::Unknown,
        })
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("launchctl")
            .args(["list"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains(&format!("com.specular.{}", SERVICE_NAME)) {
            Ok(ServiceStatus::Running)
        } else {
            Ok(ServiceStatus::Stopped)
        }
    }

    #[cfg(target_os = "windows")]
    {
        use windows_service::{
            service::ServiceAccess,
            service_manager::{ServiceManager, ServiceManagerAccess},
        };

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => {
                let status = service.query_status()?;
                use windows_service::service::ServiceState;
                Ok(match status.current_state {
                    ServiceState::Running => ServiceStatus::Running,
                    ServiceState::Stopped => ServiceStatus::Stopped,
                    _ => ServiceStatus::Unknown,
                })
            }
            Err(_) => Ok(ServiceStatus::NotInstalled),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(ServiceStatus::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    NotInstalled,
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceStatus::Running => write!(f, "Running"),
            ServiceStatus::Stopped => write!(f, "Stopped"),
            ServiceStatus::NotInstalled => write!(f, "Not Installed"),
            ServiceStatus::Unknown => write!(f, "Unknown"),
        }
    }
}
