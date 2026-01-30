//! Service installation and management
//!
//! Handles installing Freehold as a startup service on each platform.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::info;

/// Install Freehold as a startup service
pub fn install() -> Result<()> {
    #[cfg(target_os = "windows")]
    return install_windows();

    #[cfg(target_os = "macos")]
    return install_macos();

    #[cfg(target_os = "linux")]
    return install_linux();

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Service installation not supported on this platform")
}

/// Uninstall Freehold startup service
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "windows")]
    return uninstall_windows();

    #[cfg(target_os = "macos")]
    return uninstall_macos();

    #[cfg(target_os = "linux")]
    return uninstall_linux();

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    anyhow::bail!("Service uninstallation not supported on this platform")
}

/// Check if Freehold is installed as a startup service
pub fn is_installed() -> bool {
    #[cfg(target_os = "windows")]
    return is_installed_windows();

    #[cfg(target_os = "macos")]
    return is_installed_macos();

    #[cfg(target_os = "linux")]
    return is_installed_linux();

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    false
}

/// Get the path to the current executable
fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to get current executable path")
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
fn install_windows() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let exe_path = current_exe()?;
    let exe_str = exe_path.to_string_lossy();

    // Open HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE)
        .context("Failed to open Run registry key")?;

    // Add Freehold entry
    run_key
        .set_value("Freehold", &exe_str.as_ref())
        .context("Failed to set registry value")?;

    info!("Installed Freehold to Windows startup");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE)
        .context("Failed to open Run registry key")?;

    run_key
        .delete_value("Freehold")
        .context("Failed to delete registry value")?;

    info!("Uninstalled Freehold from Windows startup");
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_installed_windows() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(run_key) = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run") {
        run_key.get_value::<String, _>("Freehold").is_ok()
    } else {
        false
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
fn install_macos() -> Result<()> {
    let exe_path = current_exe()?;
    let exe_str = exe_path.to_string_lossy();

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.freehold.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/freehold.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/freehold.err</string>
</dict>
</plist>
"#,
        exe_str
    );

    let launch_agents = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("Library/LaunchAgents");

    std::fs::create_dir_all(&launch_agents).context("Failed to create LaunchAgents directory")?;

    let plist_path = launch_agents.join("com.freehold.client.plist");
    std::fs::write(&plist_path, plist_content).context("Failed to write plist file")?;

    // Load the service
    std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .status()
        .context("Failed to load launchd service")?;

    info!("Installed Freehold to macOS startup");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_macos() -> Result<()> {
    let plist_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("Library/LaunchAgents/com.freehold.client.plist");

    if plist_path.exists() {
        // Unload the service
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&plist_path)
            .status();

        std::fs::remove_file(&plist_path).context("Failed to remove plist file")?;
    }

    info!("Uninstalled Freehold from macOS startup");
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_installed_macos() -> bool {
    let plist_path = dirs::home_dir()
        .map(|h| h.join("Library/LaunchAgents/com.freehold.client.plist"))
        .unwrap_or_default();
    plist_path.exists()
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
fn install_linux() -> Result<()> {
    let exe_path = current_exe()?;
    let exe_str = exe_path.to_string_lossy();

    let service_content = format!(
        r#"[Unit]
Description=Freehold Network Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"#,
        exe_str
    );

    let systemd_user = dirs::config_dir()
        .context("Failed to get config directory")?
        .join("systemd/user");

    std::fs::create_dir_all(&systemd_user).context("Failed to create systemd user directory")?;

    let service_path = systemd_user.join("freehold.service");
    std::fs::write(&service_path, service_content).context("Failed to write service file")?;

    // Reload systemd and enable service
    std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .context("Failed to reload systemd")?;

    std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", "freehold.service"])
        .status()
        .context("Failed to enable service")?;

    info!("Installed Freehold as systemd user service");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux() -> Result<()> {
    // Disable and stop service
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "freehold.service"])
        .status();

    let service_path = dirs::config_dir()
        .context("Failed to get config directory")?
        .join("systemd/user/freehold.service");

    if service_path.exists() {
        std::fs::remove_file(&service_path).context("Failed to remove service file")?;
    }

    // Reload systemd
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    info!("Uninstalled Freehold systemd user service");
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_installed_linux() -> bool {
    let service_path = dirs::config_dir()
        .map(|c| c.join("systemd/user/freehold.service"))
        .unwrap_or_default();
    service_path.exists()
}
