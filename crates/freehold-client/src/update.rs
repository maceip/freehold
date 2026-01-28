//! Auto-update functionality
//!
//! Checks GitHub releases for updates and self-updates the binary.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

const GITHUB_REPO: &str = "maceip/freehold";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Check for updates and return the latest version if newer
pub async fn check_for_update() -> Result<Option<String>> {
    let client = reqwest::Client::builder()
        .user_agent("freehold-client")
        .build()?;

    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to fetch latest release")?;

    if !response.status().is_success() {
        anyhow::bail!("GitHub API returned status: {}", response.status());
    }

    let release: GitHubRelease = response
        .json()
        .await
        .context("Failed to parse release JSON")?;

    let latest_version = release.tag_name.trim_start_matches('v');

    if is_newer_version(latest_version, CURRENT_VERSION) {
        Ok(Some(latest_version.to_string()))
    } else {
        Ok(None)
    }
}

/// Perform self-update to the latest version
pub async fn self_update() -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("freehold-client")
        .build()?;

    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    info!("Checking for updates from {}", GITHUB_REPO);

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to fetch latest release")?;

    if !response.status().is_success() {
        anyhow::bail!("GitHub API returned status: {}", response.status());
    }

    let release: GitHubRelease = response
        .json()
        .await
        .context("Failed to parse release JSON")?;

    let latest_version = release.tag_name.trim_start_matches('v');

    if !is_newer_version(latest_version, CURRENT_VERSION) {
        info!("Already at latest version ({})", CURRENT_VERSION);
        return Ok(());
    }

    info!(
        "Update available: {} -> {}",
        CURRENT_VERSION, latest_version
    );

    // Find the appropriate asset for this platform
    let asset_name = get_asset_name();
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .context(format!("No release asset found for {}", asset_name))?;

    info!("Downloading {}...", asset.name);

    // Download the new binary
    let binary_data = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("Failed to download update")?
        .bytes()
        .await
        .context("Failed to read update data")?;

    // Get paths
    let current_exe = std::env::current_exe()
        .context("Failed to get current executable path")?;
    let backup_exe = current_exe.with_extension("old");
    let new_exe = current_exe.with_extension("new");

    // Write new binary
    std::fs::write(&new_exe, &binary_data)
        .context("Failed to write new binary")?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_exe, std::fs::Permissions::from_mode(0o755))
            .context("Failed to set executable permissions")?;
    }

    // Rename current -> backup
    if backup_exe.exists() {
        std::fs::remove_file(&backup_exe).ok();
    }
    std::fs::rename(&current_exe, &backup_exe)
        .context("Failed to backup current executable")?;

    // Rename new -> current
    std::fs::rename(&new_exe, &current_exe)
        .context("Failed to install new executable")?;

    info!("Updated to version {}. Please restart Freehold.", latest_version);

    // Clean up backup
    std::fs::remove_file(&backup_exe).ok();

    Ok(())
}

/// Check for updates on startup (non-blocking)
pub fn check_update_background() {
    tokio::spawn(async {
        match check_for_update().await {
            Ok(Some(version)) => {
                info!("Update available: {} -> {}", CURRENT_VERSION, version);
                info!("Run 'freehold --update' to update");
            }
            Ok(None) => {
                // Already up to date
            }
            Err(e) => {
                warn!("Failed to check for updates: {}", e);
            }
        }
    });
}

/// Get the asset name for this platform
fn get_asset_name() -> String {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return "freehold-windows-x86_64.exe".to_string();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "freehold-linux-x86_64".to_string();

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return "freehold-macos-x86_64".to_string();

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "freehold-macos-aarch64".to_string();

    #[allow(unreachable_code)]
    {
        format!(
            "freehold-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    }
}

/// Compare two semver versions, return true if `new` is newer than `current`
fn is_newer_version(new: &str, current: &str) -> bool {
    let parse_version = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = v
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };

    let new_ver = parse_version(new);
    let cur_ver = parse_version(current);

    new_ver > cur_ver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("1.0.0", "0.1.0"));
        assert!(is_newer_version("1.1.0", "1.0.0"));
        assert!(is_newer_version("1.0.1", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
        assert!(!is_newer_version("0.9.0", "1.0.0"));
    }
}
