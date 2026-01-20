use clap::{Parser, Subcommand};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod crypto;
mod proxy;
mod service;

#[cfg(feature = "tray")]
mod tray;

#[derive(Parser)]
#[command(name = "carebears")]
#[command(author, version)]
#[command(about = "Carebears - Sharing is caring: internet addressable secure origins for all!", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install Carebears as a background service (Windows/Mac/Linux)
    Install {
        /// Domain name to serve (e.g., myapp.example.com)
        #[arg(short, long)]
        domain: String,

        /// Target backend address to proxy to
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        target: String,
    },

    /// Start the proxy in the current terminal (for debugging)
    Run {
        /// Domain name to serve
        #[arg(short, long)]
        domain: String,

        /// Target backend address to proxy to
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        target: String,

        /// Use self-signed certificate (for testing)
        #[arg(long, default_value = "true")]
        self_signed: bool,

        /// Listen address for HTTPS
        #[arg(short, long, default_value = "[::]:443")]
        listen: String,

        /// Run with system tray icon (requires 'tray' feature)
        #[cfg(feature = "tray")]
        #[arg(long)]
        tray: bool,
    },

    /// Start with system tray only (no console output)
    #[cfg(feature = "tray")]
    Tray {
        /// Domain name to serve
        #[arg(short, long)]
        domain: String,

        /// Target backend address to proxy to
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        target: String,
    },

    /// Check connectivity and relay status
    Status,

    /// Uninstall the background service
    Uninstall,

    /// Generate a self-signed certificate for testing
    GenCert {
        /// Domain name for the certificate
        #[arg(short, long)]
        domain: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .compact()
        .init();

    let result = run(cli).await;

    if let Err(e) = result {
        error!("Error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Install { domain, target } => {
            info!("Installing Carebears service...");
            service::manage_service("install", &domain, &target)?;
            info!("Installation complete!");
        }

        Commands::Run {
            domain,
            target,
            self_signed,
            listen,
            #[cfg(feature = "tray")]
            tray: with_tray,
        } => {
            info!("╔═══════════════════════════════════════╗");
            info!("║       🐻 Carebears Proxy 🐻           ║");
            info!("╚═══════════════════════════════════════╝");
            info!("");
            info!("Domain:    {}", domain);
            info!("Target:    {}", target);
            info!("Listen:    {}", listen);
            info!("TLS:       {}", if self_signed { "self-signed" } else { "ACME" });
            #[cfg(feature = "tray")]
            info!("Tray:      {}", if with_tray { "enabled" } else { "disabled" });
            info!("");

            #[cfg(feature = "tray")]
            if with_tray {
                run_with_tray(&domain, &target, &listen).await?;
            } else {
                proxy::start_proxy(&domain, &target, &listen).await?;
            }

            #[cfg(not(feature = "tray"))]
            proxy::start_proxy(&domain, &target, &listen).await?;
        }

        #[cfg(feature = "tray")]
        Commands::Tray { domain, target } => {
            // Tray-only mode - minimal console output
            run_with_tray(&domain, &target).await?;
        }

        Commands::Status => {
            info!("Checking Carebears status...");
            info!("");

            // Check service status
            let svc_status = service::check_service_status()?;
            info!("Service:   {}", svc_status);

            // Check relay connectivity
            let relay_status = proxy::check_relay_status().await?;
            info!("Relay:     {}", relay_status);

            info!("");
            info!("To view detailed logs, run with -v flag");
        }

        Commands::Uninstall => {
            info!("Uninstalling Carebears service...");
            service::manage_service("uninstall", "", "")?;
            info!("Uninstallation complete!");
        }

        Commands::GenCert { domain } => {
            info!("Generating self-signed certificate for {}...", domain);
            let bundle = crypto::generate_self_signed(&domain)?;
            info!(
                "Certificate generated with {} cert(s) in chain",
                bundle.cert_chain.len()
            );
            info!("Saved to: ~/.local/share/carebears/certs/");
        }
    }

    Ok(())
}

/// Run proxy with system tray integration
#[cfg(feature = "tray")]
async fn run_with_tray(domain: &str, target: &str, listen: &str) -> anyhow::Result<()> {
    use tray::{TrayCommand, TrayManager};

    info!("Starting Carebears with system tray...");

    // Initialize tray
    let (mut tray_manager, _cmd_sender) = TrayManager::new(Some(domain.to_string()))?;

    // Start proxy in background
    let domain_clone = domain.to_string();
    let target_clone = target.to_string();
    let listen_clone = listen.to_string();

    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy::start_proxy(&domain_clone, &target_clone, &listen_clone).await {
            error!("Proxy error: {}", e);
        }
    });

    // Simulate heartbeat updates (in real app, this would come from the proxy)
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            // In real implementation, check actual heartbeat status
            info!("Heartbeat tick");
        }
    });

    // Handle tray commands
    loop {
        if let Some(cmd) = tray_manager.try_recv_command() {
            match cmd {
                TrayCommand::Quit => {
                    info!("Quit requested from tray");
                    tray_manager.set_shutting_down()?;
                    break;
                }
                TrayCommand::OpenDashboard => {
                    info!("Opening dashboard...");
                    // TODO: Open browser to dashboard URL
                }
                TrayCommand::CopyAddress => {
                    info!("Copy address requested");
                    // TODO: Copy proxy address to clipboard
                }
                TrayCommand::Reconnect => {
                    info!("Reconnect requested");
                    // TODO: Trigger reconnection
                }
                TrayCommand::ViewLogs => {
                    info!("View logs requested");
                    // TODO: Open log file or log viewer
                }
            }
        }

        // Small sleep to prevent busy loop
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Cleanup
    heartbeat_handle.abort();
    proxy_handle.abort();

    info!("Carebears shutdown complete");
    Ok(())
}
