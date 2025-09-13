//! AWDL Daemon Binary
//!
//! This is the main entry point for the AWDL daemon.
//! It initializes and runs the AWDL protocol daemon with proper
//! configuration, logging, and signal handling.

use awdl_rust::{
    daemon::{
        DaemonBuilder, DaemonConfig, DaemonUtils
    },
    AwdlError, Result
};
use clap::{Arg, Command};
use std::{
    path::PathBuf,
    process,
};
use tracing::{info, error, warn};
use tracing_subscriber::EnvFilter;

/// Default configuration file path
const DEFAULT_CONFIG_PATH: &str = "/etc/awdl/daemon.conf";

/// Default PID file path
const DEFAULT_PID_PATH: &str = "/var/run/awdl.pid";

/// Default log level
const DEFAULT_LOG_LEVEL: &str = "info";

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("awdl-daemon")
        .version(env!("CARGO_PKG_VERSION"))
        .author("AWDL Rust Implementation")
        .about("Apple Wireless Direct Link (AWDL) Protocol Daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value(DEFAULT_CONFIG_PATH)
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as daemon (background process)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("pid-file")
                .short('p')
                .long("pid-file")
                .value_name("FILE")
                .help("PID file path")
                .default_value(DEFAULT_PID_PATH)
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value(DEFAULT_LOG_LEVEL)
        )
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to use")
        )
        .arg(
            Arg::new("no-fork")
                .long("no-fork")
                .help("Don't fork into background (for debugging)")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    init_logging(log_level)?;

    info!("Starting AWDL Daemon v{}", env!("CARGO_PKG_VERSION"));

    // Check if running as root (required for raw sockets)
    if !DaemonUtils::is_privileged() {
        error!("AWDL daemon requires root privileges for raw socket access");
        process::exit(1);
    }

    // Get configuration file path
    let config_path = PathBuf::from(matches.get_one::<String>("config").unwrap());
    let pid_file = PathBuf::from(matches.get_one::<String>("pid-file").unwrap());
    let daemon_mode = matches.get_flag("daemon") && !matches.get_flag("no-fork");
    let interface = matches.get_one::<String>("interface").map(|s| s.clone());

    // Load configuration
    let mut config = load_configuration(&config_path).await?;
    
    // Override interface if specified
    if let Some(iface) = interface {
        config.io.interface = iface;
    }

    // Check if daemon is already running
    if DaemonUtils::is_daemon_running(&pid_file)? {
        error!("AWDL daemon is already running (PID file exists: {})", pid_file.display());
        process::exit(1);
    }

    // Daemonize if requested
    if daemon_mode {
        info!("Forking into background...");
        // Note: Daemonization would be implemented here for production use
        // For now, we'll run in foreground mode
    }

    // Create PID file
    DaemonUtils::create_pid_file(&pid_file)?;

    // Setup signal handlers
    let shutdown_signal = setup_signal_handlers().await;

    // Build and start daemon
    let result = run_daemon(config, shutdown_signal).await;

    // Cleanup
    if let Err(e) = DaemonUtils::remove_pid_file(&pid_file) {
        warn!("Failed to remove PID file: {}", e);
    }

    match result {
        Ok(_) => {
            info!("AWDL daemon shutdown complete");
            Ok(())
        }
        Err(e) => {
            error!("AWDL daemon error: {}", e);
            process::exit(1);
        }
    }
}

/// Initialize logging system
fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level)
        .map_err(|e| AwdlError::Config(format!("Invalid log level '{}': {}", level, e)))?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    Ok(())
}

/// Load daemon configuration from file
async fn load_configuration(config_path: &PathBuf) -> Result<DaemonConfig> {
    if !config_path.exists() {
        warn!("Configuration file not found: {}, using defaults", config_path.display());
        return Ok(DaemonConfig::default());
    }

    info!("Loading configuration from: {}", config_path.display());
    
    // For now, return default config
    // TODO: Implement actual config file parsing
    Ok(DaemonConfig::default())
}

/// Setup signal handlers for graceful shutdown
async fn setup_signal_handlers() -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            
            let mut sigterm = signal(SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt())
                .expect("Failed to register SIGINT handler");
            let mut sighup = signal(SignalKind::hangup())
                .expect("Failed to register SIGHUP handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating graceful shutdown");
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP, reloading configuration");
                    // TODO: Implement config reload
                }
            }
        }
        
        #[cfg(windows)]
        {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        
        let _ = tx.send(());
    });
    
    rx
}

/// Run the main daemon loop
async fn run_daemon(
    config: DaemonConfig,
    shutdown_signal: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    info!("Initializing AWDL daemon components...");

    // Build daemon using the builder pattern
    let mut daemon = DaemonBuilder::new()
        .with_config(config)
        .with_interface(None) // Will use config interface
        .build()
        .await?;

    info!("Starting AWDL daemon...");
    
    // Start the daemon
    daemon.start().await?;
    
    info!("AWDL daemon started successfully");
    
    // Wait for shutdown signal
    let _ = shutdown_signal.await;
    
    info!("Shutdown signal received, stopping daemon...");
    
    // Stop the daemon gracefully
    daemon.stop().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/awdl/daemon.conf");
        assert_eq!(DEFAULT_PID_PATH, "/var/run/awdl.pid");
        assert_eq!(DEFAULT_LOG_LEVEL, "info");
    }
    
    #[tokio::test]
    async fn test_load_nonexistent_config() {
        let path = PathBuf::from("/nonexistent/config.conf");
        let config = load_configuration(&path).await.unwrap();
        // Should return default config
        assert_eq!(config.general.node_name, "awdl-node");
    }
}
