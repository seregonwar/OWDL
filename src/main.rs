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
use tokio::net::UdpSocket;
use pcap::Device;

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
        .arg(
            Arg::new("raw")
                .long("raw")
                .help("Enable raw 802.11 capture/injection mode (Npcap on Windows)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("commview")
                .long("commview")
                .help("Use CommView for WiFi backend on Windows (requires building with --features commview)")
                .action(clap::ArgAction::SetTrue)
        )
        .subcommand(
            Command::new("udp-test")
                .about("Send a UDP test packet to the AWDL daemon (useful on Windows for testing I/O and event wiring)")
                .arg(
                    Arg::new("dest")
                        .long("dest")
                        .value_name("HOST")
                        .help("Destination host/IP for the UDP test packet")
                        .default_value("127.0.0.1")
                )
                .arg(
                    Arg::new("port")
                        .long("port")
                        .value_name("PORT")
                        .help("Destination UDP port for the test packet")
                        .value_parser(clap::value_parser!(u16))
                        .default_value("6363")
                )
                .arg(
                    Arg::new("message")
                        .long("message")
                        .value_name("MSG")
                        .help("Message payload to send in the test packet")
                        .default_value("awdl-test")
                )
        )
        .subcommand(
            Command::new("devlist")
                .about("List available pcap/Npcap devices (Windows: use one of these with --interface)")
                .arg(
                    Arg::new("show-datalink")
                        .long("show-datalink")
                        .help("Attempt to open each device to print datalink (may require Administrator)")
                        .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("cv-devlist")
                .about("List CommView adapters (requires build with --features commview)")
        )
        .get_matches();

    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    init_logging(log_level)?;

    info!("Starting AWDL Daemon v{}", env!("CARGO_PKG_VERSION"));

    // Handle subcommands first
    if let Some((sub, sub_m)) = matches.subcommand() {
        if sub == "udp-test" {
            let dest = sub_m.get_one::<String>("dest").cloned().unwrap();
            let port = *sub_m.get_one::<u16>("port").unwrap_or(&6363u16);
            let msg = sub_m.get_one::<String>("message").cloned().unwrap();

            let addr = format!("{}:{}", dest, port);
            info!("Sending UDP test packet to {}...", addr);

            let sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await
                .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to bind UDP socket: {}", e))))?;
            let sent = sock.send_to(msg.as_bytes(), &addr).await
                .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to send UDP packet: {}", e))))?;

            info!("UDP test packet sent ({} bytes) to {}", sent, addr);
            return Ok(());
        } else if sub == "devlist" {
            let show_datalink = sub_m.get_flag("show-datalink");
            let devices = Device::list()
                .map_err(|e| AwdlError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to list pcap devices: {}", e))))?;
            println!("Found {} device(s):", devices.len());
            for dev in devices {
                let name = dev.name;
                let desc = dev.desc.unwrap_or_default();
                if show_datalink {
                    // Best-effort: try open to get datalink
                    match pcap::Capture::from_device(name.as_str()).and_then(|c| c.timeout(1).open()) {
                        Ok(cap) => {
                            println!("- {} : {} | datalink={:?}", name, desc, cap.get_datalink());
                        }
                        Err(e) => {
                            println!("- {} : {} | datalink=<unavailable> ({})", name, desc, e);
                        }
                    }
                } else {
                    println!("- {} : {}", name, desc);
                }
            }
            return Ok(());
        } else if sub == "cv-devlist" {
            if cfg!(feature = "commview") {
                println!("CommView adapter listing is not yet implemented in this build step (stub). Rebuild will add full support.");
            } else {
                println!("CommView feature not enabled. Rebuild with: cargo run --features commview -- cv-devlist");
            }
            return Ok(());
        }
    }

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
    let raw_mode = matches.get_flag("raw");
    let commview_mode = matches.get_flag("commview");

    // Load configuration
    let mut config = load_configuration(&config_path).await?;
    
    // Override interface if specified
    if let Some(iface) = interface {
        config.io.interface = iface;
    }
    // Enable raw mode if requested
    if raw_mode {
        config.io.raw_socket = true;
    }
    // CommView requested
    if commview_mode {
        if cfg!(feature = "commview") {
            warn!("CommView backend requested. Full integration will route raw capture via CommView (to be implemented next)");
        } else {
            error!("CommView backend requested but feature not enabled. Rebuild with: cargo run --features commview -- ...");
            process::exit(1);
        }
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
    // Important: pass IoConfig from loaded config so flags like --raw take effect
    let io_conf = config.io.clone();
    let mut daemon = DaemonBuilder::new()
        .with_config(config)
        .with_io_config(io_conf)
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
