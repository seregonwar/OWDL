//! Nexus802 Daemon
//! 
//! Main daemon process that manages PHY backends and provides frame access
//! to client applications via IPC.

use clap::{Arg, Command};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use nexus802::{
    config::Nexus802Config,
    phy::{PhyBackend, MonitorModeType, ChannelConfig},
    Nexus802Error, Result,
};

#[cfg(feature = "bridge-wsl2")]
use nexus802::bridge::BridgeBackend;

/// Main daemon state
struct DaemonState {
    config: Nexus802Config,
    phy_backend: Option<Box<dyn PhyBackend>>,
    running: bool,
}

impl DaemonState {
    fn new(config: Nexus802Config) -> Self {
        Self {
            config,
            phy_backend: None,
            running: false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("nexus802-daemon")
        .version(nexus802::VERSION)
        .about("Nexus802 Multi-Tier IEEE 802.11 Protocol Daemon")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("nexus802.toml"),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info"),
        )
        .arg(
            Arg::new("backend")
                .short('b')
                .long("backend")
                .value_name("BACKEND")
                .help("Force specific backend (bridge-wsl2, vendor-commview, ndis-filter)")
        )
        .arg(
            Arg::new("channel")
                .long("channel")
                .value_name("CHANNEL")
                .help("Initial channel (1-14 for 2.4GHz)")
        )
        .get_matches();

    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    init_logging(log_level)?;

    info!("Starting Nexus802 daemon v{}", nexus802::VERSION);

    // Load configuration
    let config_path = matches.get_one::<String>("config").unwrap();
    let mut config = load_config(config_path).await?;

    // Override backend if specified
    if let Some(backend) = matches.get_one::<String>("backend") {
        config.phy.preferred_backend = backend.clone();
    }

    // Override channel if specified
    if let Some(channel_str) = matches.get_one::<String>("channel") {
        if let Ok(channel) = channel_str.parse::<u16>() {
            if (1..=14).contains(&channel) {
                config.phy.default_channel.primary = channel;
                config.phy.default_channel.center_freq = 2412 + (channel - 1) * 5;
            }
        }
    }

    // Initialize daemon state
    let state = Arc::new(RwLock::new(DaemonState::new(config)));

    // Initialize PHY backend
    initialize_phy_backend(&state).await?;

    // Start main daemon loop
    run_daemon(state).await?;

    info!("Nexus802 daemon shutdown complete");
    Ok(())
}

/// Initialize logging subsystem
fn init_logging(level: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level_filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    Ok(())
}

/// Load configuration from file
async fn load_config(config_path: &str) -> Result<Nexus802Config> {
    let path = PathBuf::from(config_path);
    
    if path.exists() {
        info!("Loading configuration from: {}", config_path);
        Nexus802Config::from_file(&path)
    } else {
        warn!("Configuration file not found, using defaults: {}", config_path);
        let config = Nexus802Config::default();
        
        // Save default configuration
        if let Err(e) = config.to_file(&path) {
            warn!("Failed to save default configuration: {}", e);
        } else {
            info!("Saved default configuration to: {}", config_path);
        }
        
        Ok(config)
    }
}

/// Initialize PHY backend based on configuration
async fn initialize_phy_backend(state: &Arc<RwLock<DaemonState>>) -> Result<()> {
    let config = {
        let state_guard = state.read().await;
        state_guard.config.clone()
    };

    let backends = config.backend_priority();
    
    for backend_name in backends {
        info!("Attempting to initialize backend: {}", backend_name);
        
        match create_backend(&backend_name, &config).await {
            Ok(mut backend) => {
                match backend.initialize().await {
                    Ok(()) => {
                        info!("Successfully initialized backend: {}", backend_name);
                        
                        // Get capabilities
                        match backend.capabilities().await {
                            Ok(caps) => {
                                info!("Backend capabilities: monitor={}, injection={}, channels={}",
                                      caps.monitor_mode, caps.frame_injection, caps.supported_channels.len());
                            }
                            Err(e) => {
                                warn!("Failed to get backend capabilities: {}", e);
                            }
                        }
                        
                        // Store backend
                        {
                            let mut state_guard = state.write().await;
                            state_guard.phy_backend = Some(backend);
                        }
                        
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to initialize backend {}: {}", backend_name, e);
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create backend {}: {}", backend_name, e);
                continue;
            }
        }
    }
    
    Err(Nexus802Error::Config {
        message: "No PHY backend could be initialized".to_string(),
    })
}

/// Create a PHY backend instance
async fn create_backend(
    backend_name: &str,
    config: &Nexus802Config,
) -> Result<Box<dyn PhyBackend>> {
    match backend_name {
        #[cfg(feature = "bridge-wsl2")]
        "bridge-wsl2" => {
            if let Some(ref bridge_config) = config.bridge {
                let backend = BridgeBackend::new(bridge_config.clone());
                Ok(Box::new(backend))
            } else {
                Err(Nexus802Error::Config {
                    message: "Bridge configuration not found".to_string(),
                })
            }
        }
        
        #[cfg(feature = "vendor-commview")]
        "vendor-commview" => {
            // TODO: Implement CommView backend
            Err(Nexus802Error::NotSupported)
        }
        
        #[cfg(feature = "ndis-filter")]
        "ndis-filter" => {
            // TODO: Implement NDIS filter backend
            Err(Nexus802Error::NotSupported)
        }
        
        _ => Err(Nexus802Error::Config {
            message: format!("Unknown backend: {}", backend_name),
        }),
    }
}

/// Main daemon loop
async fn run_daemon(state: Arc<RwLock<DaemonState>>) -> Result<()> {
    info!("Starting daemon main loop");
    
    // Mark daemon as running
    {
        let mut state_guard = state.write().await;
        state_guard.running = true;
    }
    
    // Enable monitor mode
    if let Err(e) = enable_monitor_mode(&state).await {
        error!("Failed to enable monitor mode: {}", e);
        return Err(e);
    }
    
    // Set initial channel
    if let Err(e) = set_initial_channel(&state).await {
        warn!("Failed to set initial channel: {}", e);
    }
    
    // Start frame processing task
    let state_clone = Arc::clone(&state);
    let frame_task = tokio::spawn(async move {
        frame_processing_loop(state_clone).await;
    });
    
    // Start statistics reporting task
    let state_clone = Arc::clone(&state);
    let stats_task = tokio::spawn(async move {
        statistics_loop(state_clone).await;
    });
    
    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
        _ = frame_task => {
            warn!("Frame processing task exited");
        }
        _ = stats_task => {
            warn!("Statistics task exited");
        }
    }
    
    // Shutdown
    shutdown_daemon(&state).await?;
    
    Ok(())
}

/// Enable monitor mode on the PHY backend
async fn enable_monitor_mode(state: &Arc<RwLock<DaemonState>>) -> Result<()> {
    // Read preferred monitor mode without holding a mutable borrow
    let monitor_mode = {
        let state_guard = state.read().await;
        state_guard.config.phy.preferred_monitor_mode
    };

    // Now get mutable access only to the backend and invoke the call
    let mut state_guard = state.write().await;
    if let Some(ref mut backend) = state_guard.phy_backend {
        info!("Enabling monitor mode: {:?}", monitor_mode);
        backend.enable_monitor_mode(monitor_mode).await?;
        info!("Monitor mode enabled successfully");
    }

    Ok(())
}

/// Set initial channel configuration
async fn set_initial_channel(state: &Arc<RwLock<DaemonState>>) -> Result<()> {
    // Clone channel config under a read lock first
    let channel = {
        let state_guard = state.read().await;
        state_guard.config.phy.default_channel.clone()
    };

    // Then acquire write lock to access backend mutably
    let mut state_guard = state.write().await;
    if let Some(ref mut backend) = state_guard.phy_backend {
        info!("Setting initial channel: {:?}", channel);
        backend.set_channel(channel).await?;
        info!("Channel set successfully");
    }

    Ok(())
}

/// Frame processing loop
async fn frame_processing_loop(state: Arc<RwLock<DaemonState>>) {
    info!("Starting frame processing loop");
    
    let mut frame_count = 0u64;
    let mut last_stats_time = std::time::Instant::now();
    
    loop {
        let running = {
            let state_guard = state.read().await;
            state_guard.running
        };
        
        if !running {
            break;
        }
        
        // Try to receive a frame
        let frame_result = {
            let mut state_guard = state.write().await;
            if let Some(ref mut backend) = state_guard.phy_backend {
                backend.recv_frame_timeout(std::time::Duration::from_millis(100)).await
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        
        match frame_result {
            Ok(Some((frame_data, metadata))) => {
                frame_count += 1;
                
                // Process frame (simplified)
                if frame_count % 1000 == 0 {
                    info!("Processed {} frames, latest: {} bytes from {:?} on {}MHz",
                          frame_count, frame_data.len(), metadata.source_type, metadata.frequency);
                }
                
                // TODO: Forward frame to clients via IPC
            }
            Ok(None) => {
                // No frame available, continue
            }
            Err(e) => {
                match e {
                    nexus802::phy::PhyError::Timeout => {
                        // Normal timeout, continue
                    }
                    _ => {
                        error!("Frame reception error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        
        // Print periodic statistics
        if last_stats_time.elapsed() >= std::time::Duration::from_secs(60) {
            info!("Frame processing stats: {} frames processed", frame_count);
            last_stats_time = std::time::Instant::now();
        }
    }
    
    info!("Frame processing loop exited");
}

/// Statistics reporting loop
async fn statistics_loop(state: Arc<RwLock<DaemonState>>) {
    info!("Starting statistics loop");
    
    loop {
        let running = {
            let state_guard = state.read().await;
            state_guard.running
        };
        
        if !running {
            break;
        }
        
        // Get and log statistics
        let stats_result = {
            let state_guard = state.read().await;
            if let Some(ref backend) = state_guard.phy_backend {
                backend.get_statistics().await
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
        };
        
        match stats_result {
            Ok(stats) => {
                info!("PHY Stats: RX={} frames ({} bytes), TX={} frames ({} bytes), dropped={}, fps={:.1}",
                      stats.frames_received, stats.bytes_received,
                      stats.frames_transmitted, stats.bytes_transmitted,
                      stats.frames_dropped, stats.avg_fps);
            }
            Err(e) => {
                warn!("Failed to get statistics: {}", e);
            }
        }
        
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
    
    info!("Statistics loop exited");
}

/// Shutdown daemon gracefully
async fn shutdown_daemon(state: &Arc<RwLock<DaemonState>>) -> Result<()> {
    info!("Shutting down daemon...");
    
    let mut state_guard = state.write().await;
    state_guard.running = false;
    
    if let Some(ref mut backend) = state_guard.phy_backend {
        info!("Disabling monitor mode...");
        if let Err(e) = backend.disable_monitor_mode().await {
            warn!("Failed to disable monitor mode: {}", e);
        }
        
        info!("Shutting down PHY backend...");
        if let Err(e) = backend.shutdown().await {
            warn!("Failed to shutdown PHY backend: {}", e);
        }
    }
    
    info!("Daemon shutdown complete");
    Ok(())
}
