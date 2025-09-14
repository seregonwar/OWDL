//! Nexus802 CLI Tool
//! 
//! Command-line interface for interacting with the Nexus802 daemon
//! and testing PHY backend functionality.

use clap::{Arg, Command};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;

use nexus802::{
    config::Nexus802Config,
    phy::{ChannelConfig, MonitorModeType, PhyBackend},
    Result,
};

#[cfg(feature = "bridge-wsl2")]
use nexus802::bridge::BridgeBackend;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("nexus802-cli")
        .version(nexus802::VERSION)
        .about("Nexus802 CLI Tool")
        .subcommand(
            Command::new("test")
                .about("Test PHY backend functionality")
                .arg(
                    Arg::new("backend")
                        .short('b')
                        .long("backend")
                        .value_name("BACKEND")
                        .help("Backend to test")
                        .default_value("bridge-wsl2"),
                )
                .arg(
                    Arg::new("channel")
                        .short('c')
                        .long("channel")
                        .value_name("CHANNEL")
                        .help("Channel to use (1-14)")
                        .default_value("6"),
                )
                .arg(
                    Arg::new("duration")
                        .short('d')
                        .long("duration")
                        .value_name("SECONDS")
                        .help("Test duration in seconds")
                        .default_value("10"),
                ),
        )
        .subcommand(
            Command::new("scan")
                .about("Scan for available networks")
                .arg(
                    Arg::new("backend")
                        .short('b')
                        .long("backend")
                        .value_name("BACKEND")
                        .help("Backend to use")
                        .default_value("bridge-wsl2"),
                )
                .arg(
                    Arg::new("channels")
                        .short('c')
                        .long("channels")
                        .value_name("CHANNELS")
                        .help("Channels to scan (comma-separated)")
                        .default_value("1,6,11"),
                ),
        )
        .subcommand(
            Command::new("config")
                .about("Configuration management")
                .subcommand(
                    Command::new("generate")
                        .about("Generate default configuration file")
                        .arg(
                            Arg::new("output")
                                .short('o')
                                .long("output")
                                .value_name("FILE")
                                .help("Output file path")
                                .default_value("nexus802.toml"),
                        ),
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate configuration file")
                        .arg(
                            Arg::new("config")
                                .short('c')
                                .long("config")
                                .value_name("FILE")
                                .help("Configuration file to validate")
                                .required(true),
                        ),
                ),
        )
        .get_matches();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    match matches.subcommand() {
        Some(("test", sub_matches)) => {
            let backend_name = sub_matches.get_one::<String>("backend").unwrap();
            let channel: u16 = sub_matches.get_one::<String>("channel").unwrap().parse().unwrap_or(6);
            let duration: u64 = sub_matches.get_one::<String>("duration").unwrap().parse().unwrap_or(10);
            
            run_backend_test(backend_name, channel, duration).await?;
        }
        Some(("scan", sub_matches)) => {
            let backend_name = sub_matches.get_one::<String>("backend").unwrap();
            let channels_str = sub_matches.get_one::<String>("channels").unwrap();
            let channels: Vec<u16> = channels_str
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            
            run_network_scan(backend_name, &channels).await?;
        }
        Some(("config", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("generate", gen_matches)) => {
                    let output = gen_matches.get_one::<String>("output").unwrap();
                    generate_config(output).await?;
                }
                Some(("validate", val_matches)) => {
                    let config_path = val_matches.get_one::<String>("config").unwrap();
                    validate_config(config_path).await?;
                }
                _ => {
                    println!("Use 'nexus802-cli config --help' for usage information");
                }
            }
        }
        _ => {
            println!("Use 'nexus802-cli --help' for usage information");
        }
    }

    Ok(())
}

/// Run PHY backend test
async fn run_backend_test(backend_name: &str, channel: u16, duration_secs: u64) -> Result<()> {
    println!("Testing backend: {} on channel {} for {} seconds", backend_name, channel, duration_secs);
    
    // Create backend
    let mut backend = create_test_backend(backend_name).await?;
    
    // Initialize backend
    println!("Initializing backend...");
    backend.initialize().await?;
    
    // Get capabilities
    let caps = backend.capabilities().await?;
    println!("Backend capabilities:");
    println!("  Monitor mode: {}", caps.monitor_mode);
    println!("  Frame injection: {}", caps.frame_injection);
    println!("  Channel switching: {}", caps.channel_switching);
    println!("  Hardware timestamps: {}", caps.hardware_timestamps);
    println!("  Supported channels: {} channels", caps.supported_channels.len());
    
    // Enable monitor mode
    if caps.monitor_mode {
        println!("Enabling monitor mode...");
        let monitor_mode = caps.best_monitor_mode().unwrap_or(MonitorModeType::Bridge);
        backend.enable_monitor_mode(monitor_mode).await?;
    }
    
    // Set channel
    if caps.channel_switching {
        let channel_config = ChannelConfig {
            primary: channel,
            width: 20,
            center_freq: 2412 + (channel - 1) * 5,
            secondary_offset: None,
        };
        println!("Setting channel to {}...", channel);
        backend.set_channel(channel_config).await?;
    }
    
    // Receive frames for specified duration
    println!("Receiving frames for {} seconds...", duration_secs);
    let start_time = std::time::Instant::now();
    let mut frame_count = 0u64;
    let mut total_bytes = 0u64;
    
    while start_time.elapsed().as_secs() < duration_secs {
        match timeout(Duration::from_millis(1000), backend.recv_frame()).await {
            Ok(Ok(Some((frame_data, metadata)))) => {
                frame_count += 1;
                total_bytes += frame_data.len() as u64;
                
                if frame_count % 100 == 0 {
                    println!("  Received {} frames ({} bytes total)", frame_count, total_bytes);
                }
                
                // Print details for first few frames
                if frame_count <= 5 {
                    println!("  Frame {}: {} bytes, {}MHz, source={:?}, signal={:?}dBm",
                             frame_count, frame_data.len(), metadata.frequency, 
                             metadata.source_type, metadata.signal_dbm);
                }
            }
            Ok(Ok(None)) => {
                // No frame available
            }
            Ok(Err(e)) => {
                println!("  Frame reception error: {}", e);
            }
            Err(_) => {
                // Timeout - normal
            }
        }
    }
    
    // Print final statistics
    println!("Test completed:");
    println!("  Total frames: {}", frame_count);
    println!("  Total bytes: {}", total_bytes);
    println!("  Average rate: {:.1} frames/sec", frame_count as f64 / duration_secs as f64);
    
    if frame_count > 0 {
        println!("  Average frame size: {:.1} bytes", total_bytes as f64 / frame_count as f64);
    }
    
    // Get final statistics from backend
    match backend.get_statistics().await {
        Ok(stats) => {
            println!("Backend statistics:");
            println!("  Frames received: {}", stats.frames_received);
            println!("  Bytes received: {}", stats.bytes_received);
            println!("  Frames dropped: {}", stats.frames_dropped);
            println!("  Average FPS: {:.1}", stats.avg_fps);
        }
        Err(e) => {
            println!("Failed to get backend statistics: {}", e);
        }
    }
    
    // Cleanup
    if caps.monitor_mode {
        println!("Disabling monitor mode...");
        backend.disable_monitor_mode().await?;
    }
    
    println!("Shutting down backend...");
    backend.shutdown().await?;
    
    println!("Test completed successfully!");
    Ok(())
}

/// Run network scanning
async fn run_network_scan(backend_name: &str, channels: &[u16]) -> Result<()> {
    println!("Scanning for networks on channels: {:?}", channels);
    
    // Create backend
    let mut backend = create_test_backend(backend_name).await?;
    
    // Initialize backend
    backend.initialize().await?;
    
    // Enable monitor mode
    let caps = backend.capabilities().await?;
    if caps.monitor_mode {
        let monitor_mode = caps.best_monitor_mode().unwrap_or(MonitorModeType::Bridge);
        backend.enable_monitor_mode(monitor_mode).await?;
    }
    
    let mut networks = std::collections::HashMap::new();
    
    for &channel in channels {
        println!("Scanning channel {}...", channel);
        
        // Set channel
        let channel_config = ChannelConfig {
            primary: channel,
            width: 20,
            center_freq: 2412 + (channel - 1) * 5,
            secondary_offset: None,
        };
        backend.set_channel(channel_config).await?;
        
        // Scan for 5 seconds per channel
        let scan_start = std::time::Instant::now();
        while scan_start.elapsed().as_secs() < 5 {
            match timeout(Duration::from_millis(100), backend.recv_frame()).await {
                Ok(Ok(Some((frame_data, metadata)))) => {
                    // Parse frame to look for beacons and probe responses
                    if let Ok(frame) = nexus802::frame::Frame802_11::new(
                        bytes::Bytes::copy_from_slice(&frame_data), 
                        metadata
                    ) {
                        if frame.is_beacon() || frame.is_probe_response() {
                            if let Some(bssid) = frame.info.bssid {
                                let key = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                                
                                let entry = networks.entry(key.clone()).or_insert_with(|| {
                                    NetworkInfo {
                                        bssid: key,
                                        channel,
                                        signal_dbm: frame.metadata.signal_dbm,
                                        frame_count: 0,
                                    }
                                });
                                
                                entry.frame_count += 1;
                                if let Some(signal) = frame.metadata.signal_dbm {
                                    if entry.signal_dbm.is_none() || entry.signal_dbm.unwrap() < signal {
                                        entry.signal_dbm = Some(signal);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    // Print results
    println!("\nScan results:");
    println!("{:<20} {:<8} {:<10} {:<10}", "BSSID", "Channel", "Signal", "Frames");
    println!("{}", "-".repeat(50));
    
    let mut sorted_networks: Vec<_> = networks.values().collect();
    sorted_networks.sort_by(|a, b| {
        b.signal_dbm.unwrap_or(-100).cmp(&a.signal_dbm.unwrap_or(-100))
    });
    
    for network in sorted_networks {
        println!("{:<20} {:<8} {:<10} {:<10}",
                 network.bssid,
                 network.channel,
                 network.signal_dbm.map_or("N/A".to_string(), |s| format!("{}dBm", s)),
                 network.frame_count);
    }
    
    println!("\nFound {} networks", networks.len());
    
    // Cleanup
    backend.disable_monitor_mode().await?;
    backend.shutdown().await?;
    
    Ok(())
}

#[derive(Debug)]
struct NetworkInfo {
    bssid: String,
    channel: u16,
    signal_dbm: Option<i8>,
    frame_count: u32,
}

/// Generate default configuration file
async fn generate_config(output_path: &str) -> Result<()> {
    println!("Generating default configuration: {}", output_path);
    
    let config = Nexus802Config::default();
    config.to_file(output_path)?;
    
    println!("Configuration file generated successfully!");
    println!("Edit the file to customize settings for your environment.");
    
    Ok(())
}

/// Validate configuration file
async fn validate_config(config_path: &str) -> Result<()> {
    println!("Validating configuration: {}", config_path);
    
    match Nexus802Config::from_file(config_path) {
        Ok(config) => {
            println!("Configuration is valid!");
            println!("  Preferred backend: {}", config.phy.preferred_backend);
            println!("  Fallback backends: {:?}", config.phy.fallback_backends);
            println!("  Default channel: {}", config.phy.default_channel.primary);
            println!("  Auto-configure: {}", config.phy.auto_configure);
        }
        Err(e) => {
            println!("Configuration validation failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

/// Create a test backend instance
async fn create_test_backend(backend_name: &str) -> Result<Box<dyn PhyBackend>> {
    match backend_name {
        #[cfg(feature = "bridge-wsl2")]
        "bridge-wsl2" => {
            let config = nexus802::config::BridgeConfig {
                wsl_distribution: "Ubuntu".to_string(),
                bridge_executable: "/usr/local/bin/nexus802-bridge".to_string(),
                shared_memory_size: 64 * 1024 * 1024,
                control_pipe_name: "\\\\.\\pipe\\nexus802-control".to_string(),
                rx_pipe_name: "\\\\.\\pipe\\nexus802-rx".to_string(),
                tx_pipe_name: "\\\\.\\pipe\\nexus802-tx".to_string(),
                timeout_seconds: 30,
                use_shared_memory: true,
            };
            
            let backend = BridgeBackend::new(config);
            Ok(Box::new(backend))
        }
        
        _ => Err(nexus802::Nexus802Error::Config {
            message: format!("Unknown backend: {}", backend_name),
        }),
    }
}
