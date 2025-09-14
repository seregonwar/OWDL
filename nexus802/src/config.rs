//! Configuration management for Nexus802

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::phy::{ChannelConfig, MonitorModeType};

/// Main configuration for Nexus802
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nexus802Config {
    /// General settings
    pub general: GeneralConfig,
    /// PHY backend configuration
    pub phy: PhyConfig,
    /// Bridge configuration (if using WSL2 bridge)
    pub bridge: Option<BridgeConfig>,
    /// Vendor driver configurations
    pub vendor: Option<VendorConfig>,
    /// NDIS filter configuration
    pub ndis: Option<NdisConfig>,
    /// Performance and monitoring settings
    pub performance: PerformanceConfig,
    /// Security settings
    pub security: SecurityConfig,
}

/// General configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Enable performance monitoring
    pub enable_monitoring: bool,
    /// Configuration file version
    pub version: String,
}

/// PHY backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhyConfig {
    /// Preferred backend type
    pub preferred_backend: String,
    /// Fallback backends in order of preference
    pub fallback_backends: Vec<String>,
    /// Auto-configuration enabled
    pub auto_configure: bool,
    /// Default channel configuration
    pub default_channel: ChannelConfig,
    /// Preferred monitor mode
    pub preferred_monitor_mode: MonitorModeType,
    /// Enable automatic fallback
    pub auto_fallback: bool,
    /// Fallback threshold (frames/sec)
    pub fallback_threshold: u32,
    /// Retry interval in seconds
    pub retry_interval: u32,
}

/// WSL2 Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// WSL2 distribution name
    pub wsl_distribution: String,
    /// Bridge executable path in WSL2
    pub bridge_executable: String,
    /// Shared memory size in bytes
    pub shared_memory_size: usize,
    /// Named pipe name for control channel
    pub control_pipe_name: String,
    /// Data pipe names
    pub rx_pipe_name: String,
    pub tx_pipe_name: String,
    /// Bridge timeout in seconds
    pub timeout_seconds: u32,
    /// Enable shared memory optimization
    pub use_shared_memory: bool,
}

/// Vendor driver configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorConfig {
    /// CommView configuration
    pub commview: Option<CommViewConfig>,
    /// Acrylic WiFi configuration
    pub acrylic: Option<AcrylicConfig>,
    /// OmniPeek configuration
    pub omnipeek: Option<OmniPeekConfig>,
}

/// CommView for WiFi configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommViewConfig {
    /// Path to CommView DLL
    pub dll_path: PathBuf,
    /// Device name or index
    pub device: String,
    /// Enable promiscuous mode
    pub promiscuous: bool,
    /// Buffer size in MB
    pub buffer_size_mb: u32,
}

/// Acrylic WiFi configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcrylicConfig {
    /// Path to Acrylic API DLL
    pub dll_path: PathBuf,
    /// Adapter GUID
    pub adapter_guid: String,
    /// Capture mode
    pub capture_mode: String,
}

/// OmniPeek configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniPeekConfig {
    /// Path to OmniPeek SDK
    pub sdk_path: PathBuf,
    /// Adapter name
    pub adapter_name: String,
    /// Capture filter
    pub capture_filter: Option<String>,
}

/// NDIS filter driver configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdisConfig {
    /// Driver service name
    pub service_name: String,
    /// Device symbolic link
    pub device_link: String,
    /// Shared memory section name
    pub shared_section_name: String,
    /// Ring buffer size
    pub ring_buffer_size: usize,
    /// Enable HVCI compatibility mode
    pub hvci_compatible: bool,
}

/// Performance and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Ring buffer size for frame processing
    pub ring_buffer_size: usize,
    /// Number of worker threads
    pub worker_threads: Option<usize>,
    /// Enable NUMA awareness
    pub numa_aware: bool,
    /// Statistics collection interval in seconds
    pub stats_interval_seconds: u32,
    /// Memory pool sizes
    pub memory_pools: MemoryPoolConfig,
}

/// Memory pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPoolConfig {
    /// Small frame pool size (< 256 bytes)
    pub small_frame_pool: usize,
    /// Medium frame pool size (256-1500 bytes)
    pub medium_frame_pool: usize,
    /// Large frame pool size (> 1500 bytes)
    pub large_frame_pool: usize,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require driver signature verification
    pub require_signed_drivers: bool,
    /// Allow test certificates
    pub allow_test_certificates: bool,
    /// Require EV certificates
    pub require_ev_certificates: bool,
    /// Enable code integrity checks
    pub enable_code_integrity: bool,
    /// Trusted certificate store path
    pub trusted_cert_store: Option<PathBuf>,
}

impl Default for Nexus802Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                log_level: "info".to_string(),
                enable_monitoring: true,
                version: crate::VERSION.to_string(),
            },
            phy: PhyConfig {
                preferred_backend: "bridge-wsl2".to_string(),
                fallback_backends: vec![
                    "vendor-commview".to_string(),
                    "vendor-acrylic".to_string(),
                    "ndis-filter".to_string(),
                ],
                auto_configure: true,
                default_channel: ChannelConfig {
                    primary: 6,
                    width: 20,
                    center_freq: 2437,
                    secondary_offset: None,
                },
                preferred_monitor_mode: MonitorModeType::WdiRaw,
                auto_fallback: true,
                fallback_threshold: 100,
                retry_interval: 30,
            },
            bridge: Some(BridgeConfig {
                wsl_distribution: "Ubuntu".to_string(),
                bridge_executable: "/usr/local/bin/nexus802-bridge".to_string(),
                shared_memory_size: 64 * 1024 * 1024, // 64MB
                control_pipe_name: "\\\\.\\pipe\\nexus802-control".to_string(),
                rx_pipe_name: "\\\\.\\pipe\\nexus802-rx".to_string(),
                tx_pipe_name: "\\\\.\\pipe\\nexus802-tx".to_string(),
                timeout_seconds: 30,
                use_shared_memory: true,
            }),
            vendor: Some(VendorConfig {
                commview: None,
                acrylic: None,
                omnipeek: None,
            }),
            ndis: Some(NdisConfig {
                service_name: "Nexus802Filter".to_string(),
                device_link: "\\\\.\\Nexus802Phy".to_string(),
                shared_section_name: "Nexus802SharedSection".to_string(),
                ring_buffer_size: crate::DEFAULT_RING_SIZE,
                hvci_compatible: true,
            }),
            performance: PerformanceConfig {
                ring_buffer_size: crate::DEFAULT_RING_SIZE,
                worker_threads: None, // Auto-detect
                numa_aware: true,
                stats_interval_seconds: 60,
                memory_pools: MemoryPoolConfig {
                    small_frame_pool: 512,
                    medium_frame_pool: 256,
                    large_frame_pool: 64,
                },
            },
            security: SecurityConfig {
                require_signed_drivers: true,
                allow_test_certificates: false,
                require_ev_certificates: false,
                enable_code_integrity: true,
                trusted_cert_store: None,
            },
        }
    }
}

impl Nexus802Config {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| crate::Nexus802Error::Config { 
                message: format!("Failed to parse config: {}", e) 
            })?;
        Ok(config)
    }
    
    /// Save configuration to TOML file
    pub fn to_file<P: AsRef<std::path::Path>>(&self, path: P) -> crate::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::Nexus802Error::Config { 
                message: format!("Failed to serialize config: {}", e) 
            })?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Get the ordered list of backends to try
    pub fn backend_priority(&self) -> Vec<String> {
        let mut backends = vec![self.phy.preferred_backend.clone()];
        backends.extend(self.phy.fallback_backends.iter().cloned());
        backends.dedup();
        backends
    }
}
