//! AWDL Daemon Configuration module
//!
//! This module handles configuration management for the AWDL daemon.
//! It provides configuration loading, validation, and management.

use crate::{AwdlError, Result};
use crate::daemon::io::IoConfig;
use crate::daemon::event::EventConfig;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;




/// Main daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// General daemon settings
    pub general: GeneralConfig,
    /// I/O configuration
    pub io: IoConfig,
    /// Event system configuration
    pub events: EventConfig,
    /// AWDL protocol configuration
    pub awdl: AwdlProtocolConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

/// General daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Daemon name
    pub name: String,
    /// Daemon version
    pub version: String,
    /// PID file path
    pub pid_file: PathBuf,
    /// Working directory
    pub work_dir: PathBuf,
    /// Run as daemon (background)
    pub daemonize: bool,
    /// User to run as
    pub user: Option<String>,
    /// Group to run as
    pub group: Option<String>,
    /// Enable debug mode
    pub debug: bool,
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval: u64,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Statistics collection interval in milliseconds
    pub stats_interval: u64,
}

/// AWDL protocol specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlProtocolConfig {
    /// Node identifier
    pub node_id: String,
    /// Device name
    pub device_name: String,
    /// Service name
    pub service_name: String,
    /// Enable synchronization
    pub enable_sync: bool,
    /// Enable election
    pub enable_election: bool,
    /// Channel configuration
    pub channels: ChannelConfig,
    /// Peer management
    pub peers: PeerConfig,
    /// Timing parameters
    pub timing: TimingConfig,
}

/// Channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Available channels
    pub available_channels: Vec<u8>,
    /// Default channel
    pub default_channel: u8,
    /// Channel switch interval (ms)
    pub switch_interval: u64,
    /// Channel dwell time (ms)
    pub dwell_time: u64,
    /// Enable channel hopping
    pub enable_hopping: bool,
}

/// Peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Maximum number of peers
    pub max_peers: usize,
    /// Peer timeout (seconds)
    pub peer_timeout: u64,
    /// Peer discovery interval (ms)
    pub discovery_interval: u64,
    /// Enable peer filtering
    pub enable_filtering: bool,
    /// Allowed peer addresses
    pub allowed_peers: Vec<String>,
    /// Blocked peer addresses
    pub blocked_peers: Vec<String>,
}

/// Timing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Availability window (TU - Time Units)
    pub availability_window: u16,
    /// Availability window period (TU)
    pub aw_period: u16,
    /// Action frame period (TU)
    pub action_frame_period: u16,
    /// Synchronization timeout (ms)
    pub sync_timeout: u64,
    /// Election timeout (ms)
    pub election_timeout: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log file path
    pub file: Option<PathBuf>,
    /// Maximum log file size (bytes)
    pub max_size: u64,
    /// Number of log files to keep
    pub max_files: u32,
    /// Enable console logging
    pub console: bool,
    /// Enable syslog
    pub syslog: bool,
    /// Log format (json, text)
    pub format: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable encryption
    pub enable_encryption: bool,
    /// Encryption algorithm
    pub encryption_algorithm: String,
    /// Key file path
    pub key_file: Option<PathBuf>,
    /// Certificate file path
    pub cert_file: Option<PathBuf>,
    /// Enable authentication
    pub enable_auth: bool,
    /// Authentication method
    pub auth_method: String,
    /// Enable access control
    pub enable_acl: bool,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of worker threads
    pub worker_threads: usize,
    /// Enable thread pool
    pub enable_thread_pool: bool,
    /// Memory pool size
    pub memory_pool_size: usize,
    /// Enable memory pool
    pub enable_memory_pool: bool,
    /// Buffer sizes
    pub buffer_sizes: BufferConfig,
    /// Cache settings
    pub cache: CacheConfig,
}

/// Buffer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Receive buffer size
    pub recv_buffer_size: usize,
    /// Send buffer size
    pub send_buffer_size: usize,
    /// Frame buffer pool size
    pub frame_buffer_pool_size: usize,
    /// Maximum frame size
    pub max_frame_size: usize,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable peer cache
    pub enable_peer_cache: bool,
    /// Peer cache size
    pub peer_cache_size: usize,
    /// Peer cache TTL (seconds)
    pub peer_cache_ttl: u64,
    /// Enable frame cache
    pub enable_frame_cache: bool,
    /// Frame cache size
    pub frame_cache_size: usize,
}

/// Configuration validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether configuration is valid
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

/// Configuration manager
pub struct ConfigManager {
    /// Current configuration
    config: DaemonConfig,
    /// Path to configuration file
    config_path: Option<PathBuf>,
    /// Configuration watchers
    watchers: Vec<Box<dyn ConfigWatcher>>,
}

impl std::fmt::Debug for ConfigManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigManager")
            .field("config", &self.config)
            .field("config_path", &self.config_path)
            .field("watchers", &format!("[{} watchers]", self.watchers.len()))
            .finish()
    }
}

/// Configuration change watcher trait
pub trait ConfigWatcher: Send + Sync {
    /// Called when configuration changes
    fn on_config_changed(&self, old_config: &DaemonConfig, new_config: &DaemonConfig);
    
    /// Get watcher name
    fn name(&self) -> &str;
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            io: IoConfig::default(),
            events: EventConfig::default(),
            awdl: AwdlProtocolConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            name: "awdl-daemon".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid_file: PathBuf::from("/var/run/awdl-daemon.pid"),
            work_dir: PathBuf::from("/var/lib/awdl"),
            daemonize: false,
            user: None,
            group: None,
            debug: false,
            heartbeat_interval: 30000,
            enable_metrics: true,
            stats_interval: 60000,
        }
    }
}

impl Default for AwdlProtocolConfig {
    fn default() -> Self {
        Self {
            node_id: uuid::Uuid::new_v4().to_string(),
            device_name: "AWDL Device".to_string(),
            service_name: "_awdl._tcp".to_string(),
            enable_sync: true,
            enable_election: true,
            channels: ChannelConfig::default(),
            peers: PeerConfig::default(),
            timing: TimingConfig::default(),
        }
    }
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            available_channels: vec![6, 44, 149],
            default_channel: 6,
            switch_interval: 100,
            dwell_time: 16,
            enable_hopping: true,
        }
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            max_peers: 100,
            peer_timeout: 30,
            discovery_interval: 1000,
            enable_filtering: false,
            allowed_peers: Vec::new(),
            blocked_peers: Vec::new(),
        }
    }
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            availability_window: 16,
            aw_period: 100,
            action_frame_period: 100,
            sync_timeout: 5000,
            election_timeout: 3000,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            max_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            console: true,
            syslog: false,
            format: "text".to_string(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_encryption: false,
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_file: None,
            cert_file: None,
            enable_auth: false,
            auth_method: "none".to_string(),
            enable_acl: false,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            enable_thread_pool: true,
            memory_pool_size: 1024 * 1024, // 1MB
            enable_memory_pool: true,
            buffer_sizes: BufferConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            recv_buffer_size: 65536,
            send_buffer_size: 65536,
            frame_buffer_pool_size: 100,
            max_frame_size: 1500,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enable_peer_cache: true,
            peer_cache_size: 1000,
            peer_cache_ttl: 300,
            enable_frame_cache: false,
            frame_cache_size: 100,
        }
    }
}

impl ConfigManager {
    /// Create new configuration manager
    pub fn new() -> Self {
        Self {
            config: DaemonConfig::default(),
            config_path: None,
            watchers: Vec::new(),
        }
    }

    /// Create configuration manager with config
    pub fn with_config(config: DaemonConfig) -> Self {
        Self {
            config,
            config_path: None,
            watchers: Vec::new(),
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| AwdlError::Config(format!("Failed to read config file: {}", e)))?;
        
        let config: DaemonConfig = match path.extension().and_then(|s| s.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .map_err(|e| AwdlError::Config(format!("Failed to parse JSON config: {}", e)))?,
            Some("toml") => toml::from_str(&content)
                .map_err(|e| AwdlError::Config(format!("Failed to parse TOML config: {}", e)))?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .map_err(|e| AwdlError::Config(format!("Failed to parse YAML config: {}", e)))?,
            _ => return Err(AwdlError::Config("Unsupported config file format".to_string())),
        };
        
        Ok(Self {
            config,
            config_path: Some(path.to_path_buf()),
            watchers: Vec::new(),
        })
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        
        let content = match path.extension().and_then(|s| s.to_str()) {
            Some("json") => serde_json::to_string_pretty(&self.config)
                .map_err(|e| AwdlError::Config(format!("Failed to serialize JSON config: {}", e)))?,
            Some("toml") => toml::to_string_pretty(&self.config)
                .map_err(|e| AwdlError::Config(format!("Failed to serialize TOML config: {}", e)))?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(&self.config)
                .map_err(|e| AwdlError::Config(format!("Failed to serialize YAML config: {}", e)))?,
            _ => return Err(AwdlError::Config("Unsupported config file format".to_string())),
        };
        
        fs::write(path, content)
            .map_err(|e| AwdlError::Config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }

    /// Get current configuration
    pub fn get_config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, new_config: DaemonConfig) -> Result<()> {
        let validation = self.validate_config(&new_config)?;
        if !validation.valid {
            return Err(AwdlError::Config(format!(
                "Configuration validation failed: {}",
                validation.errors.join(", ")
            )));
        }
        
        let old_config = self.config.clone();
        self.config = new_config;
        
        // Notify watchers
        for watcher in &self.watchers {
            watcher.on_config_changed(&old_config, &self.config);
        }
        
        Ok(())
    }

    /// Validate configuration
    pub fn validate_config(&self, config: &DaemonConfig) -> Result<ValidationResult> {
        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        
        // Validate general config
        if config.general.name.is_empty() {
            result.errors.push("Daemon name cannot be empty".to_string());
        }
        
        // Validate I/O config
        if config.io.udp_port == 0 {
            result.errors.push("UDP port cannot be 0".to_string());
        }
        
        if config.io.tcp_port == 0 {
            result.errors.push("TCP port cannot be 0".to_string());
        }
        
        if config.io.max_packet_size == 0 {
            result.errors.push("Max packet size cannot be 0".to_string());
        }
        
        // Validate AWDL config
        if config.awdl.node_id.is_empty() {
            result.errors.push("Node ID cannot be empty".to_string());
        }
        
        if config.awdl.channels.available_channels.is_empty() {
            result.errors.push("At least one channel must be available".to_string());
        }
        
        if !config.awdl.channels.available_channels.contains(&config.awdl.channels.default_channel) {
            result.errors.push("Default channel must be in available channels".to_string());
        }
        
        // Validate timing config
        if config.awdl.timing.availability_window == 0 {
            result.errors.push("Availability window cannot be 0".to_string());
        }
        
        if config.awdl.timing.aw_period == 0 {
            result.errors.push("AW period cannot be 0".to_string());
        }
        
        // Validate performance config
        if config.performance.worker_threads == 0 {
            result.warnings.push("Worker threads is 0, using default".to_string());
        }
        
        // Validate logging config
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&config.logging.level.as_str()) {
            result.errors.push(format!(
                "Invalid log level '{}', must be one of: {}",
                config.logging.level,
                valid_levels.join(", ")
            ));
        }
        
        // Check if any errors occurred
        result.valid = result.errors.is_empty();
        
        Ok(result)
    }

    /// Add configuration watcher
    pub fn add_watcher(&mut self, watcher: Box<dyn ConfigWatcher>) {
        self.watchers.push(watcher);
    }

    /// Remove configuration watcher
    pub fn remove_watcher(&mut self, name: &str) {
        self.watchers.retain(|w| w.name() != name);
    }

    /// Reload configuration from file
    pub fn reload(&mut self) -> Result<()> {
        if let Some(path) = &self.config_path {
            let new_manager = Self::load_from_file(path)?;
            self.update_config(new_manager.config)?;
        } else {
            return Err(AwdlError::Config("No config file path set".to_string()));
        }
        
        Ok(())
    }

    /// Get configuration as JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.config)
            .map_err(|e| AwdlError::Config(format!("Failed to serialize config to JSON: {}", e)))
    }

    /// Get configuration as TOML string
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(&self.config)
            .map_err(|e| AwdlError::Config(format!("Failed to serialize config to TOML: {}", e)))
    }

    /// Get configuration as YAML string
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(&self.config)
            .map_err(|e| AwdlError::Config(format!("Failed to serialize config to YAML: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert_eq!(config.general.name, "awdl-daemon");
        assert_eq!(config.io.udp_port, 6363);
        assert!(config.awdl.enable_sync);
        assert!(config.awdl.enable_election);
    }

    #[test]
    fn test_config_manager_creation() {
        let manager = ConfigManager::new();
        assert_eq!(manager.config.general.name, "awdl-daemon");
        assert!(manager.config_path.is_none());
    }

    #[test]
    fn test_config_validation() {
        let manager = ConfigManager::new();
        let config = DaemonConfig::default();
        
        let result = manager.validate_config(&config).unwrap();
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_config_validation_errors() {
        let manager = ConfigManager::new();
        let mut config = DaemonConfig::default();
        config.general.name = String::new();
        config.io.udp_port = 0;
        
        let result = manager.validate_config(&config).unwrap();
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let manager = ConfigManager::new();
        
        let json = manager.to_json().unwrap();
        assert!(json.contains("awdl-daemon"));
        
        let toml = manager.to_toml().unwrap();
        assert!(toml.contains("awdl-daemon"));
        
        let yaml = manager.to_yaml().unwrap();
        assert!(yaml.contains("awdl-daemon"));
    }

    // Note: File operations test removed due to missing tempfile dependency

    struct TestWatcher {
        name: String,
    }

    impl ConfigWatcher for TestWatcher {
        fn on_config_changed(&self, _old_config: &DaemonConfig, _new_config: &DaemonConfig) {
            // Test implementation
        }
        
        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_config_watchers() {
        let mut manager = ConfigManager::new();
        
        let watcher = Box::new(TestWatcher {
            name: "test_watcher".to_string(),
        });
        
        manager.add_watcher(watcher);
        assert_eq!(manager.watchers.len(), 1);
        
        manager.remove_watcher("test_watcher");
        assert_eq!(manager.watchers.len(), 0);
    }
}