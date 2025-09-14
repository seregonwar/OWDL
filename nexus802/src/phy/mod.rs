//! Physical layer abstraction for IEEE 802.11 frame access
//! 
//! This module provides a unified interface for accessing 802.11 frames across
//! different backend implementations (WDI, Native 802.11, Bridge, Vendor drivers).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

pub mod capabilities;
pub mod monitor_mode;

pub use capabilities::*;
pub use monitor_mode::*;

/// Errors that can occur in PHY operations
#[derive(Error, Debug)]
pub enum PhyError {
    #[error("Backend not available: {backend}")]
    BackendUnavailable { backend: String },
    
    #[error("Monitor mode not supported")]
    MonitorModeNotSupported,
    
    #[error("Frame injection not supported")]
    InjectionNotSupported,
    
    #[error("Channel switching not supported")]
    ChannelSwitchNotSupported,
    
    #[error("Invalid channel: {channel}")]
    InvalidChannel { channel: u16 },
    
    #[error("Frame too large: {size} bytes (max: {max})")]
    FrameTooLarge { size: usize, max: usize },
    
    #[error("Hardware error: {message}")]
    Hardware { message: String },
    
    #[error("Timeout waiting for operation")]
    Timeout,
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Metadata associated with a received frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameMetadata {
    /// Timestamp when frame was received (microseconds since epoch)
    pub timestamp: u64,
    /// Channel frequency in MHz
    pub frequency: u16,
    /// Channel flags (HT, VHT, etc.)
    pub channel_flags: u16,
    /// Signal strength in dBm
    pub signal_dbm: Option<i8>,
    /// Noise floor in dBm
    pub noise_dbm: Option<i8>,
    /// Signal-to-noise ratio in dB
    pub snr_db: Option<u8>,
    /// Frame check sequence present
    pub fcs_present: bool,
    /// Source of the frame
    pub source_type: FrameSourceType,
    /// Additional vendor-specific metadata
    pub vendor_data: Option<Vec<u8>>,
}

/// Type of frame source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameSourceType {
    /// Native NDIS 802.11
    Native80211 = 1,
    /// WDI (Windows Driver Interface)
    Wdi = 2,
    /// WSL2/Linux bridge
    Bridge = 3,
    /// Vendor-specific driver
    Vendor = 4,
    /// Mock/test backend
    Mock = 5,
}

/// Channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Primary channel number (1-14 for 2.4GHz, 36+ for 5GHz)
    pub primary: u16,
    /// Channel width in MHz (20, 40, 80, 160)
    pub width: u16,
    /// Center frequency in MHz
    pub center_freq: u16,
    /// Secondary channel offset for 40MHz (above/below)
    pub secondary_offset: Option<i8>,
}

/// Frame transmission metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxMetadata {
    /// Channel to transmit on
    pub channel: ChannelConfig,
    /// Transmission power in dBm
    pub power_dbm: Option<i8>,
    /// Data rate in Mbps
    pub rate_mbps: Option<u16>,
    /// Number of retries
    pub retries: Option<u8>,
    /// Wait for ACK
    pub wait_ack: bool,
}

/// Main trait for PHY backend implementations
#[async_trait]
pub trait PhyBackend: Send + Sync {
    /// Get backend capabilities
    async fn capabilities(&self) -> Result<PhyCapabilities, PhyError>;
    
    /// Initialize the backend
    async fn initialize(&mut self) -> Result<(), PhyError>;
    
    /// Enable monitor mode
    async fn enable_monitor_mode(&mut self, mode: MonitorModeType) -> Result<(), PhyError>;
    
    /// Disable monitor mode and return to normal operation
    async fn disable_monitor_mode(&mut self) -> Result<(), PhyError>;
    
    /// Set channel configuration
    async fn set_channel(&mut self, config: ChannelConfig) -> Result<(), PhyError>;
    
    /// Get current channel configuration
    async fn get_channel(&self) -> Result<ChannelConfig, PhyError>;
    
    /// Receive a frame with metadata (non-blocking)
    async fn recv_frame(&mut self) -> Result<Option<(Vec<u8>, FrameMetadata)>, PhyError>;
    
    /// Receive a frame with timeout
    async fn recv_frame_timeout(
        &mut self, 
        timeout: Duration
    ) -> Result<Option<(Vec<u8>, FrameMetadata)>, PhyError>;
    
    /// Inject a frame
    async fn inject_frame(&mut self, frame: &[u8], metadata: TxMetadata) -> Result<(), PhyError>;
    
    /// Get backend statistics
    async fn get_statistics(&self) -> Result<PhyStatistics, PhyError>;
    
    /// Shutdown the backend
    async fn shutdown(&mut self) -> Result<(), PhyError>;
}

/// PHY backend statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhyStatistics {
    /// Total frames received
    pub frames_received: u64,
    /// Total frames transmitted
    pub frames_transmitted: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total bytes transmitted
    pub bytes_transmitted: u64,
    /// Frames dropped due to buffer overflow
    pub frames_dropped: u64,
    /// Average frames per second (last 60 seconds)
    pub avg_fps: f64,
    /// Current CPU usage percentage
    pub cpu_usage: f32,
    /// Current memory usage in bytes
    pub memory_usage: usize,
    /// Average processing latency in microseconds
    pub avg_latency_us: u32,
}
