//! PHY backend capability detection and management

use serde::{Deserialize, Serialize};

/// Capabilities of a PHY backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhyCapabilities {
    /// Backend can capture frames in monitor mode
    pub monitor_mode: bool,
    /// Backend supports raw frame indication
    pub raw_frame_indication: bool,
    /// Backend can inject frames
    pub frame_injection: bool,
    /// Backend supports channel switching
    pub channel_switching: bool,
    /// Backend provides accurate timestamps
    pub hardware_timestamps: bool,
    /// Backend provides signal strength information
    pub signal_strength: bool,
    /// Backend includes FCS in frames
    pub fcs_present: bool,
    /// Supported monitor mode types
    pub supported_monitor_modes: Vec<MonitorModeType>,
    /// Supported channels (frequency in MHz)
    pub supported_channels: Vec<u16>,
    /// Maximum frame size supported
    pub max_frame_size: usize,
    /// Backend-specific version information
    pub version: String,
    /// Additional backend-specific capabilities
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for PhyCapabilities {
    fn default() -> Self {
        Self {
            monitor_mode: false,
            raw_frame_indication: false,
            frame_injection: false,
            channel_switching: false,
            hardware_timestamps: false,
            signal_strength: false,
            fcs_present: false,
            supported_monitor_modes: Vec::new(),
            supported_channels: Vec::new(),
            max_frame_size: crate::MAX_FRAME_SIZE,
            version: String::new(),
            extensions: std::collections::HashMap::new(),
        }
    }
}

impl PhyCapabilities {
    /// Check if a specific monitor mode is supported
    pub fn supports_monitor_mode(&self, mode: MonitorModeType) -> bool {
        self.supported_monitor_modes.contains(&mode)
    }
    
    /// Check if a specific channel is supported
    pub fn supports_channel(&self, frequency: u16) -> bool {
        self.supported_channels.contains(&frequency)
    }
    
    /// Get the best available monitor mode
    pub fn best_monitor_mode(&self) -> Option<MonitorModeType> {
        // Priority order: WDI Raw > Native 802.11 > WDI Promiscuous > Vendor > Bridge
        for mode in &[
            MonitorModeType::WdiRaw,
            MonitorModeType::Native80211,
            MonitorModeType::WdiPromiscuous,
            MonitorModeType::Vendor,
            MonitorModeType::Bridge,
        ] {
            if self.supports_monitor_mode(*mode) {
                return Some(*mode);
            }
        }
        None
    }
}

/// Monitor mode types supported by different backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorModeType {
    /// No monitor mode
    None = 0,
    /// WDI raw frame mode (Windows 10/11 preferred)
    WdiRaw = 1,
    /// Native 802.11 monitor mode (legacy)
    Native80211 = 2,
    /// WDI promiscuous mode (limited)
    WdiPromiscuous = 3,
    /// Vendor-specific monitor mode
    Vendor = 4,
    /// Bridge mode (WSL2/external)
    Bridge = 5,
    /// USB adapter mode
    Usb = 6,
}
