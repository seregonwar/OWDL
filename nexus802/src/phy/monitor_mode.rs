//! Monitor mode management and state tracking

use serde::{Deserialize, Serialize};
use std::time::Instant;

pub use super::capabilities::MonitorModeType;

/// Monitor mode context and state management
#[derive(Debug)]
pub struct MonitorModeContext {
    /// Currently active monitor mode
    pub active_mode: MonitorModeType,
    /// Whether monitor mode is currently enabled
    pub is_active: bool,
    /// When monitor mode was last activated
    pub activated_at: Option<Instant>,
    /// Original configuration before entering monitor mode
    pub original_config: Option<OriginalConfig>,
    /// Mode-specific context data
    pub mode_context: ModeContext,
}

/// Original configuration to restore when exiting monitor mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalConfig {
    /// Original operation mode
    pub operation_mode: String,
    /// Original BSSID if connected
    pub bssid: Option<[u8; 6]>,
    /// Original channel configuration
    pub channel: Option<super::ChannelConfig>,
}

/// Mode-specific context data
#[derive(Debug)]
pub enum ModeContext {
    /// No active mode
    None,
    
    /// Native 802.11 context
    Native80211 {
        original_mode: String,
        original_bssid: Option<[u8; 6]>,
    },
    
    /// WDI context
    Wdi {
        original_config: Vec<u8>, // Serialized WDI config
        current_mode: String,
    },
    
    /// Bridge context
    Bridge {
        bridge_process: Option<u32>, // Process ID
        bridge_pipe: Option<String>, // Pipe name
        shared_memory: Option<String>, // Shared memory name
    },
    
    /// Vendor driver context
    Vendor {
        driver_name: String,
        driver_handle: Option<usize>, // Platform-specific handle
        vendor_config: Vec<u8>,
    },
}

impl Default for MonitorModeContext {
    fn default() -> Self {
        Self {
            active_mode: MonitorModeType::None,
            is_active: false,
            activated_at: None,
            original_config: None,
            mode_context: ModeContext::None,
        }
    }
}

impl MonitorModeContext {
    /// Create a new monitor mode context
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Activate monitor mode with the specified type
    pub fn activate(&mut self, mode: MonitorModeType, original_config: Option<OriginalConfig>) {
        self.active_mode = mode;
        self.is_active = true;
        self.activated_at = Some(Instant::now());
        self.original_config = original_config;
        
        // Initialize mode-specific context
        self.mode_context = match mode {
            MonitorModeType::None => ModeContext::None,
            MonitorModeType::Native80211 => ModeContext::Native80211 {
                original_mode: String::new(),
                original_bssid: None,
            },
            MonitorModeType::WdiRaw | MonitorModeType::WdiPromiscuous => ModeContext::Wdi {
                original_config: Vec::new(),
                current_mode: String::new(),
            },
            MonitorModeType::Bridge => ModeContext::Bridge {
                bridge_process: None,
                bridge_pipe: None,
                shared_memory: None,
            },
            MonitorModeType::Vendor => ModeContext::Vendor {
                driver_name: String::new(),
                driver_handle: None,
                vendor_config: Vec::new(),
            },
            MonitorModeType::Usb => ModeContext::None, // USB adapters don't need special context
        };
    }
    
    /// Deactivate monitor mode
    pub fn deactivate(&mut self) {
        self.active_mode = MonitorModeType::None;
        self.is_active = false;
        self.activated_at = None;
        self.mode_context = ModeContext::None;
        // Keep original_config for potential restoration
    }
    
    /// Get the duration monitor mode has been active
    pub fn active_duration(&self) -> Option<std::time::Duration> {
        self.activated_at.map(|start| start.elapsed())
    }
    
    /// Check if the context is for a specific mode type
    pub fn is_mode(&self, mode: MonitorModeType) -> bool {
        self.active_mode == mode && self.is_active
    }
}
