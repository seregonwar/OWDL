//! # AWDL Rust Implementation made by SeregonWar https://github.com/seregonwar
//!
//! This is a Rust implementation of the Apple Wireless Direct Link (AWDL) protocol.
//! AWDL is a proprietary mesh networking protocol used by Apple devices for
//! peer-to-peer communication.
//!
//! ## Architecture
//!
//! The implementation is organized into several modules:
//! - `frame`: Protocol frame structures and parsing
//! - `state`: Node state management
//! - `peers`: Peer discovery and management
//! - `sync`: Synchronization mechanisms
//! - `election`: Master election algorithm
//! - `channel`: Channel management and sequencing
//! - `wire`: Low-level wire protocol utilities
//! - `daemon`: High-level daemon functionality

pub mod channel;
pub mod election;
pub mod frame;
pub mod peers;
pub mod state;
pub mod sync;
pub mod wire;

// Daemon modules
pub mod daemon;

// Re-export commonly used types
pub use crate::{
    frame::*,
    state::*,
    peers::*,
    sync::*,
    election::*,
    channel::*,
    wire::*,
};

// Error types
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AwdlError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Invalid frame: {0}")]
    InvalidFrame(String),
    
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    #[error("Event error: {0}")]
    Event(String),
    
    #[error("Buffer is full")]
    BufferFull,
    
    #[error("Buffer is empty")]
    BufferEmpty,
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("System error: {0}")]
    System(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

pub type Result<T> = std::result::Result<T, AwdlError>;

// Constants
pub const AWDL_VERSION: u8 = 1;
pub const AWDL_OUI: [u8; 3] = [0x00, 0x17, 0xf2];
pub const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];
pub const AWDL_LLC_PROTOCOL_ID: u16 = 0x0800;
pub const IEEE80211_VENDOR_SPECIFIC: u8 = 127;
pub const AWDL_TYPE: u8 = 8;

// Utility functions
pub fn init_logging() {
    env_logger::init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(AWDL_VERSION, 1);
        assert_eq!(AWDL_OUI, [0x00, 0x17, 0xf2]);
        assert_eq!(AWDL_TYPE, 8);
    }
}