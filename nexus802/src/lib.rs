//! # Nexus802 - Multi-Tier IEEE 802.11 Protocol Implementation
//! 
//! A Rust implementation of a multi-tier protocol for accessing IEEE 802.11 frames
//! on Windows systems, providing fallback mechanisms across different access methods.
//! 
//! ## Architecture Overview
//! 
//! - **Tier 1**: NDIS WDI-Aware Filter Driver (kernel-mode)
//! - **Tier 2**: Hybrid Bridge Architecture (WSL2/Linux + Vendor Drivers)
//! - **Tier 3**: Advanced Frame Processing Pipeline
//! - **Tier 4**: Intelligent Fallback & Auto-Configuration
//! - **Tier 5**: Security & Compliance Framework
//! - **Tier 6**: Performance Optimization & Monitoring

pub mod phy;
pub mod frame;
pub mod config;
pub mod error;
pub mod radiotap;

#[cfg(feature = "bridge-wsl2")]
pub mod bridge;

pub use phy::{PhyBackend, PhyCapabilities, PhyError, FrameMetadata};
pub use frame::{Frame802_11, UnifiedFrameDescriptor};
pub use config::Nexus802Config;
pub use error::{Nexus802Error, Result};

/// Current version of the Nexus802 protocol
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum frame size supported (including radiotap header)
pub const MAX_FRAME_SIZE: usize = 4096;

/// Default ring buffer size for frame processing
pub const DEFAULT_RING_SIZE: usize = 1024;
