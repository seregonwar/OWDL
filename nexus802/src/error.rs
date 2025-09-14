//! Error types for Nexus802

use thiserror::Error;

/// Main error type for Nexus802 operations
#[derive(Error, Debug)]
pub enum Nexus802Error {
    #[error("PHY backend error: {0}")]
    Phy(#[from] crate::phy::PhyError),
    
    #[error("Frame processing error: {message}")]
    Frame { message: String },
    
    #[error("Configuration error: {message}")]
    Config { message: String },
    
    #[error("Bridge communication error: {message}")]
    Bridge { message: String },
    
    #[error("Vendor driver error: {message}")]
    Vendor { message: String },
    
    #[error("NDIS filter error: {message}")]
    Ndis { message: String },
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Not supported on this platform")]
    NotSupported,
    
    #[error("Operation timed out")]
    Timeout,
    
    #[error("Resource unavailable: {resource}")]
    ResourceUnavailable { resource: String },
}

/// Result type alias for Nexus802 operations
pub type Result<T> = std::result::Result<T, Nexus802Error>;
