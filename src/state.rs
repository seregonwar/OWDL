//! AWDL State management
//!
//! This module contains the state management structures for AWDL nodes.


use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::peers::AwdlPeer;
use crate::sync::AwdlSyncState;
use crate::election::AwdlElectionState;
use crate::channel::AwdlChannelManager;

/// AWDL node capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwdlCapabilities {
    pub supports_v2: bool,
    pub supports_ipv6: bool,
    pub supports_ranging: bool,
    pub supports_data_transfer: bool,
}

impl Default for AwdlCapabilities {
    fn default() -> Self {
        Self {
            supports_v2: true,
            supports_ipv6: true,
            supports_ranging: false,
            supports_data_transfer: true,
        }
    }
}

/// AWDL node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlConfig {
    /// Node's MAC address
    pub self_address: [u8; 6],
    /// Node name/identifier
    pub node_name: String,
    /// Supported capabilities
    pub capabilities: AwdlCapabilities,
    /// Channel hopping enabled
    pub channel_hopping_enabled: bool,
    /// Master election enabled
    pub election_enabled: bool,
    /// Synchronization enabled
    pub sync_enabled: bool,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Peer timeout duration
    pub peer_timeout: Duration,
    /// Beacon interval
    pub beacon_interval: Duration,
}

impl Default for AwdlConfig {
    fn default() -> Self {
        Self {
            self_address: [0; 6],
            node_name: "awdl-rust-node".to_string(),
            capabilities: AwdlCapabilities::default(),
            channel_hopping_enabled: true,
            election_enabled: true,
            sync_enabled: true,
            max_peers: 32,
            peer_timeout: Duration::from_secs(30),
            beacon_interval: Duration::from_millis(100),
        }
    }
}

/// AWDL node state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlNodeState {
    /// Node is initializing
    Init = 0,
    /// Node is scanning for peers
    Scan = 1,
    /// Node is in normal operation
    Active = 2,
    /// Node is suspended
    Suspend = 3,
    /// Node is shutting down
    Shutdown = 4,
}

impl Default for AwdlNodeState {
    fn default() -> Self {
        Self::Init
    }
}

/// AWDL statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlStats {
    /// Number of frames transmitted
    pub tx_frames: u64,
    /// Number of frames received
    pub rx_frames: u64,
    /// Number of bytes transmitted
    pub tx_bytes: u64,
    /// Number of bytes received
    pub rx_bytes: u64,
    /// Number of transmission errors
    pub tx_errors: u64,
    /// Number of reception errors
    pub rx_errors: u64,
    /// Number of dropped frames
    pub dropped_frames: u64,
    /// Number of peers discovered
    pub peers_discovered: u64,
    /// Number of peers lost
    pub peers_lost: u64,
    /// Start time
    pub start_time: SystemTime,
}

impl Default for AwdlStats {
    fn default() -> Self {
        Self {
            tx_frames: 0,
            rx_frames: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_errors: 0,
            rx_errors: 0,
            dropped_frames: 0,
            peers_discovered: 0,
            peers_lost: 0,
            start_time: SystemTime::now(),
        }
    }
}

impl AwdlStats {
    /// Create new statistics with current time
    pub fn new() -> Self {
        Self::default()
    }

    /// Get uptime duration
    pub fn uptime(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default()
    }

    /// Record transmitted frame
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_frames += 1;
        self.tx_bytes += bytes as u64;
    }

    /// Record received frame
    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_frames += 1;
        self.rx_bytes += bytes as u64;
    }

    /// Record transmission error
    pub fn record_tx_error(&mut self) {
        self.tx_errors += 1;
    }

    /// Record reception error
    pub fn record_rx_error(&mut self) {
        self.rx_errors += 1;
    }

    /// Record dropped frame
    pub fn record_dropped(&mut self) {
        self.dropped_frames += 1;
    }

    /// Record peer discovery
    pub fn record_peer_discovered(&mut self) {
        self.peers_discovered += 1;
    }

    /// Record peer loss
    pub fn record_peer_lost(&mut self) {
        self.peers_lost += 1;
    }
}

/// Main AWDL state structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AwdlState {
    /// Node configuration
    pub config: AwdlConfig,
    /// Current node state
    pub node_state: AwdlNodeState,
    /// Node UUID
    pub node_id: Uuid,
    /// Current sequence number
    pub sequence_number: u32,
    /// Statistics
    pub stats: AwdlStats,
    /// Peer management
    pub peers: HashMap<[u8; 6], AwdlPeer>,
    /// Synchronization state
    pub sync_state: AwdlSyncState,
    /// Election state
    pub election_state: AwdlElectionState,
    /// Channel state
    pub channel_state: AwdlChannelManager,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Is master node
    pub is_master: bool,
    /// Master address (if known)
    pub master_address: Option<[u8; 6]>,
}

impl AwdlState {
    /// Create new AWDL state with configuration
    pub fn new(config: AwdlConfig) -> Self {
        let self_address = config.self_address;
        Self {
            config,
            node_state: AwdlNodeState::Init,
            node_id: Uuid::new_v4(),
            sequence_number: 0,
            stats: AwdlStats::new(),
            peers: HashMap::new(),
            sync_state: AwdlSyncState::new(),
            election_state: AwdlElectionState::new(self_address),
            channel_state: AwdlChannelManager::new(),
            last_activity: Utc::now(),
            is_master: false,
            master_address: None,
        }
    }

    /// Create new AWDL state with default configuration
    pub fn with_address(address: [u8; 6]) -> Self {
        let mut config = AwdlConfig::default();
        config.self_address = address;
        Self::new(config)
    }

    /// Get next sequence number
    pub fn next_sequence_number(&mut self) -> u32 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.sequence_number
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if node is active
    pub fn is_active(&self) -> bool {
        matches!(self.node_state, AwdlNodeState::Active)
    }

    /// Set node state
    pub fn set_state(&mut self, state: AwdlNodeState) {
        log::info!("Node state transition: {:?} -> {:?}", self.node_state, state);
        self.node_state = state;
        self.update_activity();
    }

    /// Add or update peer
    pub fn add_peer(&mut self, peer: AwdlPeer) {
        let address = peer.address;
        let is_new = !self.peers.contains_key(&address);
        
        self.peers.insert(address, peer);
        
        if is_new {
            self.stats.record_peer_discovered();
            log::info!("New peer discovered: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                address[0], address[1], address[2], address[3], address[4], address[5]);
        }
        
        self.update_activity();
    }

    /// Remove peer
    pub fn remove_peer(&mut self, address: &[u8; 6]) -> Option<AwdlPeer> {
        let peer = self.peers.remove(address);
        if peer.is_some() {
            self.stats.record_peer_lost();
            log::info!("Peer lost: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                address[0], address[1], address[2], address[3], address[4], address[5]);
        }
        peer
    }

    /// Get peer by address
    pub fn get_peer(&self, address: &[u8; 6]) -> Option<&AwdlPeer> {
        self.peers.get(address)
    }

    /// Get mutable peer by address
    pub fn get_peer_mut(&mut self, address: &[u8; 6]) -> Option<&mut AwdlPeer> {
        self.peers.get_mut(address)
    }

    /// Get all peers
    pub fn get_peers(&self) -> impl Iterator<Item = &AwdlPeer> {
        self.peers.values()
    }

    /// Get number of active peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Clean up expired peers
    pub fn cleanup_peers(&mut self) {
        let timeout = self.config.peer_timeout;
        let now = Utc::now();
        
        let expired_peers: Vec<[u8; 6]> = self.peers
            .iter()
            .filter(|(_, peer)| now.signed_duration_since(peer.last_seen).to_std().unwrap_or(Duration::ZERO) > timeout)
            .map(|(addr, _)| *addr)
            .collect();
        
        for addr in expired_peers {
            self.remove_peer(&addr);
        }
    }

    /// Set master status
    pub fn set_master(&mut self, is_master: bool, master_address: Option<[u8; 6]>) {
        if self.is_master != is_master {
            log::info!("Master status changed: {} -> {}", self.is_master, is_master);
            self.is_master = is_master;
        }
        
        if self.master_address != master_address {
            if let Some(addr) = master_address {
                log::info!("Master address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
            } else {
                log::info!("Master address cleared");
            }
            self.master_address = master_address;
        }
        
        self.update_activity();
    }

    /// Check if we are the master
    pub fn is_master_node(&self) -> bool {
        self.is_master
    }

    /// Get master address
    pub fn get_master_address(&self) -> Option<[u8; 6]> {
        self.master_address
    }

    /// Get node uptime
    pub fn uptime(&self) -> Duration {
        self.stats.uptime()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        (Utc::now() - self.last_activity).to_std().unwrap_or_default()
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = AwdlStats::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_awdl_state_creation() {
        let address = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let state = AwdlState::with_address(address);
        
        assert_eq!(state.config.self_address, address);
        assert_eq!(state.node_state, AwdlNodeState::Init);
        assert_eq!(state.sequence_number, 0);
        assert!(!state.is_master);
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_sequence_number() {
        let mut state = AwdlState::with_address([0; 6]);
        
        assert_eq!(state.next_sequence_number(), 1);
        assert_eq!(state.next_sequence_number(), 2);
        assert_eq!(state.sequence_number, 2);
    }

    #[test]
    fn test_state_transitions() {
        let mut state = AwdlState::with_address([0; 6]);
        
        assert_eq!(state.node_state, AwdlNodeState::Init);
        assert!(!state.is_active());
        
        state.set_state(AwdlNodeState::Active);
        assert_eq!(state.node_state, AwdlNodeState::Active);
        assert!(state.is_active());
    }

    #[test]
    fn test_master_status() {
        let mut state = AwdlState::with_address([0; 6]);
        let master_addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        
        assert!(!state.is_master_node());
        assert!(state.get_master_address().is_none());
        
        state.set_master(true, Some(master_addr));
        assert!(state.is_master_node());
        assert_eq!(state.get_master_address(), Some(master_addr));
    }

    #[test]
    fn test_statistics() {
        let mut stats = AwdlStats::new();
        
        stats.record_tx(100);
        stats.record_rx(200);
        stats.record_tx_error();
        
        assert_eq!(stats.tx_frames, 1);
        assert_eq!(stats.tx_bytes, 100);
        assert_eq!(stats.rx_frames, 1);
        assert_eq!(stats.rx_bytes, 200);
        assert_eq!(stats.tx_errors, 1);
    }
}