//! AWDL Peer management
//!
//! This module contains structures and functions for managing AWDL peers.


use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use std::net::Ipv6Addr;
use crate::Result;
use crate::frame::{AwdlTlv, AwdlTlvType};
use crate::sync::AwdlSyncParams;
use crate::election::AwdlElectionParams;

/// AWDL peer capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwdlPeerCapabilities {
    pub supports_v2: bool,
    pub supports_ipv6: bool,
    pub supports_ranging: bool,
    pub supports_data_transfer: bool,
    pub supports_real_time: bool,
}

impl Default for AwdlPeerCapabilities {
    fn default() -> Self {
        Self {
            supports_v2: false,
            supports_ipv6: false,
            supports_ranging: false,
            supports_data_transfer: true,
            supports_real_time: false,
        }
    }
}

/// AWDL peer state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlPeerState {
    /// Peer discovered but not yet synchronized
    Discovered = 0,
    /// Peer is synchronized
    Synchronized = 1,
    /// Peer is active and communicating
    Active = 2,
    /// Peer is inactive/sleeping
    Inactive = 3,
    /// Peer connection lost
    Lost = 4,
}

impl Default for AwdlPeerState {
    fn default() -> Self {
        Self::Discovered
    }
}

/// AWDL peer statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AwdlPeerStats {
    /// Number of frames received from this peer
    pub rx_frames: u64,
    /// Number of frames transmitted to this peer
    pub tx_frames: u64,
    /// Number of bytes received from this peer
    pub rx_bytes: u64,
    /// Number of bytes transmitted to this peer
    pub tx_bytes: u64,
    /// Number of reception errors from this peer
    pub rx_errors: u64,
    /// Number of transmission errors to this peer
    pub tx_errors: u64,
    /// Signal strength (RSSI) in dBm
    pub rssi: i8,
    /// Signal-to-noise ratio
    pub snr: i8,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

impl AwdlPeerStats {
    /// Record received frame
    pub fn record_rx(&mut self, bytes: usize, rssi: i8) {
        self.rx_frames += 1;
        self.rx_bytes += bytes as u64;
        self.rssi = rssi;
    }

    /// Record transmitted frame
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_frames += 1;
        self.tx_bytes += bytes as u64;
    }

    /// Record reception error
    pub fn record_rx_error(&mut self) {
        self.rx_errors += 1;
    }

    /// Record transmission error
    pub fn record_tx_error(&mut self) {
        self.tx_errors += 1;
    }

    /// Update RTT measurement
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }
}

/// AWDL peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlPeer {
    /// Peer MAC address
    pub address: [u8; 6],
    /// Peer name/identifier
    pub name: Option<String>,
    /// Peer state
    pub state: AwdlPeerState,
    /// Peer capabilities
    pub capabilities: AwdlPeerCapabilities,
    /// IPv6 address (if available)
    pub ipv6_address: Option<Ipv6Addr>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Synchronization parameters
    pub sync_params: Option<AwdlSyncParams>,
    /// Election parameters
    pub election_params: Option<AwdlElectionParams>,
    /// Peer statistics
    pub stats: AwdlPeerStats,
    /// Current channel
    pub channel: Option<u8>,
    /// Sequence number of last received frame
    pub last_sequence: u32,
    /// Is this peer the master?
    pub is_master: bool,
    /// Distance to master (hops)
    pub master_distance: u8,
    /// Services advertised by this peer
    pub services: HashMap<String, Vec<u8>>,
}

impl AwdlPeer {
    /// Create new peer with address
    pub fn new(address: [u8; 6]) -> Self {
        let now = Utc::now();
        Self {
            address,
            name: None,
            state: AwdlPeerState::Discovered,
            capabilities: AwdlPeerCapabilities::default(),
            ipv6_address: None,
            last_seen: now,
            first_seen: now,
            sync_params: None,
            election_params: None,
            stats: AwdlPeerStats::default(),
            channel: None,
            last_sequence: 0,
            is_master: false,
            master_distance: 255,
            services: HashMap::new(),
        }
    }

    /// Update peer with received frame information
    pub fn update_from_frame(&mut self, tlvs: &[AwdlTlv], rssi: i8, sequence: u32) {
        self.last_seen = Utc::now();
        self.last_sequence = sequence;
        self.stats.rssi = rssi;

        // Process TLVs to extract peer information
        for tlv in tlvs {
            match tlv.tlv_type {
                AwdlTlvType::SynchronizationParameters => {
                    if let Ok(params) = AwdlSyncParams::parse(&tlv.value) {
                        self.sync_params = Some(params);
                    }
                }
                AwdlTlvType::ElectionParameters | AwdlTlvType::ElectionParametersV2 => {
                    if let Ok(params) = AwdlElectionParams::parse(&tlv.value) {
                        self.election_params = Some(params.clone());
                        self.is_master = params.is_master();
                        self.master_distance = params.distance_to_master;
                    }
                }
                AwdlTlvType::ServiceParameters | AwdlTlvType::ServiceParametersV2 => {
                    // Parse service parameters
                    self.parse_service_parameters(&tlv.value);
                }
                AwdlTlvType::Version => {
                    // Parse version information
                    self.parse_version_info(&tlv.value);
                }
                _ => {}
            }
        }

        // Update state based on received information
        if self.state == AwdlPeerState::Discovered && self.sync_params.is_some() {
            self.state = AwdlPeerState::Synchronized;
        }
    }

    /// Parse service parameters from TLV value
    fn parse_service_parameters(&mut self, _data: &[u8]) {
        // TODO: Implement service parameter parsing
        // This would parse the service advertisement data
    }

    /// Parse version information from TLV value
    fn parse_version_info(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let version = data[0];
            self.capabilities.supports_v2 = version >= 2;
        }
    }

    /// Update peer activity
    pub fn update_activity(&mut self) {
        self.last_seen = Utc::now();
        
        // Transition to active state if synchronized
        if self.state == AwdlPeerState::Synchronized {
            self.state = AwdlPeerState::Active;
        }
    }

    /// Check if peer is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, AwdlPeerState::Active | AwdlPeerState::Synchronized)
    }

    /// Check if peer has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        (Utc::now() - self.last_seen).to_std().unwrap_or_default() > timeout
    }

    /// Get age of peer (time since first seen)
    pub fn age(&self) -> Duration {
        (Utc::now() - self.first_seen).to_std().unwrap_or_default()
    }

    /// Get idle time (time since last seen)
    pub fn idle_time(&self) -> Duration {
        (Utc::now() - self.last_seen).to_std().unwrap_or_default()
    }

    /// Set peer name
    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    /// Set IPv6 address
    pub fn set_ipv6_address(&mut self, address: Ipv6Addr) {
        self.ipv6_address = Some(address);
        self.capabilities.supports_ipv6 = true;
    }

    /// Add service
    pub fn add_service(&mut self, service_name: String, service_data: Vec<u8>) {
        self.services.insert(service_name, service_data);
    }

    /// Remove service
    pub fn remove_service(&mut self, service_name: &str) -> Option<Vec<u8>> {
        self.services.remove(service_name)
    }

    /// Get service data
    pub fn get_service(&self, service_name: &str) -> Option<&Vec<u8>> {
        self.services.get(service_name)
    }

    /// Get all service names
    pub fn get_service_names(&self) -> impl Iterator<Item = &String> {
        self.services.keys()
    }

    /// Check if peer advertises a specific service
    pub fn has_service(&self, service_name: &str) -> bool {
        self.services.contains_key(service_name)
    }

    /// Get formatted address string
    pub fn address_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.address[4],
            self.address[5]
        )
    }

    /// Get peer display name (name or address)
    pub fn display_name(&self) -> String {
        self.name
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.address_string())
    }

    /// Record received frame
    pub fn record_rx_frame(&mut self, bytes: usize, rssi: i8) {
        self.stats.record_rx(bytes, rssi);
        self.update_activity();
    }

    /// Record transmitted frame
    pub fn record_tx_frame(&mut self, bytes: usize) {
        self.stats.record_tx(bytes);
    }

    /// Mark peer as lost
    pub fn mark_lost(&mut self) {
        self.state = AwdlPeerState::Lost;
    }

    /// Check if peer is master
    pub fn is_master_peer(&self) -> bool {
        self.is_master
    }

    /// Get distance to master
    pub fn get_master_distance(&self) -> u8 {
        self.master_distance
    }

    /// Update master information
    pub fn update_master_info(&mut self, is_master: bool, distance: u8) {
        self.is_master = is_master;
        self.master_distance = distance;
    }
}

/// Peer manager for handling multiple peers
#[derive(Debug, Default)]
pub struct AwdlPeerManager {
    peers: HashMap<[u8; 6], AwdlPeer>,
    max_peers: usize,
    peer_timeout: Duration,
}

impl AwdlPeerManager {
    /// Create new peer manager
    pub fn new(max_peers: usize, peer_timeout: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            peer_timeout,
        }
    }

    /// Add or update peer
    pub fn add_peer(&mut self, peer: AwdlPeer) -> bool {
        let address = peer.address;
        
        // Check if we have room for new peers
        if !self.peers.contains_key(&address) && self.peers.len() >= self.max_peers {
            log::warn!("Maximum number of peers ({}) reached", self.max_peers);
            return false;
        }
        
        self.peers.insert(address, peer);
        true
    }

    /// Get peer by address
    pub fn get_peer(&self, address: &[u8; 6]) -> Option<&AwdlPeer> {
        self.peers.get(address)
    }

    /// Get mutable peer by address
    pub fn get_peer_mut(&mut self, address: &[u8; 6]) -> Option<&mut AwdlPeer> {
        self.peers.get_mut(address)
    }

    /// Remove peer
    pub fn remove_peer(&mut self, address: &[u8; 6]) -> Option<AwdlPeer> {
        self.peers.remove(address)
    }

    /// Get all peers
    pub fn get_peers(&self) -> impl Iterator<Item = &AwdlPeer> {
        self.peers.values()
    }

    /// Get all active peers
    pub fn get_active_peers(&self) -> impl Iterator<Item = &AwdlPeer> {
        self.peers.values().filter(|peer| peer.is_active())
    }

    /// Get master peer (if any)
    pub fn get_master_peer(&self) -> Option<&AwdlPeer> {
        self.peers.values().find(|peer| peer.is_master)
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get active peer count
    pub fn active_peer_count(&self) -> usize {
        self.peers.values().filter(|peer| peer.is_active()).count()
    }

    /// Clean up expired peers
    pub fn cleanup_expired_peers(&mut self) -> Vec<[u8; 6]> {
        let expired_peers: Vec<[u8; 6]> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.is_expired(self.peer_timeout))
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &expired_peers {
            self.peers.remove(addr);
        }

        expired_peers
    }

    /// Find peers by service
    pub fn find_peers_with_service(&self, service_name: &str) -> Vec<&AwdlPeer> {
        self.peers
            .values()
            .filter(|peer| peer.has_service(service_name))
            .collect()
    }

    /// Clear all peers
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    /// Initialize peer manager
    pub async fn init(&mut self) -> Result<()> {
        // Initialize peer manager - nothing specific needed for now
        Ok(())
    }

    /// Stop peer manager
    pub async fn stop(&mut self) -> Result<()> {
        // Clean up all peers
        self.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_creation() {
        let address = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let peer = AwdlPeer::new(address);
        
        assert_eq!(peer.address, address);
        assert_eq!(peer.state, AwdlPeerState::Discovered);
        assert!(!peer.is_master);
        assert_eq!(peer.services.len(), 0);
    }

    #[test]
    fn test_peer_activity() {
        let mut peer = AwdlPeer::new([0; 6]);
        
        assert_eq!(peer.state, AwdlPeerState::Discovered);
        
        peer.state = AwdlPeerState::Synchronized;
        peer.update_activity();
        
        assert_eq!(peer.state, AwdlPeerState::Active);
        assert!(peer.is_active());
    }

    #[test]
    fn test_peer_services() {
        let mut peer = AwdlPeer::new([0; 6]);
        
        peer.add_service("test-service".to_string(), vec![1, 2, 3]);
        
        assert!(peer.has_service("test-service"));
        assert_eq!(peer.get_service("test-service"), Some(&vec![1, 2, 3]));
        
        let removed = peer.remove_service("test-service");
        assert_eq!(removed, Some(vec![1, 2, 3]));
        assert!(!peer.has_service("test-service"));
    }

    #[test]
    fn test_peer_manager() {
        let mut manager = AwdlPeerManager::new(2, Duration::from_secs(30));
        
        let peer1 = AwdlPeer::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let peer2 = AwdlPeer::new([0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let peer3 = AwdlPeer::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        
        assert!(manager.add_peer(peer1));
        assert!(manager.add_peer(peer2));
        assert!(!manager.add_peer(peer3)); // Should fail due to max_peers limit
        
        assert_eq!(manager.peer_count(), 2);
    }
}