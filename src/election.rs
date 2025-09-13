//! AWDL Election management
//!
//! This module contains structures and functions for AWDL master election.


use serde::{Deserialize, Serialize};
use std::time::Duration;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use crate::{AwdlError, Result};

/// AWDL election metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwdlElectionMetric {
    /// Self metric value
    pub self_metric: u32,
    /// Master metric value
    pub master_metric: u32,
    /// Self counter
    pub self_counter: u32,
    /// Master counter
    pub master_counter: u32,
}

impl AwdlElectionMetric {
    /// Create new election metric
    pub fn new() -> Self {
        Self {
            self_metric: 0,
            master_metric: 0,
            self_counter: 0,
            master_counter: 0,
        }
    }

    /// Compare with another metric to determine if this is better
    pub fn is_better_than(&self, other: &AwdlElectionMetric) -> bool {
        // Higher metric is better
        if self.self_metric != other.master_metric {
            return self.self_metric > other.master_metric;
        }
        
        // If metrics are equal, higher counter is better
        self.self_counter > other.master_counter
    }

    /// Update self metric
    pub fn update_self_metric(&mut self, metric: u32) {
        self.self_metric = metric;
        self.self_counter = self.self_counter.wrapping_add(1);
    }

    /// Update master metric
    pub fn update_master_metric(&mut self, metric: u32, counter: u32) {
        self.master_metric = metric;
        self.master_counter = counter;
    }

    /// Reset metrics
    pub fn reset(&mut self) {
        self.self_metric = 0;
        self.master_metric = 0;
        self.self_counter = 0;
        self.master_counter = 0;
    }
}

impl Default for AwdlElectionMetric {
    fn default() -> Self {
        Self::new()
    }
}

/// AWDL election parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlElectionParams {
    /// Election ID
    pub election_id: u16,
    /// Distance to master
    pub distance_to_master: u8,
    /// Master channel
    pub master_channel: u8,
    /// Synchronization tree height
    pub height: u8,
    /// Election flags
    pub flags: u8,
    /// Reserved field
    pub reserved: u16,
}

impl AwdlElectionParams {
    /// Create new election parameters
    pub fn new() -> Self {
        Self {
            election_id: 0,
            distance_to_master: 15, // Max valid distance
            master_channel: 0,
            height: 0,
            flags: 0,
            reserved: 0,
        }
    }

    /// Parse election parameters from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(AwdlError::Parse("Insufficient data for election parameters".to_string()));
        }

        let election_id = u16::from_le_bytes([data[0], data[1]]);
        let distance_to_master = data[2];
        let master_channel = data[3];
        let height = data[4];
        let flags = data[5];
        let reserved = u16::from_le_bytes([data[6], data[7]]);

        Ok(Self {
            election_id,
            distance_to_master,
            master_channel,
            height,
            flags,
            reserved,
        })
    }

    /// Serialize election parameters to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&self.election_id.to_le_bytes());
        data.push(self.distance_to_master);
        data.push(self.master_channel);
        data.push(self.height);
        data.push(self.flags);
        data.extend_from_slice(&self.reserved.to_le_bytes());
        data
    }

    /// Get serialized size
    pub fn size() -> usize {
        8
    }

    /// Check if this node is master
    pub fn is_master(&self) -> bool {
        self.distance_to_master == 0
    }

    /// Check if election parameters are valid
    pub fn is_valid(&self) -> bool {
        self.distance_to_master <= 15 && // Max distance in AWDL
        self.height <= 15 // Max tree height
    }
}

impl Default for AwdlElectionParams {
    fn default() -> Self {
        Self::new()
    }
}

/// AWDL election state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlElectionState {
    /// Current election parameters
    pub params: AwdlElectionParams,
    /// Election metrics
    pub metric: AwdlElectionMetric,
    /// Master address
    pub master_address: [u8; 6],
    /// Self address
    pub self_address: [u8; 6],
    /// Election tree (address -> distance)
    pub election_tree: HashMap<[u8; 6], u8>,
    /// Last election update timestamp
    pub last_election_update: DateTime<Utc>,
    /// Election timeout
    pub election_timeout: Duration,
    /// Is currently master
    pub is_master: bool,
    /// Election in progress
    pub election_in_progress: bool,
    /// Master election counter
    pub master_election_counter: u32,
}

impl AwdlElectionState {
    /// Create new election state
    pub fn new(self_address: [u8; 6]) -> Self {
        Self {
            params: AwdlElectionParams::new(),
            metric: AwdlElectionMetric::new(),
            master_address: [0; 6],
            self_address,
            election_tree: HashMap::new(),
            last_election_update: Utc::now(),
            election_timeout: Duration::from_secs(5),
            is_master: false,
            election_in_progress: false,
            master_election_counter: 0,
        }
    }

    /// Start election process
    pub fn start_election(&mut self) {
        log::info!("Starting AWDL election process");
        
        self.election_in_progress = true;
        self.params.election_id = self.params.election_id.wrapping_add(1);
        self.last_election_update = Utc::now();
        
        // Calculate self metric based on various factors
        self.calculate_self_metric();
        
        // Initially assume we are the master
        self.become_master();
    }

    /// Process election parameters from another node
    pub fn process_election_params(&mut self, params: AwdlElectionParams, sender_address: [u8; 6]) -> bool {
        let mut election_changed = false;
        
        // Update election tree
        self.election_tree.insert(sender_address, params.distance_to_master + 1);
        
        // Check if we should update our master
        if self.should_update_master(&params, &sender_address) {
            self.update_master(params, sender_address);
            election_changed = true;
        }
        
        self.last_election_update = Utc::now();
        election_changed
    }

    /// Check if we should update our master
    fn should_update_master(&self, params: &AwdlElectionParams, sender_address: &[u8; 6]) -> bool {
        // If we're not synchronized or this is a newer election
        if params.election_id > self.params.election_id {
            return true;
        }
        
        // If same election ID, check distance
        if params.election_id == self.params.election_id {
            let new_distance = params.distance_to_master + 1;
            if new_distance < self.params.distance_to_master {
                return true;
            }
            
            // If same distance, use address as tiebreaker
            if new_distance == self.params.distance_to_master {
                return sender_address < &self.master_address;
            }
        }
        
        false
    }

    /// Update master information
    fn update_master(&mut self, params: AwdlElectionParams, sender_address: [u8; 6]) {
        log::info!("Updating master to {:02x?}, distance: {}", 
            sender_address, params.distance_to_master + 1);
        
        self.params.election_id = params.election_id;
        self.params.distance_to_master = params.distance_to_master + 1;
        self.params.master_channel = params.master_channel;
        self.params.height = params.height + 1;
        
        // If distance is 1, this sender is the master
        if params.distance_to_master == 0 {
            self.master_address = sender_address;
        } else {
            // Otherwise, keep the existing master address
            // In a real implementation, we'd need to track the actual master
        }
        
        self.is_master = false;
        self.master_election_counter = self.master_election_counter.wrapping_add(1);
    }

    /// Become master
    fn become_master(&mut self) {
        log::info!("Becoming AWDL master");
        
        self.is_master = true;
        self.master_address = self.self_address;
        self.params.distance_to_master = 0;
        self.params.height = 0;
        self.master_election_counter = self.master_election_counter.wrapping_add(1);
    }

    /// Calculate self metric based on various factors
    fn calculate_self_metric(&mut self) {
        // In a real implementation, this would consider:
        // - Battery level
        // - AC power status
        // - Network connectivity
        // - Device capabilities
        // - Load balancing factors
        
        let mut metric = 100; // Base metric
        
        // Add randomness to avoid ties
        metric += (self.self_address[5] as u32) % 50;
        
        // Consider number of peers (more peers = better master candidate)
        metric += (self.election_tree.len() as u32) * 10;
        
        self.metric.update_self_metric(metric);
        
        log::debug!("Calculated self metric: {}", metric);
    }

    /// Check election timeout
    pub fn check_election_timeout(&mut self) -> bool {
        let elapsed = (Utc::now() - self.last_election_update).to_std().unwrap_or_default();
        
        if elapsed > self.election_timeout {
            log::warn!("Election timeout after {:?}", elapsed);
            
            if !self.is_master {
                // Start new election if we haven't heard from master
                self.start_election();
                return true;
            }
        }
        
        false
    }

    /// Get election parameters for transmission
    pub fn get_election_params_for_tx(&self) -> AwdlElectionParams {
        self.params.clone()
    }

    /// Update election tree with peer information
    pub fn update_election_tree(&mut self, address: [u8; 6], distance: u8) {
        if distance < 255 {
            self.election_tree.insert(address, distance);
        } else {
            self.election_tree.remove(&address);
        }
    }

    /// Remove peer from election tree
    pub fn remove_peer_from_election(&mut self, address: &[u8; 6]) {
        self.election_tree.remove(address);
        
        // If this was our master, start new election
        if *address == self.master_address && !self.is_master {
            log::info!("Master {:02x?} removed, starting new election", address);
            self.start_election();
        }
    }

    /// Get election statistics
    pub fn get_election_stats(&self) -> ElectionStats {
        ElectionStats {
            is_master: self.is_master,
            election_id: self.params.election_id,
            distance_to_master: self.params.distance_to_master,
            master_address: self.master_address,
            tree_size: self.election_tree.len(),
            self_metric: self.metric.self_metric,
            master_metric: self.metric.master_metric,
            election_age: Utc::now().signed_duration_since(self.last_election_update).to_std().unwrap_or(Duration::ZERO),
        }
    }

    /// Reset election state
    pub fn reset(&mut self) {
        self.params = AwdlElectionParams::new();
        self.metric.reset();
        self.master_address = [0; 6];
        self.election_tree.clear();
        self.is_master = false;
        self.election_in_progress = false;
        self.master_election_counter = 0;
        self.last_election_update = Utc::now();
        
        log::info!("Election state reset");
    }

    /// Check if election state is valid
    pub fn is_valid(&self) -> bool {
        self.params.is_valid() &&
        (self.is_master || self.master_address != [0; 6])
    }
}

/// Election statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionStats {
    pub is_master: bool,
    pub election_id: u16,
    pub distance_to_master: u8,
    pub master_address: [u8; 6],
    pub tree_size: usize,
    pub self_metric: u32,
    pub master_metric: u32,
    pub election_age: Duration,
}

/// AWDL election manager
#[derive(Debug)]
pub struct AwdlElectionManager {
    state: AwdlElectionState,
    election_interval: Duration,
    last_election_run: DateTime<Utc>,
}

impl AwdlElectionManager {
    /// Create new election manager
    pub fn new(self_address: [u8; 6]) -> Self {
        Self {
            state: AwdlElectionState::new(self_address),
            election_interval: Duration::from_secs(30), // Run election every 30 seconds
            last_election_run: Utc::now(),
        }
    }

    /// Get election state
    pub fn get_state(&self) -> &AwdlElectionState {
        &self.state
    }

    /// Get mutable election state
    pub fn get_state_mut(&mut self) -> &mut AwdlElectionState {
        &mut self.state
    }

    /// Run election process
    pub fn run_election(&mut self) -> bool {
        let now = Utc::now();
        let mut election_changed = false;
        
        // Check if it's time to run election
        if (now - self.last_election_run).to_std().unwrap_or_default() >= self.election_interval {
            if !self.state.is_master {
                self.state.start_election();
                election_changed = true;
            }
            self.last_election_run = now;
        }
        
        // Check for election timeout
        if self.state.check_election_timeout() {
            election_changed = true;
        }
        
        election_changed
    }

    /// Process incoming election parameters
    pub fn process_election_update(&mut self, params: AwdlElectionParams, sender_address: [u8; 6]) -> bool {
        self.state.process_election_params(params, sender_address)
    }

    /// Handle peer removal
    pub fn handle_peer_removed(&mut self, address: &[u8; 6]) {
        self.state.remove_peer_from_election(address);
    }

    /// Force election restart
    pub fn force_election(&mut self) {
        log::info!("Forcing election restart");
        self.state.start_election();
        self.last_election_run = Utc::now();
    }

    /// Get next election time
    pub fn get_next_election_time(&self) -> DateTime<Utc> {
        self.last_election_run + chrono::Duration::from_std(self.election_interval).unwrap_or_default()
    }

    /// Initialize election manager
    pub async fn init(&mut self) -> Result<()> {
        // Initialize election manager - reset state
        self.state.reset();
        self.last_election_run = Utc::now();
        Ok(())
    }

    /// Stop election manager
    pub async fn stop(&mut self) -> Result<()> {
        // Reset election state
        self.state.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_election_metric() {
        let mut metric = AwdlElectionMetric::new();
        
        metric.update_self_metric(100);
        assert_eq!(metric.self_metric, 100);
        assert_eq!(metric.self_counter, 1);
        
        let other_metric = AwdlElectionMetric {
            self_metric: 0,
            master_metric: 50,
            self_counter: 0,
            master_counter: 0,
        };
        
        assert!(metric.is_better_than(&other_metric));
    }

    #[test]
    fn test_election_params() {
        let params = AwdlElectionParams::new();
        
        assert!(params.is_valid());
        assert!(!params.is_master());
        
        let serialized = params.serialize();
        assert_eq!(serialized.len(), AwdlElectionParams::size());
        
        let parsed = AwdlElectionParams::parse(&serialized).unwrap();
        assert_eq!(parsed.election_id, params.election_id);
        assert_eq!(parsed.distance_to_master, params.distance_to_master);
    }

    #[test]
    fn test_election_state() {
        let self_addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut state = AwdlElectionState::new(self_addr);
        
        assert_eq!(state.self_address, self_addr);
        assert!(!state.is_master);
        
        state.start_election();
        assert!(state.is_master);
        assert_eq!(state.master_address, self_addr);
        assert_eq!(state.params.distance_to_master, 0);
    }

    #[test]
    fn test_election_manager() {
        let self_addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut manager = AwdlElectionManager::new(self_addr);
        
        assert!(!manager.get_state().is_master);
        
        manager.force_election();
        assert!(manager.get_state().is_master);
        
        let stats = manager.get_state().get_election_stats();
        assert!(stats.is_master);
        assert_eq!(stats.master_address, self_addr);
    }
}