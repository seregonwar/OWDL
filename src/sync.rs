//! AWDL Synchronization management
//!
//! This module contains structures and functions for AWDL synchronization.


use serde::{Deserialize, Serialize};
use std::time::Duration;
use chrono::{DateTime, Utc};
use bytes::{Buf, BufMut};
use crate::{AwdlError, Result};

/// AWDL synchronization tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlSyncTreeNode {
    /// Node address
    pub address: [u8; 6],
    /// Distance from master
    pub distance: u8,
    /// Synchronization quality
    pub sync_quality: u8,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// AWDL synchronization parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlSyncParams {
    /// Availability window (AW) period in TU (Time Units)
    pub aw_period: u16,
    /// Action frame period in AW periods
    pub action_frame_period: u16,
    /// Availability window length in TU
    pub aw_length: u16,
    /// Availability window extension length in TU
    pub aw_ext_length: u16,
    /// Availability window common length in TU
    pub aw_common_length: u16,
    /// Remaining availability window length in TU
    pub aw_remaining: u16,
    /// Extension count
    pub ext_count: u8,
    /// Country code
    pub country_code: [u8; 2],
    /// Social channels
    pub social_channels: Vec<u8>,
}

impl Default for AwdlSyncParams {
    fn default() -> Self {
        Self {
            aw_period: 512,           // 512 TU = ~524ms
            action_frame_period: 4,   // Every 4 AW periods
            aw_length: 16,            // 16 TU = ~16ms
            aw_ext_length: 8,         // 8 TU = ~8ms
            aw_common_length: 4,      // 4 TU = ~4ms
            aw_remaining: 0,
            ext_count: 0,
            country_code: [b'U', b'S'], // Default to US
            social_channels: vec![6, 44, 149], // Default social channels
        }
    }
}

impl AwdlSyncParams {
    /// Parse synchronization parameters from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            return Err(AwdlError::Parse("Insufficient data for sync parameters".to_string()));
        }

        let mut buf = data;
        
        let aw_period = buf.get_u16();
        let action_frame_period = buf.get_u16();
        let aw_length = buf.get_u16();
        let aw_ext_length = buf.get_u16();
        let aw_common_length = buf.get_u16();
        let aw_remaining = buf.get_u16();
        let ext_count = buf.get_u8();
        
        let mut country_code = [0u8; 2];
        if buf.remaining() >= 2 {
            buf.copy_to_slice(&mut country_code);
        }
        
        // Parse social channels if available
        let mut social_channels = Vec::new();
        while buf.remaining() > 0 {
            social_channels.push(buf.get_u8());
        }
        
        if social_channels.is_empty() {
            social_channels = vec![6, 44, 149]; // Default channels
        }

        Ok(Self {
            aw_period,
            action_frame_period,
            aw_length,
            aw_ext_length,
            aw_common_length,
            aw_remaining,
            ext_count,
            country_code,
            social_channels,
        })
    }

    /// Serialize synchronization parameters to bytes
    pub fn serialize(&self, buf: &mut impl BufMut) -> Result<()> {
        buf.put_u16(self.aw_period);
        buf.put_u16(self.action_frame_period);
        buf.put_u16(self.aw_length);
        buf.put_u16(self.aw_ext_length);
        buf.put_u16(self.aw_common_length);
        buf.put_u16(self.aw_remaining);
        buf.put_u8(self.ext_count);
        buf.put_slice(&self.country_code);
        
        for &channel in &self.social_channels {
            buf.put_u8(channel);
        }
        
        Ok(())
    }

    /// Get serialized size
    pub fn size(&self) -> usize {
        13 + 2 + self.social_channels.len() // Fixed fields + country code + channels
    }

    /// Get availability window duration
    pub fn aw_duration(&self) -> Duration {
        Duration::from_micros((self.aw_length as u64) * 1024) // 1 TU = 1024 microseconds
    }

    /// Get availability window period duration
    pub fn aw_period_duration(&self) -> Duration {
        Duration::from_micros((self.aw_period as u64) * 1024)
    }

    /// Check if parameters are valid
    pub fn is_valid(&self) -> bool {
        self.aw_period > 0
            && self.aw_length > 0
            && self.aw_length <= self.aw_period
            && self.aw_common_length <= self.aw_length
            && !self.social_channels.is_empty()
    }
}

/// AWDL synchronization state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlSyncState {
    /// Current synchronization parameters
    pub params: AwdlSyncParams,
    /// Master timestamp (microseconds since epoch)
    pub master_timestamp: u64,
    /// Local timestamp when master timestamp was received
    pub local_timestamp: DateTime<Utc>,
    /// Synchronization tree
    pub sync_tree: Vec<AwdlSyncTreeNode>,
    /// Current availability window number
    pub current_aw: u32,
    /// Time offset from master (microseconds)
    pub time_offset: i64,
    /// Synchronization quality (0-255)
    pub sync_quality: u8,
    /// Is synchronized with master
    pub is_synchronized: bool,
    /// Last synchronization update time
    pub last_sync_update: DateTime<Utc>,
    /// Drift compensation
    pub drift_compensation: i32,
}

impl AwdlSyncState {
    /// Create new synchronization state
    pub fn new() -> Self {
        Self {
            params: AwdlSyncParams::default(),
            master_timestamp: 0,
            local_timestamp: Utc::now(),
            sync_tree: Vec::new(),
            current_aw: 0,
            time_offset: 0,
            sync_quality: 0,
            is_synchronized: false,
            last_sync_update: Utc::now(),
            drift_compensation: 0,
        }
    }

    /// Update synchronization parameters
    pub fn update_params(&mut self, params: AwdlSyncParams) {
        if params.is_valid() {
            self.params = params;
            log::debug!("Updated sync parameters: AW period={}, length={}", 
                self.params.aw_period, self.params.aw_length);
        } else {
            log::warn!("Invalid sync parameters received");
        }
    }

    /// Update master timestamp
    pub fn update_master_timestamp(&mut self, master_timestamp: u64) {
        let now = Utc::now();
        let old_offset = self.time_offset;
        
        // Calculate new time offset
        let local_us = now.timestamp_micros() as u64;
        self.time_offset = master_timestamp as i64 - local_us as i64;
        
        // Update drift compensation
        if self.is_synchronized {
            let drift = self.time_offset - old_offset;
            self.drift_compensation = (self.drift_compensation as i64 + drift / 10) as i32;
        }
        
        self.master_timestamp = master_timestamp;
        self.local_timestamp = now;
        self.last_sync_update = now;
        self.is_synchronized = true;
        
        log::debug!("Updated master timestamp: offset={}μs, drift={}μs", 
            self.time_offset, self.drift_compensation);
    }

    /// Get current master time in microseconds
    pub fn get_master_time(&self) -> u64 {
        if !self.is_synchronized {
            return 0;
        }
        
        let elapsed = (Utc::now() - self.local_timestamp).num_microseconds().unwrap_or(0) as u64;
        let compensated_elapsed = elapsed as i64 + self.drift_compensation as i64;
        
        (self.master_timestamp as i64 + compensated_elapsed) as u64
    }

    /// Get current availability window number
    pub fn get_current_aw(&self) -> u32 {
        if !self.is_synchronized {
            return 0;
        }
        
        let master_time = self.get_master_time();
        let aw_period_us = self.params.aw_period_duration().as_micros() as u64;
        
        (master_time / aw_period_us) as u32
    }

    /// Get time until next availability window
    pub fn time_to_next_aw(&self) -> Duration {
        if !self.is_synchronized {
            return Duration::from_secs(0);
        }
        
        let master_time = self.get_master_time();
        let aw_period_us = self.params.aw_period_duration().as_micros() as u64;
        let time_in_period = master_time % aw_period_us;
        let time_to_next = aw_period_us - time_in_period;
        
        Duration::from_micros(time_to_next)
    }

    /// Check if currently in availability window
    pub fn is_in_aw(&self) -> bool {
        if !self.is_synchronized {
            return false;
        }
        
        let master_time = self.get_master_time();
        let aw_period_us = self.params.aw_period_duration().as_micros() as u64;
        let aw_length_us = self.params.aw_duration().as_micros() as u64;
        let time_in_period = master_time % aw_period_us;
        
        time_in_period < aw_length_us
    }

    /// Get remaining time in current availability window
    pub fn aw_remaining_time(&self) -> Duration {
        if !self.is_synchronized || !self.is_in_aw() {
            return Duration::from_secs(0);
        }
        
        let master_time = self.get_master_time();
        let aw_period_us = self.params.aw_period_duration().as_micros() as u64;
        let aw_length_us = self.params.aw_duration().as_micros() as u64;
        let time_in_period = master_time % aw_period_us;
        let remaining = aw_length_us - time_in_period;
        
        Duration::from_micros(remaining)
    }

    /// Update synchronization tree
    pub fn update_sync_tree(&mut self, nodes: Vec<AwdlSyncTreeNode>) {
        self.sync_tree = nodes;
        
        // Update sync quality based on tree
        self.sync_quality = if self.sync_tree.is_empty() {
            0
        } else {
            let avg_quality: u32 = self.sync_tree.iter()
                .map(|node| node.sync_quality as u32)
                .sum::<u32>() / self.sync_tree.len() as u32;
            avg_quality.min(255) as u8
        };
    }

    /// Add node to synchronization tree
    pub fn add_sync_node(&mut self, node: AwdlSyncTreeNode) {
        // Remove existing node with same address
        self.sync_tree.retain(|n| n.address != node.address);
        
        // Add new node
        self.sync_tree.push(node);
        
        // Limit tree size
        if self.sync_tree.len() > 32 {
            self.sync_tree.sort_by_key(|n| n.distance);
            self.sync_tree.truncate(32);
        }
    }

    /// Remove node from synchronization tree
    pub fn remove_sync_node(&mut self, address: &[u8; 6]) {
        self.sync_tree.retain(|node| node.address != *address);
    }

    /// Get synchronization tree node by address
    pub fn get_sync_node(&self, address: &[u8; 6]) -> Option<&AwdlSyncTreeNode> {
        self.sync_tree.iter().find(|node| node.address == *address)
    }

    /// Check if synchronization is valid
    pub fn is_sync_valid(&self) -> bool {
        if !self.is_synchronized {
            return false;
        }
        
        let sync_age = (Utc::now() - self.last_sync_update).to_std().unwrap_or_default();
        sync_age < Duration::from_secs(5) // Sync is valid for 5 seconds
    }

    /// Reset synchronization state
    pub fn reset(&mut self) {
        self.master_timestamp = 0;
        self.local_timestamp = Utc::now();
        self.time_offset = 0;
        self.sync_quality = 0;
        self.is_synchronized = false;
        self.sync_tree.clear();
        self.drift_compensation = 0;
        
        log::info!("Synchronization state reset");
    }

    /// Get synchronization statistics
    pub fn get_sync_stats(&self) -> SyncStats {
        SyncStats {
            is_synchronized: self.is_synchronized,
            time_offset: self.time_offset,
            sync_quality: self.sync_quality,
            tree_size: self.sync_tree.len(),
            drift_compensation: self.drift_compensation,
            sync_age: (Utc::now() - self.last_sync_update).to_std().unwrap_or_default(),
        }
    }
}

impl Default for AwdlSyncState {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    pub is_synchronized: bool,
    pub time_offset: i64,
    pub sync_quality: u8,
    pub tree_size: usize,
    pub drift_compensation: i32,
    pub sync_age: Duration,
}

/// Synchronization manager
#[derive(Debug)]
pub struct AwdlSyncManager {
    state: AwdlSyncState,
    sync_timeout: Duration,
}

impl AwdlSyncManager {
    /// Create new synchronization manager
    pub fn new() -> Self {
        Self {
            state: AwdlSyncState::new(),
            sync_timeout: Duration::from_secs(10),
        }
    }

    /// Get synchronization state
    pub fn get_state(&self) -> &AwdlSyncState {
        &self.state
    }

    /// Get mutable synchronization state
    pub fn get_state_mut(&mut self) -> &mut AwdlSyncState {
        &mut self.state
    }

    /// Process synchronization update
    pub fn process_sync_update(&mut self, params: AwdlSyncParams, master_timestamp: u64) {
        self.state.update_params(params);
        self.state.update_master_timestamp(master_timestamp);
    }

    /// Check and handle synchronization timeout
    pub fn check_sync_timeout(&mut self) -> bool {
        if self.state.is_synchronized {
            let sync_age = Utc::now().signed_duration_since(self.state.last_sync_update).to_std().unwrap_or(Duration::ZERO);
            if sync_age > self.sync_timeout {
                log::warn!("Synchronization timeout after {:?}", sync_age);
                self.state.reset();
                return true;
            }
        }
        false
    }

    /// Get next action time (when to send next frame or perform action)
    pub fn get_next_action_time(&self) -> Option<DateTime<Utc>> {
        if !self.state.is_synchronized {
            return None;
        }
        
        let time_to_next_aw = self.state.time_to_next_aw();
        Some(Utc::now() + chrono::Duration::from_std(time_to_next_aw).unwrap_or_default())
    }

    /// Initialize sync manager
    pub async fn init(&mut self) -> Result<()> {
        // Initialize sync manager - reset state
        self.state.reset();
        Ok(())
    }

    /// Stop sync manager
    pub async fn stop(&mut self) -> Result<()> {
        // Reset synchronization state
        self.state.reset();
        Ok(())
    }
}

impl Default for AwdlSyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_params_default() {
        let params = AwdlSyncParams::default();
        
        assert!(params.is_valid());
        assert_eq!(params.aw_period, 512);
        assert_eq!(params.aw_length, 16);
        assert!(!params.social_channels.is_empty());
    }

    #[test]
    fn test_sync_state_creation() {
        let state = AwdlSyncState::new();
        
        assert!(!state.is_synchronized);
        assert_eq!(state.sync_quality, 0);
        assert_eq!(state.time_offset, 0);
        assert!(state.sync_tree.is_empty());
    }

    #[test]
    fn test_sync_manager() {
        let mut manager = AwdlSyncManager::new();
        
        assert!(!manager.get_state().is_synchronized);
        
        let params = AwdlSyncParams::default();
        let timestamp = 1000000; // 1 second in microseconds
        
        manager.process_sync_update(params, timestamp);
        
        assert!(manager.get_state().is_synchronized);
        assert_eq!(manager.get_state().master_timestamp, timestamp);
    }

    #[test]
    fn test_aw_calculations() {
        let mut state = AwdlSyncState::new();
        
        // Set up synchronization
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        
        state.update_master_timestamp(timestamp);
        
        assert!(state.is_synchronized);
        
        let current_aw = state.get_current_aw();
        let time_to_next = state.time_to_next_aw();
        
        assert!(current_aw > 0);
        assert!(time_to_next <= state.params.aw_period_duration());
    }
}