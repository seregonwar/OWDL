//! AWDL Channel management
//!
//! This module contains structures and functions for AWDL channel management.


use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use crate::{AwdlError, Result};

/// AWDL channel encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlChanEncoding {
    /// Legacy encoding
    Legacy = 0,
    /// High Throughput (HT) encoding
    Ht = 1,
    /// Very High Throughput (VHT) encoding
    Vht = 2,
    /// High Efficiency (HE) encoding
    He = 3,
}

impl AwdlChanEncoding {
    /// Parse encoding from u8
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(AwdlChanEncoding::Legacy),
            1 => Ok(AwdlChanEncoding::Ht),
            2 => Ok(AwdlChanEncoding::Vht),
            3 => Ok(AwdlChanEncoding::He),
            _ => Err(AwdlError::Parse(format!("Invalid channel encoding: {}", value))),
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get encoding name
    pub fn name(&self) -> &'static str {
        match self {
            AwdlChanEncoding::Legacy => "Legacy",
            AwdlChanEncoding::Ht => "HT",
            AwdlChanEncoding::Vht => "VHT",
            AwdlChanEncoding::He => "HE",
        }
    }

    /// Check if encoding supports multiple streams
    pub fn supports_mimo(&self) -> bool {
        matches!(self, AwdlChanEncoding::Ht | AwdlChanEncoding::Vht | AwdlChanEncoding::He)
    }

    /// Get maximum bandwidth for encoding
    pub fn max_bandwidth(&self) -> u16 {
        match self {
            AwdlChanEncoding::Legacy => 20,
            AwdlChanEncoding::Ht => 40,
            AwdlChanEncoding::Vht => 160,
            AwdlChanEncoding::He => 160,
        }
    }
}

impl Default for AwdlChanEncoding {
    fn default() -> Self {
        AwdlChanEncoding::Legacy
    }
}

/// AWDL channel bandwidth
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlChanBandwidth {
    /// 20 MHz bandwidth
    Bw20 = 0,
    /// 40 MHz bandwidth
    Bw40 = 1,
    /// 80 MHz bandwidth
    Bw80 = 2,
    /// 160 MHz bandwidth
    Bw160 = 3,
}

impl AwdlChanBandwidth {
    /// Parse bandwidth from u8
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(AwdlChanBandwidth::Bw20),
            1 => Ok(AwdlChanBandwidth::Bw40),
            2 => Ok(AwdlChanBandwidth::Bw80),
            3 => Ok(AwdlChanBandwidth::Bw160),
            _ => Err(AwdlError::Parse(format!("Invalid channel bandwidth: {}", value))),
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Get bandwidth in MHz
    pub fn mhz(&self) -> u16 {
        match self {
            AwdlChanBandwidth::Bw20 => 20,
            AwdlChanBandwidth::Bw40 => 40,
            AwdlChanBandwidth::Bw80 => 80,
            AwdlChanBandwidth::Bw160 => 160,
        }
    }

    /// Get bandwidth name
    pub fn name(&self) -> &'static str {
        match self {
            AwdlChanBandwidth::Bw20 => "20MHz",
            AwdlChanBandwidth::Bw40 => "40MHz",
            AwdlChanBandwidth::Bw80 => "80MHz",
            AwdlChanBandwidth::Bw160 => "160MHz",
        }
    }
}

impl Default for AwdlChanBandwidth {
    fn default() -> Self {
        AwdlChanBandwidth::Bw20
    }
}

/// AWDL channel information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwdlChan {
    /// Channel number
    pub number: u8,
    /// Channel encoding
    pub encoding: AwdlChanEncoding,
    /// Channel bandwidth
    pub bandwidth: AwdlChanBandwidth,
    /// Channel flags
    pub flags: u8,
    /// Operating class
    pub op_class: u8,
}

impl AwdlChan {
    /// Create new channel
    pub fn new(number: u8) -> Self {
        Self {
            number,
            encoding: AwdlChanEncoding::default(),
            bandwidth: AwdlChanBandwidth::default(),
            flags: 0,
            op_class: 0,
        }
    }

    /// Create channel with encoding and bandwidth
    pub fn with_encoding_bandwidth(number: u8, encoding: AwdlChanEncoding, bandwidth: AwdlChanBandwidth) -> Self {
        Self {
            number,
            encoding,
            bandwidth,
            flags: 0,
            op_class: Self::calculate_op_class(number, bandwidth),
        }
    }

    /// Parse channel from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(AwdlError::Parse("Insufficient data for channel".to_string()));
        }

        let number = data[0];
        let encoding = AwdlChanEncoding::from_u8(data[1])?;
        let bandwidth = AwdlChanBandwidth::from_u8(data[2])?;
        let flags = data[3];
        let op_class = data[4];

        Ok(Self {
            number,
            encoding,
            bandwidth,
            flags,
            op_class,
        })
    }

    /// Serialize channel to bytes
    pub fn serialize(&self) -> Vec<u8> {
        vec![
            self.number,
            self.encoding.to_u8(),
            self.bandwidth.to_u8(),
            self.flags,
            self.op_class,
        ]
    }

    /// Get serialized size
    pub fn size() -> usize {
        5
    }

    /// Get channel frequency in MHz
    pub fn frequency(&self) -> u16 {
        Self::channel_to_frequency(self.number)
    }

    /// Convert channel number to frequency
    pub fn channel_to_frequency(channel: u8) -> u16 {
        match channel {
            // 2.4 GHz band
            1..=14 => 2412 + (channel as u16 - 1) * 5,
            // 5 GHz band
            36..=64 => 5000 + channel as u16 * 5,
            100..=144 => 5000 + channel as u16 * 5,
            149..=165 => 5000 + channel as u16 * 5,
            // 6 GHz band (simplified)
            1..=233 if channel > 200 => 5950 + (channel as u16 - 1) * 5,
            _ => 0, // Invalid channel
        }
    }

    /// Convert frequency to channel number
    pub fn frequency_to_channel(freq: u16) -> u8 {
        match freq {
            // 2.4 GHz band
            2412..=2484 => ((freq - 2412) / 5 + 1) as u8,
            // 5 GHz band
            5000..=5825 => ((freq - 5000) / 5) as u8,
            // 6 GHz band (simplified)
            5950..=7115 => ((freq - 5950) / 5 + 1) as u8,
            _ => 0, // Invalid frequency
        }
    }

    /// Calculate operating class for channel and bandwidth
    fn calculate_op_class(channel: u8, bandwidth: AwdlChanBandwidth) -> u8 {
        match (Self::get_band(channel), bandwidth) {
            (Band::Band24, AwdlChanBandwidth::Bw20) => 81,
            (Band::Band24, AwdlChanBandwidth::Bw40) => 83,
            (Band::Band5, AwdlChanBandwidth::Bw20) => 115,
            (Band::Band5, AwdlChanBandwidth::Bw40) => 116,
            (Band::Band5, AwdlChanBandwidth::Bw80) => 128,
            (Band::Band5, AwdlChanBandwidth::Bw160) => 129,
            (Band::Band6, AwdlChanBandwidth::Bw20) => 131,
            (Band::Band6, AwdlChanBandwidth::Bw40) => 132,
            (Band::Band6, AwdlChanBandwidth::Bw80) => 133,
            (Band::Band6, AwdlChanBandwidth::Bw160) => 134,
            _ => 0, // Unknown
        }
    }

    /// Get band for channel
    fn get_band(channel: u8) -> Band {
        match channel {
            1..=14 => Band::Band24,
            36..=165 => Band::Band5,
            1..=233 if channel > 200 => Band::Band6,
            _ => Band::Unknown,
        }
    }

    /// Check if channel is valid
    pub fn is_valid(&self) -> bool {
        self.number > 0 && self.frequency() > 0
    }

    /// Check if channel is in 2.4 GHz band
    pub fn is_2ghz(&self) -> bool {
        matches!(self.number, 1..=14)
    }

    /// Check if channel is in 5 GHz band
    pub fn is_5ghz(&self) -> bool {
        matches!(self.number, 36..=165)
    }

    /// Check if channel is in 6 GHz band
    pub fn is_6ghz(&self) -> bool {
        self.number > 200
    }

    /// Get channel description
    pub fn description(&self) -> String {
        format!(
            "Ch{} ({} MHz, {}, {})",
            self.number,
            self.frequency(),
            self.encoding.name(),
            self.bandwidth.name()
        )
    }

    /// Check if channels overlap
    pub fn overlaps_with(&self, other: &AwdlChan) -> bool {
        let self_freq = self.frequency();
        let other_freq = other.frequency();
        let self_bw = self.bandwidth.mhz();
        let other_bw = other.bandwidth.mhz();
        
        let self_start = self_freq - self_bw / 2;
        let self_end = self_freq + self_bw / 2;
        let other_start = other_freq - other_bw / 2;
        let other_end = other_freq + other_bw / 2;
        
        !(self_end <= other_start || other_end <= self_start)
    }
}

impl Default for AwdlChan {
    fn default() -> Self {
        Self::new(6) // Default to channel 6 (2.4 GHz)
    }
}

/// Frequency band
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Band {
    Band24,
    Band5,
    Band6,
    Unknown,
}

/// Channel sequence for AWDL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlChannelSequence {
    /// List of channels in sequence
    pub channels: Vec<AwdlChan>,
    /// Current channel index
    pub current_index: usize,
    /// Sequence step duration
    pub step_duration: Duration,
    /// Last channel change time
    pub last_change: DateTime<Utc>,
    /// Sequence ID
    pub sequence_id: u16,
}

impl AwdlChannelSequence {
    /// Create new channel sequence
    pub fn new(channels: Vec<AwdlChan>) -> Self {
        Self {
            channels,
            current_index: 0,
            step_duration: Duration::from_millis(100), // 100ms per channel
            last_change: Utc::now(),
            sequence_id: 0,
        }
    }

    /// Create default social channel sequence
    pub fn default_social() -> Self {
        let channels = vec![
            AwdlChan::new(6),   // 2.4 GHz
            AwdlChan::new(44),  // 5 GHz
            AwdlChan::new(149), // 5 GHz
        ];
        Self::new(channels)
    }

    /// Get current channel
    pub fn current_channel(&self) -> Option<&AwdlChan> {
        self.channels.get(self.current_index)
    }

    /// Advance to next channel if it's time
    pub fn advance_if_time(&mut self) -> bool {
        if self.channels.is_empty() {
            return false;
        }

        let now = Utc::now();
        if (now - self.last_change).to_std().unwrap_or_default() >= self.step_duration {
            self.current_index = (self.current_index + 1) % self.channels.len();
            self.last_change = now;
            
            log::debug!("Advanced to channel {}: {}", 
                self.current_index, 
                self.current_channel().map(|c| c.description()).unwrap_or_default());
            
            return true;
        }
        
        false
    }

    /// Force advance to next channel
    pub fn advance(&mut self) {
        if !self.channels.is_empty() {
            self.current_index = (self.current_index + 1) % self.channels.len();
            self.last_change = Utc::now();
        }
    }

    /// Set channel by index
    pub fn set_channel_index(&mut self, index: usize) -> bool {
        if index < self.channels.len() {
            self.current_index = index;
            self.last_change = Utc::now();
            true
        } else {
            false
        }
    }

    /// Add channel to sequence
    pub fn add_channel(&mut self, channel: AwdlChan) {
        if channel.is_valid() {
            self.channels.push(channel);
        }
    }

    /// Remove channel from sequence
    pub fn remove_channel(&mut self, channel_num: u8) {
        self.channels.retain(|c| c.number != channel_num);
        
        // Adjust current index if needed
        if self.current_index >= self.channels.len() && !self.channels.is_empty() {
            self.current_index = 0;
        }
    }

    /// Get time until next channel change
    pub fn time_to_next_change(&self) -> Duration {
        let elapsed = (Utc::now() - self.last_change).to_std().unwrap_or_default();
        if elapsed >= self.step_duration {
            Duration::from_secs(0)
        } else {
            self.step_duration - elapsed
        }
    }

    /// Update sequence parameters
    pub fn update_sequence(&mut self, channels: Vec<AwdlChan>, step_duration: Duration) {
        self.channels = channels;
        self.step_duration = step_duration;
        self.current_index = 0;
        self.last_change = Utc::now();
        self.sequence_id = self.sequence_id.wrapping_add(1);
    }

    /// Check if sequence is valid
    pub fn is_valid(&self) -> bool {
        !self.channels.is_empty() && self.channels.iter().all(|c| c.is_valid())
    }
}

/// Channel manager for AWDL
#[derive(Debug, Serialize, Deserialize)]
pub struct AwdlChannelManager {
    /// Social channel sequence
    pub social_sequence: AwdlChannelSequence,
    /// Data channel
    pub data_channel: Option<AwdlChan>,
    /// Channel statistics
    pub channel_stats: HashMap<u8, ChannelStats>,
    /// Preferred channels
    pub preferred_channels: Vec<u8>,
    /// Blocked channels
    pub blocked_channels: Vec<u8>,
}

impl AwdlChannelManager {
    /// Create new channel manager
    pub fn new() -> Self {
        Self {
            social_sequence: AwdlChannelSequence::default_social(),
            data_channel: None,
            channel_stats: HashMap::new(),
            preferred_channels: vec![6, 44, 149], // Default preferred channels
            blocked_channels: Vec::new(),
        }
    }

    /// Update social channel sequence
    pub fn update_social_sequence(&mut self, channels: Vec<AwdlChan>) {
        let step_duration = self.social_sequence.step_duration;
        self.social_sequence.update_sequence(channels, step_duration);
        
        log::info!("Updated social channel sequence with {} channels", 
            self.social_sequence.channels.len());
    }

    /// Set data channel
    pub fn set_data_channel(&mut self, channel: AwdlChan) {
        if channel.is_valid() {
            log::info!("Set data channel to {}", channel.description());
            self.data_channel = Some(channel);
        }
    }

    /// Get current social channel
    pub fn get_current_social_channel(&self) -> Option<&AwdlChan> {
        self.social_sequence.current_channel()
    }

    /// Advance social channel sequence
    pub fn advance_social_sequence(&mut self) -> bool {
        self.social_sequence.advance_if_time()
    }

    /// Update channel statistics
    pub fn update_channel_stats(&mut self, channel: u8, rssi: i8, noise: i8) {
        let stats = self.channel_stats.entry(channel).or_insert_with(ChannelStats::new);
        stats.update(rssi, noise);
    }

    /// Get best channel for data communication
    pub fn get_best_data_channel(&self) -> Option<AwdlChan> {
        let mut best_channel = None;
        let mut best_score = i32::MIN;
        
        for &channel_num in &self.preferred_channels {
            if self.blocked_channels.contains(&channel_num) {
                continue;
            }
            
            let score = if let Some(stats) = self.channel_stats.get(&channel_num) {
                stats.get_quality_score()
            } else {
                0 // No stats available
            };
            
            if score > best_score {
                best_score = score;
                best_channel = Some(AwdlChan::new(channel_num));
            }
        }
        
        best_channel
    }

    /// Block channel
    pub fn block_channel(&mut self, channel: u8) {
        if !self.blocked_channels.contains(&channel) {
            self.blocked_channels.push(channel);
            log::info!("Blocked channel {}", channel);
        }
    }

    /// Unblock channel
    pub fn unblock_channel(&mut self, channel: u8) {
        self.blocked_channels.retain(|&c| c != channel);
        log::info!("Unblocked channel {}", channel);
    }

    /// Check if channel is blocked
    pub fn is_channel_blocked(&self, channel: u8) -> bool {
        self.blocked_channels.contains(&channel)
    }

    /// Get channel statistics
    pub fn get_channel_stats(&self, channel: u8) -> Option<&ChannelStats> {
        self.channel_stats.get(&channel)
    }

    /// Initialize channel manager
    pub async fn init(&mut self) -> Result<()> {
        // Reset channel statistics and sequences
        self.channel_stats.clear();
        self.data_channel = None;
        self.social_sequence = AwdlChannelSequence::default_social();
        Ok(())
    }

    /// Stop channel manager
    pub async fn stop(&mut self) -> Result<()> {
        // Clear all channel data
        self.channel_stats.clear();
        self.data_channel = None;
        Ok(())
    }
}

impl Default for AwdlChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    /// Average RSSI
    pub avg_rssi: f32,
    /// Average noise
    pub avg_noise: f32,
    /// Sample count
    pub sample_count: u32,
    /// Last update time
    pub last_update: DateTime<Utc>,
}

impl ChannelStats {
    /// Create new channel statistics
    pub fn new() -> Self {
        Self {
            avg_rssi: 0.0,
            avg_noise: 0.0,
            sample_count: 0,
            last_update: Utc::now(),
        }
    }

    /// Update statistics with new sample
    pub fn update(&mut self, rssi: i8, noise: i8) {
        let alpha = 0.1; // Exponential moving average factor
        
        if self.sample_count == 0 {
            self.avg_rssi = rssi as f32;
            self.avg_noise = noise as f32;
        } else {
            self.avg_rssi = (1.0 - alpha) * self.avg_rssi + alpha * (rssi as f32);
            self.avg_noise = (1.0 - alpha) * self.avg_noise + alpha * (noise as f32);
        }
        
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_update = Utc::now();
    }

    /// Get signal-to-noise ratio
    pub fn get_snr(&self) -> f32 {
        self.avg_rssi - self.avg_noise
    }

    /// Get quality score (higher is better)
    pub fn get_quality_score(&self) -> i32 {
        if self.sample_count == 0 {
            return 0;
        }
        
        let snr = self.get_snr();
        let age_penalty = (Utc::now() - self.last_update).num_seconds() as f32 * 0.1;
        
        (snr - age_penalty) as i32
    }
}

impl Default for ChannelStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_encoding() {
        let encoding = AwdlChanEncoding::Ht;
        assert_eq!(encoding.to_u8(), 1);
        assert_eq!(AwdlChanEncoding::from_u8(1).unwrap(), encoding);
        assert!(encoding.supports_mimo());
        assert_eq!(encoding.max_bandwidth(), 40);
    }

    #[test]
    fn test_channel_bandwidth() {
        let bw = AwdlChanBandwidth::Bw40;
        assert_eq!(bw.mhz(), 40);
        assert_eq!(bw.name(), "40MHz");
    }

    #[test]
    fn test_channel() {
        let chan = AwdlChan::new(6);
        assert_eq!(chan.number, 6);
        assert_eq!(chan.frequency(), 2437);
        assert!(chan.is_2ghz());
        assert!(!chan.is_5ghz());
        assert!(chan.is_valid());
        
        let chan5 = AwdlChan::new(44);
        assert_eq!(chan5.frequency(), 5220);
        assert!(chan5.is_5ghz());
    }

    #[test]
    fn test_channel_sequence() {
        let channels = vec![AwdlChan::new(6), AwdlChan::new(44)];
        let mut seq = AwdlChannelSequence::new(channels);
        
        assert_eq!(seq.current_channel().unwrap().number, 6);
        
        seq.advance();
        assert_eq!(seq.current_channel().unwrap().number, 44);
        
        seq.advance();
        assert_eq!(seq.current_channel().unwrap().number, 6); // Wrap around
    }

    #[test]
    fn test_channel_manager() {
        let mut manager = AwdlChannelManager::new();
        
        assert!(manager.get_current_social_channel().is_some());
        
        let data_chan = AwdlChan::new(149);
        manager.set_data_channel(data_chan.clone());
        assert_eq!(manager.data_channel.as_ref().unwrap().number, 149);
        
        manager.update_channel_stats(6, -50, -90);
        let stats = manager.get_channel_stats(6).unwrap();
        assert_eq!(stats.avg_rssi, -50.0);
        assert_eq!(stats.get_snr(), 40.0);
    }
}