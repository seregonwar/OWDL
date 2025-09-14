//! Radiotap header generation and parsing
//! 
//! Based on the IEEE 802.11 Radiotap specification for capturing and injecting
//! 802.11 frames with metadata.

use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::phy::{FrameMetadata, FrameSourceType};

/// Radiotap header present flags
pub mod present_flags {
    pub const TSFT: u32 = 1 << 0;
    pub const FLAGS: u32 = 1 << 1;
    pub const RATE: u32 = 1 << 2;
    pub const CHANNEL: u32 = 1 << 3;
    pub const FHSS: u32 = 1 << 4;
    pub const DBM_ANTSIGNAL: u32 = 1 << 5;
    pub const DBM_ANTNOISE: u32 = 1 << 6;
    pub const LOCK_QUALITY: u32 = 1 << 7;
    pub const TX_ATTENUATION: u32 = 1 << 8;
    pub const DB_TX_ATTENUATION: u32 = 1 << 9;
    pub const DBM_TX_POWER: u32 = 1 << 10;
    pub const ANTENNA: u32 = 1 << 11;
    pub const DB_ANTSIGNAL: u32 = 1 << 12;
    pub const DB_ANTNOISE: u32 = 1 << 13;
    pub const RX_FLAGS: u32 = 1 << 14;
    pub const TX_FLAGS: u32 = 1 << 15;
    pub const RTS_RETRIES: u32 = 1 << 16;
    pub const DATA_RETRIES: u32 = 1 << 17;
    pub const EXT: u32 = 1 << 31;
}

/// Extended radiotap present flags (custom extensions)
pub mod ext_present_flags {
    pub const SOURCE_TYPE: u32 = 1 << 0;
    pub const QUALITY_METRICS: u32 = 1 << 1;
    pub const TIMING_INFO: u32 = 1 << 2;
    pub const VENDOR_DATA: u32 = 1 << 3;
}

/// Channel flags
pub mod channel_flags {
    pub const TURBO: u16 = 0x0010;
    pub const CCK: u16 = 0x0020;
    pub const OFDM: u16 = 0x0040;
    pub const SPECTRUM_2GHZ: u16 = 0x0080;
    pub const SPECTRUM_5GHZ: u16 = 0x0100;
    pub const PASSIVE: u16 = 0x0200;
    pub const DYN: u16 = 0x0400;
    pub const GFSK: u16 = 0x0800;
    pub const GSM: u16 = 0x1000;
    pub const STATIC_TURBO: u16 = 0x2000;
    pub const HALF_RATE: u16 = 0x4000;
    pub const QUARTER_RATE: u16 = 0x8000;
}

/// RX flags
pub mod rx_flags {
    pub const BAD_PLCP: u16 = 0x0002;
}

/// Enhanced radiotap header with Nexus802 extensions
#[derive(Debug, Clone)]
pub struct EnhancedRadiotapHeader {
    /// Standard radiotap fields
    pub version: u8,
    pub length: u16,
    pub present: u32,
    
    /// Extended presence fields
    pub present_ext1: Option<u32>,
    pub present_ext2: Option<u32>,
    
    /// Standard fields
    pub timestamp: Option<u64>,
    pub flags: Option<u8>,
    pub rate: Option<u8>,
    pub channel_frequency: Option<u16>,
    pub channel_flags: Option<u16>,
    pub antenna_signal: Option<i8>,
    pub antenna_noise: Option<i8>,
    pub antenna: Option<u8>,
    pub rx_flags: Option<u16>,
    pub tx_flags: Option<u16>,
    
    /// Custom extensions
    pub source_type: Option<u8>,
    pub quality_rssi: Option<u16>,
    pub quality_snr: Option<u16>,
    pub quality_noise_floor: Option<u16>,
    pub hardware_timestamp: Option<u64>,
    pub processing_delay: Option<u32>,
    pub vendor_data: Option<Vec<u8>>,
}

impl EnhancedRadiotapHeader {
    /// Create a new radiotap header from frame metadata
    pub fn from_metadata(metadata: &FrameMetadata) -> Self {
        let mut header = Self::default();
        
        // Set standard fields
        header.timestamp = Some(metadata.timestamp);
        header.channel_frequency = Some(metadata.frequency);
        header.channel_flags = Some(metadata.channel_flags);
        header.antenna_signal = metadata.signal_dbm;
        header.antenna_noise = metadata.noise_dbm;
        
        // Set custom extensions
        header.source_type = Some(metadata.source_type as u8);
        
        if let Some(snr) = metadata.snr_db {
            header.quality_snr = Some(snr as u16);
        }
        
        if let Some(vendor_data) = &metadata.vendor_data {
            header.vendor_data = Some(vendor_data.clone());
        }
        
        // Calculate present flags
        header.update_present_flags();
        
        header
    }
    
    /// Update present flags based on available fields
    fn update_present_flags(&mut self) {
        let mut present = 0u32;
        let mut present_ext1 = 0u32;
        
        if self.timestamp.is_some() {
            present |= present_flags::TSFT;
        }
        if self.flags.is_some() {
            present |= present_flags::FLAGS;
        }
        if self.rate.is_some() {
            present |= present_flags::RATE;
        }
        if self.channel_frequency.is_some() {
            present |= present_flags::CHANNEL;
        }
        if self.antenna_signal.is_some() {
            present |= present_flags::DBM_ANTSIGNAL;
        }
        if self.antenna_noise.is_some() {
            present |= present_flags::DBM_ANTNOISE;
        }
        if self.antenna.is_some() {
            present |= present_flags::ANTENNA;
        }
        if self.rx_flags.is_some() {
            present |= present_flags::RX_FLAGS;
        }
        if self.tx_flags.is_some() {
            present |= present_flags::TX_FLAGS;
        }
        
        // Custom extensions
        if self.source_type.is_some() {
            present_ext1 |= ext_present_flags::SOURCE_TYPE;
        }
        if self.quality_rssi.is_some() || self.quality_snr.is_some() || self.quality_noise_floor.is_some() {
            present_ext1 |= ext_present_flags::QUALITY_METRICS;
        }
        if self.hardware_timestamp.is_some() || self.processing_delay.is_some() {
            present_ext1 |= ext_present_flags::TIMING_INFO;
        }
        if self.vendor_data.is_some() {
            present_ext1 |= ext_present_flags::VENDOR_DATA;
        }
        
        // Set extension flag if we have custom fields
        if present_ext1 != 0 {
            present |= present_flags::EXT;
            self.present_ext1 = Some(present_ext1);
        }
        
        self.present = present;
    }
    
    /// Serialize radiotap header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        
        // Calculate total length first
        let mut length = 4; // Basic header
        
        if self.present & present_flags::EXT != 0 {
            length += 4; // Extended present field
        }
        
        // Add field lengths
        if self.timestamp.is_some() { length += 8; }
        if self.flags.is_some() { length += 1; }
        if self.rate.is_some() { length += 1; }
        if self.channel_frequency.is_some() { length += 4; } // freq + flags
        if self.antenna_signal.is_some() { length += 1; }
        if self.antenna_noise.is_some() { length += 1; }
        if self.antenna.is_some() { length += 1; }
        if self.rx_flags.is_some() { length += 2; }
        if self.tx_flags.is_some() { length += 2; }
        
        // Custom extensions
        if self.source_type.is_some() { length += 1; }
        if self.quality_rssi.is_some() { length += 2; }
        if self.quality_snr.is_some() { length += 2; }
        if self.quality_noise_floor.is_some() { length += 2; }
        if self.hardware_timestamp.is_some() { length += 8; }
        if self.processing_delay.is_some() { length += 4; }
        if let Some(vendor_data) = &self.vendor_data {
            length += 4 + vendor_data.len(); // OUI + sub_namespace + length + data
        }
        
        // Align to 4-byte boundary
        length = (length + 3) & !3;
        
        // Write basic header
        buf.put_u8(self.version);
        buf.put_u8(0); // padding
        buf.put_u16_le(length as u16);
        buf.put_u32_le(self.present);
        
        // Write extended present field if needed
        if let Some(present_ext1) = self.present_ext1 {
            buf.put_u32_le(present_ext1);
        }
        
        // Write standard fields in order
        if let Some(timestamp) = self.timestamp {
            buf.put_u64_le(timestamp);
        }
        if let Some(flags) = self.flags {
            buf.put_u8(flags);
        }
        if let Some(rate) = self.rate {
            buf.put_u8(rate);
        }
        if let Some(freq) = self.channel_frequency {
            buf.put_u16_le(freq);
            buf.put_u16_le(self.channel_flags.unwrap_or(0));
        }
        if let Some(signal) = self.antenna_signal {
            buf.put_i8(signal);
        }
        if let Some(noise) = self.antenna_noise {
            buf.put_i8(noise);
        }
        if let Some(antenna) = self.antenna {
            buf.put_u8(antenna);
        }
        if let Some(rx_flags) = self.rx_flags {
            buf.put_u16_le(rx_flags);
        }
        if let Some(tx_flags) = self.tx_flags {
            buf.put_u16_le(tx_flags);
        }
        
        // Write custom extensions
        if let Some(source_type) = self.source_type {
            buf.put_u8(source_type);
        }
        if let Some(rssi) = self.quality_rssi {
            buf.put_u16_le(rssi);
        }
        if let Some(snr) = self.quality_snr {
            buf.put_u16_le(snr);
        }
        if let Some(noise_floor) = self.quality_noise_floor {
            buf.put_u16_le(noise_floor);
        }
        if let Some(hw_timestamp) = self.hardware_timestamp {
            buf.put_u64_le(hw_timestamp);
        }
        if let Some(delay) = self.processing_delay {
            buf.put_u32_le(delay);
        }
        if let Some(vendor_data) = &self.vendor_data {
            // Nexus802 OUI (made up for this example)
            buf.put_u8(0x00);
            buf.put_u8(0x50);
            buf.put_u8(0xC2);
            buf.put_u8(0x01); // sub_namespace
            buf.put_u16_le(vendor_data.len() as u16);
            buf.put_slice(vendor_data);
        }
        
        // Pad to 4-byte boundary
        while buf.len() % 4 != 0 {
            buf.put_u8(0);
        }
        
        buf.to_vec()
    }
    
    /// Parse radiotap header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), crate::Nexus802Error> {
        if data.len() < 4 {
            return Err(crate::Nexus802Error::Frame {
                message: "Radiotap header too short".to_string(),
            });
        }
        
        let mut buf = &data[..];
        
        let version = buf.get_u8();
        let _pad = buf.get_u8();
        let length = buf.get_u16_le() as usize;
        let present = buf.get_u32_le();
        
        if data.len() < length {
            return Err(crate::Nexus802Error::Frame {
                message: "Incomplete radiotap header".to_string(),
            });
        }
        
        let mut header = Self {
            version,
            length: length as u16,
            present,
            ..Default::default()
        };
        
        // Parse extended present fields
        if present & present_flags::EXT != 0 {
            if buf.remaining() < 4 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing extended present field".to_string(),
                });
            }
            header.present_ext1 = Some(buf.get_u32_le());
        }
        
        // Parse standard fields
        if present & present_flags::TSFT != 0 {
            if buf.remaining() < 8 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing timestamp field".to_string(),
                });
            }
            header.timestamp = Some(buf.get_u64_le());
        }
        
        if present & present_flags::FLAGS != 0 {
            if buf.remaining() < 1 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing flags field".to_string(),
                });
            }
            header.flags = Some(buf.get_u8());
        }
        
        if present & present_flags::RATE != 0 {
            if buf.remaining() < 1 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing rate field".to_string(),
                });
            }
            header.rate = Some(buf.get_u8());
        }
        
        if present & present_flags::CHANNEL != 0 {
            if buf.remaining() < 4 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing channel field".to_string(),
                });
            }
            header.channel_frequency = Some(buf.get_u16_le());
            header.channel_flags = Some(buf.get_u16_le());
        }
        
        if present & present_flags::DBM_ANTSIGNAL != 0 {
            if buf.remaining() < 1 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing antenna signal field".to_string(),
                });
            }
            header.antenna_signal = Some(buf.get_i8());
        }
        
        if present & present_flags::DBM_ANTNOISE != 0 {
            if buf.remaining() < 1 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing antenna noise field".to_string(),
                });
            }
            header.antenna_noise = Some(buf.get_i8());
        }
        
        if present & present_flags::ANTENNA != 0 {
            if buf.remaining() < 1 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing antenna field".to_string(),
                });
            }
            header.antenna = Some(buf.get_u8());
        }
        
        if present & present_flags::RX_FLAGS != 0 {
            if buf.remaining() < 2 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing RX flags field".to_string(),
                });
            }
            header.rx_flags = Some(buf.get_u16_le());
        }
        
        if present & present_flags::TX_FLAGS != 0 {
            if buf.remaining() < 2 {
                return Err(crate::Nexus802Error::Frame {
                    message: "Missing TX flags field".to_string(),
                });
            }
            header.tx_flags = Some(buf.get_u16_le());
        }
        
        // Parse custom extensions if present
        if let Some(present_ext1) = header.present_ext1 {
            if present_ext1 & ext_present_flags::SOURCE_TYPE != 0 {
                if buf.remaining() < 1 {
                    return Err(crate::Nexus802Error::Frame {
                        message: "Missing source type field".to_string(),
                    });
                }
                header.source_type = Some(buf.get_u8());
            }
            
            if present_ext1 & ext_present_flags::QUALITY_METRICS != 0 {
                if buf.remaining() < 6 {
                    return Err(crate::Nexus802Error::Frame {
                        message: "Missing quality metrics fields".to_string(),
                    });
                }
                header.quality_rssi = Some(buf.get_u16_le());
                header.quality_snr = Some(buf.get_u16_le());
                header.quality_noise_floor = Some(buf.get_u16_le());
            }
            
            if present_ext1 & ext_present_flags::TIMING_INFO != 0 {
                if buf.remaining() < 12 {
                    return Err(crate::Nexus802Error::Frame {
                        message: "Missing timing info fields".to_string(),
                    });
                }
                header.hardware_timestamp = Some(buf.get_u64_le());
                header.processing_delay = Some(buf.get_u32_le());
            }
            
            if present_ext1 & ext_present_flags::VENDOR_DATA != 0 {
                if buf.remaining() < 6 {
                    return Err(crate::Nexus802Error::Frame {
                        message: "Missing vendor data header".to_string(),
                    });
                }
                let _oui = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
                let _sub_namespace = buf.get_u8();
                let vendor_len = buf.get_u16_le() as usize;
                
                if buf.remaining() < vendor_len {
                    return Err(crate::Nexus802Error::Frame {
                        message: "Incomplete vendor data".to_string(),
                    });
                }
                
                let mut vendor_data = vec![0u8; vendor_len];
                buf.copy_to_slice(&mut vendor_data);
                header.vendor_data = Some(vendor_data);
            }
        }
        
        Ok((header, length))
    }
}

impl Default for EnhancedRadiotapHeader {
    fn default() -> Self {
        Self {
            version: 0,
            length: 0,
            present: 0,
            present_ext1: None,
            present_ext2: None,
            timestamp: None,
            flags: None,
            rate: None,
            channel_frequency: None,
            channel_flags: None,
            antenna_signal: None,
            antenna_noise: None,
            antenna: None,
            rx_flags: None,
            tx_flags: None,
            source_type: None,
            quality_rssi: None,
            quality_snr: None,
            quality_noise_floor: None,
            hardware_timestamp: None,
            processing_delay: None,
            vendor_data: None,
        }
    }
}

/// Build enhanced radiotap frame from metadata and 802.11 data
pub fn build_radiotap_frame(metadata: &FrameMetadata, ieee80211_data: &[u8]) -> Vec<u8> {
    let radiotap_header = EnhancedRadiotapHeader::from_metadata(metadata);
    let radiotap_bytes = radiotap_header.to_bytes();
    
    let mut frame = Vec::with_capacity(radiotap_bytes.len() + ieee80211_data.len());
    frame.extend_from_slice(&radiotap_bytes);
    frame.extend_from_slice(ieee80211_data);
    
    frame
}
