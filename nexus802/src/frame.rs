//! IEEE 802.11 frame processing and manipulation

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::phy::{FrameMetadata, FrameSourceType};

/// IEEE 802.11 frame with associated metadata
#[derive(Debug, Clone)]
pub struct Frame802_11 {
    /// Raw frame data (including radiotap header if present)
    pub data: Bytes,
    /// Frame metadata
    pub metadata: FrameMetadata,
    /// Parsed frame information
    pub info: FrameInfo,
}

/// Unified frame descriptor for aggregation pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedFrameDescriptor {
    /// Source type that provided this frame
    pub source_type: FrameSourceType,
    /// Hardware timestamp (microseconds since epoch)
    pub timestamp: u64,
    /// Frame length in bytes
    pub length: usize,
    /// Processing priority (higher = more important)
    pub priority: u8,
    /// Channel frequency in MHz
    pub frequency: u16,
    /// Signal strength in dBm
    pub signal_dbm: Option<i8>,
    /// Frame check sequence present
    pub fcs_present: bool,
    /// Processing flags
    pub flags: FrameFlags,
}

/// Frame processing flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FrameFlags {
    /// Frame failed FCS check
    pub fcs_failed: bool,
    /// Frame was decrypted
    pub decrypted: bool,
    /// Frame is a duplicate
    pub duplicate: bool,
    /// Frame was fragmented
    pub fragmented: bool,
    /// Frame has radiotap header
    pub has_radiotap: bool,
}

/// Parsed frame information
#[derive(Debug, Clone)]
pub struct FrameInfo {
    /// Frame type (management, control, data)
    pub frame_type: FrameType,
    /// Frame subtype
    pub subtype: u8,
    /// Source MAC address
    pub src_addr: Option<[u8; 6]>,
    /// Destination MAC address
    pub dst_addr: Option<[u8; 6]>,
    /// BSSID
    pub bssid: Option<[u8; 6]>,
    /// Sequence number
    pub sequence: Option<u16>,
    /// Fragment number
    pub fragment: Option<u8>,
    /// Frame body length
    pub body_length: usize,
}

/// IEEE 802.11 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    /// Management frames (beacon, probe, auth, etc.)
    Management = 0,
    /// Control frames (RTS, CTS, ACK, etc.)
    Control = 1,
    /// Data frames
    Data = 2,
    /// Extension frames
    Extension = 3,
}

impl Frame802_11 {
    /// Create a new frame from raw data
    pub fn new(data: Bytes, metadata: FrameMetadata) -> crate::Result<Self> {
        let info = Self::parse_frame_info(&data, metadata.fcs_present)?;
        
        Ok(Self {
            data,
            metadata,
            info,
        })
    }
    
    /// Parse basic frame information from raw data
    fn parse_frame_info(data: &[u8], fcs_present: bool) -> crate::Result<FrameInfo> {
        // Skip radiotap header if present
        let (ieee80211_data, _radiotap_len) = Self::skip_radiotap(data)?;
        
        if ieee80211_data.len() < 24 {
            return Err(crate::Nexus802Error::Frame {
                message: "Frame too short for 802.11 header".to_string(),
            });
        }
        
        // Parse frame control field
        let frame_control = u16::from_le_bytes([ieee80211_data[0], ieee80211_data[1]]);
        let frame_type_bits = (frame_control >> 2) & 0x3;
        let subtype = ((frame_control >> 4) & 0xF) as u8;
        
        let frame_type = match frame_type_bits {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            _ => unreachable!(),
        };
        
        // Extract addresses based on frame type
        let (src_addr, dst_addr, bssid) = Self::extract_addresses(ieee80211_data, frame_type)?;
        
        // Extract sequence control
        let (sequence, fragment) = if ieee80211_data.len() >= 24 {
            let seq_ctrl = u16::from_le_bytes([ieee80211_data[22], ieee80211_data[23]]);
            let sequence = Some((seq_ctrl >> 4) & 0xFFF);
            let fragment = Some((seq_ctrl & 0xF) as u8);
            (sequence, fragment)
        } else {
            (None, None)
        };
        
        // Calculate body length
        let header_len = Self::calculate_header_length(ieee80211_data, frame_type)?;
        let fcs_len = if fcs_present { 4 } else { 0 };
        let body_length = ieee80211_data.len().saturating_sub(header_len + fcs_len);
        
        Ok(FrameInfo {
            frame_type,
            subtype,
            src_addr,
            dst_addr,
            bssid,
            sequence,
            fragment,
            body_length,
        })
    }
    
    /// Skip radiotap header and return 802.11 data
    fn skip_radiotap(data: &[u8]) -> crate::Result<(&[u8], usize)> {
        if data.len() < 4 {
            return Ok((data, 0));
        }
        
        // Check for radiotap magic
        if data[0] != 0 {
            return Ok((data, 0)); // Not radiotap
        }
        
        // Get radiotap length
        let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        
        if data.len() < radiotap_len {
            return Err(crate::Nexus802Error::Frame {
                message: "Invalid radiotap header length".to_string(),
            });
        }
        
        Ok((&data[radiotap_len..], radiotap_len))
    }
    
    /// Extract MAC addresses from frame
    fn extract_addresses(data: &[u8], frame_type: FrameType) -> crate::Result<(Option<[u8; 6]>, Option<[u8; 6]>, Option<[u8; 6]>)> {
        if data.len() < 24 {
            return Ok((None, None, None));
        }
        
        let addr1 = Self::extract_mac_addr(data, 4);
        let addr2 = Self::extract_mac_addr(data, 10);
        let addr3 = Self::extract_mac_addr(data, 16);
        
        match frame_type {
            FrameType::Management | FrameType::Data => {
                // For most management and data frames:
                // addr1 = destination, addr2 = source, addr3 = BSSID
                Ok((addr2, addr1, addr3))
            },
            FrameType::Control => {
                // Control frames have variable addressing
                Ok((addr2, addr1, None))
            },
            FrameType::Extension => {
                Ok((addr2, addr1, addr3))
            },
        }
    }
    
    /// Extract MAC address from specific offset
    fn extract_mac_addr(data: &[u8], offset: usize) -> Option<[u8; 6]> {
        if data.len() >= offset + 6 {
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&data[offset..offset + 6]);
            Some(addr)
        } else {
            None
        }
    }
    
    /// Calculate 802.11 header length
    fn calculate_header_length(data: &[u8], frame_type: FrameType) -> crate::Result<usize> {
        match frame_type {
            FrameType::Management => Ok(24), // Basic management frame header
            FrameType::Control => {
                // Control frames have variable lengths
                if data.len() >= 2 {
                    let frame_control = u16::from_le_bytes([data[0], data[1]]);
                    let subtype = (frame_control >> 4) & 0xF;
                    match subtype {
                        10 | 11 => Ok(16), // PS-Poll, CF-End
                        12 | 13 => Ok(20), // CF-End+CF-Ack
                        _ => Ok(10), // RTS, CTS, ACK, etc.
                    }
                } else {
                    Ok(10)
                }
            },
            FrameType::Data => {
                // Data frames can have QoS and HT control fields
                let mut len = 24;
                if data.len() >= 2 {
                    let frame_control = u16::from_le_bytes([data[0], data[1]]);
                    let subtype = (frame_control >> 4) & 0xF;
                    
                    // Check for QoS data frame
                    if subtype & 0x8 != 0 {
                        len += 2; // QoS control field
                    }
                    
                    // Check for HT control field (order bit set)
                    if frame_control & 0x8000 != 0 {
                        len += 4; // HT control field
                    }
                }
                Ok(len)
            },
            FrameType::Extension => Ok(24), // Assume basic header for extension frames
        }
    }
    
    /// Get the 802.11 frame data without radiotap header
    pub fn ieee80211_data(&self) -> crate::Result<&[u8]> {
        let (data, _) = Self::skip_radiotap(&self.data)?;
        Ok(data)
    }
    
    /// Check if frame is a beacon
    pub fn is_beacon(&self) -> bool {
        self.info.frame_type == FrameType::Management && self.info.subtype == 8
    }
    
    /// Check if frame is a probe request
    pub fn is_probe_request(&self) -> bool {
        self.info.frame_type == FrameType::Management && self.info.subtype == 4
    }
    
    /// Check if frame is a probe response
    pub fn is_probe_response(&self) -> bool {
        self.info.frame_type == FrameType::Management && self.info.subtype == 5
    }
    
    /// Check if frame is data
    pub fn is_data(&self) -> bool {
        self.info.frame_type == FrameType::Data
    }
    
    /// Get frame as unified descriptor
    pub fn to_descriptor(&self) -> UnifiedFrameDescriptor {
        UnifiedFrameDescriptor {
            source_type: self.metadata.source_type,
            timestamp: self.metadata.timestamp,
            length: self.data.len(),
            priority: match self.info.frame_type {
                FrameType::Management => 3,
                FrameType::Control => 2,
                FrameType::Data => 1,
                FrameType::Extension => 1,
            },
            frequency: self.metadata.frequency,
            signal_dbm: self.metadata.signal_dbm,
            fcs_present: self.metadata.fcs_present,
            flags: FrameFlags {
                fcs_failed: false, // TODO: Parse from radiotap
                decrypted: false,
                duplicate: false,
                fragmented: self.info.fragment.map_or(false, |f| f > 0),
                has_radiotap: self.data.len() > 4 && self.data[0] == 0,
            },
        }
    }
}

impl fmt::Display for Frame802_11 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "802.11 {:?} frame (subtype={}), len={}, src={:?}, dst={:?}",
            self.info.frame_type,
            self.info.subtype,
            self.data.len(),
            self.info.src_addr.map(|a| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                a[0], a[1], a[2], a[3], a[4], a[5])),
            self.info.dst_addr.map(|a| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                a[0], a[1], a[2], a[3], a[4], a[5]))
        )
    }
}

impl Default for FrameFlags {
    fn default() -> Self {
        Self {
            fcs_failed: false,
            decrypted: false,
            duplicate: false,
            fragmented: false,
            has_radiotap: false,
        }
    }
}
