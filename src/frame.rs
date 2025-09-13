//! AWDL Frame structures and parsing
//!
//! This module contains the data structures and parsing logic for AWDL protocol frames.


use serde::{Deserialize, Serialize};
use bytes::{Buf, BufMut, Bytes};
use crate::{AwdlError, Result};

/// Maximum frame size
pub const AWDL_FRAME_MAX_LEN: usize = 2048;

/// AWDL Action frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlActionType {
    Psf = 0,
    Mif = 1,
    Arpa = 2,
    DataPathState = 3,
    Unknown(u8),
}

impl From<u8> for AwdlActionType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Psf,
            1 => Self::Mif,
            2 => Self::Arpa,
            3 => Self::DataPathState,
            other => Self::Unknown(other),
        }
    }
}

impl From<AwdlActionType> for u8 {
    fn from(action_type: AwdlActionType) -> Self {
        match action_type {
            AwdlActionType::Psf => 0,
            AwdlActionType::Mif => 1,
            AwdlActionType::Arpa => 2,
            AwdlActionType::DataPathState => 3,
            AwdlActionType::Unknown(val) => val,
        }
    }
}

/// AWDL TLV (Type-Length-Value) types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AwdlTlvType {
    SynchronizationParameters = 4,
    ElectionParameters = 5,
    ServiceParameters = 6,
    EnhancedDataRate = 7,
    DataPathState = 8,
    Arpa = 9,
    Version = 10,
    Synchronization = 11,
    ElectionParametersV2 = 12,
    ServiceParametersV2 = 13,
    Ht = 14,
    Vht = 15,
    ChannelSequence = 16,
    SynchronizationTree = 17,
    Unknown(u8),
}

impl From<u8> for AwdlTlvType {
    fn from(value: u8) -> Self {
        match value {
            4 => Self::SynchronizationParameters,
            5 => Self::ElectionParameters,
            6 => Self::ServiceParameters,
            7 => Self::EnhancedDataRate,
            8 => Self::DataPathState,
            9 => Self::Arpa,
            10 => Self::Version,
            11 => Self::Synchronization,
            12 => Self::ElectionParametersV2,
            13 => Self::ServiceParametersV2,
            14 => Self::Ht,
            15 => Self::Vht,
            16 => Self::ChannelSequence,
            17 => Self::SynchronizationTree,
            other => Self::Unknown(other),
        }
    }
}

impl From<AwdlTlvType> for u8 {
    fn from(tlv_type: AwdlTlvType) -> Self {
        match tlv_type {
            AwdlTlvType::SynchronizationParameters => 4,
            AwdlTlvType::ElectionParameters => 5,
            AwdlTlvType::ServiceParameters => 6,
            AwdlTlvType::EnhancedDataRate => 7,
            AwdlTlvType::DataPathState => 8,
            AwdlTlvType::Arpa => 9,
            AwdlTlvType::Version => 10,
            AwdlTlvType::Synchronization => 11,
            AwdlTlvType::ElectionParametersV2 => 12,
            AwdlTlvType::ServiceParametersV2 => 13,
            AwdlTlvType::Ht => 14,
            AwdlTlvType::Vht => 15,
            AwdlTlvType::ChannelSequence => 16,
            AwdlTlvType::SynchronizationTree => 17,
            AwdlTlvType::Unknown(val) => val,
        }
    }
}

/// TLV structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlTlv {
    pub tlv_type: AwdlTlvType,
    pub length: u16,
    pub value: Bytes,
}

/// AWDL Action frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlAction {
    pub action_type: AwdlActionType,
    pub tlvs: Vec<AwdlTlv>,
}

/// AWDL Data frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwdlData {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
    pub payload: Bytes,
}

/// Main AWDL frame structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AwdlFrame {
    Action(AwdlAction),
    Data(AwdlData),
}

impl AwdlTlv {
    /// Create a new TLV
    pub fn new(tlv_type: AwdlTlvType, value: Bytes) -> Self {
        Self {
            tlv_type,
            length: value.len() as u16,
            value,
        }
    }

    /// Parse TLV from buffer
    pub fn parse(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < 3 {
            return Err(AwdlError::Parse("Insufficient data for TLV header".to_string()));
        }

        let tlv_type = AwdlTlvType::from(buf.get_u8());
        let length = buf.get_u16();

        if buf.remaining() < length as usize {
            return Err(AwdlError::Parse("Insufficient data for TLV value".to_string()));
        }

        let mut value_bytes = vec![0u8; length as usize];
        buf.copy_to_slice(&mut value_bytes);
        let value = Bytes::from(value_bytes);

        Ok(Self {
            tlv_type,
            length,
            value,
        })
    }

    /// Serialize TLV to buffer
    pub fn serialize(&self, buf: &mut impl BufMut) -> Result<()> {
        buf.put_u8(self.tlv_type.into());
        buf.put_u16(self.length);
        buf.put_slice(&self.value);
        Ok(())
    }

    /// Get the total size of the TLV when serialized
    pub fn size(&self) -> usize {
        3 + self.value.len() // type (1) + length (2) + value
    }
}

impl AwdlAction {
    /// Create a new action frame
    pub fn new(action_type: AwdlActionType) -> Self {
        Self {
            action_type,
            tlvs: Vec::new(),
        }
    }

    /// Add a TLV to the action frame
    pub fn add_tlv(&mut self, tlv: AwdlTlv) {
        self.tlvs.push(tlv);
    }

    /// Get TLV by type
    pub fn get_tlv(&self, tlv_type: AwdlTlvType) -> Option<&AwdlTlv> {
        self.tlvs.iter().find(|tlv| tlv.tlv_type == tlv_type)
    }

    /// Parse action frame from buffer
    pub fn parse(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < 1 {
            return Err(AwdlError::Parse("Insufficient data for action type".to_string()));
        }

        let action_type = AwdlActionType::from(buf.get_u8());
        let mut tlvs = Vec::new();

        while buf.remaining() > 0 {
            let tlv = AwdlTlv::parse(buf)?;
            tlvs.push(tlv);
        }

        Ok(Self { action_type, tlvs })
    }

    /// Serialize action frame to buffer
    pub fn serialize(&self, buf: &mut impl BufMut) -> Result<()> {
        buf.put_u8(self.action_type.into());
        
        for tlv in &self.tlvs {
            tlv.serialize(buf)?;
        }
        
        Ok(())
    }

    /// Get the total size of the action frame when serialized
    pub fn size(&self) -> usize {
        1 + self.tlvs.iter().map(|tlv| tlv.size()).sum::<usize>()
    }
}

impl AwdlData {
    /// Create a new data frame
    pub fn new(dst: [u8; 6], src: [u8; 6], ether_type: u16, payload: Bytes) -> Self {
        Self {
            dst,
            src,
            ether_type,
            payload,
        }
    }

    /// Parse data frame from buffer
    pub fn parse(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < 14 {
            return Err(AwdlError::Parse("Insufficient data for Ethernet header".to_string()));
        }

        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        
        buf.copy_to_slice(&mut dst);
        buf.copy_to_slice(&mut src);
        let ether_type = buf.get_u16();

        let payload_len = buf.remaining();
        let mut payload_bytes = vec![0u8; payload_len];
        buf.copy_to_slice(&mut payload_bytes);
        let payload = Bytes::from(payload_bytes);

        Ok(Self {
            dst,
            src,
            ether_type,
            payload,
        })
    }

    /// Serialize data frame to buffer
    pub fn serialize(&self, buf: &mut impl BufMut) -> Result<()> {
        buf.put_slice(&self.dst);
        buf.put_slice(&self.src);
        buf.put_u16(self.ether_type);
        buf.put_slice(&self.payload);
        Ok(())
    }

    /// Get the total size of the data frame when serialized
    pub fn size(&self) -> usize {
        14 + self.payload.len() // dst (6) + src (6) + ether_type (2) + payload
    }
}

impl AwdlFrame {
    /// Parse AWDL frame from buffer
    pub fn parse(buf: &mut impl Buf, is_action: bool) -> Result<Self> {
        if is_action {
            Ok(AwdlFrame::Action(AwdlAction::parse(buf)?))
        } else {
            Ok(AwdlFrame::Data(AwdlData::parse(buf)?))
        }
    }

    /// Serialize AWDL frame to buffer
    pub fn serialize(&self, buf: &mut impl BufMut) -> Result<()> {
        match self {
            AwdlFrame::Action(action) => action.serialize(buf),
            AwdlFrame::Data(data) => data.serialize(buf),
        }
    }

    /// Get the total size of the frame when serialized
    pub fn size(&self) -> usize {
        match self {
            AwdlFrame::Action(action) => action.size(),
            AwdlFrame::Data(data) => data.size(),
        }
    }

    /// Check if frame is an action frame
    pub fn is_action(&self) -> bool {
        matches!(self, AwdlFrame::Action(_))
    }

    /// Check if frame is a data frame
    pub fn is_data(&self) -> bool {
        matches!(self, AwdlFrame::Data(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_creation() {
        let value = Bytes::from(vec![1, 2, 3, 4]);
        let tlv = AwdlTlv::new(AwdlTlvType::Version, value.clone());
        
        assert_eq!(tlv.tlv_type, AwdlTlvType::Version);
        assert_eq!(tlv.length, 4);
        assert_eq!(tlv.value, value);
    }

    #[test]
    fn test_action_frame_creation() {
        let mut action = AwdlAction::new(AwdlActionType::Psf);
        let tlv = AwdlTlv::new(AwdlTlvType::Version, Bytes::from(vec![1]));
        
        action.add_tlv(tlv);
        
        assert_eq!(action.action_type, AwdlActionType::Psf);
        assert_eq!(action.tlvs.len(), 1);
        assert!(action.get_tlv(AwdlTlvType::Version).is_some());
    }

    #[test]
    fn test_data_frame_creation() {
        let dst = [1, 2, 3, 4, 5, 6];
        let src = [6, 5, 4, 3, 2, 1];
        let payload = Bytes::from(vec![0xaa, 0xbb, 0xcc]);
        
        let data = AwdlData::new(dst, src, 0x0800, payload.clone());
        
        assert_eq!(data.dst, dst);
        assert_eq!(data.src, src);
        assert_eq!(data.ether_type, 0x0800);
        assert_eq!(data.payload, payload);
    }
}