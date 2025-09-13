//! AWDL Wire format handling
//!
//! This module contains structures and functions for AWDL wire format handling,
//! including buffer management and data serialization.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use std::time::{Duration, Instant};
use crate::{AwdlError, Result};

/// Maximum buffer size for AWDL packets
pub const AWDL_MAX_BUFFER_SIZE: usize = 2048;

/// Buffer alignment
pub const AWDL_BUFFER_ALIGNMENT: usize = 4;

/// Wire buffer for AWDL data
#[derive(Debug, Clone)]
pub struct AwdlWireBuffer {
    /// Buffer data
    pub data: Vec<u8>,
    /// Current read position
    pub read_pos: usize,
    /// Current write position
    pub write_pos: usize,
    /// Buffer capacity
    pub capacity: usize,
    /// Creation timestamp
    pub created_at: Instant,
}

impl AwdlWireBuffer {
    /// Create new wire buffer
    pub fn new(capacity: usize) -> Self {
        let capacity = std::cmp::min(capacity, AWDL_MAX_BUFFER_SIZE);
        Self {
            data: vec![0; capacity],
            read_pos: 0,
            write_pos: 0,
            capacity,
            created_at: Instant::now(),
        }
    }

    /// Create buffer with default capacity
    pub fn default() -> Self {
        Self::new(1024)
    }

    /// Create buffer from existing data
    pub fn from_data(data: Vec<u8>) -> Self {
        let capacity = data.len();
        let write_pos = data.len();
        Self {
            data,
            read_pos: 0,
            write_pos,
            capacity,
            created_at: Instant::now(),
        }
    }

    /// Get available bytes for reading
    pub fn available(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Get remaining space for writing
    pub fn remaining(&self) -> usize {
        self.capacity - self.write_pos
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.read_pos >= self.write_pos
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.write_pos >= self.capacity
    }

    /// Reset buffer positions
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    /// Compact buffer (move unread data to beginning)
    pub fn compact(&mut self) {
        if self.read_pos > 0 {
            let available = self.available();
            if available > 0 {
                self.data.copy_within(self.read_pos..self.write_pos, 0);
            }
            self.read_pos = 0;
            self.write_pos = available;
        }
    }

    /// Write data to buffer
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let available_space = self.remaining();
        let to_write = std::cmp::min(data.len(), available_space);
        
        if to_write == 0 {
            return Err(AwdlError::BufferFull);
        }
        
        self.data[self.write_pos..self.write_pos + to_write]
            .copy_from_slice(&data[..to_write]);
        self.write_pos += to_write;
        
        Ok(to_write)
    }

    /// Write single byte
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        if self.remaining() < 1 {
            return Err(AwdlError::BufferFull);
        }
        
        self.data[self.write_pos] = value;
        self.write_pos += 1;
        Ok(())
    }

    /// Write u16 in little endian
    pub fn write_u16_le(&mut self, value: u16) -> Result<()> {
        let bytes = value.to_le_bytes();
        self.write(&bytes).map(|_| ())
    }

    /// Write u32 in little endian
    pub fn write_u32_le(&mut self, value: u32) -> Result<()> {
        let bytes = value.to_le_bytes();
        self.write(&bytes).map(|_| ())
    }

    /// Write u64 in little endian
    pub fn write_u64_le(&mut self, value: u64) -> Result<()> {
        let bytes = value.to_le_bytes();
        self.write(&bytes).map(|_| ())
    }

    /// Read data from buffer
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let available = self.available();
        let to_read = std::cmp::min(buf.len(), available);
        
        if to_read == 0 {
            return Ok(0);
        }
        
        buf[..to_read].copy_from_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;
        
        Ok(to_read)
    }

    /// Read single byte
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.available() < 1 {
            return Err(AwdlError::BufferEmpty);
        }
        
        let value = self.data[self.read_pos];
        self.read_pos += 1;
        Ok(value)
    }

    /// Read u16 in little endian
    pub fn read_u16_le(&mut self) -> Result<u16> {
        if self.available() < 2 {
            return Err(AwdlError::BufferEmpty);
        }
        
        let mut bytes = [0u8; 2];
        self.read(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Read u32 in little endian
    pub fn read_u32_le(&mut self) -> Result<u32> {
        if self.available() < 4 {
            return Err(AwdlError::BufferEmpty);
        }
        
        let mut bytes = [0u8; 4];
        self.read(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read u64 in little endian
    pub fn read_u64_le(&mut self) -> Result<u64> {
        if self.available() < 8 {
            return Err(AwdlError::BufferEmpty);
        }
        
        let mut bytes = [0u8; 8];
        self.read(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Peek at data without advancing read position
    pub fn peek(&self, buf: &mut [u8]) -> Result<usize> {
        let available = self.available();
        let to_read = std::cmp::min(buf.len(), available);
        
        if to_read == 0 {
            return Ok(0);
        }
        
        buf[..to_read].copy_from_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        Ok(to_read)
    }

    /// Peek single byte
    pub fn peek_u8(&self) -> Result<u8> {
        if self.available() < 1 {
            return Err(AwdlError::BufferEmpty);
        }
        
        Ok(self.data[self.read_pos])
    }

    /// Skip bytes in read buffer
    pub fn skip(&mut self, count: usize) -> Result<()> {
        if self.available() < count {
            return Err(AwdlError::BufferEmpty);
        }
        
        self.read_pos += count;
        Ok(())
    }

    /// Get slice of available data
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.read_pos..self.write_pos]
    }

    /// Get mutable slice of available data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.read_pos..self.write_pos]
    }

    /// Get age of buffer
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Resize buffer capacity
    pub fn resize(&mut self, new_capacity: usize) -> Result<()> {
        let new_capacity = std::cmp::min(new_capacity, AWDL_MAX_BUFFER_SIZE);
        
        if new_capacity < self.write_pos {
            return Err(AwdlError::InvalidParameter("New capacity too small".to_string()));
        }
        
        self.data.resize(new_capacity, 0);
        self.capacity = new_capacity;
        Ok(())
    }

    /// Clone buffer data
    pub fn clone_data(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl Default for AwdlWireBuffer {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Wire buffer pool for efficient buffer management
#[derive(Debug)]
pub struct AwdlWireBufferPool {
    /// Available buffers
    available: VecDeque<AwdlWireBuffer>,
    /// Buffer size
    buffer_size: usize,
    /// Maximum pool size
    max_pool_size: usize,
    /// Pool statistics
    stats: BufferPoolStats,
}

impl AwdlWireBufferPool {
    /// Create new buffer pool
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            available: VecDeque::new(),
            buffer_size,
            max_pool_size,
            stats: BufferPoolStats::new(),
        }
    }

    /// Get buffer from pool or create new one
    pub fn get_buffer(&mut self) -> AwdlWireBuffer {
        if let Some(mut buffer) = self.available.pop_front() {
            buffer.reset();
            buffer.created_at = Instant::now();
            self.stats.reused += 1;
            buffer
        } else {
            self.stats.created += 1;
            AwdlWireBuffer::new(self.buffer_size)
        }
    }

    /// Return buffer to pool
    pub fn return_buffer(&mut self, buffer: AwdlWireBuffer) {
        if self.available.len() < self.max_pool_size {
            self.available.push_back(buffer);
            self.stats.returned += 1;
        } else {
            self.stats.discarded += 1;
        }
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> &BufferPoolStats {
        &self.stats
    }

    /// Clear pool
    pub fn clear(&mut self) {
        self.available.clear();
        self.stats = BufferPoolStats::new();
    }

    /// Get pool size
    pub fn size(&self) -> usize {
        self.available.len()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.available.is_empty()
    }
}

impl Default for AwdlWireBufferPool {
    fn default() -> Self {
        Self::new(1024, 32)
    }
}

/// Buffer pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferPoolStats {
    /// Buffers created
    pub created: u64,
    /// Buffers reused from pool
    pub reused: u64,
    /// Buffers returned to pool
    pub returned: u64,
    /// Buffers discarded (pool full)
    pub discarded: u64,
}

impl BufferPoolStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self {
            created: 0,
            reused: 0,
            returned: 0,
            discarded: 0,
        }
    }

    /// Get total buffer operations
    pub fn total_operations(&self) -> u64 {
        self.created + self.reused
    }

    /// Get reuse rate
    pub fn reuse_rate(&self) -> f64 {
        let total = self.total_operations();
        if total > 0 {
            self.reused as f64 / total as f64
        } else {
            0.0
        }
    }

    /// Get discard rate
    pub fn discard_rate(&self) -> f64 {
        let total = self.returned + self.discarded;
        if total > 0 {
            self.discarded as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl Default for BufferPoolStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire format serializer
#[derive(Debug)]
pub struct AwdlWireSerializer {
    /// Output buffer
    buffer: AwdlWireBuffer,
    /// Checksum calculator
    checksum: u32,
    /// Compression enabled
    compression: bool,
}

impl AwdlWireSerializer {
    /// Create new serializer
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: AwdlWireBuffer::new(capacity),
            checksum: 0,
            compression: false,
        }
    }

    /// Enable/disable compression
    pub fn set_compression(&mut self, enabled: bool) {
        self.compression = enabled;
    }

    /// Reset serializer
    pub fn reset(&mut self) {
        self.buffer.reset();
        self.checksum = 0;
    }

    /// Write header
    pub fn write_header(&mut self, magic: u32, version: u16, flags: u16) -> Result<()> {
        self.buffer.write_u32_le(magic)?;
        self.buffer.write_u16_le(version)?;
        self.buffer.write_u16_le(flags)?;
        self.update_checksum(&magic.to_le_bytes());
        self.update_checksum(&version.to_le_bytes());
        self.update_checksum(&flags.to_le_bytes());
        Ok(())
    }

    /// Write TLV (Type-Length-Value)
    pub fn write_tlv(&mut self, tlv_type: u8, data: &[u8]) -> Result<()> {
        let length = data.len() as u16;
        
        self.buffer.write_u8(tlv_type)?;
        self.buffer.write_u16_le(length)?;
        self.buffer.write(data)?;
        
        self.update_checksum(&[tlv_type]);
        self.update_checksum(&length.to_le_bytes());
        self.update_checksum(data);
        
        Ok(())
    }

    /// Write variable length integer
    pub fn write_varint(&mut self, value: u64) -> Result<()> {
        let mut val = value;
        while val >= 0x80 {
            self.buffer.write_u8((val as u8) | 0x80)?;
            val >>= 7;
        }
        self.buffer.write_u8(val as u8)?;
        Ok(())
    }

    /// Write string with length prefix
    pub fn write_string(&mut self, s: &str) -> Result<()> {
        let bytes = s.as_bytes();
        self.write_varint(bytes.len() as u64)?;
        self.buffer.write(bytes)?;
        self.update_checksum(bytes);
        Ok(())
    }

    /// Finalize serialization with checksum
    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        // Write checksum at the end
        self.buffer.write_u32_le(self.checksum)?;
        Ok(self.buffer.clone_data())
    }

    /// Update checksum with data
    fn update_checksum(&mut self, data: &[u8]) {
        for &byte in data {
            self.checksum = self.checksum.wrapping_add(byte as u32);
        }
    }

    /// Get current buffer size
    pub fn size(&self) -> usize {
        self.buffer.available()
    }

    /// Get buffer reference
    pub fn buffer(&self) -> &AwdlWireBuffer {
        &self.buffer
    }
}

/// Wire format deserializer
#[derive(Debug)]
pub struct AwdlWireDeserializer {
    /// Input buffer
    buffer: AwdlWireBuffer,
    /// Expected checksum
    expected_checksum: u32,
    /// Calculated checksum
    calculated_checksum: u32,
    /// Compression enabled
    compression: bool,
}

impl AwdlWireDeserializer {
    /// Create new deserializer
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            buffer: AwdlWireBuffer::from_data(data),
            expected_checksum: 0,
            calculated_checksum: 0,
            compression: false,
        }
    }

    /// Enable/disable compression
    pub fn set_compression(&mut self, enabled: bool) {
        self.compression = enabled;
    }

    /// Read header
    pub fn read_header(&mut self) -> Result<(u32, u16, u16)> {
        let magic = self.buffer.read_u32_le()?;
        let version = self.buffer.read_u16_le()?;
        let flags = self.buffer.read_u16_le()?;
        
        self.update_checksum(&magic.to_le_bytes());
        self.update_checksum(&version.to_le_bytes());
        self.update_checksum(&flags.to_le_bytes());
        
        Ok((magic, version, flags))
    }

    /// Read TLV (Type-Length-Value)
    pub fn read_tlv(&mut self) -> Result<(u8, Vec<u8>)> {
        let tlv_type = self.buffer.read_u8()?;
        let length = self.buffer.read_u16_le()?;
        
        let mut data = vec![0u8; length as usize];
        self.buffer.read(&mut data)?;
        
        self.update_checksum(&[tlv_type]);
        self.update_checksum(&length.to_le_bytes());
        self.update_checksum(&data);
        
        Ok((tlv_type, data))
    }

    /// Read variable length integer
    pub fn read_varint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        
        loop {
            let byte = self.buffer.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            
            if byte & 0x80 == 0 {
                break;
            }
            
            shift += 7;
            if shift >= 64 {
                return Err(AwdlError::Parse("Varint too large".to_string()));
            }
        }
        
        Ok(result)
    }

    /// Read string with length prefix
    pub fn read_string(&mut self) -> Result<String> {
        let length = self.read_varint()? as usize;
        let mut bytes = vec![0u8; length];
        self.buffer.read(&mut bytes)?;
        self.update_checksum(&bytes);
        
        String::from_utf8(bytes)
            .map_err(|e| AwdlError::Parse(format!("Invalid UTF-8: {}", e)))
    }

    /// Verify checksum
    pub fn verify_checksum(&mut self) -> Result<bool> {
        if self.buffer.available() < 4 {
            return Err(AwdlError::Parse("Missing checksum".to_string()));
        }
        
        self.expected_checksum = self.buffer.read_u32_le()?;
        Ok(self.calculated_checksum == self.expected_checksum)
    }

    /// Update checksum with data
    fn update_checksum(&mut self, data: &[u8]) {
        for &byte in data {
            self.calculated_checksum = self.calculated_checksum.wrapping_add(byte as u32);
        }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.buffer.available()
    }

    /// Check if more data is available
    pub fn has_more(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Get buffer reference
    pub fn buffer(&self) -> &AwdlWireBuffer {
        &self.buffer
    }
}

/// Wire format utilities
pub struct AwdlWireUtils;

impl AwdlWireUtils {
    /// Calculate CRC32 checksum
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFFFFFFu32;
        
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        
        !crc
    }

    /// Align size to boundary
    pub fn align_size(size: usize, alignment: usize) -> usize {
        (size + alignment - 1) & !(alignment - 1)
    }

    /// Pad data to alignment
    pub fn pad_to_alignment(data: &mut Vec<u8>, alignment: usize) {
        let current_len = data.len();
        let aligned_len = Self::align_size(current_len, alignment);
        data.resize(aligned_len, 0);
    }

    /// Compress data using simple RLE
    pub fn compress_rle(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        
        let mut compressed = Vec::new();
        let mut i = 0;
        
        while i < data.len() {
            let current = data[i];
            let mut count = 1;
            
            // Count consecutive identical bytes
            while i + count < data.len() && data[i + count] == current && count < 255 {
                count += 1;
            }
            
            if count > 3 || current == 0 {
                // Use RLE encoding
                compressed.push(0); // Escape byte
                compressed.push(count as u8);
                compressed.push(current);
            } else {
                // Store literally
                for _ in 0..count {
                    compressed.push(current);
                    if current == 0 {
                        compressed.push(1); // Escape zero
                    }
                }
            }
            
            i += count;
        }
        
        compressed
    }

    /// Decompress RLE data
    pub fn decompress_rle(data: &[u8]) -> Result<Vec<u8>> {
        let mut decompressed = Vec::new();
        let mut i = 0;
        
        while i < data.len() {
            if data[i] == 0 && i + 2 < data.len() {
                // RLE sequence
                let count = data[i + 1] as usize;
                let value = data[i + 2];
                
                for _ in 0..count {
                    decompressed.push(value);
                }
                
                i += 3;
            } else {
                // Literal byte
                decompressed.push(data[i]);
                i += 1;
            }
        }
        
        Ok(decompressed)
    }

    /// Validate buffer integrity
    pub fn validate_buffer(buffer: &AwdlWireBuffer) -> bool {
        buffer.read_pos <= buffer.write_pos && 
        buffer.write_pos <= buffer.capacity &&
        buffer.data.len() == buffer.capacity
    }

    /// Calculate buffer utilization
    pub fn buffer_utilization(buffer: &AwdlWireBuffer) -> f64 {
        if buffer.capacity == 0 {
            0.0
        } else {
            buffer.available() as f64 / buffer.capacity as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_buffer() {
        let mut buffer = AwdlWireBuffer::new(64);
        
        // Test writing
        assert!(buffer.write(b"hello").is_ok());
        assert_eq!(buffer.available(), 5);
        assert_eq!(buffer.remaining(), 59);
        
        // Test reading
        let mut read_buf = [0u8; 5];
        assert_eq!(buffer.read(&mut read_buf).unwrap(), 5);
        assert_eq!(&read_buf, b"hello");
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_wire_buffer_integers() {
        let mut buffer = AwdlWireBuffer::new(64);
        
        // Write integers
        buffer.write_u8(0x12).unwrap();
        buffer.write_u16_le(0x3456).unwrap();
        buffer.write_u32_le(0x789ABCDE).unwrap();
        
        // Read integers
        assert_eq!(buffer.read_u8().unwrap(), 0x12);
        assert_eq!(buffer.read_u16_le().unwrap(), 0x3456);
        assert_eq!(buffer.read_u32_le().unwrap(), 0x789ABCDE);
    }

    #[test]
    fn test_buffer_pool() {
        let mut pool = AwdlWireBufferPool::new(64, 4);
        
        // Get buffer from empty pool
        let buffer1 = pool.get_buffer();
        assert_eq!(pool.get_stats().created, 1);
        
        // Return buffer to pool
        pool.return_buffer(buffer1);
        assert_eq!(pool.get_stats().returned, 1);
        
        // Get buffer from pool (should reuse)
        let _buffer2 = pool.get_buffer();
        assert_eq!(pool.get_stats().reused, 1);
    }

    #[test]
    fn test_serializer() {
        let mut serializer = AwdlWireSerializer::new(128);
        
        serializer.write_header(0x12345678, 1, 0).unwrap();
        serializer.write_tlv(1, b"test data").unwrap();
        serializer.write_string("hello world").unwrap();
        
        let data = serializer.finalize().unwrap();
        assert!(!data.is_empty());
        
        // Test deserializer
        let mut deserializer = AwdlWireDeserializer::new(data);
        let (magic, version, flags) = deserializer.read_header().unwrap();
        assert_eq!(magic, 0x12345678);
        assert_eq!(version, 1);
        assert_eq!(flags, 0);
        
        let (tlv_type, tlv_data) = deserializer.read_tlv().unwrap();
        assert_eq!(tlv_type, 1);
        assert_eq!(tlv_data, b"test data");
        
        let string = deserializer.read_string().unwrap();
        assert_eq!(string, "hello world");
    }

    #[test]
    fn test_wire_utils() {
        let data = b"hello world";
        let crc = AwdlWireUtils::crc32(data);
        assert_ne!(crc, 0);
        
        assert_eq!(AwdlWireUtils::align_size(10, 4), 12);
        assert_eq!(AwdlWireUtils::align_size(12, 4), 12);
        
        let compressed = AwdlWireUtils::compress_rle(b"aaabbbccc");
        let decompressed = AwdlWireUtils::decompress_rle(&compressed).unwrap();
        assert_eq!(decompressed, b"aaabbbccc");
    }
}