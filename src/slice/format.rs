//! Slice-based binary format (k2r v2).
//!
//! File structure:
//! ```text
//! +--------------------+
//! |  HEADER (64 bytes) |  Magic "K2RULEV2", version, slice_count, fallback_target
//! +--------------------+
//! |  SLICE INDEX       |  Array of SliceEntry (type, target, offset, size)
//! +--------------------+
//! |  SLICE 0 DATA      |  FST or sorted array
//! +--------------------+
//! |  SLICE 1 DATA      |
//! +--------------------+
//! |      ...           |
//! +--------------------+
//! ```

use crate::{Error, Result, Target};

/// Magic bytes for K2Rule v2 slice-based format
pub const MAGIC: [u8; 8] = *b"K2RULEV2";

/// Current format version
pub const FORMAT_VERSION: u32 = 1;

/// Header size in bytes (64 bytes)
pub const HEADER_SIZE: usize = 64;

/// Slice type identifiers
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceType {
    /// FST-based domain set
    FstDomain = 0x01,
    /// IPv4 CIDR ranges
    CidrV4 = 0x02,
    /// IPv6 CIDR ranges
    CidrV6 = 0x03,
    /// GeoIP country codes
    GeoIp = 0x04,
    /// Exact IPv4 addresses
    ExactIpV4 = 0x05,
    /// Exact IPv6 addresses
    ExactIpV6 = 0x06,
}

impl SliceType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::FstDomain),
            0x02 => Some(Self::CidrV4),
            0x03 => Some(Self::CidrV6),
            0x04 => Some(Self::GeoIp),
            0x05 => Some(Self::ExactIpV4),
            0x06 => Some(Self::ExactIpV6),
            _ => None,
        }
    }
}

/// File header (64 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SliceHeader {
    /// Magic bytes: "K2RULEV2"
    pub magic: [u8; 8],
    /// Format version
    pub version: u32,
    /// Number of slices
    pub slice_count: u32,
    /// Fallback target when no rule matches
    pub fallback_target: u8,
    /// Reserved padding
    pub _reserved1: [u8; 3],
    /// Unix timestamp
    pub timestamp: i64,
    /// SHA-256 checksum (first 16 bytes)
    pub checksum: [u8; 16],
    /// Reserved for future use
    pub _reserved2: [u8; 16],
}

impl SliceHeader {
    pub fn new(fallback: Target) -> Self {
        Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            slice_count: 0,
            fallback_target: fallback.as_u8(),
            _reserved1: [0; 3],
            timestamp: 0,
            checksum: [0; 16],
            _reserved2: [0; 16],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if self.version > FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    pub fn fallback(&self) -> Target {
        Target::from_u8(self.fallback_target).unwrap_or(Target::Direct)
    }
}

/// Slice index entry (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SliceEntry {
    /// Slice type
    pub slice_type: u8,
    /// Target for this slice
    pub target: u8,
    /// Reserved
    pub _reserved: [u8; 2],
    /// Offset to slice data (from file start)
    pub offset: u32,
    /// Size of slice data
    pub size: u32,
    /// Number of entries in this slice
    pub count: u32,
}

impl SliceEntry {
    pub fn new(slice_type: SliceType, target: Target) -> Self {
        Self {
            slice_type: slice_type as u8,
            target: target.as_u8(),
            _reserved: [0; 2],
            offset: 0,
            size: 0,
            count: 0,
        }
    }

    pub fn get_type(&self) -> Option<SliceType> {
        SliceType::from_u8(self.slice_type)
    }

    pub fn get_target(&self) -> Target {
        Target::from_u8(self.target).unwrap_or(Target::Direct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<SliceHeader>(), HEADER_SIZE);
    }

    #[test]
    fn test_slice_entry_size() {
        assert_eq!(mem::size_of::<SliceEntry>(), 16);
    }

    #[test]
    fn test_header_validation() {
        let header = SliceHeader::new(Target::Direct);
        assert!(header.validate().is_ok());

        let mut bad_header = header;
        bad_header.magic = [0; 8];
        assert!(bad_header.validate().is_err());
    }

    #[test]
    fn test_slice_type_roundtrip() {
        assert_eq!(SliceType::from_u8(0x01), Some(SliceType::FstDomain));
        assert_eq!(SliceType::from_u8(0x02), Some(SliceType::CidrV4));
        assert_eq!(SliceType::from_u8(0x03), Some(SliceType::CidrV6));
        assert_eq!(SliceType::from_u8(0x04), Some(SliceType::GeoIp));
        assert_eq!(SliceType::from_u8(0xFF), None);
    }

    #[test]
    fn test_slice_entry() {
        let entry = SliceEntry::new(SliceType::FstDomain, Target::Proxy);
        assert_eq!(entry.get_type(), Some(SliceType::FstDomain));
        assert_eq!(entry.get_target(), Target::Proxy);
    }
}
