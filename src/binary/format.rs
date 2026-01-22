//! Binary format constants and structures.

use bitflags::bitflags;

/// Magic bytes for identifying K2Rule binary files.
pub const MAGIC: [u8; 8] = *b"K2RULE\x00\x01";

/// Current format version.
pub const FORMAT_VERSION: u32 = 1;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 128;

bitflags! {
    /// Format flags for binary files.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FormatFlags: u32 {
        /// File is designed for memory mapping.
        const MMAP_SAFE = 0b00000001;
        /// Payload is LZ4 compressed.
        const PAYLOAD_COMPRESSED = 0b00000010;
        /// Payload contains rule metadata/names.
        const HAS_METADATA = 0b00000100;
    }
}

/// Binary file header (128 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BinaryHeader {
    /// Magic bytes: "K2RULE\x00\x01"
    pub magic: [u8; 8],
    /// Format version (u32 LE)
    pub version: u32,
    /// Format flags
    pub flags: u32,
    /// Unix timestamp when file was generated (i64)
    pub timestamp: i64,
    /// SHA-256 checksum of entire file (excluding this field)
    pub checksum: [u8; 32],
    /// Offset to domain index section
    pub domain_index_offset: u32,
    /// Size of domain index section
    pub domain_index_size: u32,
    /// Offset to CIDR index section
    pub cidr_index_offset: u32,
    /// Size of CIDR index section
    pub cidr_index_size: u32,
    /// Offset to GeoIP index section
    pub geoip_index_offset: u32,
    /// Size of GeoIP index section
    pub geoip_index_size: u32,
    /// Offset to IP index section
    pub ip_index_offset: u32,
    /// Size of IP index section
    pub ip_index_size: u32,
    /// Offset to payload section
    pub payload_offset: u32,
    /// Size of payload section
    pub payload_size: u32,
    /// Number of domain rules
    pub domain_count: u32,
    /// Number of CIDR rules
    pub cidr_count: u32,
    /// Number of GeoIP rules
    pub geoip_count: u32,
    /// Number of exact IP rules
    pub ip_count: u32,
    /// Reserved for future use
    pub reserved: [u8; 16],
}

impl BinaryHeader {
    /// Create a new header with default values.
    pub fn new() -> Self {
        Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FormatFlags::MMAP_SAFE.bits(),
            timestamp: 0,
            checksum: [0; 32],
            domain_index_offset: HEADER_SIZE as u32,
            domain_index_size: 0,
            cidr_index_offset: HEADER_SIZE as u32,
            cidr_index_size: 0,
            geoip_index_offset: HEADER_SIZE as u32,
            geoip_index_size: 0,
            ip_index_offset: HEADER_SIZE as u32,
            ip_index_size: 0,
            payload_offset: HEADER_SIZE as u32,
            payload_size: 0,
            domain_count: 0,
            cidr_count: 0,
            geoip_count: 0,
            ip_count: 0,
            reserved: [0; 16],
        }
    }

    /// Validate the header magic and version.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.magic != MAGIC {
            return Err(crate::Error::InvalidMagic);
        }
        if self.version > FORMAT_VERSION {
            return Err(crate::Error::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    /// Get format flags.
    pub fn format_flags(&self) -> FormatFlags {
        FormatFlags::from_bits_truncate(self.flags)
    }
}

impl Default for BinaryHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain index header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainIndexHeader {
    /// Number of exact match buckets
    pub exact_count: u32,
    /// Number of suffix entries
    pub suffix_count: u32,
    /// Offset to exact match hash table (relative to domain index start)
    pub exact_bucket_offset: u32,
    /// Offset to suffix array (relative to domain index start)
    pub suffix_array_offset: u32,
}

/// Domain exact match entry (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainExactEntry {
    /// FNV-1a hash of the domain
    pub hash: u64,
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 7],
}

/// Domain suffix match entry (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DomainSuffixEntry {
    /// FNV-1a hash of the suffix
    pub hash: u64,
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 3],
    /// Offset to domain string in payload
    pub payload_offset: u32,
    /// Length of domain string
    pub domain_len: u16,
    /// Padding
    pub _padding2: [u8; 6],
}

/// CIDR index header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CidrIndexHeader {
    /// Number of IPv4 CIDR entries
    pub v4_count: u32,
    /// Number of IPv6 CIDR entries
    pub v6_count: u32,
}

/// IPv4 CIDR entry (8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CidrV4Entry {
    /// Network address (big-endian)
    pub network: u32,
    /// Prefix length
    pub prefix_len: u8,
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 2],
}

/// IPv6 CIDR entry (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CidrV6Entry {
    /// Network address (big-endian)
    pub network: [u8; 16],
    /// Prefix length
    pub prefix_len: u8,
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 6],
}

/// GeoIP entry (4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GeoIpEntry {
    /// 2-letter ISO country code (ASCII)
    pub country_code: [u8; 2],
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: u8,
}

/// IPv4 exact match entry (8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IpV4Entry {
    /// IP address (native endian)
    pub ip: u32,
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 3],
}

/// IPv6 exact match entry (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IpV6Entry {
    /// IP address (big-endian)
    pub ip: [u8; 16],
    /// Target (0=Direct, 1=Proxy, 2=Reject)
    pub target: u8,
    /// Padding
    pub _padding: [u8; 7],
}

/// FNV-1a 64-bit hash function.
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<BinaryHeader>(), HEADER_SIZE);
    }

    #[test]
    fn test_entry_sizes() {
        assert_eq!(mem::size_of::<DomainExactEntry>(), 16);
        assert_eq!(mem::size_of::<DomainSuffixEntry>(), 24);
        assert_eq!(mem::size_of::<CidrV4Entry>(), 8);
        assert_eq!(mem::size_of::<CidrV6Entry>(), 24);
        assert_eq!(mem::size_of::<GeoIpEntry>(), 4);
        assert_eq!(mem::size_of::<IpV4Entry>(), 8);
        assert_eq!(mem::size_of::<IpV6Entry>(), 24);
    }

    #[test]
    fn test_fnv1a_hash() {
        // Known FNV-1a test vectors
        assert_ne!(fnv1a_hash(b""), 0);
        assert_ne!(fnv1a_hash(b"hello"), fnv1a_hash(b"world"));
        assert_eq!(fnv1a_hash(b"test"), fnv1a_hash(b"test"));
    }

    #[test]
    fn test_header_validation() {
        let header = BinaryHeader::new();
        assert!(header.validate().is_ok());

        let mut bad_header = header;
        bad_header.magic = [0; 8];
        assert!(bad_header.validate().is_err());
    }
}
