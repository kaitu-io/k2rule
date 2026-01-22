//! Binary rule file reader with memory-mapping support.

use memmap2::Mmap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::format::*;
use crate::{Error, Result, Target};

/// Memory-mapped binary rule reader.
///
/// This reader provides efficient O(log n) or O(1) lookups
/// for all rule types using memory-mapped file access.
pub struct BinaryRuleReader {
    mmap: Mmap,
}

impl BinaryRuleReader {
    /// Open a binary rule file.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.len() < HEADER_SIZE {
            return Err(Error::InvalidHeaderSize {
                expected: HEADER_SIZE,
                actual: mmap.len(),
            });
        }

        // Validate header
        let reader = Self { mmap };
        reader.header().validate()?;

        // TODO: Verify checksum

        Ok(reader)
    }

    /// Open a binary rule file from bytes.
    ///
    /// This writes the data to a temp file and then memory-maps it.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        use std::io::Write;

        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidHeaderSize {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Write to a temp file and mmap it
        let mut temp_file = tempfile::tempfile()?;
        temp_file.write_all(&data)?;

        let mmap = unsafe { Mmap::map(&temp_file)? };

        let reader = Self { mmap };
        reader.header().validate()?;

        Ok(reader)
    }

    /// Get the file header.
    pub fn header(&self) -> &BinaryHeader {
        unsafe { &*(self.mmap.as_ptr() as *const BinaryHeader) }
    }

    /// Match a domain name.
    ///
    /// Returns the target if a matching rule is found.
    pub fn match_domain(&self, domain: &str) -> Option<Target> {
        let domain_lower = domain.to_lowercase();
        let hash = fnv1a_hash(domain_lower.as_bytes());

        // Check exact match first (O(1) average)
        if let Some(target) = self.lookup_exact_domain(hash) {
            return Some(target);
        }

        // Check suffix matches
        let mut current = domain_lower.as_str();
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            let suffix_hash = fnv1a_hash(current.as_bytes());
            if let Some(target) = self.lookup_suffix_domain(suffix_hash, current) {
                return Some(target);
            }
        }

        None
    }

    /// Match an IP address.
    ///
    /// Returns the target if a matching rule is found.
    pub fn match_ip(&self, ip: IpAddr) -> Option<Target> {
        // Check exact IP match first
        if let Some(target) = self.lookup_exact_ip(&ip) {
            return Some(target);
        }

        // Then check CIDR
        self.lookup_cidr(&ip)
    }

    /// Match an IP or domain.
    pub fn match_input(&self, ip_or_domain: &str) -> Option<Target> {
        if let Ok(ip) = ip_or_domain.parse::<IpAddr>() {
            self.match_ip(ip)
        } else {
            self.match_domain(ip_or_domain)
        }
    }

    fn lookup_exact_domain(&self, hash: u64) -> Option<Target> {
        let header = self.header();
        if header.domain_count == 0 {
            return None;
        }

        // Get domain index header
        let domain_idx_offset = header.domain_index_offset as usize;
        if domain_idx_offset + std::mem::size_of::<DomainIndexHeader>() > self.mmap.len() {
            return None;
        }

        let domain_header = unsafe {
            &*(self.mmap[domain_idx_offset..].as_ptr() as *const DomainIndexHeader)
        };

        let bucket_count = domain_header.exact_count as usize;
        if bucket_count == 0 {
            return None;
        }

        // Open addressing with linear probing
        let bucket_start = domain_idx_offset + domain_header.exact_bucket_offset as usize;
        let mut idx = (hash as usize) % bucket_count;

        for _ in 0..bucket_count {
            let entry_offset = bucket_start + idx * std::mem::size_of::<DomainExactEntry>();
            if entry_offset + std::mem::size_of::<DomainExactEntry>() > self.mmap.len() {
                return None;
            }

            let entry = unsafe {
                &*(self.mmap[entry_offset..].as_ptr() as *const DomainExactEntry)
            };

            if entry.hash == 0 {
                return None; // Empty slot
            }

            if entry.hash == hash {
                return Target::from_u8(entry.target);
            }

            idx = (idx + 1) % bucket_count;
        }

        None
    }

    fn lookup_suffix_domain(&self, hash: u64, suffix: &str) -> Option<Target> {
        let header = self.header();
        if header.domain_count == 0 {
            return None;
        }

        let domain_idx_offset = header.domain_index_offset as usize;
        let domain_header = unsafe {
            &*(self.mmap[domain_idx_offset..].as_ptr() as *const DomainIndexHeader)
        };

        let suffix_count = domain_header.suffix_count as usize;
        if suffix_count == 0 {
            return None;
        }

        let suffix_start = domain_idx_offset + domain_header.suffix_array_offset as usize;

        // Binary search
        let entries = unsafe {
            std::slice::from_raw_parts(
                self.mmap[suffix_start..].as_ptr() as *const DomainSuffixEntry,
                suffix_count,
            )
        };

        match entries.binary_search_by_key(&hash, |e| e.hash) {
            Ok(idx) => {
                let entry = &entries[idx];

                // Verify string match (in case of hash collision)
                let payload_offset = header.payload_offset as usize + entry.payload_offset as usize;
                let domain_len = entry.domain_len as usize;

                if payload_offset + domain_len <= self.mmap.len() {
                    let stored_suffix =
                        std::str::from_utf8(&self.mmap[payload_offset..payload_offset + domain_len])
                            .ok()?;

                    if stored_suffix == suffix {
                        return Target::from_u8(entry.target);
                    }
                }

                None
            }
            Err(_) => None,
        }
    }

    fn lookup_exact_ip(&self, ip: &IpAddr) -> Option<Target> {
        let header = self.header();
        if header.ip_count == 0 {
            return None;
        }

        let ip_idx_offset = header.ip_index_offset as usize;
        // TODO: Implement IP index lookup
        let _ = ip_idx_offset;
        let _ = ip;

        None
    }

    fn lookup_cidr(&self, ip: &IpAddr) -> Option<Target> {
        match ip {
            IpAddr::V4(v4) => self.lookup_cidr_v4(*v4),
            IpAddr::V6(v6) => self.lookup_cidr_v6(*v6),
        }
    }

    fn lookup_cidr_v4(&self, ip: Ipv4Addr) -> Option<Target> {
        let header = self.header();
        if header.cidr_count == 0 {
            return None;
        }

        let cidr_idx_offset = header.cidr_index_offset as usize;
        let cidr_header = unsafe {
            &*(self.mmap[cidr_idx_offset..].as_ptr() as *const CidrIndexHeader)
        };

        let v4_count = cidr_header.v4_count as usize;
        if v4_count == 0 {
            return None;
        }

        let v4_start = cidr_idx_offset + std::mem::size_of::<CidrIndexHeader>();
        let entries = unsafe {
            std::slice::from_raw_parts(
                self.mmap[v4_start..].as_ptr() as *const CidrV4Entry,
                v4_count,
            )
        };

        let ip_u32 = u32::from(ip);

        // Find the most specific matching CIDR
        let mut best_match: Option<(u8, Target)> = None;

        for entry in entries {
            let network = u32::from_be(entry.network);
            let mask = if entry.prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - entry.prefix_len)
            };

            if (ip_u32 & mask) == (network & mask) {
                match best_match {
                    Some((best_prefix, _)) if entry.prefix_len <= best_prefix => continue,
                    _ => {
                        if let Some(target) = Target::from_u8(entry.target) {
                            best_match = Some((entry.prefix_len, target));
                        }
                    }
                }
            }
        }

        best_match.map(|(_, target)| target)
    }

    fn lookup_cidr_v6(&self, ip: Ipv6Addr) -> Option<Target> {
        let header = self.header();
        if header.cidr_count == 0 {
            return None;
        }

        let cidr_idx_offset = header.cidr_index_offset as usize;
        let cidr_header = unsafe {
            &*(self.mmap[cidr_idx_offset..].as_ptr() as *const CidrIndexHeader)
        };

        let v6_count = cidr_header.v6_count as usize;
        if v6_count == 0 {
            return None;
        }

        // Skip IPv4 entries
        let v4_size = cidr_header.v4_count as usize * std::mem::size_of::<CidrV4Entry>();
        let v6_start = cidr_idx_offset + std::mem::size_of::<CidrIndexHeader>() + v4_size;

        let entries = unsafe {
            std::slice::from_raw_parts(
                self.mmap[v6_start..].as_ptr() as *const CidrV6Entry,
                v6_count,
            )
        };

        let ip_bytes = ip.octets();

        // Find the most specific matching CIDR
        let mut best_match: Option<(u8, Target)> = None;

        for entry in entries {
            if matches_ipv6_cidr(&ip_bytes, &entry.network, entry.prefix_len) {
                match best_match {
                    Some((best_prefix, _)) if entry.prefix_len <= best_prefix => continue,
                    _ => {
                        if let Some(target) = Target::from_u8(entry.target) {
                            best_match = Some((entry.prefix_len, target));
                        }
                    }
                }
            }
        }

        best_match.map(|(_, target)| target)
    }
}

/// Check if an IPv6 address matches a CIDR range.
fn matches_ipv6_cidr(ip: &[u8; 16], network: &[u8; 16], prefix_len: u8) -> bool {
    let full_bytes = prefix_len as usize / 8;
    let remaining_bits = prefix_len as usize % 8;

    // Check full bytes
    if ip[..full_bytes] != network[..full_bytes] {
        return false;
    }

    // Check remaining bits
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = 0xFF << (8 - remaining_bits);
        if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_ipv6_cidr() {
        let ip: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let network: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert!(matches_ipv6_cidr(&ip, &network, 7));
        assert!(matches_ipv6_cidr(&ip, &network, 8));
        assert!(!matches_ipv6_cidr(&ip, &network, 128));
    }
}
