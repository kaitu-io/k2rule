//! Slice-based rule file reader.

use fst::Set;
use std::net::IpAddr;

use super::format::*;
use crate::{Error, Result, Target};

/// Reader for slice-based rule files.
pub struct SliceReader {
    data: Vec<u8>,
    header: SliceHeader,
    entries: Vec<SliceEntry>,
}

impl SliceReader {
    /// Load from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidHeaderSize {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Parse header
        let header = unsafe { *(data.as_ptr() as *const SliceHeader) };
        header.validate()?;

        // Parse slice entries
        let slice_count = header.slice_count as usize;
        let entry_size = std::mem::size_of::<SliceEntry>();
        let entries_end = HEADER_SIZE + slice_count * entry_size;

        if data.len() < entries_end {
            return Err(Error::Config("Slice index truncated".to_string()));
        }

        let mut entries = Vec::with_capacity(slice_count);
        for i in 0..slice_count {
            let offset = HEADER_SIZE + i * entry_size;
            let entry = unsafe { *(data[offset..].as_ptr() as *const SliceEntry) };
            entries.push(entry);
        }

        Ok(Self {
            data: data.to_vec(),
            header,
            entries,
        })
    }

    /// Get the fallback target.
    pub fn fallback(&self) -> Target {
        self.header.fallback()
    }

    /// Get number of slices.
    pub fn slice_count(&self) -> usize {
        self.entries.len()
    }

    /// Match a domain against all slices in order.
    ///
    /// Returns the target of the first matching slice, or None if no match.
    /// The caller should use `fallback()` when None is returned.
    pub fn match_domain(&self, domain: &str) -> Option<Target> {
        let normalized = domain.to_lowercase();

        for entry in &self.entries {
            if entry.get_type() != Some(SliceType::FstDomain) {
                continue;
            }

            if self.match_domain_in_slice(entry, &normalized) {
                return Some(entry.get_target());
            }
        }

        None
    }

    /// Match an IP address against all slices in order.
    ///
    /// Returns the target of the first matching slice, or None if no match.
    pub fn match_ip(&self, ip: IpAddr) -> Option<Target> {
        for entry in &self.entries {
            match (entry.get_type(), &ip) {
                (Some(SliceType::CidrV4), IpAddr::V4(v4)) => {
                    if self.match_cidr_v4_in_slice(entry, (*v4).into()) {
                        return Some(entry.get_target());
                    }
                }
                (Some(SliceType::CidrV6), IpAddr::V6(v6)) => {
                    if self.match_cidr_v6_in_slice(entry, v6.octets()) {
                        return Some(entry.get_target());
                    }
                }
                _ => continue,
            }
        }

        None
    }

    /// Match a GeoIP country code against all slices in order.
    pub fn match_geoip(&self, country: &str) -> Option<Target> {
        let country_upper = country.to_uppercase();
        let country_bytes = country_upper.as_bytes();

        for entry in &self.entries {
            if entry.get_type() != Some(SliceType::GeoIp) {
                continue;
            }

            if self.match_geoip_in_slice(entry, country_bytes) {
                return Some(entry.get_target());
            }
        }

        None
    }

    fn match_domain_in_slice(&self, entry: &SliceEntry, domain: &str) -> bool {
        let offset = entry.offset as usize;
        let size = entry.size as usize;

        if offset + size > self.data.len() {
            return false;
        }

        let fst_data = &self.data[offset..offset + size];
        let fst = match Set::new(fst_data.to_vec()) {
            Ok(f) => f,
            Err(_) => return false,
        };

        // Try exact match (reversed with dot prefix)
        let with_dot = format!(".{}", domain);
        let reversed: String = with_dot.chars().rev().collect();
        if fst.contains(&reversed) {
            return true;
        }

        // Check parent domains for suffix match
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            let suffix_with_dot = format!(".{}", suffix);
            let reversed_suffix: String = suffix_with_dot.chars().rev().collect();
            if fst.contains(&reversed_suffix) {
                return true;
            }
        }

        false
    }

    fn match_cidr_v4_in_slice(&self, entry: &SliceEntry, ip: u32) -> bool {
        let offset = entry.offset as usize;
        let count = entry.count as usize;

        // Each entry is 8 bytes: network (4) + prefix_len (1) + padding (3)
        for i in 0..count {
            let entry_offset = offset + i * 8;
            if entry_offset + 8 > self.data.len() {
                break;
            }

            let network =
                u32::from_be_bytes(self.data[entry_offset..entry_offset + 4].try_into().unwrap());
            let prefix_len = self.data[entry_offset + 4];

            let mask = if prefix_len == 0 {
                0
            } else if prefix_len >= 32 {
                !0u32
            } else {
                !0u32 << (32 - prefix_len)
            };

            if (ip & mask) == (network & mask) {
                return true;
            }
        }

        false
    }

    fn match_cidr_v6_in_slice(&self, entry: &SliceEntry, ip: [u8; 16]) -> bool {
        let offset = entry.offset as usize;
        let count = entry.count as usize;

        // Each entry is 24 bytes: network (16) + prefix_len (1) + padding (7)
        for i in 0..count {
            let entry_offset = offset + i * 24;
            if entry_offset + 24 > self.data.len() {
                break;
            }

            let network: [u8; 16] = self.data[entry_offset..entry_offset + 16]
                .try_into()
                .unwrap();
            let prefix_len = self.data[entry_offset + 16];

            if self.matches_ipv6_cidr(&ip, &network, prefix_len) {
                return true;
            }
        }

        false
    }

    fn matches_ipv6_cidr(&self, ip: &[u8; 16], network: &[u8; 16], prefix_len: u8) -> bool {
        let full_bytes = prefix_len as usize / 8;
        let remaining_bits = prefix_len as usize % 8;

        if full_bytes > 0 && ip[..full_bytes] != network[..full_bytes] {
            return false;
        }

        if remaining_bits > 0 && full_bytes < 16 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
                return false;
            }
        }

        true
    }

    fn match_geoip_in_slice(&self, entry: &SliceEntry, country: &[u8]) -> bool {
        let offset = entry.offset as usize;
        let count = entry.count as usize;

        // Each entry is 4 bytes: country_code (2) + padding (2)
        for i in 0..count {
            let entry_offset = offset + i * 4;
            if entry_offset + 4 > self.data.len() {
                break;
            }

            let stored_country = &self.data[entry_offset..entry_offset + 2];
            if country.len() >= 2 && stored_country[0] == country[0] && stored_country[1] == country[1]
            {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slice::SliceWriter;

    #[test]
    fn test_read_empty_file() {
        let mut writer = SliceWriter::new(Target::Direct);
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(reader.fallback(), Target::Direct);
        assert_eq!(reader.slice_count(), 0);
    }

    #[test]
    fn test_match_domain_single_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        writer
            .add_domain_slice(&["google.com", "youtube.com"], Target::Proxy)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("www.google.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("unknown.com"), None);
    }

    #[test]
    fn test_match_domain_ordering() {
        // Test that slice order determines priority
        let mut writer = SliceWriter::new(Target::Direct);
        // First slice: cn.bing.com -> Direct
        writer
            .add_domain_slice(&["cn.bing.com"], Target::Direct)
            .unwrap();
        // Second slice: bing.com -> Proxy
        writer
            .add_domain_slice(&["bing.com"], Target::Proxy)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        // cn.bing.com should match first slice (Direct)
        assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
        // www.cn.bing.com should also match first slice
        assert_eq!(
            reader.match_domain("www.cn.bing.com"),
            Some(Target::Direct)
        );
        // bing.com should match second slice (Proxy)
        assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
        // www.bing.com should match second slice (Proxy)
        assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_match_with_fallback() {
        let mut writer = SliceWriter::new(Target::Proxy);
        writer
            .add_domain_slice(&["direct.com"], Target::Direct)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        // Matched domain
        assert_eq!(reader.match_domain("direct.com"), Some(Target::Direct));
        // Unmatched domain returns None (caller should use fallback)
        assert_eq!(reader.match_domain("unknown.com"), None);
        // Fallback is accessible
        assert_eq!(reader.fallback(), Target::Proxy);
    }

    #[test]
    fn test_match_cidr_v4() {
        let mut writer = SliceWriter::new(Target::Direct);
        // 10.0.0.0/8 -> Direct
        writer
            .add_cidr_v4_slice(&[(0x0A000000, 8)], Target::Direct)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(
            reader.match_ip("10.1.2.3".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(reader.match_ip("192.168.1.1".parse().unwrap()), None);
    }

    #[test]
    fn test_match_cidr_v6() {
        let mut writer = SliceWriter::new(Target::Direct);
        // fc00::/7 -> Direct
        let network: [u8; 16] = [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        writer
            .add_cidr_v6_slice(&[(network, 7)], Target::Direct)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(
            reader.match_ip("fc00::1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(
            reader.match_ip("fd00::1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(reader.match_ip("2001:db8::1".parse().unwrap()), None);
    }

    #[test]
    fn test_match_geoip() {
        let mut writer = SliceWriter::new(Target::Proxy);
        writer
            .add_geoip_slice(&["CN", "US"], Target::Direct)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));
        assert_eq!(reader.match_geoip("US"), Some(Target::Direct));
        assert_eq!(reader.match_geoip("JP"), None);
    }

    #[test]
    fn test_mixed_slice_ordering() {
        let mut writer = SliceWriter::new(Target::Proxy);
        // Order: domain -> cidr -> geoip
        writer
            .add_domain_slice(&["local.lan"], Target::Direct)
            .unwrap();
        writer
            .add_cidr_v4_slice(&[(0x0A000000, 8)], Target::Direct)
            .unwrap();
        writer
            .add_geoip_slice(&["CN"], Target::Direct)
            .unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(reader.slice_count(), 3);
        assert_eq!(reader.match_domain("local.lan"), Some(Target::Direct));
        assert_eq!(
            reader.match_ip("10.0.0.1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));
    }
}
