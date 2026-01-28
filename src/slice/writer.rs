//! Slice-based rule file writer.

use fst::Set;

use super::format::*;
use crate::{Error, Result, Target};

/// Builder for slice-based rule files.
pub struct SliceWriter {
    fallback: Target,
    slices: Vec<SliceData>,
}

struct SliceData {
    entry: SliceEntry,
    data: Vec<u8>,
}

impl SliceWriter {
    pub fn new(fallback: Target) -> Self {
        Self {
            fallback,
            slices: Vec::new(),
        }
    }

    /// Add a domain slice using FST.
    ///
    /// Domains are stored in reversed form for efficient suffix matching.
    /// A leading dot is added if not present (suffix match semantics).
    pub fn add_domain_slice(&mut self, domains: &[&str], target: Target) -> Result<()> {
        if domains.is_empty() {
            return Ok(());
        }

        // Normalize and reverse domains for suffix matching
        let mut reversed: Vec<String> = domains
            .iter()
            .map(|d| {
                let normalized = d.to_lowercase();
                let with_dot = if normalized.starts_with('.') {
                    normalized
                } else {
                    format!(".{}", normalized)
                };
                with_dot.chars().rev().collect()
            })
            .collect();

        reversed.sort();
        reversed.dedup();

        let count = reversed.len() as u32;

        // Build FST
        let fst_set = Set::from_iter(reversed.iter().map(|s| s.as_str()))
            .map_err(|e| Error::Config(format!("Failed to build FST: {}", e)))?;
        let data = fst_set.as_fst().as_bytes().to_vec();

        let mut entry = SliceEntry::new(SliceType::FstDomain, target);
        entry.count = count;

        self.slices.push(SliceData { entry, data });
        Ok(())
    }

    /// Add an IPv4 CIDR slice.
    ///
    /// Each CIDR is a tuple of (network_u32, prefix_len).
    pub fn add_cidr_v4_slice(&mut self, cidrs: &[(u32, u8)], target: Target) -> Result<()> {
        if cidrs.is_empty() {
            return Ok(());
        }

        let mut sorted = cidrs.to_vec();
        sorted.sort_by_key(|(network, _)| *network);

        // Each entry: network (4 bytes BE) + prefix_len (1 byte) + padding (3 bytes) = 8 bytes
        let mut data = Vec::with_capacity(sorted.len() * 8);
        for (network, prefix_len) in &sorted {
            data.extend_from_slice(&network.to_be_bytes());
            data.push(*prefix_len);
            data.extend_from_slice(&[0u8; 3]); // padding
        }

        let mut entry = SliceEntry::new(SliceType::CidrV4, target);
        entry.count = sorted.len() as u32;

        self.slices.push(SliceData { entry, data });
        Ok(())
    }

    /// Add an IPv6 CIDR slice.
    ///
    /// Each CIDR is a tuple of (network_bytes, prefix_len).
    pub fn add_cidr_v6_slice(&mut self, cidrs: &[([u8; 16], u8)], target: Target) -> Result<()> {
        if cidrs.is_empty() {
            return Ok(());
        }

        let mut sorted = cidrs.to_vec();
        sorted.sort_by_key(|(network, _)| *network);

        // Each entry: network (16 bytes) + prefix_len (1 byte) + padding (7 bytes) = 24 bytes
        let mut data = Vec::with_capacity(sorted.len() * 24);
        for (network, prefix_len) in &sorted {
            data.extend_from_slice(network);
            data.push(*prefix_len);
            data.extend_from_slice(&[0u8; 7]); // padding to 24 bytes
        }

        let mut entry = SliceEntry::new(SliceType::CidrV6, target);
        entry.count = sorted.len() as u32;

        self.slices.push(SliceData { entry, data });
        Ok(())
    }

    /// Add a GeoIP slice.
    ///
    /// Countries are 2-letter ISO country codes.
    pub fn add_geoip_slice(&mut self, countries: &[&str], target: Target) -> Result<()> {
        if countries.is_empty() {
            return Ok(());
        }

        // Each entry: country_code (2 bytes) + padding (2 bytes) = 4 bytes
        let mut data = Vec::with_capacity(countries.len() * 4);
        for country in countries {
            let bytes = country.to_uppercase();
            let bytes = bytes.as_bytes();
            data.push(bytes.first().copied().unwrap_or(0));
            data.push(bytes.get(1).copied().unwrap_or(0));
            data.extend_from_slice(&[0u8; 2]); // padding
        }

        let mut entry = SliceEntry::new(SliceType::GeoIp, target);
        entry.count = countries.len() as u32;

        self.slices.push(SliceData { entry, data });
        Ok(())
    }

    /// Build the final binary data.
    pub fn build(&mut self) -> Result<Vec<u8>> {
        let slice_count = self.slices.len();
        let index_size = slice_count * std::mem::size_of::<SliceEntry>();

        // Calculate offsets
        let data_start = HEADER_SIZE + index_size;
        let mut current_offset = data_start;

        for slice in &mut self.slices {
            slice.entry.offset = current_offset as u32;
            slice.entry.size = slice.data.len() as u32;
            current_offset += slice.data.len();
        }

        // Build output
        let total_size = current_offset;
        let mut output = Vec::with_capacity(total_size);

        // Write header
        let mut header = SliceHeader::new(self.fallback);
        header.slice_count = slice_count as u32;
        header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let header_bytes = unsafe {
            std::slice::from_raw_parts(&header as *const SliceHeader as *const u8, HEADER_SIZE)
        };
        output.extend_from_slice(header_bytes);

        // Write slice index
        for slice in &self.slices {
            let entry_bytes = unsafe {
                std::slice::from_raw_parts(
                    &slice.entry as *const SliceEntry as *const u8,
                    std::mem::size_of::<SliceEntry>(),
                )
            };
            output.extend_from_slice(entry_bytes);
        }

        // Write slice data
        for slice in &self.slices {
            output.extend_from_slice(&slice.data);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_empty_slices() {
        let mut writer = SliceWriter::new(Target::Direct);
        let data = writer.build().unwrap();

        assert!(data.len() >= HEADER_SIZE);
        assert_eq!(&data[0..8], b"K2RULEV2");
    }

    #[test]
    fn test_write_domain_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        writer
            .add_domain_slice(&["google.com", "youtube.com"], Target::Proxy)
            .unwrap();

        let data = writer.build().unwrap();

        // Should have header + 1 slice entry + FST data
        assert!(data.len() > HEADER_SIZE + 16);

        // Verify slice count in header
        let slice_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn test_write_multiple_slices() {
        let mut writer = SliceWriter::new(Target::Proxy);
        writer
            .add_domain_slice(&["private.local"], Target::Direct)
            .unwrap();
        writer
            .add_domain_slice(&["blocked.com"], Target::Reject)
            .unwrap();
        writer
            .add_domain_slice(&["proxy.com"], Target::Proxy)
            .unwrap();

        let data = writer.build().unwrap();

        let slice_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(slice_count, 3);
    }

    #[test]
    fn test_write_cidr_v4_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        // 10.0.0.0/8
        writer
            .add_cidr_v4_slice(&[(0x0A000000, 8)], Target::Direct)
            .unwrap();

        let data = writer.build().unwrap();
        assert!(data.len() > HEADER_SIZE);

        let slice_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn test_write_cidr_v6_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        // fc00::/7
        let network: [u8; 16] = [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        writer
            .add_cidr_v6_slice(&[(network, 7)], Target::Direct)
            .unwrap();

        let data = writer.build().unwrap();
        assert!(data.len() > HEADER_SIZE);
    }

    #[test]
    fn test_write_geoip_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        writer
            .add_geoip_slice(&["CN", "US"], Target::Direct)
            .unwrap();

        let data = writer.build().unwrap();
        assert!(data.len() > HEADER_SIZE);

        let slice_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(slice_count, 1);
    }

    #[test]
    fn test_fallback_in_header() {
        let mut writer = SliceWriter::new(Target::Proxy);
        let data = writer.build().unwrap();

        // fallback_target is at offset 16 (after magic + version + slice_count)
        assert_eq!(data[16], Target::Proxy.as_u8());
    }
}
