//! Binary rule file writer.

use sha2::{Digest, Sha256};

use super::format::*;
use crate::{Result, Target};

/// Intermediate representation of rules for binary serialization.
#[derive(Debug, Default)]
pub struct IntermediateRules {
    /// Exact match domains (domain, target)
    pub exact_domains: Vec<(String, Target)>,
    /// Suffix match domains (suffix without leading dot, target)
    pub suffix_domains: Vec<(String, Target)>,
    /// IPv4 CIDR ranges (network, prefix_len, target)
    pub v4_cidrs: Vec<(u32, u8, Target)>,
    /// IPv6 CIDR ranges (network bytes, prefix_len, target)
    pub v6_cidrs: Vec<([u8; 16], u8, Target)>,
    /// GeoIP country codes (code, target)
    pub geoip_countries: Vec<(String, Target)>,
    /// Exact IPv4 addresses (ip, target)
    pub exact_v4_ips: Vec<(u32, Target)>,
    /// Exact IPv6 addresses (ip bytes, target)
    pub exact_v6_ips: Vec<([u8; 16], Target)>,
    /// Fallback target
    pub fallback_target: Target,
}

impl IntermediateRules {
    /// Create a new empty IntermediateRules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a domain pattern.
    pub fn add_domain(&mut self, pattern: &str, target: Target) {
        let pattern = pattern.trim().to_lowercase();
        if pattern.starts_with('.') {
            self.suffix_domains.push((pattern[1..].to_string(), target));
        } else {
            self.exact_domains.push((pattern, target));
        }
    }

    /// Add an IPv4 CIDR range.
    pub fn add_v4_cidr(&mut self, network: u32, prefix_len: u8, target: Target) {
        self.v4_cidrs.push((network, prefix_len, target));
    }

    /// Add an IPv6 CIDR range.
    pub fn add_v6_cidr(&mut self, network: [u8; 16], prefix_len: u8, target: Target) {
        self.v6_cidrs.push((network, prefix_len, target));
    }

    /// Add a GeoIP country code.
    pub fn add_geoip(&mut self, country: &str, target: Target) {
        self.geoip_countries.push((country.to_uppercase(), target));
    }

    /// Set the fallback target.
    pub fn set_fallback(&mut self, target: Target) {
        self.fallback_target = target;
    }
}

/// Binary rule file writer.
pub struct BinaryRuleWriter {
    buffer: Vec<u8>,
}

impl BinaryRuleWriter {
    /// Create a new writer.
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1024 * 1024), // 1MB initial
        }
    }

    /// Write rules to a binary format.
    pub fn write(&mut self, rules: &IntermediateRules) -> Result<Vec<u8>> {
        self.buffer.clear();

        // Reserve space for header
        self.buffer.resize(HEADER_SIZE, 0);

        // Write domain index
        let domain_index_offset = self.buffer.len() as u32;
        let domain_index_size = self.write_domain_index(rules)?;

        // Write CIDR index
        let cidr_index_offset = self.buffer.len() as u32;
        let cidr_index_size = self.write_cidr_index(rules)?;

        // Write GeoIP index
        let geoip_index_offset = self.buffer.len() as u32;
        let geoip_index_size = self.write_geoip_index(rules)?;

        // Write IP index
        let ip_index_offset = self.buffer.len() as u32;
        let ip_index_size = self.write_ip_index(rules)?;

        // Write payload (domain strings)
        let payload_offset = self.buffer.len() as u32;
        let payload_size = self.write_payload(rules)?;

        // Create header
        let header = BinaryHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FormatFlags::MMAP_SAFE.bits(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            checksum: [0; 32], // Will be filled later
            domain_index_offset,
            domain_index_size,
            cidr_index_offset,
            cidr_index_size,
            geoip_index_offset,
            geoip_index_size,
            ip_index_offset,
            ip_index_size,
            payload_offset,
            payload_size,
            domain_count: (rules.exact_domains.len() + rules.suffix_domains.len()) as u32,
            cidr_count: (rules.v4_cidrs.len() + rules.v6_cidrs.len()) as u32,
            geoip_count: rules.geoip_countries.len() as u32,
            ip_count: (rules.exact_v4_ips.len() + rules.exact_v6_ips.len()) as u32,
            reserved: [0; 16],
        };

        // Write header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const BinaryHeader as *const u8,
                HEADER_SIZE,
            )
        };
        self.buffer[..HEADER_SIZE].copy_from_slice(header_bytes);

        // Compute checksum (hash everything except the checksum field)
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer[0..0x18]); // Before checksum
        hasher.update(&[0u8; 32]); // Zero placeholder for checksum
        hasher.update(&self.buffer[0x38..]); // After checksum
        let checksum = hasher.finalize();

        // Write checksum
        self.buffer[0x18..0x38].copy_from_slice(&checksum);

        Ok(std::mem::take(&mut self.buffer))
    }

    fn write_domain_index(&mut self, rules: &IntermediateRules) -> Result<u32> {
        let start_offset = self.buffer.len();

        // Calculate hash table size (load factor 0.7)
        let exact_count = rules.exact_domains.len();
        let bucket_count = if exact_count > 0 {
            ((exact_count as f64 / 0.7) as usize)
                .next_power_of_two()
                .max(16)
        } else {
            0
        };

        // Write header
        let header = DomainIndexHeader {
            exact_count: bucket_count as u32,
            suffix_count: rules.suffix_domains.len() as u32,
            exact_bucket_offset: std::mem::size_of::<DomainIndexHeader>() as u32,
            suffix_array_offset: (std::mem::size_of::<DomainIndexHeader>()
                + bucket_count * std::mem::size_of::<DomainExactEntry>())
                as u32,
        };

        self.write_struct(&header);

        // Build exact match hash table
        let mut buckets = vec![
            DomainExactEntry {
                hash: 0,
                target: 0,
                _padding: [0; 7],
            };
            bucket_count
        ];

        for (domain, target) in &rules.exact_domains {
            let hash = fnv1a_hash(domain.as_bytes());
            let mut idx = (hash as usize) % bucket_count.max(1);

            for _ in 0..bucket_count {
                if buckets[idx].hash == 0 {
                    buckets[idx] = DomainExactEntry {
                        hash,
                        target: target.as_u8(),
                        _padding: [0; 7],
                    };
                    break;
                }
                idx = (idx + 1) % bucket_count;
            }
        }

        for bucket in &buckets {
            self.write_struct(bucket);
        }

        // Write suffix array (sorted by hash)
        // First, calculate cumulative payload offsets
        let mut payload_offset = 0u32;
        let mut suffix_entries: Vec<_> = rules
            .suffix_domains
            .iter()
            .map(|(domain, target)| {
                let hash = fnv1a_hash(domain.as_bytes());
                let current_offset = payload_offset;
                payload_offset += domain.len() as u32;
                (
                    hash,
                    DomainSuffixEntry {
                        hash,
                        target: target.as_u8(),
                        _padding: [0; 3],
                        payload_offset: current_offset,
                        domain_len: domain.len() as u16,
                        _padding2: [0; 6],
                    },
                    domain.clone(),
                )
            })
            .collect();

        suffix_entries.sort_by_key(|(hash, _, _)| *hash);

        for (_, entry, _) in &suffix_entries {
            self.write_struct(entry);
        }

        Ok((self.buffer.len() - start_offset) as u32)
    }

    fn write_cidr_index(&mut self, rules: &IntermediateRules) -> Result<u32> {
        let start_offset = self.buffer.len();

        // Sort CIDRs by network address
        let mut v4_sorted = rules.v4_cidrs.clone();
        v4_sorted.sort_by_key(|(network, _, _)| *network);

        let mut v6_sorted = rules.v6_cidrs.clone();
        v6_sorted.sort_by_key(|(network, _, _)| *network);

        // Write header
        let header = CidrIndexHeader {
            v4_count: v4_sorted.len() as u32,
            v6_count: v6_sorted.len() as u32,
        };
        self.write_struct(&header);

        // Write IPv4 entries
        for (network, prefix_len, target) in &v4_sorted {
            let entry = CidrV4Entry {
                network: network.to_be(),
                prefix_len: *prefix_len,
                target: target.as_u8(),
                _padding: [0; 2],
            };
            self.write_struct(&entry);
        }

        // Write IPv6 entries
        for (network, prefix_len, target) in &v6_sorted {
            let entry = CidrV6Entry {
                network: *network,
                prefix_len: *prefix_len,
                target: target.as_u8(),
                _padding: [0; 6],
            };
            self.write_struct(&entry);
        }

        Ok((self.buffer.len() - start_offset) as u32)
    }

    fn write_geoip_index(&mut self, rules: &IntermediateRules) -> Result<u32> {
        let start_offset = self.buffer.len();

        for (country, target) in &rules.geoip_countries {
            let bytes = country.as_bytes();
            let entry = GeoIpEntry {
                country_code: [
                    bytes.first().copied().unwrap_or(0),
                    bytes.get(1).copied().unwrap_or(0),
                ],
                target: target.as_u8(),
                _padding: 0,
            };
            self.write_struct(&entry);
        }

        Ok((self.buffer.len() - start_offset) as u32)
    }

    fn write_ip_index(&mut self, rules: &IntermediateRules) -> Result<u32> {
        let start_offset = self.buffer.len();

        // Sort IPs
        let mut v4_sorted = rules.exact_v4_ips.clone();
        v4_sorted.sort_by_key(|(ip, _)| *ip);

        let mut v6_sorted = rules.exact_v6_ips.clone();
        v6_sorted.sort_by_key(|(ip, _)| *ip);

        // Write count header
        let v4_count = v4_sorted.len() as u32;
        let v6_count = v6_sorted.len() as u32;
        self.buffer.extend_from_slice(&v4_count.to_le_bytes());
        self.buffer.extend_from_slice(&v6_count.to_le_bytes());

        // Write IPv4 entries
        for (ip, target) in &v4_sorted {
            let entry = IpV4Entry {
                ip: *ip,
                target: target.as_u8(),
                _padding: [0; 3],
            };
            self.write_struct(&entry);
        }

        // Write IPv6 entries
        for (ip, target) in &v6_sorted {
            let entry = IpV6Entry {
                ip: *ip,
                target: target.as_u8(),
                _padding: [0; 7],
            };
            self.write_struct(&entry);
        }

        Ok((self.buffer.len() - start_offset) as u32)
    }

    fn write_payload(&mut self, rules: &IntermediateRules) -> Result<u32> {
        let start_offset = self.buffer.len();

        // Write suffix domain strings
        for (domain, _) in &rules.suffix_domains {
            self.buffer.extend_from_slice(domain.as_bytes());
        }

        Ok((self.buffer.len() - start_offset) as u32)
    }

    fn write_struct<T>(&mut self, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.buffer.extend_from_slice(bytes);
    }
}

impl Default for BinaryRuleWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_empty_rules() {
        let rules = IntermediateRules::new();
        let mut writer = BinaryRuleWriter::new();
        let data = writer.write(&rules).unwrap();

        assert!(data.len() >= HEADER_SIZE);
        assert_eq!(&data[0..8], &MAGIC);
    }

    #[test]
    fn test_write_with_domains() {
        let mut rules = IntermediateRules::new();
        rules.add_domain("google.com", Target::Proxy);
        rules.add_domain(".youtube.com", Target::Proxy);

        let mut writer = BinaryRuleWriter::new();
        let data = writer.write(&rules).unwrap();

        assert!(data.len() > HEADER_SIZE);
    }
}
