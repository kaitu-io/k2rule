# Slice-Based Rule Format (k2r v2) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the current k2r format with a slice-based format that preserves rule ordering and uses optimal data structures (FST for domains) per slice.

**Architecture:** Each rule-set becomes a "slice" with its own data structure. Slices are stored sequentially and queried in order until a match is found. Domain slices use FST for compact storage; CIDR/GeoIP slices use sorted arrays. The fallback target is stored in the header, eliminating the need for a default parameter.

**Tech Stack:** Rust, fst crate, flate2 for gzip

---

## File Format Overview

```
+--------------------+
|  HEADER (64 bytes) |  Magic "K2RULEV2", version, slice_count, fallback_target
+--------------------+
|  SLICE INDEX       |  Array of SliceEntry (type, target, offset, size)
+--------------------+
|  SLICE 0 DATA      |  FST or sorted array
+--------------------+
|  SLICE 1 DATA      |
+--------------------+
|      ...           |
+--------------------+
```

## Slice Types

| Type ID | Name | Data Structure | Content |
|---------|------|----------------|---------|
| 0x01 | FST_DOMAIN | FST Set | Domain suffixes (reversed) |
| 0x02 | CIDR_V4 | Sorted array | IPv4 CIDR ranges |
| 0x03 | CIDR_V6 | Sorted array | IPv6 CIDR ranges |
| 0x04 | GEOIP | Small array | Country codes |
| 0x05 | EXACT_IP_V4 | Sorted array | Exact IPv4 addresses |
| 0x06 | EXACT_IP_V6 | Sorted array | Exact IPv6 addresses |

---

### Task 1: Define Slice Format Structures

**Files:**
- Create: `src/slice/format.rs`
- Create: `src/slice/mod.rs`
- Modify: `src/lib.rs` (add `pub mod slice;`)

**Step 1: Write the failing test**

```rust
// src/slice/format.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_header_size() {
        assert_eq!(mem::size_of::<SliceHeader>(), 64);
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
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test slice::format::tests --no-fail-fast 2>&1`
Expected: FAIL with "cannot find module `slice`"

**Step 3: Write minimal implementation**

```rust
// src/slice/mod.rs
pub mod format;

// src/slice/format.rs
//! Slice-based binary format (k2r v2).

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
```

Update `src/lib.rs`:
```rust
pub mod slice;
```

**Step 4: Run test to verify it passes**

Run: `cargo test slice::format::tests -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/slice/ src/lib.rs
git commit -m "feat(slice): add slice-based format structures (k2r v2)"
```

---

### Task 2: Implement Slice Writer

**Files:**
- Create: `src/slice/writer.rs`
- Modify: `src/slice/mod.rs`

**Step 1: Write the failing test**

```rust
// src/slice/writer.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;

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
        writer.add_domain_slice(
            &["google.com", "youtube.com"],
            Target::Proxy,
        ).unwrap();

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
        writer.add_domain_slice(&["private.local"], Target::Direct).unwrap();
        writer.add_domain_slice(&["blocked.com"], Target::Reject).unwrap();
        writer.add_domain_slice(&["proxy.com"], Target::Proxy).unwrap();

        let data = writer.build().unwrap();

        let slice_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(slice_count, 3);
    }

    #[test]
    fn test_write_cidr_v4_slice() {
        let mut writer = SliceWriter::new(Target::Direct);
        // 10.0.0.0/8
        writer.add_cidr_v4_slice(&[(0x0A000000, 8)], Target::Direct).unwrap();

        let data = writer.build().unwrap();
        assert!(data.len() > HEADER_SIZE);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test slice::writer::tests --no-fail-fast 2>&1`
Expected: FAIL with "cannot find struct `SliceWriter`"

**Step 3: Write minimal implementation**

```rust
// src/slice/writer.rs
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
    pub fn add_cidr_v4_slice(&mut self, cidrs: &[(u32, u8)], target: Target) -> Result<()> {
        if cidrs.is_empty() {
            return Ok(());
        }

        let mut sorted = cidrs.to_vec();
        sorted.sort_by_key(|(network, _)| *network);

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
    pub fn add_cidr_v6_slice(&mut self, cidrs: &[([u8; 16], u8)], target: Target) -> Result<()> {
        if cidrs.is_empty() {
            return Ok(());
        }

        let mut sorted = cidrs.to_vec();
        sorted.sort_by_key(|(network, _)| *network);

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
    pub fn add_geoip_slice(&mut self, countries: &[&str], target: Target) -> Result<()> {
        if countries.is_empty() {
            return Ok(());
        }

        let mut data = Vec::with_capacity(countries.len() * 4);
        for country in countries {
            let bytes = country.as_bytes();
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
            std::slice::from_raw_parts(
                &header as *const SliceHeader as *const u8,
                HEADER_SIZE,
            )
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
```

Update `src/slice/mod.rs`:
```rust
pub mod format;
pub mod writer;

pub use format::*;
pub use writer::SliceWriter;
```

**Step 4: Run test to verify it passes**

Run: `cargo test slice::writer::tests -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/slice/
git commit -m "feat(slice): implement SliceWriter for building slice-based files"
```

---

### Task 3: Implement Slice Reader

**Files:**
- Create: `src/slice/reader.rs`
- Modify: `src/slice/mod.rs`

**Step 1: Write the failing test**

```rust
// src/slice/reader.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::slice::SliceWriter;
    use crate::Target;

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
        writer.add_domain_slice(&["google.com", "youtube.com"], Target::Proxy).unwrap();
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
        writer.add_domain_slice(&["cn.bing.com"], Target::Direct).unwrap();
        // Second slice: bing.com -> Proxy
        writer.add_domain_slice(&["bing.com"], Target::Proxy).unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        // cn.bing.com should match first slice (Direct)
        assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
        // www.cn.bing.com should also match first slice
        assert_eq!(reader.match_domain("www.cn.bing.com"), Some(Target::Direct));
        // bing.com should match second slice (Proxy)
        assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
        // www.bing.com should match second slice (Proxy)
        assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_match_with_fallback() {
        let mut writer = SliceWriter::new(Target::Proxy);
        writer.add_domain_slice(&["direct.com"], Target::Direct).unwrap();
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
        writer.add_cidr_v4_slice(&[(0x0A000000, 8)], Target::Direct).unwrap();
        let data = writer.build().unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(reader.match_ip("10.1.2.3".parse().unwrap()), Some(Target::Direct));
        assert_eq!(reader.match_ip("192.168.1.1".parse().unwrap()), None);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test slice::reader::tests --no-fail-fast 2>&1`
Expected: FAIL with "cannot find struct `SliceReader`"

**Step 3: Write minimal implementation**

```rust
// src/slice/reader.rs
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

        // Try exact match (reversed)
        let reversed: String = domain.chars().rev().collect();
        if fst.contains(&reversed) {
            return true;
        }

        // Try suffix matches
        let with_dot = format!(".{}", domain);
        let reversed_with_dot: String = with_dot.chars().rev().collect();
        if fst.contains(&reversed_with_dot) {
            return true;
        }

        // Check parent domains
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

            let network = u32::from_be_bytes(
                self.data[entry_offset..entry_offset + 4].try_into().unwrap()
            );
            let prefix_len = self.data[entry_offset + 4];

            let mask = if prefix_len == 0 {
                0
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

        if ip[..full_bytes] != network[..full_bytes] {
            return false;
        }

        if remaining_bits > 0 && full_bytes < 16 {
            let mask = 0xFF << (8 - remaining_bits);
            if (ip[full_bytes] & mask) != (network[full_bytes] & mask) {
                return false;
            }
        }

        true
    }
}
```

Update `src/slice/mod.rs`:
```rust
pub mod format;
pub mod reader;
pub mod writer;

pub use format::*;
pub use reader::SliceReader;
pub use writer::SliceWriter;
```

**Step 4: Run test to verify it passes**

Run: `cargo test slice::reader::tests -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/slice/
git commit -m "feat(slice): implement SliceReader for querying slice-based files"
```

---

### Task 4: Implement Clash Config to Slices Converter

**Files:**
- Create: `src/slice/converter.rs`
- Modify: `src/slice/mod.rs`

**Step 1: Write the failing test**

```rust
// src/slice/converter.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Target;

    #[test]
    fn test_convert_simple_rules() {
        let yaml = r#"
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - MATCH,DIRECT
"#;
        let converter = SliceConverter::new();
        let (data, fallback) = converter.convert(yaml).unwrap();

        assert_eq!(fallback, Target::Direct);

        let reader = SliceReader::from_bytes(&data).unwrap();

        // Order matters: cn.bing.com should be Direct (first match)
        assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
        assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_convert_with_rule_providers() {
        let yaml = r#"
rules:
  - RULE-SET,private,DIRECT
  - RULE-SET,proxy,PROXY
  - MATCH,PROXY
rule-providers:
  private:
    type: http
    behavior: domain
    url: "http://example.com/private.txt"
  proxy:
    type: http
    behavior: domain
    url: "http://example.com/proxy.txt"
"#;
        let mut converter = SliceConverter::new();
        converter.set_provider_rules("private", vec!["local.lan".to_string()]);
        converter.set_provider_rules("proxy", vec!["google.com".to_string()]);

        let (data, fallback) = converter.convert(yaml).unwrap();

        assert_eq!(fallback, Target::Proxy);

        let reader = SliceReader::from_bytes(&data).unwrap();
        assert_eq!(reader.match_domain("local.lan"), Some(Target::Direct));
        assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_merge_adjacent_same_target() {
        let yaml = r#"
rules:
  - RULE-SET,proxy1,PROXY
  - RULE-SET,proxy2,PROXY
  - MATCH,DIRECT
rule-providers:
  proxy1:
    type: http
    behavior: domain
    url: "http://example.com/proxy1.txt"
  proxy2:
    type: http
    behavior: domain
    url: "http://example.com/proxy2.txt"
"#;
        let mut converter = SliceConverter::new();
        converter.set_provider_rules("proxy1", vec!["a.com".to_string()]);
        converter.set_provider_rules("proxy2", vec!["b.com".to_string()]);

        let (data, _) = converter.convert(yaml).unwrap();
        let reader = SliceReader::from_bytes(&data).unwrap();

        // Adjacent same-type same-target slices should be merged
        // So we should have 1 slice instead of 2
        assert_eq!(reader.slice_count(), 1);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test slice::converter::tests --no-fail-fast 2>&1`
Expected: FAIL with "cannot find struct `SliceConverter`"

**Step 3: Write minimal implementation**

```rust
// src/slice/converter.rs
//! Convert Clash config to slice-based format.

use std::collections::HashMap;
use serde::Deserialize;

use super::{SliceReader, SliceWriter};
use crate::{Result, Target};

#[derive(Debug, Deserialize)]
struct ClashConfig {
    #[serde(default)]
    rules: Vec<String>,
    #[serde(rename = "rule-providers", default)]
    rule_providers: HashMap<String, RuleProvider>,
}

#[derive(Debug, Deserialize)]
struct RuleProvider {
    behavior: String,
    #[serde(default)]
    rules: Vec<String>,
}

/// Intermediate rule for a single slice.
#[derive(Debug)]
struct PendingSlice {
    slice_type: PendingSliceType,
    target: Target,
    domains: Vec<String>,
    cidrs_v4: Vec<(u32, u8)>,
    cidrs_v6: Vec<([u8; 16], u8)>,
    geoips: Vec<String>,
}

#[derive(Debug, PartialEq)]
enum PendingSliceType {
    Domain,
    CidrV4,
    CidrV6,
    GeoIp,
    Mixed,
}

impl PendingSlice {
    fn new_domain(target: Target) -> Self {
        Self {
            slice_type: PendingSliceType::Domain,
            target,
            domains: Vec::new(),
            cidrs_v4: Vec::new(),
            cidrs_v6: Vec::new(),
            geoips: Vec::new(),
        }
    }

    fn new_cidr_v4(target: Target) -> Self {
        Self {
            slice_type: PendingSliceType::CidrV4,
            target,
            domains: Vec::new(),
            cidrs_v4: Vec::new(),
            cidrs_v6: Vec::new(),
            geoips: Vec::new(),
        }
    }

    fn new_geoip(target: Target) -> Self {
        Self {
            slice_type: PendingSliceType::GeoIp,
            target,
            domains: Vec::new(),
            cidrs_v4: Vec::new(),
            cidrs_v6: Vec::new(),
            geoips: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.cidrs_v4.is_empty()
            && self.cidrs_v6.is_empty()
            && self.geoips.is_empty()
    }

    fn can_merge(&self, other: &Self) -> bool {
        self.slice_type == other.slice_type && self.target == other.target
    }

    fn merge(&mut self, other: Self) {
        self.domains.extend(other.domains);
        self.cidrs_v4.extend(other.cidrs_v4);
        self.cidrs_v6.extend(other.cidrs_v6);
        self.geoips.extend(other.geoips);
    }
}

/// Converter from Clash config to slice-based format.
pub struct SliceConverter {
    provider_rules: HashMap<String, Vec<String>>,
}

impl SliceConverter {
    pub fn new() -> Self {
        Self {
            provider_rules: HashMap::new(),
        }
    }

    pub fn set_provider_rules(&mut self, name: &str, rules: Vec<String>) {
        self.provider_rules.insert(name.to_string(), rules);
    }

    /// Convert Clash YAML to slice-based binary format.
    /// Returns (binary_data, fallback_target).
    pub fn convert(&self, yaml: &str) -> Result<(Vec<u8>, Target)> {
        let config: ClashConfig = serde_yaml::from_str(yaml)?;

        let mut fallback = Target::Direct;
        let mut pending_slices: Vec<PendingSlice> = Vec::new();

        for rule_str in &config.rules {
            let parts: Vec<&str> = rule_str.split(',').collect();
            if parts.len() < 2 {
                continue;
            }

            let rule_type = parts[0].trim();
            let target = Target::from_str_lossy(parts.last().unwrap_or(&"DIRECT"));

            match rule_type {
                "MATCH" => {
                    fallback = target;
                }
                "DOMAIN" | "DOMAIN-SUFFIX" => {
                    if parts.len() >= 3 {
                        let domain = parts[1].trim();
                        let domain_pattern = if rule_type == "DOMAIN-SUFFIX" {
                            format!(".{}", domain)
                        } else {
                            domain.to_string()
                        };

                        self.add_to_pending_slices(
                            &mut pending_slices,
                            PendingSliceType::Domain,
                            target,
                            |s| s.domains.push(domain_pattern),
                        );
                    }
                }
                "RULE-SET" => {
                    if parts.len() >= 3 {
                        let provider_name = parts[1].trim();
                        let behavior = config
                            .rule_providers
                            .get(provider_name)
                            .map(|p| p.behavior.as_str())
                            .unwrap_or("domain");

                        let rules = self
                            .provider_rules
                            .get(provider_name)
                            .cloned()
                            .or_else(|| {
                                config.rule_providers
                                    .get(provider_name)
                                    .map(|p| p.rules.clone())
                            })
                            .unwrap_or_default();

                        self.add_provider_to_slices(&mut pending_slices, behavior, &rules, target);
                    }
                }
                "GEOIP" => {
                    if parts.len() >= 3 {
                        let country = parts[1].trim();
                        self.add_to_pending_slices(
                            &mut pending_slices,
                            PendingSliceType::GeoIp,
                            target,
                            |s| s.geoips.push(country.to_uppercase()),
                        );
                    }
                }
                "IP-CIDR" => {
                    if parts.len() >= 3 {
                        let cidr = parts[1].trim();
                        if let Some((network, prefix)) = parse_cidr_v4(cidr) {
                            self.add_to_pending_slices(
                                &mut pending_slices,
                                PendingSliceType::CidrV4,
                                target,
                                |s| s.cidrs_v4.push((network, prefix)),
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Merge adjacent same-type same-target slices
        let merged_slices = self.merge_adjacent_slices(pending_slices);

        // Build binary
        let mut writer = SliceWriter::new(fallback);

        for slice in merged_slices {
            if slice.is_empty() {
                continue;
            }

            match slice.slice_type {
                PendingSliceType::Domain => {
                    let refs: Vec<&str> = slice.domains.iter().map(|s| s.as_str()).collect();
                    writer.add_domain_slice(&refs, slice.target)?;
                }
                PendingSliceType::CidrV4 => {
                    writer.add_cidr_v4_slice(&slice.cidrs_v4, slice.target)?;
                }
                PendingSliceType::CidrV6 => {
                    writer.add_cidr_v6_slice(&slice.cidrs_v6, slice.target)?;
                }
                PendingSliceType::GeoIp => {
                    let refs: Vec<&str> = slice.geoips.iter().map(|s| s.as_str()).collect();
                    writer.add_geoip_slice(&refs, slice.target)?;
                }
                PendingSliceType::Mixed => {}
            }
        }

        let data = writer.build()?;
        Ok((data, fallback))
    }

    fn add_to_pending_slices<F>(
        &self,
        slices: &mut Vec<PendingSlice>,
        slice_type: PendingSliceType,
        target: Target,
        f: F,
    ) where
        F: FnOnce(&mut PendingSlice),
    {
        // Check if we can append to the last slice
        if let Some(last) = slices.last_mut() {
            if last.slice_type == slice_type && last.target == target {
                f(last);
                return;
            }
        }

        // Create new slice
        let mut slice = match slice_type {
            PendingSliceType::Domain => PendingSlice::new_domain(target),
            PendingSliceType::CidrV4 => PendingSlice::new_cidr_v4(target),
            PendingSliceType::GeoIp => PendingSlice::new_geoip(target),
            _ => return,
        };
        f(&mut slice);
        slices.push(slice);
    }

    fn add_provider_to_slices(
        &self,
        slices: &mut Vec<PendingSlice>,
        behavior: &str,
        rules: &[String],
        target: Target,
    ) {
        match behavior {
            "domain" => {
                let mut domains = Vec::new();
                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }
                    let domain = if rule.starts_with("+.") {
                        format!(".{}", &rule[2..])
                    } else if rule.starts_with('.') {
                        rule.to_string()
                    } else {
                        format!(".{}", rule)
                    };
                    domains.push(domain);
                }

                if domains.is_empty() {
                    return;
                }

                // Check if we can merge with last slice
                if let Some(last) = slices.last_mut() {
                    if last.slice_type == PendingSliceType::Domain && last.target == target {
                        last.domains.extend(domains);
                        return;
                    }
                }

                let mut slice = PendingSlice::new_domain(target);
                slice.domains = domains;
                slices.push(slice);
            }
            "ipcidr" => {
                let mut cidrs_v4 = Vec::new();
                let mut cidrs_v6 = Vec::new();

                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }
                    if let Some((network, prefix)) = parse_cidr_v4(rule) {
                        cidrs_v4.push((network, prefix));
                    } else if let Some((network, prefix)) = parse_cidr_v6(rule) {
                        cidrs_v6.push((network, prefix));
                    }
                }

                if !cidrs_v4.is_empty() {
                    if let Some(last) = slices.last_mut() {
                        if last.slice_type == PendingSliceType::CidrV4 && last.target == target {
                            last.cidrs_v4.extend(cidrs_v4);
                        } else {
                            let mut slice = PendingSlice::new_cidr_v4(target);
                            slice.cidrs_v4 = cidrs_v4;
                            slices.push(slice);
                        }
                    } else {
                        let mut slice = PendingSlice::new_cidr_v4(target);
                        slice.cidrs_v4 = cidrs_v4;
                        slices.push(slice);
                    }
                }

                // Handle IPv6 separately if needed
                let _ = cidrs_v6;
            }
            _ => {}
        }
    }

    fn merge_adjacent_slices(&self, slices: Vec<PendingSlice>) -> Vec<PendingSlice> {
        let mut result: Vec<PendingSlice> = Vec::new();

        for slice in slices {
            if let Some(last) = result.last_mut() {
                if last.can_merge(&slice) {
                    last.merge(slice);
                    continue;
                }
            }
            result.push(slice);
        }

        result
    }
}

impl Default for SliceConverter {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix: u8 = parts[1].parse().ok()?;
    let addr: std::net::Ipv4Addr = parts[0].parse().ok()?;
    Some((u32::from(addr), prefix))
}

fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix: u8 = parts[1].parse().ok()?;
    let addr: std::net::Ipv6Addr = parts[0].parse().ok()?;
    Some((addr.octets(), prefix))
}
```

Update `src/slice/mod.rs`:
```rust
pub mod converter;
pub mod format;
pub mod reader;
pub mod writer;

pub use converter::SliceConverter;
pub use format::*;
pub use reader::SliceReader;
pub use writer::SliceWriter;
```

**Step 4: Run test to verify it passes**

Run: `cargo test slice::converter::tests -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/slice/
git commit -m "feat(slice): implement SliceConverter for Clash config"
```

---

### Task 5: Add CLI Command for Slice-Based Generation

**Files:**
- Modify: `src/bin/gen.rs`

**Step 1: Write the failing test (manual verification)**

Add a new CLI command `generate-slice` and verify it works manually.

**Step 2: Write implementation**

Add to `src/bin/gen.rs`:

```rust
// Add to Commands enum:
    /// Generate slice-based rule file (k2r v2)
    GenerateSlice {
        /// Input Clash YAML file
        #[arg(short, long)]
        input: PathBuf,

        /// Output binary file (.k2r2 or .k2r2.gz)
        #[arg(short, long)]
        output: PathBuf,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

// Add to main match:
        Commands::GenerateSlice { input, output, verbose } => {
            if let Err(e) = generate_slice(&input, &output, verbose) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }

// Add function:
fn generate_slice(input: &PathBuf, output: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    use k2rule::slice::SliceConverter;

    if verbose {
        println!("Reading input file: {:?}", input);
    }

    let yaml_content = fs::read_to_string(input)?;
    let config: ClashConfig = serde_yaml::from_str(&yaml_content)?;

    // Create HTTP client for downloading rule providers
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut converter = SliceConverter::new();

    // Download and load each rule provider
    for (name, provider) in &config.rule_providers {
        if let Some(url) = &provider.url {
            if verbose {
                println!("  Downloading provider '{}': {}", name, url);
            }

            match client.get(url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        let content = response.text()?;
                        let lines = parse_provider_payload(&content);

                        if verbose {
                            println!("    Loaded {} rules", lines.len());
                        }

                        converter.set_provider_rules(name, lines);
                    } else {
                        eprintln!("  Warning: Failed to download {}: {}", name, response.status());
                    }
                }
                Err(e) => {
                    eprintln!("  Warning: Failed to download {}: {}", name, e);
                }
            }
        }
    }

    let (binary_data, fallback) = converter.convert(&yaml_content)?;

    if verbose {
        println!("Generated slice-based file:");
        println!("  Fallback target: {:?}", fallback);
        println!("  Binary size: {} bytes", binary_data.len());
    }

    // Check if output should be gzip compressed
    let is_gzip = output
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "gz")
        .unwrap_or(false);

    if is_gzip {
        let file = fs::File::create(output)?;
        let mut encoder = GzEncoder::new(file, Compression::best());
        encoder.write_all(&binary_data)?;
        encoder.finish()?;
    } else {
        let mut file = fs::File::create(output)?;
        file.write_all(&binary_data)?;
    }

    println!("Successfully generated slice-based rule file: {:?}", output);
    Ok(())
}
```

**Step 3: Run manual test**

Run: `cargo run --bin k2rule-gen -- generate-slice -i clash_rules/cn_whitelist.yml -o /tmp/test.k2r2 -v`
Expected: File generated successfully

**Step 4: Commit**

```bash
git add src/bin/gen.rs
git commit -m "feat(cli): add generate-slice command for k2r v2 format"
```

---

### Task 6: Add Public Exports and Integration Tests

**Files:**
- Modify: `src/lib.rs`
- Create: `tests/slice_integration.rs`

**Step 1: Write integration test**

```rust
// tests/slice_integration.rs
use k2rule::slice::{SliceConverter, SliceReader};
use k2rule::Target;

#[test]
fn test_full_workflow_cn_whitelist_style() {
    let yaml = r#"
rules:
  - RULE-SET,private,DIRECT
  - RULE-SET,reject,REJECT
  - RULE-SET,proxy,PROXY
  - RULE-SET,direct,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
rule-providers:
  private:
    type: http
    behavior: domain
    url: "http://example.com"
  reject:
    type: http
    behavior: domain
    url: "http://example.com"
  proxy:
    type: http
    behavior: domain
    url: "http://example.com"
  direct:
    type: http
    behavior: domain
    url: "http://example.com"
"#;

    let mut converter = SliceConverter::new();
    converter.set_provider_rules("private", vec!["local.lan".to_string(), "localhost".to_string()]);
    converter.set_provider_rules("reject", vec!["ads.example.com".to_string()]);
    converter.set_provider_rules("proxy", vec!["google.com".to_string(), "youtube.com".to_string()]);
    converter.set_provider_rules("direct", vec!["baidu.com".to_string(), "taobao.com".to_string()]);

    let (data, fallback) = converter.convert(yaml).unwrap();

    assert_eq!(fallback, Target::Proxy);

    let reader = SliceReader::from_bytes(&data).unwrap();

    // Test each rule set in order
    assert_eq!(reader.match_domain("local.lan"), Some(Target::Direct));
    assert_eq!(reader.match_domain("ads.example.com"), Some(Target::Reject));
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.youtube.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("baidu.com"), Some(Target::Direct));

    // Unknown domain returns None (use fallback)
    assert_eq!(reader.match_domain("unknown.com"), None);
    assert_eq!(reader.fallback(), Target::Proxy);
}

#[test]
fn test_ordering_priority() {
    // Ensure that first match wins
    let yaml = r#"
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - MATCH,DIRECT
"#;

    let converter = SliceConverter::new();
    let (data, _) = converter.convert(yaml).unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // cn.bing.com matches first rule
    assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("www.cn.bing.com"), Some(Target::Direct));

    // bing.com matches second rule
    assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
}
```

**Step 2: Update lib.rs exports**

```rust
// Add to src/lib.rs
pub mod slice;
pub use slice::{SliceConverter, SliceReader, SliceWriter};
```

**Step 3: Run tests**

Run: `cargo test slice_integration -v`
Expected: PASS

**Step 4: Commit**

```bash
git add src/lib.rs tests/
git commit -m "feat: add public slice module exports and integration tests"
```

---

### Task 7: Update README Documentation

**Files:**
- Modify: `README.md`

Add documentation for the new slice-based format. Include:
- Format overview
- Usage examples
- CLI commands
- Migration notes

**Step 1: Update README**

Add section after existing binary format documentation.

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add slice-based format (k2r v2) documentation"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Define format structures | `src/slice/format.rs`, `src/slice/mod.rs` |
| 2 | Implement SliceWriter | `src/slice/writer.rs` |
| 3 | Implement SliceReader | `src/slice/reader.rs` |
| 4 | Implement SliceConverter | `src/slice/converter.rs` |
| 5 | Add CLI command | `src/bin/gen.rs` |
| 6 | Integration tests | `tests/slice_integration.rs`, `src/lib.rs` |
| 7 | Documentation | `README.md` |

Total estimated slices per config:
- cn_blacklist: ~5 slices (after merge)
- cn_whitelist: ~9 slices (after merge)

---

Plan complete and saved to `docs/plans/2026-01-29-slice-based-rule-format.md`. Two execution options:

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

Which approach?
