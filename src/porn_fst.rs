//! FST-based porn domain checker.
//!
//! Uses Finite State Transducer (FST) for extremely compact storage of domain lists.
//! FST exploits common prefixes and suffixes in domain names for compression.
//!
//! Benefits over the previous k2r + heuristic approach:
//! - Much smaller file size (FST compression is very efficient for strings)
//! - Simpler implementation (no need for separate heuristic detection)
//! - All domains stored in one compact structure
//!
//! # File Format
//!
//! ```text
//! +------------------+
//! |  MAGIC (8 bytes) |  "PORNFST\x01"
//! +------------------+
//! |  VERSION (4 bytes)|  u32 LE
//! +------------------+
//! | TIMESTAMP (8 bytes)| i64 LE (Unix timestamp)
//! +------------------+
//! | DOMAIN_COUNT (4) |  u32 LE
//! +------------------+
//! |    FST DATA      |  Variable (fst::Set bytes)
//! +------------------+
//! ```

use crate::{Error, Result};
use flate2::read::GzDecoder;
use fst::Set;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Magic bytes for FST porn domain file format
const MAGIC: &[u8; 8] = b"PORNFST\x01";
/// Current version of the file format
const VERSION: u32 = 1;
/// Header size: magic (8) + version (4) + timestamp (8) + domain_count (4) = 24 bytes
const HEADER_SIZE: usize = 24;

/// Build an FST-based porn domain file from a list of domains.
///
/// Domains starting with `.` are treated as suffix matches (e.g., `.pornhub.com`
/// matches `pornhub.com` and `www.pornhub.com`).
///
/// # Arguments
/// * `domains` - List of domain patterns to include
///
/// # Returns
/// Binary data containing the FST file with header
pub fn build_porn_fst(domains: &[&str]) -> Result<Vec<u8>> {
    // Normalize and reverse domains for suffix matching
    // FST requires sorted input, so we sort after reversing
    let mut reversed_domains: Vec<String> = domains
        .iter()
        .map(|d| {
            let normalized = d.to_lowercase();
            // Reverse the domain for suffix matching
            // e.g., ".pornhub.com" -> "moc.buhpron."
            normalized.chars().rev().collect::<String>()
        })
        .collect();

    // FST requires lexicographically sorted input
    reversed_domains.sort();
    reversed_domains.dedup();

    let domain_count = reversed_domains.len() as u32;

    // Build FST set
    let fst_set = Set::from_iter(reversed_domains.iter().map(|s| s.as_str()))
        .map_err(|e| Error::Config(format!("Failed to build FST: {}", e)))?;
    let fst_bytes = fst_set.as_fst().as_bytes();

    // Build header
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut output = Vec::with_capacity(HEADER_SIZE + fst_bytes.len());

    // Write header
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&timestamp.to_le_bytes());
    output.extend_from_slice(&domain_count.to_le_bytes());

    // Write FST data
    output.extend_from_slice(fst_bytes);

    Ok(output)
}

/// FST-based porn domain checker.
///
/// Provides efficient lookup for porn domains using a Finite State Transducer.
/// Supports suffix matching for subdomains.
pub struct FstPornChecker {
    /// The FST set containing reversed domain patterns
    fst: Set<Vec<u8>>,
    /// Number of domains in the set
    domain_count: u32,
    /// File format version
    version: u32,
}

impl FstPornChecker {
    /// Load an FST porn checker from raw bytes.
    ///
    /// # Arguments
    /// * `data` - Raw bytes containing the FST file
    ///
    /// # Returns
    /// FstPornChecker instance or error if data is invalid
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Config("FST data too short".to_string()));
        }

        // Verify magic
        if &data[0..8] != MAGIC {
            return Err(Error::Config("Invalid FST magic bytes".to_string()));
        }

        // Read header
        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        // Skip timestamp at [12..20]
        let domain_count = u32::from_le_bytes(data[20..24].try_into().unwrap());

        // Load FST
        let fst_data = &data[HEADER_SIZE..];
        let fst = Set::new(fst_data.to_vec())
            .map_err(|e| Error::Config(format!("Failed to load FST: {}", e)))?;

        Ok(Self {
            fst,
            domain_count,
            version,
        })
    }

    /// Load an FST porn checker from a file.
    ///
    /// Supports both plain `.fst` and gzip-compressed `.fst.gz` files.
    ///
    /// # Arguments
    /// * `path` - Path to the FST file
    ///
    /// # Returns
    /// FstPornChecker instance or error if file is invalid
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;

        // Check if gzip compressed
        let is_gzip = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "gz")
            .unwrap_or(false);

        if is_gzip {
            Self::from_gzip_bytes(&data)
        } else {
            Self::from_bytes(&data)
        }
    }

    /// Load an FST porn checker from gzip-compressed bytes.
    ///
    /// # Arguments
    /// * `data` - Gzip-compressed FST data
    ///
    /// # Returns
    /// FstPornChecker instance or error if data is invalid
    pub fn from_gzip_bytes(data: &[u8]) -> Result<Self> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| Error::Config(format!("Failed to decompress FST data: {}", e)))?;
        Self::from_bytes(&decompressed)
    }

    /// Check if a domain is in the porn list.
    ///
    /// Supports suffix matching: if `.example.com` is in the list,
    /// both `example.com` and `www.example.com` will match.
    ///
    /// # Arguments
    /// * `domain` - Domain to check (case-insensitive)
    ///
    /// # Returns
    /// `true` if the domain matches a porn pattern
    pub fn is_porn(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        let normalized = domain.to_lowercase();

        // Try exact match first (reversed)
        let reversed: String = normalized.chars().rev().collect();
        if self.fst.contains(&reversed) {
            return true;
        }

        // Try suffix match: check if any suffix pattern matches
        // For domain "www.pornhub.com", we check:
        // - ".www.pornhub.com" (reversed: "moc.buhpron.www.")
        // - ".pornhub.com" (reversed: "moc.buhpron.")
        // - ".com" (reversed: "moc.")
        let with_dot = format!(".{}", normalized);
        let reversed_with_dot: String = with_dot.chars().rev().collect();
        if self.fst.contains(&reversed_with_dot) {
            return true;
        }

        // Check all parent domains for suffix matches
        let parts: Vec<&str> = normalized.split('.').collect();
        for i in 1..parts.len() {
            let suffix = parts[i..].join(".");
            let suffix_with_dot = format!(".{}", suffix);
            let reversed_suffix: String = suffix_with_dot.chars().rev().collect();
            if self.fst.contains(&reversed_suffix) {
                return true;
            }
        }

        false
    }

    /// Get the number of domains in the set.
    pub fn domain_count(&self) -> u32 {
        self.domain_count
    }

    /// Get the file format version.
    pub fn version(&self) -> u32 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ==================== Basic Functionality Tests ====================

    /// Test that we can build an FST from a list of domains
    #[test]
    fn test_build_fst_from_domains() {
        let domains = vec!["pornhub.com", "xvideos.com", "example.xxx"];
        let fst_data = build_porn_fst(&domains).unwrap();

        // FST data should be non-empty
        assert!(!fst_data.is_empty());
        // Should start with magic bytes
        assert_eq!(&fst_data[0..8], b"PORNFST\x01");
    }

    /// Test that we can load and query an FST
    #[test]
    fn test_load_and_query_fst() {
        let domains = vec!["pornhub.com", "xvideos.com", "redtube.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        // Exact matches should work
        assert!(checker.is_porn("pornhub.com"));
        assert!(checker.is_porn("xvideos.com"));
        assert!(checker.is_porn("redtube.com"));

        // Non-matches should return false
        assert!(!checker.is_porn("google.com"));
        assert!(!checker.is_porn("github.com"));
    }

    /// Test suffix matching (subdomains)
    #[test]
    fn test_suffix_matching() {
        // Store domains with leading dot for suffix matching
        let domains = vec![".pornhub.com", ".xvideos.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        // Root domain should match
        assert!(checker.is_porn("pornhub.com"), "root domain should match");
        // Subdomains should match
        assert!(checker.is_porn("www.pornhub.com"), "www subdomain should match");
        assert!(checker.is_porn("video.pornhub.com"), "subdomain should match");
        assert!(checker.is_porn("a.b.c.pornhub.com"), "deep subdomain should match");

        // Different domains should not match
        assert!(!checker.is_porn("google.com"));
        assert!(!checker.is_porn("notpornhub.com"), "similar domain should not match");
    }

    /// Test case insensitive matching
    #[test]
    fn test_case_insensitive() {
        let domains = vec![".pornhub.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        assert!(checker.is_porn("PORNHUB.COM"));
        assert!(checker.is_porn("PornHub.Com"));
        assert!(checker.is_porn("WWW.PORNHUB.COM"));
    }

    /// Test large domain list
    #[test]
    fn test_large_domain_list() {
        // Generate a list of 10000 fake domains
        let domains: Vec<String> = (0..10000)
            .map(|i| format!(".domain{}.com", i))
            .collect();
        let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();

        let fst_data = build_porn_fst(&domain_refs).unwrap();
        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        // Check some domains
        assert!(checker.is_porn("domain0.com"));
        assert!(checker.is_porn("domain9999.com"));
        assert!(checker.is_porn("www.domain5000.com"));
        assert!(!checker.is_porn("domain10000.com")); // Not in list
    }

    // ==================== File I/O Tests ====================

    /// Test saving and loading from file
    #[test]
    fn test_save_and_load_file() {
        let domains = vec![".pornhub.com", ".xvideos.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("porn.fst");

        // Save to file
        std::fs::write(&file_path, &fst_data).unwrap();

        // Load from file
        let checker = FstPornChecker::open(&file_path).unwrap();

        assert!(checker.is_porn("pornhub.com"));
        assert!(checker.is_porn("www.xvideos.com"));
    }

    /// Test saving and loading gzip-compressed file
    #[test]
    fn test_save_and_load_gzip_file() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let domains = vec![".pornhub.com", ".xvideos.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("porn.fst.gz");

        // Save gzip compressed
        let file = std::fs::File::create(&file_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&fst_data).unwrap();
        encoder.finish().unwrap();

        // Load from gzip file
        let checker = FstPornChecker::open(&file_path).unwrap();

        assert!(checker.is_porn("pornhub.com"));
        assert!(checker.is_porn("www.xvideos.com"));
    }

    /// Test metadata (domain count, version)
    #[test]
    fn test_metadata() {
        let domains = vec![".pornhub.com", ".xvideos.com", ".redtube.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        assert_eq!(checker.domain_count(), 3);
        assert_eq!(checker.version(), 1);
    }

    // ==================== Edge Cases ====================

    /// Test empty domain list
    #[test]
    fn test_empty_domains() {
        let domains: Vec<&str> = vec![];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        assert!(!checker.is_porn("anything.com"));
        assert_eq!(checker.domain_count(), 0);
    }

    /// Test empty query
    #[test]
    fn test_empty_query() {
        let domains = vec![".pornhub.com"];
        let fst_data = build_porn_fst(&domains).unwrap();

        let checker = FstPornChecker::from_bytes(&fst_data).unwrap();

        assert!(!checker.is_porn(""));
    }

    /// Test invalid magic bytes
    #[test]
    fn test_invalid_magic() {
        let invalid_data = b"INVALID\x00\x00\x00\x00\x00";
        let result = FstPornChecker::from_bytes(invalid_data);
        assert!(result.is_err());
    }
}
