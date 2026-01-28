//! Porn domain checker module.
//!
//! This module provides functionality to check if a domain is a known porn site.
//! It uses the same binary format as k2rule for efficient domain lookup.
//!
//! # Example
//!
//! ```ignore
//! use k2rule::porn::PornDomainChecker;
//! use std::path::Path;
//!
//! // Create checker with remote URL and local cache directory
//! let mut checker = PornDomainChecker::new(
//!     "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.k2r.gz",
//!     Path::new("/tmp/k2rule-porn-cache"),
//! );
//!
//! // Initialize: loads from cache or downloads
//! checker.init()?;
//!
//! // Check if a domain is porn
//! if checker.is_porn("example-adult-site.com") {
//!     println!("This is a porn site!");
//! }
//!
//! // Check for updates (uses ETag for efficiency)
//! if checker.update()? {
//!     println!("Porn domain list updated!");
//! }
//! ```

use flate2::read::GzDecoder;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::binary::{BinaryRuleReader, MAGIC};
use crate::Result;

/// Porn domain checker.
///
/// Uses the k2rule binary format to efficiently check if domains are known porn sites.
/// The checker downloads and caches a list of porn domains, supporting:
/// - Automatic gzip decompression
/// - ETag-based conditional requests
/// - Atomic cache updates
/// - Hot reload without restart
pub struct PornDomainChecker {
    /// Remote URL of the porn domain list (typically .k2r.gz)
    url: String,
    /// Local cache directory
    cache_dir: PathBuf,
    /// Binary reader (None until initialized)
    reader: Option<BinaryRuleReader>,
    /// ETag from last download (for conditional requests)
    etag: Option<String>,
    /// Source version from meta.json (e.g., "2026-01-28T08:17:56Z")
    source_version: Option<String>,
}

impl PornDomainChecker {
    /// Create a new porn domain checker.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to download porn domain list from (should be .k2r.gz for gzip compressed)
    /// * `cache_dir` - Directory to store cached rule files
    pub fn new(url: &str, cache_dir: &Path) -> Self {
        Self {
            url: url.to_string(),
            cache_dir: cache_dir.to_path_buf(),
            reader: None,
            etag: None,
            source_version: None,
        }
    }

    /// Get the path to the cached rule file.
    fn rules_path(&self) -> PathBuf {
        self.cache_dir.join("porn_domains.k2r")
    }

    /// Get the path to the ETag file.
    fn etag_path(&self) -> PathBuf {
        self.cache_dir.join("porn_domains.k2r.etag")
    }

    /// Get the path to the source version file.
    fn version_path(&self) -> PathBuf {
        self.cache_dir.join("porn_domains.version")
    }

    /// Get the path for temporary download file.
    fn temp_path(&self) -> PathBuf {
        self.cache_dir.join("porn_domains.k2r.tmp")
    }

    /// Initialize the checker: load from cache or download.
    ///
    /// If a cached rule file exists, it will be loaded.
    /// Otherwise, rules will be downloaded from the remote URL.
    pub fn init(&mut self) -> Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(&self.cache_dir)?;

        // Try to load ETag from file
        if let Ok(etag) = fs::read_to_string(self.etag_path()) {
            self.etag = Some(etag.trim().to_string());
        }

        // Try to load source version from file
        if let Ok(version) = fs::read_to_string(self.version_path()) {
            self.source_version = Some(version.trim().to_string());
        }

        // Try to load from cache first
        let rules_path = self.rules_path();
        if rules_path.exists() {
            match self.load_from_file(&rules_path) {
                Ok(()) => {
                    log::info!("Loaded porn domains from cache: {:?}", rules_path);
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("Failed to load cached porn domains, will download: {}", e);
                }
            }
        }

        // Download from remote
        self.download_and_update()?;
        Ok(())
    }

    /// Initialize from local file only (no download).
    ///
    /// Useful when you have a pre-generated file and don't want to download.
    pub fn init_from_file(&mut self, path: &Path) -> Result<()> {
        self.load_from_file(path)
    }

    /// Initialize from bytes (e.g., embedded in binary).
    ///
    /// The data can be gzip compressed or raw k2r format.
    pub fn init_from_bytes(&mut self, data: &[u8]) -> Result<()> {
        // Check if gzip compressed
        let decompressed = if self.is_gzip(data) {
            let mut decoder = GzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| crate::Error::Config(format!("Gzip decompression failed: {}", e)))?;
            decompressed
        } else {
            data.to_vec()
        };

        // Validate
        self.validate_binary(&decompressed)?;

        // Create reader
        let reader = BinaryRuleReader::from_bytes(decompressed)?;
        self.reader = Some(reader);
        Ok(())
    }

    /// Check for updates and download if available.
    ///
    /// Uses ETag for conditional requests to avoid unnecessary downloads.
    ///
    /// Returns `true` if rules were updated, `false` if no update was needed.
    pub fn update(&mut self) -> Result<bool> {
        // Build request with conditional headers
        let mut request = ureq::get(&self.url);

        if let Some(ref etag) = self.etag {
            request = request.set("If-None-Match", etag);
        }

        let response = request.call().map_err(|e| match e {
            ureq::Error::Status(304, _) => {
                // Not Modified - return early
                crate::Error::Config("304 Not Modified".to_string())
            }
            ureq::Error::Status(code, _) => {
                crate::Error::Config(format!("HTTP error: {}", code))
            }
            ureq::Error::Transport(t) => crate::Error::Config(format!("Transport error: {}", t)),
        });

        // Handle 304 Not Modified
        match response {
            Err(crate::Error::Config(ref msg)) if msg == "304 Not Modified" => {
                log::debug!("Porn domains not modified (304)");
                return Ok(false);
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }

        let response = response?;

        // Save new ETag if present
        if let Some(new_etag) = response.header("ETag") {
            self.etag = Some(new_etag.to_string());
            fs::write(self.etag_path(), new_etag)?;
        }

        // Download and decompress
        self.process_response(response)?;

        Ok(true)
    }

    /// Download and update rules (ignoring ETag).
    fn download_and_update(&mut self) -> Result<()> {
        let response = ureq::get(&self.url)
            .call()
            .map_err(|e| crate::Error::Config(format!("Download failed: {}", e)))?;

        // Save ETag if present
        if let Some(etag) = response.header("ETag") {
            self.etag = Some(etag.to_string());
            fs::write(self.etag_path(), etag)?;
        }

        self.process_response(response)?;
        Ok(())
    }

    /// Process HTTP response: decompress and atomically update.
    fn process_response(&mut self, response: ureq::Response) -> Result<()> {
        let temp_path = self.temp_path();
        let rules_path = self.rules_path();

        // Read response body
        let mut raw_data = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut raw_data)
            .map_err(|e| crate::Error::Config(format!("Failed to read response: {}", e)))?;

        let raw_len = raw_data.len();

        // Decompress gzip if needed
        let (decompressed_data, was_compressed) = if self.is_gzip(&raw_data) {
            let mut decoder = GzDecoder::new(&raw_data[..]);
            let mut data = Vec::new();
            decoder
                .read_to_end(&mut data)
                .map_err(|e| crate::Error::Config(format!("Gzip decompression failed: {}", e)))?;
            (data, true)
        } else {
            // Assume already decompressed
            (raw_data, false)
        };

        // Validate file integrity (magic number)
        self.validate_binary(&decompressed_data)?;

        // Write to temp file
        let mut temp_file = fs::File::create(&temp_path)?;
        temp_file.write_all(&decompressed_data)?;
        temp_file.sync_all()?;
        drop(temp_file);

        // Atomic rename
        fs::rename(&temp_path, &rules_path)?;

        if was_compressed {
            log::info!(
                "Downloaded and saved porn domains: {} bytes (compressed: {} bytes)",
                decompressed_data.len(),
                raw_len
            );
        } else {
            log::info!(
                "Downloaded and saved porn domains: {} bytes",
                decompressed_data.len()
            );
        }

        // Hot reload into reader
        self.load_from_file(&rules_path)?;

        Ok(())
    }

    /// Check if data is gzip compressed.
    fn is_gzip(&self, data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
    }

    /// Validate binary file integrity.
    fn validate_binary(&self, data: &[u8]) -> Result<()> {
        if data.len() < MAGIC.len() {
            return Err(crate::Error::Config("File too small".to_string()));
        }

        if &data[..MAGIC.len()] != &MAGIC {
            return Err(crate::Error::InvalidMagic);
        }

        Ok(())
    }

    /// Load rules from a file and create/reload the reader.
    fn load_from_file(&mut self, path: &Path) -> Result<()> {
        let reader = BinaryRuleReader::open(path)?;
        self.reader = Some(reader);
        Ok(())
    }

    /// Check if a domain is a known porn site.
    ///
    /// Returns `true` if the domain matches the porn domain list.
    /// Returns `false` if not initialized or no match found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if checker.is_porn("example-adult-site.com") {
    ///     println!("Blocked!");
    /// }
    /// ```
    pub fn is_porn(&self, domain: &str) -> bool {
        match &self.reader {
            Some(reader) => reader.match_domain(domain).is_some(),
            None => false,
        }
    }

    /// Check if the checker has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.reader.is_some()
    }

    /// Get the current ETag (if any).
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Get the source version (from meta.json).
    pub fn source_version(&self) -> Option<&str> {
        self.source_version.as_deref()
    }

    /// Set the source version (called when generating).
    pub fn set_source_version(&mut self, version: &str) {
        self.source_version = Some(version.to_string());
        // Also save to file if cache_dir exists
        if self.cache_dir.exists() {
            let _ = fs::write(self.version_path(), version);
        }
    }

    /// Get the URL being used.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the cache directory.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryRuleWriter, IntermediateRules};
    use crate::Target;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn create_test_porn_rules() -> Vec<u8> {
        let mut rules = IntermediateRules::new();
        // Use Reject target for porn domains (but we only check for presence)
        rules.add_domain("pornhub.com", Target::Reject);
        rules.add_domain(".xvideos.com", Target::Reject);
        rules.add_domain("adult-site.com", Target::Reject);

        let mut writer = BinaryRuleWriter::new();
        writer.write(&rules).unwrap()
    }

    fn create_gzip_rules() -> Vec<u8> {
        let data = create_test_porn_rules();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_is_gzip() {
        let checker = PornDomainChecker::new("http://test", Path::new("/tmp"));

        let gzip_data = create_gzip_rules();
        assert!(checker.is_gzip(&gzip_data));

        let plain_data = create_test_porn_rules();
        assert!(!checker.is_gzip(&plain_data));
    }

    #[test]
    fn test_validate_binary() {
        let checker = PornDomainChecker::new("http://test", Path::new("/tmp"));

        let valid_data = create_test_porn_rules();
        assert!(checker.validate_binary(&valid_data).is_ok());

        let invalid_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(checker.validate_binary(&invalid_data).is_err());
    }

    #[test]
    fn test_cache_paths() {
        let checker = PornDomainChecker::new(
            "http://example.com/porn_domains.k2r.gz",
            Path::new("/cache/k2rule"),
        );

        assert_eq!(
            checker.rules_path(),
            PathBuf::from("/cache/k2rule/porn_domains.k2r")
        );
        assert_eq!(
            checker.etag_path(),
            PathBuf::from("/cache/k2rule/porn_domains.k2r.etag")
        );
        assert_eq!(
            checker.version_path(),
            PathBuf::from("/cache/k2rule/porn_domains.version")
        );
    }

    #[test]
    fn test_not_initialized_returns_false() {
        let checker = PornDomainChecker::new("http://test", Path::new("/tmp"));

        assert!(!checker.is_initialized());
        assert!(!checker.is_porn("pornhub.com"));
    }

    #[test]
    fn test_init_from_bytes() {
        let mut checker = PornDomainChecker::new("http://test", Path::new("/tmp"));

        let data = create_test_porn_rules();
        checker.init_from_bytes(&data).unwrap();

        assert!(checker.is_initialized());
        assert!(checker.is_porn("pornhub.com"));
        assert!(checker.is_porn("www.xvideos.com"));
        assert!(checker.is_porn("sub.xvideos.com"));
        assert!(!checker.is_porn("google.com"));
    }

    #[test]
    fn test_init_from_gzip_bytes() {
        let mut checker = PornDomainChecker::new("http://test", Path::new("/tmp"));

        let data = create_gzip_rules();
        checker.init_from_bytes(&data).unwrap();

        assert!(checker.is_initialized());
        assert!(checker.is_porn("pornhub.com"));
    }

    #[test]
    fn test_init_from_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path();

        // Pre-populate cache with valid rules
        let rules_path = cache_dir.join("porn_domains.k2r");
        let rules_data = create_test_porn_rules();
        fs::write(&rules_path, &rules_data).unwrap();

        let mut checker =
            PornDomainChecker::new("http://example.com/porn_domains.k2r.gz", cache_dir);

        checker.init().unwrap();

        assert!(checker.is_initialized());
        assert!(checker.is_porn("pornhub.com"));
        assert!(!checker.is_porn("google.com"));
    }
}
