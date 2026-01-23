//! Remote rule manager for downloading, caching, and hot-reloading rule files.
//!
//! This module provides `RemoteRuleManager` which handles:
//! - Downloading rule files from a remote URL
//! - Gzip decompression
//! - Local caching with atomic updates
//! - ETag-based conditional requests (304 Not Modified)
//! - Hot reload support via `CachedBinaryReader`

use flate2::read::GzDecoder;
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::binary::{CachedBinaryReader, CachedReaderConfig, MAGIC};
use crate::metadata::UpdateMetadata;
use crate::{Result, Target};

/// Remote rule manager for downloading and caching rule files.
///
/// # Example
///
/// ```ignore
/// use k2rule::remote::RemoteRuleManager;
/// use k2rule::Target;
/// use std::path::Path;
///
/// let mut manager = RemoteRuleManager::new(
///     "https://example.com/rules.k2r.gz",
///     Path::new("/tmp/k2rule-cache"),
///     Target::Direct,
/// );
///
/// // Initialize: load from cache or download
/// manager.init()?;
///
/// // Query rules
/// let target = manager.match_domain("google.com");
///
/// // Check for updates (returns true if updated)
/// if manager.update()? {
///     println!("Rules updated!");
/// }
/// ```
pub struct RemoteRuleManager {
    /// Remote URL of the rule file (typically .k2r.gz)
    url: String,
    /// Local cache directory
    cache_dir: PathBuf,
    /// Cached binary reader (None until initialized)
    reader: Option<CachedBinaryReader>,
    /// ETag from last download (for conditional requests)
    etag: Option<String>,
    /// Fallback target when no rule matches or reader unavailable
    fallback: Target,
    /// Reader configuration
    reader_config: CachedReaderConfig,
    /// Update interval for periodic checks
    update_interval: Duration,
    /// Path to metadata file for tracking updates
    metadata_path: PathBuf,
}

impl RemoteRuleManager {
    /// Create a new remote rule manager.
    ///
    /// # Arguments
    ///
    /// * `url` - URL to download rules from (should be .k2r.gz for gzip compressed)
    /// * `cache_dir` - Directory to store cached rule files
    /// * `fallback` - Target to return when no rule matches or rules unavailable
    pub fn new(url: &str, cache_dir: &Path, fallback: Target) -> Self {
        let cache_path = cache_dir.to_path_buf();
        Self {
            url: url.to_string(),
            cache_dir: cache_path.clone(),
            reader: None,
            etag: None,
            fallback,
            reader_config: CachedReaderConfig::default(),
            update_interval: Duration::from_secs(86400), // 1 day default
            metadata_path: cache_path.join("rules.k2r.meta"),
        }
    }

    /// Create with custom cache configuration.
    pub fn with_config(
        url: &str,
        cache_dir: &Path,
        fallback: Target,
        reader_config: CachedReaderConfig,
    ) -> Self {
        let cache_path = cache_dir.to_path_buf();
        Self {
            url: url.to_string(),
            cache_dir: cache_path.clone(),
            reader: None,
            etag: None,
            fallback,
            reader_config,
            update_interval: Duration::from_secs(86400), // 1 day default
            metadata_path: cache_path.join("rules.k2r.meta"),
        }
    }

    /// Set a custom update interval for periodic checks.
    ///
    /// Default is 1 day (86400 seconds).
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Get the path to the cached rule file.
    fn rules_path(&self) -> PathBuf {
        self.cache_dir.join("rules.k2r")
    }

    /// Get the path to the ETag file.
    fn etag_path(&self) -> PathBuf {
        self.cache_dir.join("rules.k2r.etag")
    }

    /// Get the path for temporary download file.
    fn temp_path(&self) -> PathBuf {
        self.cache_dir.join("rules.k2r.tmp")
    }

    /// Initialize the manager: load from cache or download.
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

        // Try to load from cache first
        let rules_path = self.rules_path();
        if rules_path.exists() {
            match self.load_from_file(&rules_path) {
                Ok(()) => {
                    log::info!("Loaded rules from cache: {:?}", rules_path);
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("Failed to load cached rules, will download: {}", e);
                }
            }
        }

        // Download from remote
        self.download_and_update()?;
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
            ureq::Error::Status(code, _) => crate::Error::Config(format!("HTTP error: {}", code)),
            ureq::Error::Transport(t) => crate::Error::Config(format!("Transport error: {}", t)),
        });

        // Handle 304 Not Modified
        match response {
            Err(crate::Error::Config(ref msg)) if msg == "304 Not Modified" => {
                log::debug!("Rules not modified (304)");
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

        // Save metadata after successful update
        let meta = UpdateMetadata::now_with_etag(self.etag.clone());
        meta.save(&self.metadata_path)?;

        Ok(true)
    }

    /// Check if an update is needed based on the configured interval.
    ///
    /// Returns `true` if the update interval has elapsed since the last update.
    pub fn needs_update(&self) -> bool {
        let meta = UpdateMetadata::load(&self.metadata_path).unwrap_or_default();
        meta.needs_update(self.update_interval)
    }

    /// Check for updates and download only if the update interval has elapsed.
    ///
    /// This combines `needs_update()` with `update()` for convenience.
    ///
    /// Returns `true` if rules were updated, `false` if no update was needed or available.
    pub fn update_if_needed(&mut self) -> Result<bool> {
        if self.needs_update() {
            self.update()
        } else {
            Ok(false)
        }
    }

    /// Get the last update time.
    ///
    /// Returns `None` if the rules have never been updated.
    pub fn last_updated(&self) -> Option<SystemTime> {
        UpdateMetadata::load(&self.metadata_path)
            .ok()
            .and_then(|m| m.last_updated)
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

        // Save metadata after successful download
        let meta = UpdateMetadata::now_with_etag(self.etag.clone());
        meta.save(&self.metadata_path)?;

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
                "Downloaded and saved rules: {} bytes (compressed: {} bytes)",
                decompressed_data.len(),
                raw_len
            );
        } else {
            log::info!(
                "Downloaded and saved rules: {} bytes",
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

        if data[..MAGIC.len()] != MAGIC {
            return Err(crate::Error::InvalidMagic);
        }

        Ok(())
    }

    /// Load rules from a file and create/reload the reader.
    fn load_from_file(&mut self, path: &Path) -> Result<()> {
        if let Some(ref reader) = self.reader {
            // Hot reload existing reader
            reader.reload(path)?;
        } else {
            // Create new reader
            let reader = CachedBinaryReader::open_with_config(
                path,
                self.reader_config.clone(),
                self.fallback,
            )?;
            self.reader = Some(reader);
        }
        Ok(())
    }

    /// Get a reference to the underlying reader.
    ///
    /// Returns `None` if not initialized.
    pub fn reader(&self) -> Option<&CachedBinaryReader> {
        self.reader.as_ref()
    }

    /// Match a domain name against the rules.
    ///
    /// Returns the fallback target if rules are not loaded.
    pub fn match_domain(&self, domain: &str) -> Target {
        match &self.reader {
            Some(reader) => reader.match_domain(domain),
            None => self.fallback,
        }
    }

    /// Match an IP address against the rules.
    ///
    /// Returns the fallback target if rules are not loaded.
    pub fn match_ip(&self, ip: IpAddr) -> Target {
        match &self.reader {
            Some(reader) => reader.match_ip(ip),
            None => self.fallback,
        }
    }

    /// Match an IP or domain string against the rules.
    ///
    /// Returns the fallback target if rules are not loaded.
    pub fn match_input(&self, ip_or_domain: &str) -> Target {
        match &self.reader {
            Some(reader) => reader.match_input(ip_or_domain),
            None => self.fallback,
        }
    }

    /// Get the fallback target.
    pub fn fallback(&self) -> Target {
        self.fallback
    }

    /// Check if the manager has been initialized with rules.
    pub fn is_initialized(&self) -> bool {
        self.reader.is_some()
    }

    /// Get the current ETag (if any).
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
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
    use std::io::Write;

    fn create_test_rules() -> Vec<u8> {
        let mut rules = IntermediateRules::new();
        rules.add_domain("google.com", Target::Proxy);
        rules.add_domain(".youtube.com", Target::Proxy);
        rules.add_domain("example.com", Target::Direct);

        let mut writer = BinaryRuleWriter::new();
        writer.write(&rules).unwrap()
    }

    fn create_gzip_rules() -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let data = create_test_rules();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_is_gzip() {
        let manager = RemoteRuleManager::new("http://test", Path::new("/tmp"), Target::Proxy);

        let gzip_data = create_gzip_rules();
        assert!(manager.is_gzip(&gzip_data));

        let plain_data = create_test_rules();
        assert!(!manager.is_gzip(&plain_data));
    }

    #[test]
    fn test_validate_binary() {
        let manager = RemoteRuleManager::new("http://test", Path::new("/tmp"), Target::Proxy);

        let valid_data = create_test_rules();
        assert!(manager.validate_binary(&valid_data).is_ok());

        let invalid_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(manager.validate_binary(&invalid_data).is_err());
    }

    #[test]
    fn test_cache_paths() {
        let manager = RemoteRuleManager::new(
            "http://example.com/rules.k2r.gz",
            Path::new("/cache/k2rule"),
            Target::Direct,
        );

        assert_eq!(
            manager.rules_path(),
            PathBuf::from("/cache/k2rule/rules.k2r")
        );
        assert_eq!(
            manager.etag_path(),
            PathBuf::from("/cache/k2rule/rules.k2r.etag")
        );
        assert_eq!(
            manager.temp_path(),
            PathBuf::from("/cache/k2rule/rules.k2r.tmp")
        );
    }

    #[test]
    fn test_fallback_when_not_initialized() {
        let manager = RemoteRuleManager::new("http://test", Path::new("/tmp"), Target::Direct);

        assert!(!manager.is_initialized());
        assert_eq!(manager.match_domain("google.com"), Target::Direct);
        assert_eq!(manager.match_ip("8.8.8.8".parse().unwrap()), Target::Direct);
    }

    #[test]
    fn test_init_from_cache() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path();

        // Pre-populate cache with valid rules
        let rules_path = cache_dir.join("rules.k2r");
        let rules_data = create_test_rules();
        fs::write(&rules_path, &rules_data).unwrap();

        let mut manager =
            RemoteRuleManager::new("http://example.com/rules.k2r.gz", cache_dir, Target::Proxy);

        manager.init().unwrap();

        assert!(manager.is_initialized());
        assert_eq!(manager.match_domain("google.com"), Target::Proxy);
        assert_eq!(manager.match_domain("example.com"), Target::Direct);
    }

    #[test]
    fn test_with_config() {
        let config = CachedReaderConfig::with_capacity(500);
        let manager = RemoteRuleManager::with_config(
            "http://test",
            Path::new("/tmp"),
            Target::Direct,
            config,
        );

        assert_eq!(manager.url(), "http://test");
        assert_eq!(manager.fallback(), Target::Direct);
    }

    #[test]
    fn test_remote_manager_update_interval() {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            RemoteRuleManager::new("https://example.com/rules.k2r", dir.path(), Target::Proxy)
                .with_update_interval(Duration::from_secs(3600));

        // No metadata exists, so needs_update should be true
        assert!(manager.needs_update());
        // No updates have happened, so last_updated should be None
        assert!(manager.last_updated().is_none());
    }

    #[test]
    fn test_remote_manager_needs_update_with_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            RemoteRuleManager::new("https://example.com/rules.k2r", dir.path(), Target::Proxy)
                .with_update_interval(Duration::from_secs(3600)); // 1 hour

        // Simulate a recent update by creating metadata
        let meta = UpdateMetadata::now();
        meta.save(dir.path().join("rules.k2r.meta")).unwrap();

        // Should not need update since we just "updated"
        assert!(!manager.needs_update());
        assert!(manager.last_updated().is_some());
    }

    #[test]
    fn test_remote_manager_needs_update_expired() {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            RemoteRuleManager::new("https://example.com/rules.k2r", dir.path(), Target::Proxy)
                .with_update_interval(Duration::from_secs(60)); // 1 minute

        // Create metadata from 2 minutes ago
        let meta = UpdateMetadata {
            last_updated: Some(SystemTime::now() - Duration::from_secs(120)),
            etag: None,
        };
        meta.save(dir.path().join("rules.k2r.meta")).unwrap();

        // Should need update since interval has elapsed
        assert!(manager.needs_update());
    }

    #[test]
    fn test_metadata_path() {
        let manager = RemoteRuleManager::new(
            "http://example.com/rules.k2r.gz",
            Path::new("/cache/k2rule"),
            Target::Direct,
        );

        assert_eq!(
            manager.metadata_path,
            PathBuf::from("/cache/k2rule/rules.k2r.meta")
        );
    }
}
