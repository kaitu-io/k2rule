//! GeoIP database manager with auto-download support.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use flate2::read::GzDecoder;

use crate::error::{Error, Result};
use crate::metadata::UpdateMetadata;
use crate::rule::geoip::init_geoip_database;

/// Default CDN URL for GeoIP database.
pub const DEFAULT_GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz";

/// Default update interval (7 days).
pub const DEFAULT_GEOIP_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Manager for GeoIP database lifecycle.
pub struct GeoIpManager {
    cache_dir: PathBuf,
    db_url: String,
    update_interval: Duration,
}

impl GeoIpManager {
    /// Create a new GeoIpManager with default URL.
    pub fn new(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
            db_url: DEFAULT_GEOIP_URL.to_string(),
            update_interval: DEFAULT_GEOIP_UPDATE_INTERVAL,
        }
    }

    /// Create a new GeoIpManager with a custom URL.
    pub fn with_url(cache_dir: impl AsRef<Path>, url: &str) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
            db_url: url.to_string(),
            update_interval: DEFAULT_GEOIP_UPDATE_INTERVAL,
        }
    }

    /// Set a custom update interval.
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Get the path to the GeoIP database file.
    pub fn db_path(&self) -> PathBuf {
        self.cache_dir.join("GeoLite2-Country.mmdb")
    }

    /// Get the path to the metadata file.
    fn metadata_path(&self) -> PathBuf {
        self.cache_dir.join("geoip.mmdb.meta")
    }

    /// Get the last update time.
    pub fn last_updated(&self) -> Option<SystemTime> {
        UpdateMetadata::load(self.metadata_path())
            .ok()
            .and_then(|m| m.last_updated)
    }

    /// Check if an update is needed based on the configured interval.
    pub fn needs_update(&self) -> bool {
        let meta = UpdateMetadata::load(self.metadata_path()).unwrap_or_default();
        meta.needs_update(self.update_interval)
    }

    /// Ensures the GeoIP database is available and initialized.
    /// Downloads if not present.
    pub fn ensure_initialized(&self) -> Result<()> {
        let db_path = self.db_path();

        // Create cache directory if needed
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Download if file doesn't exist
        if !db_path.exists() {
            self.download_database()?;
        }

        // Initialize the global GeoIP database
        init_geoip_database(&db_path)?;
        Ok(())
    }

    /// Downloads the GeoIP database from the configured URL.
    fn download_database(&self) -> Result<()> {
        let db_path = self.db_path();
        let temp_path = self.cache_dir.join("geoip.mmdb.tmp");

        // Download using ureq (blocking)
        let response = ureq::get(&self.db_url)
            .call()
            .map_err(|e| Error::Config(format!("Failed to download GeoIP database: {}", e)))?;

        if response.status() != 200 {
            return Err(Error::Config(format!(
                "Failed to download GeoIP database: HTTP {}",
                response.status()
            )));
        }

        // Read response body
        let mut bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Config(format!("Failed to read response: {}", e)))?;

        // Decompress if gzipped
        let decompressed = if self.db_url.ends_with(".gz") {
            let mut decoder = GzDecoder::new(&bytes[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        } else {
            bytes
        };

        // Write to temp file
        let mut file = File::create(&temp_path)?;
        file.write_all(&decompressed)?;
        file.sync_all()?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &db_path)?;

        // Update metadata
        let meta = UpdateMetadata::now();
        meta.save(self.metadata_path())?;

        log::info!(
            "Downloaded GeoIP database: {} bytes",
            decompressed.len()
        );

        Ok(())
    }

    /// Forces an update of the database.
    pub fn update(&mut self) -> Result<bool> {
        self.download_database()?;
        init_geoip_database(&self.db_path())?;
        Ok(true)
    }

    /// Updates if needed based on interval.
    pub fn update_if_needed(&mut self) -> Result<bool> {
        if self.needs_update() {
            self.update()
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_geoip_manager_new() {
        let dir = tempdir().unwrap();
        let manager = GeoIpManager::new(dir.path());
        assert_eq!(manager.db_path(), dir.path().join("GeoLite2-Country.mmdb"));
        assert!(manager.last_updated().is_none());
        assert!(manager.needs_update());
    }

    #[test]
    fn test_geoip_manager_with_url() {
        let dir = tempdir().unwrap();
        let manager =
            GeoIpManager::with_url(dir.path(), "https://custom.example.com/geoip.mmdb.gz");
        assert_eq!(manager.db_path(), dir.path().join("GeoLite2-Country.mmdb"));
    }

    #[test]
    fn test_geoip_manager_update_interval() {
        let dir = tempdir().unwrap();
        let manager =
            GeoIpManager::new(dir.path()).with_update_interval(Duration::from_secs(86400));
        assert!(manager.needs_update());
    }

    #[test]
    fn test_geoip_manager_needs_update_with_metadata() {
        let dir = tempdir().unwrap();
        let manager =
            GeoIpManager::new(dir.path()).with_update_interval(Duration::from_secs(86400));

        // Create metadata indicating recent update
        let meta = UpdateMetadata::now();
        meta.save(dir.path().join("geoip.mmdb.meta")).unwrap();

        // Should not need update (just updated)
        assert!(!manager.needs_update());
    }

    #[test]
    fn test_geoip_manager_metadata_path() {
        let dir = tempdir().unwrap();
        let manager = GeoIpManager::new(dir.path());
        assert_eq!(
            manager.metadata_path(),
            dir.path().join("geoip.mmdb.meta")
        );
    }

    #[test]
    fn test_geoip_manager_needs_update_expired() {
        let dir = tempdir().unwrap();
        let manager =
            GeoIpManager::new(dir.path()).with_update_interval(Duration::from_secs(60)); // 1 minute

        // Create metadata from 2 minutes ago
        let meta = UpdateMetadata {
            last_updated: Some(SystemTime::now() - Duration::from_secs(120)),
            etag: None,
        };
        meta.save(dir.path().join("geoip.mmdb.meta")).unwrap();

        // Should need update since interval has elapsed
        assert!(manager.needs_update());
    }

    #[test]
    fn test_geoip_manager_default_url() {
        let dir = tempdir().unwrap();
        let manager = GeoIpManager::new(dir.path());
        assert_eq!(manager.db_url, DEFAULT_GEOIP_URL);
    }

    #[test]
    fn test_geoip_manager_default_interval() {
        let dir = tempdir().unwrap();
        let manager = GeoIpManager::new(dir.path());
        assert_eq!(manager.update_interval, DEFAULT_GEOIP_UPDATE_INTERVAL);
    }
}
