//! Metadata storage for tracking update times.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::error::Result;

/// Metadata for tracking update information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateMetadata {
    #[serde(with = "system_time_serde")]
    pub last_updated: Option<SystemTime>,
    pub etag: Option<String>,
}

mod system_time_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match time {
            Some(t) => {
                let duration = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                Some(duration.as_secs()).serialize(serializer)
            }
            None => None::<u64>.serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs: Option<u64> = Option::deserialize(deserializer)?;
        Ok(secs.map(|s| UNIX_EPOCH + Duration::from_secs(s)))
    }
}

impl UpdateMetadata {
    /// Create metadata with current time.
    pub fn now() -> Self {
        Self {
            last_updated: Some(SystemTime::now()),
            etag: None,
        }
    }

    /// Create metadata with current time and optional ETag.
    pub fn now_with_etag(etag: Option<String>) -> Self {
        Self {
            last_updated: Some(SystemTime::now()),
            etag,
        }
    }

    /// Load metadata from a file.
    ///
    /// Returns default metadata if the file doesn't exist.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let meta: Self =
            serde_json::from_str(&content).map_err(|e| crate::error::Error::Config(e.to_string()))?;
        Ok(meta)
    }

    /// Save metadata to a file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::Config(e.to_string()))?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Check if an update is needed based on the given interval.
    ///
    /// Returns `true` if:
    /// - No last_updated time is recorded
    /// - The elapsed time since last_updated exceeds the interval
    pub fn needs_update(&self, interval: Duration) -> bool {
        match self.last_updated {
            None => true,
            Some(last) => {
                let elapsed = SystemTime::now().duration_since(last).unwrap_or(Duration::MAX);
                elapsed >= interval
            }
        }
    }

    /// Get the last updated time.
    pub fn last_updated(&self) -> Option<SystemTime> {
        self.last_updated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.meta");
        let meta = UpdateMetadata {
            last_updated: Some(SystemTime::now()),
            etag: Some("abc123".to_string()),
        };
        meta.save(&path).unwrap();
        let loaded = UpdateMetadata::load(&path).unwrap();
        assert!(loaded.last_updated.is_some());
        assert_eq!(loaded.etag, Some("abc123".to_string()));
    }

    #[test]
    fn test_metadata_needs_update() {
        let meta = UpdateMetadata {
            last_updated: Some(SystemTime::now() - Duration::from_secs(3600)),
            etag: None,
        };
        // 1h ago, 30min interval -> needs update
        assert!(meta.needs_update(Duration::from_secs(1800)));
        // 1h ago, 2h interval -> doesn't need update
        assert!(!meta.needs_update(Duration::from_secs(7200)));
    }

    #[test]
    fn test_metadata_missing_file() {
        let loaded = UpdateMetadata::load("/nonexistent/path.meta");
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().last_updated.is_none());
    }

    #[test]
    fn test_metadata_now() {
        let meta = UpdateMetadata::now();
        assert!(meta.last_updated.is_some());
        assert!(meta.etag.is_none());
    }

    #[test]
    fn test_metadata_now_with_etag() {
        let meta = UpdateMetadata::now_with_etag(Some("test-etag".to_string()));
        assert!(meta.last_updated.is_some());
        assert_eq!(meta.etag, Some("test-etag".to_string()));
    }

    #[test]
    fn test_metadata_default_needs_update() {
        let meta = UpdateMetadata::default();
        assert!(meta.needs_update(Duration::from_secs(1)));
    }
}
