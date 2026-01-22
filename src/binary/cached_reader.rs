//! Cached binary rule reader with hot reload support.
//!
//! This module provides a high-performance rule reader with:
//! - LRU cache for query results
//! - Atomic hot reload support for updating rules without downtime
//! - Thread-safe concurrent access

use arc_swap::ArcSwap;
use quick_cache::sync::Cache;
use std::path::Path;
use std::sync::Arc;

use super::reader::BinaryRuleReader;
use crate::{Result, Target};

/// Default cache capacity (number of entries).
const DEFAULT_CACHE_CAPACITY: usize = 10_000;

/// Cache entry representing a query result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Hash of the query string
    hash: u64,
}

impl CacheKey {
    fn new(query: &str) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        query.to_lowercase().hash(&mut hasher);
        Self {
            hash: hasher.finish(),
        }
    }
}

/// Configuration for the cached reader.
#[derive(Debug, Clone)]
pub struct CachedReaderConfig {
    /// Maximum number of entries in the cache.
    pub cache_capacity: usize,
    /// Whether to enable caching.
    pub cache_enabled: bool,
}

impl Default for CachedReaderConfig {
    fn default() -> Self {
        Self {
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            cache_enabled: true,
        }
    }
}

impl CachedReaderConfig {
    /// Create a new configuration with the specified cache capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            cache_capacity: capacity,
            cache_enabled: true,
        }
    }

    /// Create a configuration with caching disabled.
    pub fn no_cache() -> Self {
        Self {
            cache_capacity: 0,
            cache_enabled: false,
        }
    }
}

/// Cached binary rule reader with hot reload support.
///
/// This reader wraps `BinaryRuleReader` and adds:
/// - LRU cache for query results to avoid repeated lookups
/// - Atomic hot reload to update rules without service interruption
///
/// # Example
///
/// ```ignore
/// use k2rule::binary::CachedBinaryReader;
/// use std::path::Path;
///
/// // Create a cached reader
/// let reader = CachedBinaryReader::open(Path::new("rules.k2r"))?;
///
/// // Query with caching
/// let target = reader.match_domain("google.com");
///
/// // Hot reload new rules
/// reader.reload(Path::new("rules_new.k2r"))?;
/// ```
pub struct CachedBinaryReader {
    /// The underlying reader, wrapped in ArcSwap for atomic replacement.
    inner: ArcSwap<BinaryRuleReader>,
    /// LRU cache for query results.
    cache: Option<Cache<u64, Option<Target>>>,
    /// Fallback target when no rule matches.
    fallback: Target,
    /// Configuration.
    config: CachedReaderConfig,
    /// Generation counter for cache invalidation.
    generation: std::sync::atomic::AtomicU64,
}

impl CachedBinaryReader {
    /// Open a binary rule file with default configuration.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_config(path, CachedReaderConfig::default(), Target::Proxy)
    }

    /// Open a binary rule file with custom configuration.
    pub fn open_with_config(
        path: &Path,
        config: CachedReaderConfig,
        fallback: Target,
    ) -> Result<Self> {
        let reader = BinaryRuleReader::open(path)?;
        let cache = if config.cache_enabled && config.cache_capacity > 0 {
            Some(Cache::new(config.cache_capacity))
        } else {
            None
        };

        Ok(Self {
            inner: ArcSwap::from_pointee(reader),
            cache,
            fallback,
            config,
            generation: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Create from bytes with default configuration.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        Self::from_bytes_with_config(data, CachedReaderConfig::default(), Target::Proxy)
    }

    /// Create from bytes with custom configuration.
    pub fn from_bytes_with_config(
        data: Vec<u8>,
        config: CachedReaderConfig,
        fallback: Target,
    ) -> Result<Self> {
        let reader = BinaryRuleReader::from_bytes(data)?;
        let cache = if config.cache_enabled && config.cache_capacity > 0 {
            Some(Cache::new(config.cache_capacity))
        } else {
            None
        };

        Ok(Self {
            inner: ArcSwap::from_pointee(reader),
            cache,
            fallback,
            config,
            generation: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Hot reload rules from a new file.
    ///
    /// This atomically replaces the underlying reader and clears the cache.
    /// In-flight queries will complete with the old rules, new queries
    /// will use the new rules.
    pub fn reload(&self, path: &Path) -> Result<()> {
        let new_reader = BinaryRuleReader::open(path)?;
        self.inner.store(Arc::new(new_reader));

        // Increment generation to invalidate cached entries
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Clear cache
        if let Some(ref cache) = self.cache {
            cache.clear();
        }

        log::info!("Hot reloaded rules from {:?}", path);
        Ok(())
    }

    /// Hot reload rules from bytes.
    pub fn reload_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        let new_reader = BinaryRuleReader::from_bytes(data)?;
        self.inner.store(Arc::new(new_reader));

        // Increment generation to invalidate cached entries
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Clear cache
        if let Some(ref cache) = self.cache {
            cache.clear();
        }

        log::info!("Hot reloaded rules from bytes");
        Ok(())
    }

    /// Match a domain name with caching.
    pub fn match_domain(&self, domain: &str) -> Target {
        if domain.is_empty() {
            return self.fallback;
        }

        let key = CacheKey::new(domain);

        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(result) = cache.get(&key.hash) {
                return result.unwrap_or(self.fallback);
            }
        }

        // Cache miss - perform lookup
        let reader = self.inner.load();
        let result = reader.match_domain(domain);

        // Store in cache
        if let Some(ref cache) = self.cache {
            cache.insert(key.hash, result);
        }

        result.unwrap_or(self.fallback)
    }

    /// Match an IP address with caching.
    pub fn match_ip(&self, ip: std::net::IpAddr) -> Target {
        let ip_str = ip.to_string();
        let key = CacheKey::new(&ip_str);

        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(result) = cache.get(&key.hash) {
                return result.unwrap_or(self.fallback);
            }
        }

        // Cache miss - perform lookup
        let reader = self.inner.load();
        let result = reader.match_ip(ip);

        // Store in cache
        if let Some(ref cache) = self.cache {
            cache.insert(key.hash, result);
        }

        result.unwrap_or(self.fallback)
    }

    /// Match an IP or domain with caching.
    pub fn match_input(&self, ip_or_domain: &str) -> Target {
        if ip_or_domain.is_empty() {
            return self.fallback;
        }

        let key = CacheKey::new(ip_or_domain);

        // Check cache first
        if let Some(ref cache) = self.cache {
            if let Some(result) = cache.get(&key.hash) {
                return result.unwrap_or(self.fallback);
            }
        }

        // Cache miss - perform lookup
        let reader = self.inner.load();
        let result = reader.match_input(ip_or_domain);

        // Store in cache
        if let Some(ref cache) = self.cache {
            cache.insert(key.hash, result);
        }

        result.unwrap_or(self.fallback)
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear();
        }
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        if let Some(ref cache) = self.cache {
            CacheStats {
                capacity: self.config.cache_capacity,
                len: cache.len(),
                enabled: true,
            }
        } else {
            CacheStats {
                capacity: 0,
                len: 0,
                enabled: false,
            }
        }
    }

    /// Get the current generation (incremented on each reload).
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the fallback target.
    pub fn fallback(&self) -> Target {
        self.fallback
    }

    /// Set the fallback target.
    pub fn set_fallback(&mut self, target: Target) {
        self.fallback = target;
    }

    /// Get a reference to the underlying reader.
    ///
    /// Note: This is primarily for inspection/debugging. The returned
    /// Arc may become stale after a hot reload.
    pub fn inner(&self) -> arc_swap::Guard<Arc<BinaryRuleReader>> {
        self.inner.load()
    }
}

/// Cache statistics.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Maximum cache capacity.
    pub capacity: usize,
    /// Current number of entries in the cache.
    pub len: usize,
    /// Whether caching is enabled.
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryRuleWriter, IntermediateRules};

    fn create_test_rules() -> Vec<u8> {
        let mut rules = IntermediateRules::new();
        rules.add_domain("google.com", Target::Proxy);
        rules.add_domain(".youtube.com", Target::Proxy);
        rules.add_domain("example.com", Target::Direct);

        let mut writer = BinaryRuleWriter::new();
        writer.write(&rules).unwrap()
    }

    #[test]
    fn test_cached_reader_basic() {
        let data = create_test_rules();
        let reader = CachedBinaryReader::from_bytes(data).unwrap();

        assert_eq!(reader.match_domain("google.com"), Target::Proxy);
        assert_eq!(reader.match_domain("www.youtube.com"), Target::Proxy);
        assert_eq!(reader.match_domain("example.com"), Target::Direct);
        assert_eq!(reader.match_domain("unknown.com"), Target::Proxy); // fallback
    }

    #[test]
    fn test_cache_hit() {
        let data = create_test_rules();
        let reader = CachedBinaryReader::from_bytes(data).unwrap();

        // First call - cache miss
        let _ = reader.match_domain("google.com");
        let stats = reader.cache_stats();
        assert_eq!(stats.len, 1);

        // Second call - cache hit
        let _ = reader.match_domain("google.com");
        let stats = reader.cache_stats();
        assert_eq!(stats.len, 1); // Still 1 entry
    }

    #[test]
    fn test_hot_reload() {
        let data1 = create_test_rules();
        let reader = CachedBinaryReader::from_bytes(data1).unwrap();

        assert_eq!(reader.match_domain("google.com"), Target::Proxy);
        assert_eq!(reader.generation(), 0);

        // Create new rules with different targets
        let mut rules2 = IntermediateRules::new();
        rules2.add_domain("google.com", Target::Direct); // Changed!

        let mut writer = BinaryRuleWriter::new();
        let data2 = writer.write(&rules2).unwrap();

        // Hot reload
        reader.reload_from_bytes(data2).unwrap();

        assert_eq!(reader.generation(), 1);
        assert_eq!(reader.match_domain("google.com"), Target::Direct); // Updated!
    }

    #[test]
    fn test_cache_clear_on_reload() {
        let data = create_test_rules();
        let reader = CachedBinaryReader::from_bytes(data.clone()).unwrap();

        // Populate cache
        let _ = reader.match_domain("google.com");
        let _ = reader.match_domain("example.com");
        assert_eq!(reader.cache_stats().len, 2);

        // Reload clears cache
        reader.reload_from_bytes(data).unwrap();
        assert_eq!(reader.cache_stats().len, 0);
    }

    #[test]
    fn test_no_cache_config() {
        let data = create_test_rules();
        let config = CachedReaderConfig::no_cache();
        let reader =
            CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

        let _ = reader.match_domain("google.com");
        let stats = reader.cache_stats();
        assert!(!stats.enabled);
        assert_eq!(stats.len, 0);
    }

    #[test]
    fn test_custom_capacity() {
        let data = create_test_rules();
        let config = CachedReaderConfig::with_capacity(100);
        let reader =
            CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

        let stats = reader.cache_stats();
        assert!(stats.enabled);
        assert_eq!(stats.capacity, 100);
    }
}
