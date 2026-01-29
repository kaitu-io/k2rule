# kaitu-rules Compatible API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make k2rule a drop-in replacement for kaitu-rules by adding compatible API methods, LRU cache with statistics, GeoIP auto-download, and periodic update support.

**Architecture:** Extend RuleSet with kaitu-rules compatible methods as thin wrappers around existing functionality. Add LRU caching layer with hit/miss statistics using `quick_cache`. Create GeoIpManager for database lifecycle management. Enhance RemoteRuleManager with periodic update support and metadata persistence.

**Tech Stack:** Rust, quick_cache (LRU), ureq (HTTP), flate2 (gzip), serde_json (metadata), parking_lot (sync)

---

## Task 1: Add `with_fallback` Constructor to RuleSet

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

Add to the existing `#[cfg(test)]` module in `src/ruleset/mod.rs`:

```rust
#[test]
fn test_with_fallback_constructor() {
    let ruleset = RuleSet::with_fallback(Target::Direct);
    assert_eq!(ruleset.config.fallback_target, Target::Direct);

    let ruleset = RuleSet::with_fallback(Target::Proxy);
    assert_eq!(ruleset.config.fallback_target, Target::Proxy);

    let ruleset = RuleSet::with_fallback(Target::Reject);
    assert_eq!(ruleset.config.fallback_target, Target::Reject);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_with_fallback_constructor --lib -- --nocapture`
Expected: FAIL with "no function or associated item named `with_fallback`"

**Step 3: Write minimal implementation**

Add to `impl RuleSet` in `src/ruleset/mod.rs`:

```rust
/// Creates a new RuleSet with the specified fallback target.
/// This is a kaitu-rules compatible constructor.
pub fn with_fallback(fallback: Target) -> Self {
    let config = RuleConfig {
        name: "custom".to_string(),
        display_name: "Custom".to_string(),
        fallback_target: fallback,
    };
    Self::new(config)
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_with_fallback_constructor --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): add with_fallback constructor for kaitu-rules compatibility"
```

---

## Task 2: Add Single-Item Domain Add Methods (add_reject_domain)

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_single_item_domain_methods() {
    let ruleset = RuleSet::with_fallback(Target::Direct);

    // Test add_direct_domain (single)
    ruleset.add_direct_domain("example.com");
    assert_eq!(ruleset.match_domain("example.com"), Target::Direct);

    // Test add_proxy_domain (single)
    ruleset.add_proxy_domain("proxy.com");
    assert_eq!(ruleset.match_domain("proxy.com"), Target::Proxy);

    // Test add_reject_domain (new)
    ruleset.add_reject_domain("blocked.com");
    assert_eq!(ruleset.match_domain("blocked.com"), Target::Reject);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_single_item_domain_methods --lib -- --nocapture`
Expected: FAIL with "no method named `add_direct_domain`" (single-item version)

**Step 3: Write minimal implementation**

Add to `impl RuleSet` in `src/ruleset/mod.rs`:

```rust
/// Adds a single domain that routes directly.
/// kaitu-rules compatible single-item method.
pub fn add_direct_domain(&self, domain: &str) {
    let mut rule = self.direct_domain.write();
    let _ = rule.add_pattern(domain);
}

/// Adds a single domain that routes through proxy.
/// kaitu-rules compatible single-item method.
pub fn add_proxy_domain(&self, domain: &str) {
    let mut rule = self.proxy_domain.write();
    let _ = rule.add_pattern(domain);
}

/// Adds a single domain that gets rejected.
/// kaitu-rules compatible method.
pub fn add_reject_domain(&self, domain: &str) {
    let mut rule = self.reject_domain.write();
    let _ = rule.add_pattern(domain);
}
```

Note: This requires adding `reject_domain: RwLock<DomainRule>` field to RuleSet struct.

**Step 4: Add reject_domain field to RuleSet struct**

In `src/ruleset/mod.rs`, modify the struct:

```rust
pub struct RuleSet {
    rules: RwLock<Vec<Arc<dyn Rule>>>,
    config: RuleConfig,
    direct_domain: RwLock<DomainRule>,
    direct_ip: RwLock<IpRule>,
    proxy_domain: RwLock<DomainRule>,
    proxy_ip: RwLock<IpRule>,
    reject_domain: RwLock<DomainRule>,  // NEW
}
```

Update `new()` to initialize it:

```rust
reject_domain: RwLock::new(DomainRule::new(Target::Reject)),
```

Update `match_input()` to check reject_domain (add before proxy_domain check):

```rust
// Check dynamic reject domain rules
{
    let reject_domain = self.reject_domain.read();
    if reject_domain.match_input(None, domain) {
        return Target::Reject;
    }
}
```

**Step 5: Run test to verify it passes**

Run: `cargo test test_single_item_domain_methods --lib -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): add single-item domain add methods with reject support"
```

---

## Task 3: Add Single-Item IP and CIDR Add Methods

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_single_item_ip_methods() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Test add_direct_ip (single)
    ruleset.add_direct_ip("192.168.1.1");
    assert_eq!(ruleset.match_ip("192.168.1.1".parse().unwrap()), Target::Direct);

    // Test add_proxy_ip (single)
    ruleset.add_proxy_ip("10.0.0.1");
    assert_eq!(ruleset.match_ip("10.0.0.1".parse().unwrap()), Target::Proxy);
}

#[test]
fn test_single_item_cidr_methods() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Test add_direct_cidr
    ruleset.add_direct_cidr("192.168.0.0/16");
    assert_eq!(ruleset.match_ip("192.168.1.100".parse().unwrap()), Target::Direct);

    // Test add_proxy_cidr
    ruleset.add_proxy_cidr("10.0.0.0/8");
    assert_eq!(ruleset.match_ip("10.1.2.3".parse().unwrap()), Target::Proxy);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_single_item_ip_methods test_single_item_cidr_methods --lib -- --nocapture`
Expected: FAIL

**Step 3: Write minimal implementation**

Add to `impl RuleSet`:

```rust
/// Adds a single IP address that routes directly.
pub fn add_direct_ip(&self, ip: &str) {
    let mut rule = self.direct_ip.write();
    let _ = rule.add_pattern(ip);
}

/// Adds a single IP address that routes through proxy.
pub fn add_proxy_ip(&self, ip: &str) {
    let mut rule = self.proxy_ip.write();
    let _ = rule.add_pattern(ip);
}

/// Adds a CIDR range that routes directly.
pub fn add_direct_cidr(&self, cidr: &str) {
    let mut rule = self.direct_cidr.write();
    let _ = rule.add_pattern(cidr);
}

/// Adds a CIDR range that routes through proxy.
pub fn add_proxy_cidr(&self, cidr: &str) {
    let mut rule = self.proxy_cidr.write();
    let _ = rule.add_pattern(cidr);
}
```

This requires adding CIDR rule fields to RuleSet:

```rust
direct_cidr: RwLock<CidrRule>,
proxy_cidr: RwLock<CidrRule>,
```

Initialize in `new()`:

```rust
direct_cidr: RwLock::new(CidrRule::new(Target::Direct)),
proxy_cidr: RwLock::new(CidrRule::new(Target::Proxy)),
```

Update `match_input()` to check CIDR rules when IP is provided.

**Step 4: Run test to verify it passes**

Run: `cargo test test_single_item --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): add single-item IP and CIDR add methods"
```

---

## Task 4: Add match_host, match_domain, and match_ip Methods

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_match_methods() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);
    ruleset.add_direct_domain("example.com");
    ruleset.add_direct_ip("192.168.1.1");

    // match_host is alias for match_input
    assert_eq!(ruleset.match_host("example.com"), Target::Direct);
    assert_eq!(ruleset.match_host("192.168.1.1"), Target::Direct);
    assert_eq!(ruleset.match_host("unknown.com"), Target::Proxy);

    // match_domain only matches domains
    assert_eq!(ruleset.match_domain("example.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("unknown.com"), Target::Proxy);

    // match_ip only matches IPs
    use std::net::IpAddr;
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(ruleset.match_ip(ip), Target::Direct);
    let unknown_ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(ruleset.match_ip(unknown_ip), Target::Proxy);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_match_methods --lib -- --nocapture`
Expected: FAIL

**Step 3: Write minimal implementation**

```rust
/// Matches a host (IP or domain). Alias for match_input.
/// kaitu-rules compatible method.
pub fn match_host(&self, host: &str) -> Target {
    self.match_input(host)
}

/// Matches a domain only (does not parse as IP).
/// kaitu-rules compatible method.
pub fn match_domain(&self, domain: &str) -> Target {
    // Check dynamic rules first (in priority order)
    // Direct domain
    {
        let direct = self.direct_domain.read();
        if direct.match_input(None, domain) {
            return Target::Direct;
        }
    }
    // Reject domain
    {
        let reject = self.reject_domain.read();
        if reject.match_input(None, domain) {
            return Target::Reject;
        }
    }
    // Proxy domain
    {
        let proxy = self.proxy_domain.read();
        if proxy.match_input(None, domain) {
            return Target::Proxy;
        }
    }
    // Static rules (domain-type only)
    {
        let rules = self.rules.read();
        for rule in rules.iter() {
            if rule.rule_type() == RuleType::Domain && rule.match_input(None, domain) {
                return rule.target();
            }
        }
    }
    self.config.fallback_target
}

/// Matches an IP address only.
/// kaitu-rules compatible method.
pub fn match_ip(&self, ip: IpAddr) -> Target {
    let ip_str = ip.to_string();
    // Check dynamic IP rules
    {
        let direct = self.direct_ip.read();
        if direct.match_input(Some(ip), &ip_str) {
            return Target::Direct;
        }
    }
    {
        let proxy = self.proxy_ip.read();
        if proxy.match_input(Some(ip), &ip_str) {
            return Target::Proxy;
        }
    }
    // Check CIDR rules
    {
        let direct = self.direct_cidr.read();
        if direct.match_input(Some(ip), &ip_str) {
            return Target::Direct;
        }
    }
    {
        let proxy = self.proxy_cidr.read();
        if proxy.match_input(Some(ip), &ip_str) {
            return Target::Proxy;
        }
    }
    // Static rules (IP and CIDR types)
    {
        let rules = self.rules.read();
        for rule in rules.iter() {
            match rule.rule_type() {
                RuleType::IpCidr | RuleType::IpMatch | RuleType::GeoIP => {
                    if rule.match_input(Some(ip), &ip_str) {
                        return rule.target();
                    }
                }
                _ => {}
            }
        }
    }
    self.config.fallback_target
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_match_methods --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): add match_host, match_domain, match_ip methods"
```

---

## Task 5: Add LRU Cache Infrastructure to RuleSet

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_cache_infrastructure() {
    let ruleset = RuleSet::with_cache_size(
        RuleConfig {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            fallback_target: Target::Proxy,
        },
        100,
    );

    ruleset.add_direct_domain("cached.com");

    // First query - cache miss
    assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);

    // Second query - should be cached
    assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);

    // Check cache stats
    let (domain_hit_rate, ip_hit_rate) = ruleset.cache_stats();
    assert!(domain_hit_rate > 0.0); // Should have at least one hit

    // Clear cache
    ruleset.clear_cache();
    let (domain_hit_rate_after, _) = ruleset.cache_stats();
    // After clear, hit rate should be NaN or 0 (no queries)
}

#[test]
fn test_rule_count() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);
    assert_eq!(ruleset.rule_count(), 0);

    ruleset.add_direct_domain("a.com");
    ruleset.add_proxy_domain("b.com");
    ruleset.add_direct_ip("1.1.1.1");

    // rule_count should count dynamic rules
    assert!(ruleset.rule_count() >= 3);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_cache_infrastructure test_rule_count --lib -- --nocapture`
Expected: FAIL

**Step 3: Write minimal implementation**

Add cache fields to RuleSet struct:

```rust
use quick_cache::sync::Cache;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct RuleSet {
    // ... existing fields ...
    domain_cache: Option<Cache<u64, Target>>,
    ip_cache: Option<Cache<u64, Target>>,
    domain_cache_hits: AtomicU64,
    domain_cache_misses: AtomicU64,
    ip_cache_hits: AtomicU64,
    ip_cache_misses: AtomicU64,
}
```

Add constructor:

```rust
/// Creates a new RuleSet with specified cache size.
pub fn with_cache_size(config: RuleConfig, cache_size: usize) -> Self {
    Self {
        rules: RwLock::new(Vec::new()),
        config,
        direct_domain: RwLock::new(DomainRule::new(Target::Direct)),
        direct_ip: RwLock::new(IpRule::new(Target::Direct)),
        proxy_domain: RwLock::new(DomainRule::new(Target::Proxy)),
        proxy_ip: RwLock::new(IpRule::new(Target::Proxy)),
        reject_domain: RwLock::new(DomainRule::new(Target::Reject)),
        direct_cidr: RwLock::new(CidrRule::new(Target::Direct)),
        proxy_cidr: RwLock::new(CidrRule::new(Target::Proxy)),
        domain_cache: Some(Cache::new(cache_size)),
        ip_cache: Some(Cache::new(cache_size)),
        domain_cache_hits: AtomicU64::new(0),
        domain_cache_misses: AtomicU64::new(0),
        ip_cache_hits: AtomicU64::new(0),
        ip_cache_misses: AtomicU64::new(0),
    }
}
```

Add cache methods:

```rust
/// Returns cache hit rates (domain_hit_rate, ip_hit_rate).
/// Returns (NaN, NaN) if no queries have been made.
pub fn cache_stats(&self) -> (f64, f64) {
    let domain_hits = self.domain_cache_hits.load(Ordering::Relaxed);
    let domain_misses = self.domain_cache_misses.load(Ordering::Relaxed);
    let domain_total = domain_hits + domain_misses;
    let domain_hit_rate = if domain_total > 0 {
        domain_hits as f64 / domain_total as f64
    } else {
        f64::NAN
    };

    let ip_hits = self.ip_cache_hits.load(Ordering::Relaxed);
    let ip_misses = self.ip_cache_misses.load(Ordering::Relaxed);
    let ip_total = ip_hits + ip_misses;
    let ip_hit_rate = if ip_total > 0 {
        ip_hits as f64 / ip_total as f64
    } else {
        f64::NAN
    };

    (domain_hit_rate, ip_hit_rate)
}

/// Clears all caches.
pub fn clear_cache(&self) {
    if let Some(ref cache) = self.domain_cache {
        cache.clear();
    }
    if let Some(ref cache) = self.ip_cache {
        cache.clear();
    }
    self.domain_cache_hits.store(0, Ordering::Relaxed);
    self.domain_cache_misses.store(0, Ordering::Relaxed);
    self.ip_cache_hits.store(0, Ordering::Relaxed);
    self.ip_cache_misses.store(0, Ordering::Relaxed);
}

/// Returns total count of rules (static + dynamic).
pub fn rule_count(&self) -> usize {
    let static_count = self.rules.read().len();
    let direct_domain_count = self.direct_domain.read().len();
    let proxy_domain_count = self.proxy_domain.read().len();
    let reject_domain_count = self.reject_domain.read().len();
    let direct_ip_count = self.direct_ip.read().len();
    let proxy_ip_count = self.proxy_ip.read().len();
    let direct_cidr_count = self.direct_cidr.read().len();
    let proxy_cidr_count = self.proxy_cidr.read().len();

    static_count
        + direct_domain_count + proxy_domain_count + reject_domain_count
        + direct_ip_count + proxy_ip_count
        + direct_cidr_count + proxy_cidr_count
}
```

Note: Need to add `len()` method to DomainRule, IpRule, and CidrRule if not exists.

**Step 4: Run test to verify it passes**

Run: `cargo test test_cache --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs src/rule/domain.rs src/rule/ip.rs src/rule/cidr.rs
git commit -m "feat(ruleset): add LRU cache infrastructure with statistics"
```

---

## Task 6: Integrate Cache into match_domain and match_ip

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_cache_hit_tracking() {
    let ruleset = RuleSet::with_cache_size(
        RuleConfig {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            fallback_target: Target::Proxy,
        },
        100,
    );

    ruleset.add_direct_domain("test.com");

    // First query - miss
    ruleset.match_domain("test.com");
    let (hit_rate, _) = ruleset.cache_stats();
    assert_eq!(hit_rate, 0.0); // 0 hits, 1 miss = 0%

    // Second query - hit
    ruleset.match_domain("test.com");
    let (hit_rate, _) = ruleset.cache_stats();
    assert_eq!(hit_rate, 0.5); // 1 hit, 1 miss = 50%

    // Third query - hit
    ruleset.match_domain("test.com");
    let (hit_rate, _) = ruleset.cache_stats();
    assert!((hit_rate - 0.666).abs() < 0.01); // 2 hits, 1 miss ≈ 66.6%
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_cache_hit_tracking --lib -- --nocapture`
Expected: FAIL (cache not integrated into match methods yet)

**Step 3: Write minimal implementation**

Update `match_domain` to use cache:

```rust
pub fn match_domain(&self, domain: &str) -> Target {
    // Check cache first
    if let Some(ref cache) = self.domain_cache {
        let key = Self::hash_key(domain);
        if let Some(target) = cache.get(&key) {
            self.domain_cache_hits.fetch_add(1, Ordering::Relaxed);
            return target;
        }
        self.domain_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    // Perform actual lookup
    let result = self.match_domain_uncached(domain);

    // Store in cache
    if let Some(ref cache) = self.domain_cache {
        let key = Self::hash_key(domain);
        cache.insert(key, result);
    }

    result
}

fn match_domain_uncached(&self, domain: &str) -> Target {
    // ... existing match_domain logic moved here ...
}

fn hash_key(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    s.to_lowercase().hash(&mut hasher);
    hasher.finish()
}
```

Similarly update `match_ip`.

**Step 4: Run test to verify it passes**

Run: `cargo test test_cache_hit_tracking --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): integrate LRU cache into match_domain and match_ip"
```

---

## Task 7: Add Cache Invalidation on Rule Addition

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_cache_invalidation_on_rule_add() {
    let ruleset = RuleSet::with_cache_size(
        RuleConfig {
            name: "test".to_string(),
            display_name: "Test".to_string(),
            fallback_target: Target::Proxy,
        },
        100,
    );

    // Query returns fallback (Proxy)
    assert_eq!(ruleset.match_domain("test.com"), Target::Proxy);

    // Add rule that should change the result
    ruleset.add_direct_domain("test.com");

    // Query should return new value (cache should be invalidated)
    assert_eq!(ruleset.match_domain("test.com"), Target::Direct);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_cache_invalidation_on_rule_add --lib -- --nocapture`
Expected: FAIL (cached value returns Proxy instead of Direct)

**Step 3: Write minimal implementation**

Update all add methods to clear relevant cache:

```rust
pub fn add_direct_domain(&self, domain: &str) {
    {
        let mut rule = self.direct_domain.write();
        let _ = rule.add_pattern(domain);
    }
    // Invalidate domain cache
    if let Some(ref cache) = self.domain_cache {
        cache.clear();
    }
}
```

Apply same pattern to: `add_proxy_domain`, `add_reject_domain`, `add_direct_ip`, `add_proxy_ip`, `add_direct_cidr`, `add_proxy_cidr`.

**Step 4: Run test to verify it passes**

Run: `cargo test test_cache_invalidation --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "feat(ruleset): add cache invalidation on rule addition"
```

---

## Task 8: Create Metadata Module for Update Tracking

**Files:**
- Create: `src/metadata.rs`
- Modify: `src/lib.rs`
- Test: `src/metadata.rs` (inline tests)

**Step 1: Write the failing test**

Create `src/metadata.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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

        // 1 hour ago, interval is 30 min -> needs update
        assert!(meta.needs_update(Duration::from_secs(1800)));

        // 1 hour ago, interval is 2 hours -> doesn't need update
        assert!(!meta.needs_update(Duration::from_secs(7200)));
    }

    #[test]
    fn test_metadata_missing_file() {
        let loaded = UpdateMetadata::load("/nonexistent/path.meta");
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().last_updated.is_none());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test metadata --lib -- --nocapture`
Expected: FAIL (module doesn't exist)

**Step 3: Write minimal implementation**

```rust
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
    /// Creates new metadata with current timestamp.
    pub fn now() -> Self {
        Self {
            last_updated: Some(SystemTime::now()),
            etag: None,
        }
    }

    /// Creates new metadata with current timestamp and etag.
    pub fn now_with_etag(etag: Option<String>) -> Self {
        Self {
            last_updated: Some(SystemTime::now()),
            etag,
        }
    }

    /// Loads metadata from file. Returns default if file doesn't exist.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let meta: Self = serde_json::from_str(&content)
            .map_err(|e| crate::error::Error::Config(e.to_string()))?;
        Ok(meta)
    }

    /// Saves metadata to file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::Config(e.to_string()))?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Checks if update is needed based on interval.
    pub fn needs_update(&self, interval: Duration) -> bool {
        match self.last_updated {
            None => true,
            Some(last) => {
                let elapsed = SystemTime::now()
                    .duration_since(last)
                    .unwrap_or(Duration::MAX);
                elapsed >= interval
            }
        }
    }

    /// Returns the last updated time.
    pub fn last_updated(&self) -> Option<SystemTime> {
        self.last_updated
    }
}
```

Add to `src/lib.rs`:

```rust
mod metadata;
pub use metadata::UpdateMetadata;
```

**Step 4: Run test to verify it passes**

Run: `cargo test metadata --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/metadata.rs src/lib.rs
git commit -m "feat: add UpdateMetadata module for tracking update times"
```

---

## Task 9: Enhance RemoteRuleManager with Periodic Update Support

**Files:**
- Modify: `src/remote.rs`
- Test: `src/remote.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_remote_manager_update_interval() {
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let manager = RemoteRuleManager::new(
        "https://example.com/rules.k2r",
        dir.path(),
        Target::Proxy,
    )
    .with_update_interval(Duration::from_secs(3600)); // 1 hour

    // Initially needs update (no last_updated)
    assert!(manager.needs_update());
    assert!(manager.last_updated().is_none());
}

#[test]
fn test_remote_manager_update_if_needed() {
    // This test would require mocking HTTP - mark as integration test
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_remote_manager_update --lib -- --nocapture`
Expected: FAIL

**Step 3: Write minimal implementation**

Add fields to RemoteRuleManager:

```rust
pub struct RemoteRuleManager {
    // ... existing fields ...
    update_interval: Duration,
    metadata_path: PathBuf,
}
```

Add methods:

```rust
/// Sets the update interval.
pub fn with_update_interval(mut self, interval: Duration) -> Self {
    self.update_interval = interval;
    self
}

/// Checks if update is needed based on interval.
pub fn needs_update(&self) -> bool {
    let meta = UpdateMetadata::load(&self.metadata_path).unwrap_or_default();
    meta.needs_update(self.update_interval)
}

/// Updates if needed based on interval.
pub fn update_if_needed(&mut self) -> Result<bool> {
    if self.needs_update() {
        self.update()
    } else {
        Ok(false)
    }
}

/// Returns the last updated time.
pub fn last_updated(&self) -> Option<SystemTime> {
    UpdateMetadata::load(&self.metadata_path)
        .ok()
        .and_then(|m| m.last_updated)
}
```

Update `update()` to save metadata after successful download:

```rust
// After successful download and reload:
let meta = UpdateMetadata::now_with_etag(self.etag.clone());
meta.save(&self.metadata_path)?;
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_remote_manager --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/remote.rs
git commit -m "feat(remote): add periodic update support with metadata tracking"
```

---

## Task 10: Create GeoIpManager Structure

**Files:**
- Create: `src/geoip_manager.rs`
- Modify: `src/lib.rs`
- Test: `src/geoip_manager.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::time::Duration;

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
        let manager = GeoIpManager::with_url(
            dir.path(),
            "https://custom.example.com/geoip.mmdb.gz",
        );

        assert_eq!(manager.db_path(), dir.path().join("GeoLite2-Country.mmdb"));
    }

    #[test]
    fn test_geoip_manager_update_interval() {
        let dir = tempdir().unwrap();
        let manager = GeoIpManager::new(dir.path())
            .with_update_interval(Duration::from_secs(86400));

        // Always needs update initially
        assert!(manager.needs_update());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test geoip_manager --lib -- --nocapture`
Expected: FAIL (module doesn't exist)

**Step 3: Write minimal implementation**

Create `src/geoip_manager.rs`:

```rust
//! GeoIP database manager with auto-download support.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

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
    /// Creates a new GeoIpManager with default settings.
    pub fn new(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
            db_url: DEFAULT_GEOIP_URL.to_string(),
            update_interval: DEFAULT_GEOIP_UPDATE_INTERVAL,
        }
    }

    /// Creates a GeoIpManager with a custom URL.
    pub fn with_url(cache_dir: impl AsRef<Path>, url: &str) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
            db_url: url.to_string(),
            update_interval: DEFAULT_GEOIP_UPDATE_INTERVAL,
        }
    }

    /// Sets the update interval.
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Returns the path to the database file.
    pub fn db_path(&self) -> PathBuf {
        self.cache_dir.join("GeoLite2-Country.mmdb")
    }

    /// Returns the path to the metadata file.
    fn metadata_path(&self) -> PathBuf {
        self.cache_dir.join("geoip.mmdb.meta")
    }

    /// Returns the last updated time.
    pub fn last_updated(&self) -> Option<SystemTime> {
        UpdateMetadata::load(self.metadata_path())
            .ok()
            .and_then(|m| m.last_updated)
    }

    /// Checks if update is needed based on interval.
    pub fn needs_update(&self) -> bool {
        let meta = UpdateMetadata::load(self.metadata_path()).unwrap_or_default();
        meta.needs_update(self.update_interval)
    }
}
```

Add to `src/lib.rs`:

```rust
mod geoip_manager;
pub use geoip_manager::{GeoIpManager, DEFAULT_GEOIP_URL, DEFAULT_GEOIP_UPDATE_INTERVAL};
```

**Step 4: Run test to verify it passes**

Run: `cargo test geoip_manager --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/geoip_manager.rs src/lib.rs
git commit -m "feat: add GeoIpManager structure with basic configuration"
```

---

## Task 11: Add GeoIpManager Download and Initialization

**Files:**
- Modify: `src/geoip_manager.rs`
- Test: `src/geoip_manager.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_geoip_manager_ensure_initialized_with_existing_db() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("GeoLite2-Country.mmdb");

    // Create a fake database file (just for file existence check)
    // In real test, would need actual mmdb file
    std::fs::write(&db_path, b"fake").unwrap();

    let manager = GeoIpManager::new(dir.path());

    // Should fail because file isn't valid mmdb
    let result = manager.ensure_initialized().await;
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_geoip_manager_ensure --lib -- --nocapture`
Expected: FAIL (method doesn't exist)

**Step 3: Write minimal implementation**

Add async methods to GeoIpManager:

```rust
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{Read, Write};

impl GeoIpManager {
    /// Ensures the GeoIP database is available and initialized.
    /// Downloads if not present or update is needed.
    pub async fn ensure_initialized(&self) -> Result<()> {
        let db_path = self.db_path();

        // Create cache directory if needed
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Download if file doesn't exist
        if !db_path.exists() {
            self.download_database().await?;
        }

        // Initialize the global GeoIP database
        init_geoip_database(&db_path)?;

        Ok(())
    }

    /// Downloads the GeoIP database from the configured URL.
    async fn download_database(&self) -> Result<()> {
        let db_path = self.db_path();
        let temp_path = self.cache_dir.join("geoip.mmdb.tmp");

        // Download using reqwest (async)
        let response = reqwest::get(&self.db_url)
            .await
            .map_err(|e| Error::Download(e))?;

        if !response.status().is_success() {
            return Err(Error::Config(format!(
                "Failed to download GeoIP database: HTTP {}",
                response.status()
            )));
        }

        let bytes = response.bytes().await.map_err(|e| Error::Download(e))?;

        // Decompress if gzipped
        let decompressed = if self.db_url.ends_with(".gz") {
            let mut decoder = GzDecoder::new(&bytes[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| Error::Io(e))?;
            decompressed
        } else {
            bytes.to_vec()
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

        Ok(())
    }

    /// Forces an update of the database.
    pub async fn update(&mut self) -> Result<bool> {
        self.download_database().await?;
        init_geoip_database(self.db_path())?;
        Ok(true)
    }

    /// Updates if needed based on interval.
    pub async fn update_if_needed(&mut self) -> Result<bool> {
        if self.needs_update() {
            self.update().await
        } else {
            Ok(false)
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_geoip_manager --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/geoip_manager.rs
git commit -m "feat(geoip): add download and initialization support"
```

---

## Task 12: Add len() Methods to Rule Types

**Files:**
- Modify: `src/rule/domain.rs`
- Modify: `src/rule/ip.rs`
- Modify: `src/rule/cidr.rs`
- Test: inline tests

**Step 1: Write the failing test**

In `src/rule/domain.rs`:

```rust
#[test]
fn test_domain_rule_len() {
    let mut rule = DomainRule::new(Target::Direct);
    assert_eq!(rule.len(), 0);

    rule.add_pattern("example.com").unwrap();
    assert_eq!(rule.len(), 1);

    rule.add_pattern(".suffix.com").unwrap();
    assert_eq!(rule.len(), 2);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_domain_rule_len --lib -- --nocapture`
Expected: FAIL

**Step 3: Write minimal implementation**

In `src/rule/domain.rs`:

```rust
impl DomainRule {
    /// Returns the number of patterns in this rule.
    pub fn len(&self) -> usize {
        let exact = self.exact_domains.read();
        let suffix = self.suffix_domains.read();
        exact.len() + suffix.len()
    }

    /// Returns true if no patterns are configured.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

Similar for IpRule and CidrRule.

**Step 4: Run test to verify it passes**

Run: `cargo test len --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/rule/domain.rs src/rule/ip.rs src/rule/cidr.rs
git commit -m "feat(rules): add len() and is_empty() methods to rule types"
```

---

## Task 13: Update Default Constructor to Not Use Cache

**Files:**
- Modify: `src/ruleset/mod.rs`
- Test: `src/ruleset/mod.rs` (inline tests)

**Step 1: Write the failing test**

```rust
#[test]
fn test_default_ruleset_no_cache() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Query multiple times
    ruleset.match_domain("test.com");
    ruleset.match_domain("test.com");

    // Cache stats should be NaN (no cache)
    let (domain_rate, ip_rate) = ruleset.cache_stats();
    assert!(domain_rate.is_nan());
    assert!(ip_rate.is_nan());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_default_ruleset_no_cache --lib -- --nocapture`
Expected: May pass or fail depending on implementation

**Step 3: Ensure implementation**

Make sure `new()` and `with_fallback()` set caches to `None`:

```rust
impl RuleSet {
    pub fn new(config: RuleConfig) -> Self {
        Self {
            // ... other fields ...
            domain_cache: None,
            ip_cache: None,
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
            ip_cache_hits: AtomicU64::new(0),
            ip_cache_misses: AtomicU64::new(0),
        }
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_default_ruleset --lib -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/ruleset/mod.rs
git commit -m "fix(ruleset): default constructor without cache"
```

---

## Task 14: Add Integration Tests

**Files:**
- Create: `tests/integration.rs`

**Step 1: Write integration tests**

```rust
//! Integration tests for kaitu-rules compatibility.

use k2rule::{GeoIpManager, RemoteRuleManager, RuleConfig, RuleSet, Target};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_ruleset_kaitu_rules_compatibility() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Single-item adds
    ruleset.add_direct_domain("direct.com");
    ruleset.add_proxy_domain("proxy.com");
    ruleset.add_reject_domain("blocked.com");
    ruleset.add_direct_ip("192.168.1.1");
    ruleset.add_proxy_ip("10.0.0.1");
    ruleset.add_direct_cidr("172.16.0.0/12");
    ruleset.add_proxy_cidr("100.64.0.0/10");

    // Match methods
    assert_eq!(ruleset.match_host("direct.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("proxy.com"), Target::Proxy);
    assert_eq!(ruleset.match_domain("blocked.com"), Target::Reject);
    assert_eq!(ruleset.match_ip("192.168.1.1".parse().unwrap()), Target::Direct);
    assert_eq!(ruleset.match_ip("172.16.5.5".parse().unwrap()), Target::Direct);

    // Stats
    assert!(ruleset.rule_count() >= 7);
}

#[test]
fn test_ruleset_with_cache() {
    let config = RuleConfig {
        name: "test".to_string(),
        display_name: "Test".to_string(),
        fallback_target: Target::Proxy,
    };
    let ruleset = RuleSet::with_cache_size(config, 1000);

    ruleset.add_direct_domain("cached.com");

    // Multiple queries
    for _ in 0..10 {
        assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);
    }

    let (hit_rate, _) = ruleset.cache_stats();
    assert!(hit_rate > 0.8); // Should have ~90% hit rate (9 hits, 1 miss)

    ruleset.clear_cache();
}
```

**Step 2: Run integration tests**

Run: `cargo test --test integration -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add integration tests for kaitu-rules compatibility"
```

---

## Task 15: Update Public Exports in lib.rs

**Files:**
- Modify: `src/lib.rs`

**Step 1: Verify current exports**

Read `src/lib.rs` and ensure all new types are exported.

**Step 2: Update exports**

```rust
// In src/lib.rs
pub use ruleset::{RuleConfig, RuleSet, RuleSetType};
pub use target::Target;
pub use rule_type::RuleType;
pub use error::{Error, Result};
pub use metadata::UpdateMetadata;
pub use geoip_manager::{GeoIpManager, DEFAULT_GEOIP_URL, DEFAULT_GEOIP_UPDATE_INTERVAL};
pub use remote::RemoteRuleManager;

// Re-export rule types
pub use rule::geoip::{init_geoip_database, init_geoip_database_from_bytes, lookup_country};
```

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "chore: update public API exports"
```

---

## Task 16: Run Full Test Suite and Fix Issues

**Files:**
- Various (depending on failures)

**Step 1: Run all tests**

Run: `cargo test --all-features`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --all-features -- -D warnings`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt -- --check`
Expected: No formatting issues

**Step 4: Fix any issues found**

Make necessary fixes based on test/clippy/fmt output.

**Step 5: Final commit**

```bash
git add -A
git commit -m "fix: address test failures and clippy warnings"
```

---

## Task 17: Final Verification

**Step 1: Run full test suite**

```bash
cargo test --all-features -- --nocapture
```

**Step 2: Verify API compatibility**

Create a small example to verify API:

```rust
// Verify all kaitu-rules compatible methods exist
fn verify_api() {
    use k2rule::{RuleSet, Target, RuleConfig, GeoIpManager, RemoteRuleManager};
    use std::time::Duration;

    // Constructor
    let rs = RuleSet::with_fallback(Target::Proxy);

    // Single-item adds
    rs.add_direct_domain("d.com");
    rs.add_proxy_domain("p.com");
    rs.add_reject_domain("r.com");
    rs.add_direct_ip("1.1.1.1");
    rs.add_proxy_ip("2.2.2.2");
    rs.add_direct_cidr("10.0.0.0/8");
    rs.add_proxy_cidr("172.16.0.0/12");

    // Matching
    let _ = rs.match_host("test.com");
    let _ = rs.match_domain("test.com");
    let _ = rs.match_ip("1.1.1.1".parse().unwrap());

    // Cache & Stats
    let _ = rs.cache_stats();
    rs.clear_cache();
    let _ = rs.rule_count();

    // GeoIpManager
    let gm = GeoIpManager::new("/tmp")
        .with_update_interval(Duration::from_secs(86400));
    let _ = gm.needs_update();
    let _ = gm.last_updated();
    let _ = gm.db_path();

    // RemoteRuleManager
    let rm = RemoteRuleManager::new("url", "/tmp", Target::Proxy)
        .with_update_interval(Duration::from_secs(3600));
    let _ = rm.needs_update();
    let _ = rm.last_updated();
}
```

**Step 3: Commit verification**

```bash
git add -A
git commit -m "docs: add API verification example"
```

---

## Summary of Changes

| Component | Changes |
|-----------|---------|
| `RuleSet` | Added `with_fallback()`, `with_cache_size()`, single-item add methods, `match_host/domain/ip()`, cache infrastructure, `cache_stats()`, `clear_cache()`, `rule_count()` |
| `DomainRule/IpRule/CidrRule` | Added `len()`, `is_empty()` |
| `RemoteRuleManager` | Added `with_update_interval()`, `needs_update()`, `update_if_needed()`, `last_updated()`, metadata persistence |
| `GeoIpManager` | New module with download, initialization, periodic update support |
| `UpdateMetadata` | New module for tracking update times |

## Files Modified/Created

- Modified: `src/ruleset/mod.rs`
- Modified: `src/remote.rs`
- Modified: `src/rule/domain.rs`
- Modified: `src/rule/ip.rs`
- Modified: `src/rule/cidr.rs`
- Modified: `src/lib.rs`
- Created: `src/metadata.rs`
- Created: `src/geoip_manager.rs`
- Created: `tests/integration.rs`
