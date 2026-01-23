//! RuleSet management and configuration.

mod config;

pub use config::{RuleConfig, RuleSetType};

use parking_lot::RwLock;
use quick_cache::sync::Cache;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::rule::{CidrRule, DomainRule, DynamicRule, GeoIpRule, IpRule, Rule};
use crate::{RuleType, Target};

/// RuleSet manages a collection of rules for matching IP addresses and domains.
///
/// Rules are matched in priority order:
/// 1. Dynamic rules (Direct IP → Direct CIDR → Direct Domain → Reject Domain → Proxy IP → Proxy CIDR → Proxy Domain)
/// 2. Static rules (in the order they were added)
/// 3. Fallback target (when no rules match)
pub struct RuleSet {
    /// Static rules in priority order
    rules: RwLock<Vec<Arc<dyn Rule>>>,
    /// Configuration for this rule set
    config: RuleConfig,
    /// Dynamic direct domain rule
    direct_domain: RwLock<DomainRule>,
    /// Dynamic direct IP rule
    direct_ip: RwLock<IpRule>,
    /// Dynamic direct CIDR rule
    direct_cidr: RwLock<CidrRule>,
    /// Dynamic proxy domain rule
    proxy_domain: RwLock<DomainRule>,
    /// Dynamic proxy IP rule
    proxy_ip: RwLock<IpRule>,
    /// Dynamic proxy CIDR rule
    proxy_cidr: RwLock<CidrRule>,
    /// Dynamic reject domain rule
    reject_domain: RwLock<DomainRule>,
    /// LRU cache for domain lookups
    domain_cache: Option<Cache<u64, Target>>,
    /// LRU cache for IP lookups
    ip_cache: Option<Cache<u64, Target>>,
    /// Domain cache hit counter
    domain_cache_hits: AtomicU64,
    /// Domain cache miss counter
    domain_cache_misses: AtomicU64,
    /// IP cache hit counter
    ip_cache_hits: AtomicU64,
    /// IP cache miss counter
    ip_cache_misses: AtomicU64,
}

impl RuleSet {
    /// Create a new RuleSet with the specified configuration.
    pub fn new(config: RuleConfig) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            config,
            direct_domain: RwLock::new(DomainRule::new(Target::Direct)),
            direct_ip: RwLock::new(IpRule::new(Target::Direct)),
            direct_cidr: RwLock::new(CidrRule::new(Target::Direct)),
            proxy_domain: RwLock::new(DomainRule::new(Target::Proxy)),
            proxy_ip: RwLock::new(IpRule::new(Target::Proxy)),
            proxy_cidr: RwLock::new(CidrRule::new(Target::Proxy)),
            reject_domain: RwLock::new(DomainRule::new(Target::Reject)),
            domain_cache: None,
            ip_cache: None,
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
            ip_cache_hits: AtomicU64::new(0),
            ip_cache_misses: AtomicU64::new(0),
        }
    }

    /// Creates a new RuleSet with LRU cache enabled.
    /// The cache_size parameter specifies the maximum number of entries in each cache.
    pub fn with_cache_size(config: RuleConfig, cache_size: usize) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            config,
            direct_domain: RwLock::new(DomainRule::new(Target::Direct)),
            direct_ip: RwLock::new(IpRule::new(Target::Direct)),
            direct_cidr: RwLock::new(CidrRule::new(Target::Direct)),
            proxy_domain: RwLock::new(DomainRule::new(Target::Proxy)),
            proxy_ip: RwLock::new(IpRule::new(Target::Proxy)),
            proxy_cidr: RwLock::new(CidrRule::new(Target::Proxy)),
            reject_domain: RwLock::new(DomainRule::new(Target::Reject)),
            domain_cache: Some(Cache::new(cache_size)),
            ip_cache: Some(Cache::new(cache_size)),
            domain_cache_hits: AtomicU64::new(0),
            domain_cache_misses: AtomicU64::new(0),
            ip_cache_hits: AtomicU64::new(0),
            ip_cache_misses: AtomicU64::new(0),
        }
    }

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

    /// Create a new RuleSet by parsing rules from a reader.
    ///
    /// The reader should contain rules in k2rule text format.
    pub fn from_reader<R: Read>(reader: R, config: RuleConfig) -> Self {
        let mut ruleset = Self::new(config);
        ruleset.parse_rules(reader);
        ruleset
    }

    /// Parse rules from a reader and add them to this rule set.
    fn parse_rules<R: Read>(&mut self, reader: R) {
        let buf_reader = BufReader::new(reader);
        let mut current_rule: Option<Box<dyn DynamicRuleAny>> = None;

        for line in buf_reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };

            // Remove comments
            let line = match line.find('#') {
                Some(idx) => &line[..idx],
                None => &line,
            };
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            // Try to parse as rule header: [name=..., rule=..., target=...]
            if line.starts_with('[') && line.ends_with(']') {
                // Finalize previous rule
                if let Some(rule) = current_rule.take() {
                    self.add_rule(rule.into_rule());
                }

                // Parse header
                let content = &line[1..line.len() - 1];
                let params = parse_header_params(content);

                let rule_type = params.get("rule").and_then(|s| RuleType::parse(s));
                let target = params
                    .get("target")
                    .map(|s| Target::from_str_lossy(s))
                    .unwrap_or(Target::Proxy);
                let disabled = params.contains_key("disable")
                    && params
                        .get("disable")
                        .map(|v| !matches!(v.to_lowercase().as_str(), "false" | "0" | "f" | "no"))
                        .unwrap_or(true);

                if disabled {
                    continue;
                }

                current_rule = match rule_type {
                    Some(RuleType::Domain) => {
                        Some(Box::new(DomainRule::new(target)) as Box<dyn DynamicRuleAny>)
                    }
                    Some(RuleType::IpCidr) => {
                        Some(Box::new(CidrRule::new(target)) as Box<dyn DynamicRuleAny>)
                    }
                    Some(RuleType::GeoIP) => {
                        Some(Box::new(GeoIpRule::new(target)) as Box<dyn DynamicRuleAny>)
                    }
                    Some(RuleType::IpMatch) => {
                        Some(Box::new(IpRule::new(target)) as Box<dyn DynamicRuleAny>)
                    }
                    _ => None,
                };
            } else if let Some(ref mut rule) = current_rule {
                // Add pattern to current rule
                let _ = rule.add_pattern_any(line);
            }
        }

        // Finalize last rule
        if let Some(rule) = current_rule.take() {
            self.add_rule(rule.into_rule());
        }
    }

    /// Get the number of static rules in this set.
    pub fn len(&self) -> usize {
        self.rules.read().len()
    }

    /// Check if this rule set has no static rules.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a copy of all static rules.
    pub fn rules(&self) -> Vec<Arc<dyn Rule>> {
        self.rules.read().clone()
    }

    /// Match an IP or domain against all rules.
    ///
    /// Returns the target from the first matching rule,
    /// or the fallback target if no rules match.
    pub fn match_input(&self, ip_or_domain: &str) -> Target {
        if ip_or_domain.is_empty() {
            return self.config.fallback_target;
        }

        let ip_or_domain_lower = ip_or_domain.to_lowercase();

        // Parse as IP if possible
        let ip: Option<IpAddr> = ip_or_domain_lower.parse().ok();
        let domain = if ip.is_none() {
            &ip_or_domain_lower
        } else {
            ""
        };

        // Check dynamic rules first (highest priority)
        // Order: Direct IP -> Direct CIDR -> Direct Domain -> Reject Domain -> Proxy IP -> Proxy CIDR -> Proxy Domain
        if self.direct_ip.read().match_input(ip, domain) {
            return Target::Direct;
        }
        if self.direct_cidr.read().match_input(ip, domain) {
            return Target::Direct;
        }
        if self.direct_domain.read().match_input(ip, domain) {
            return Target::Direct;
        }
        // Check dynamic reject domain rules
        if self.reject_domain.read().match_input(ip, domain) {
            return Target::Reject;
        }
        if self.proxy_ip.read().match_input(ip, domain) {
            return Target::Proxy;
        }
        if self.proxy_cidr.read().match_input(ip, domain) {
            return Target::Proxy;
        }
        if self.proxy_domain.read().match_input(ip, domain) {
            return Target::Proxy;
        }

        // Check static rules
        let rules = self.rules.read();
        for rule in rules.iter() {
            if rule.match_input(ip, domain) {
                return rule.target();
            }
        }

        self.config.fallback_target
    }

    /// Get the fallback target for this rule set.
    pub fn fallback_target(&self) -> Target {
        self.config.fallback_target
    }

    /// Get the configuration for this rule set.
    pub fn config(&self) -> &RuleConfig {
        &self.config
    }

    /// Add a static rule to this set.
    pub fn add_rule(&self, rule: Arc<dyn Rule>) {
        self.rules.write().push(rule);
    }

    /// Add multiple domains that should route directly (batch method).
    pub fn add_direct_domains(&self, domains: &[&str]) {
        let mut rule = self.direct_domain.write();
        for domain in domains {
            let _ = rule.add_pattern(domain);
        }
        drop(rule);
        self.clear_domain_cache();
    }

    /// Add multiple domains that should route through proxy (batch method).
    pub fn add_proxy_domains(&self, domains: &[&str]) {
        let mut rule = self.proxy_domain.write();
        for domain in domains {
            let _ = rule.add_pattern(domain);
        }
        drop(rule);
        self.clear_domain_cache();
    }

    /// Add multiple IP addresses that should route directly (batch method).
    pub fn add_direct_ips(&self, ips: &[&str]) {
        let rule = self.direct_ip.read();
        for ip in ips {
            rule.add_ip(ip);
        }
        drop(rule);
        self.clear_ip_cache();
    }

    /// Add multiple IP addresses that should route through proxy (batch method).
    pub fn add_proxy_ips(&self, ips: &[&str]) {
        let rule = self.proxy_ip.read();
        for ip in ips {
            rule.add_ip(ip);
        }
        drop(rule);
        self.clear_ip_cache();
    }

    /// Adds a single domain that routes directly.
    /// kaitu-rules compatible single-item method.
    pub fn add_direct_domain(&self, domain: &str) {
        let mut rule = self.direct_domain.write();
        let _ = rule.add_pattern(domain);
        drop(rule);
        self.clear_domain_cache();
    }

    /// Adds a single domain that routes through proxy.
    /// kaitu-rules compatible single-item method.
    pub fn add_proxy_domain(&self, domain: &str) {
        let mut rule = self.proxy_domain.write();
        let _ = rule.add_pattern(domain);
        drop(rule);
        self.clear_domain_cache();
    }

    /// Adds a single domain that gets rejected.
    /// kaitu-rules compatible method.
    pub fn add_reject_domain(&self, domain: &str) {
        let mut rule = self.reject_domain.write();
        let _ = rule.add_pattern(domain);
        drop(rule);
        self.clear_domain_cache();
    }

    /// Adds a single IP address that routes directly.
    pub fn add_direct_ip(&self, ip: &str) {
        let mut rule = self.direct_ip.write();
        let _ = rule.add_pattern(ip);
        drop(rule);
        self.clear_ip_cache();
    }

    /// Adds a single IP address that routes through proxy.
    pub fn add_proxy_ip(&self, ip: &str) {
        let mut rule = self.proxy_ip.write();
        let _ = rule.add_pattern(ip);
        drop(rule);
        self.clear_ip_cache();
    }

    /// Adds a CIDR range that routes directly.
    pub fn add_direct_cidr(&self, cidr: &str) {
        let mut rule = self.direct_cidr.write();
        let _ = rule.add_pattern(cidr);
        drop(rule);
        self.clear_ip_cache();
    }

    /// Adds a CIDR range that routes through proxy.
    pub fn add_proxy_cidr(&self, cidr: &str) {
        let mut rule = self.proxy_cidr.write();
        let _ = rule.add_pattern(cidr);
        drop(rule);
        self.clear_ip_cache();
    }

    /// Matches a host (IP or domain). Alias for match_input.
    /// kaitu-rules compatible method.
    pub fn match_host(&self, host: &str) -> Target {
        self.match_input(host)
    }

    /// Matches a domain only (does not parse as IP).
    /// kaitu-rules compatible method.
    pub fn match_domain(&self, domain: &str) -> Target {
        // Check cache first if enabled
        if let Some(ref cache) = self.domain_cache {
            let key = hash_key(domain);
            if let Some(target) = cache.get(&key) {
                self.domain_cache_hits.fetch_add(1, Ordering::Relaxed);
                return target;
            }
            self.domain_cache_misses.fetch_add(1, Ordering::Relaxed);
            let result = self.match_domain_uncached(domain);
            cache.insert(key, result);
            return result;
        }
        self.match_domain_uncached(domain)
    }

    /// Internal uncached domain matching logic.
    fn match_domain_uncached(&self, domain: &str) -> Target {
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
        // Check cache first if enabled
        if let Some(ref cache) = self.ip_cache {
            let key = hash_key(&ip_str);
            if let Some(target) = cache.get(&key) {
                self.ip_cache_hits.fetch_add(1, Ordering::Relaxed);
                return target;
            }
            self.ip_cache_misses.fetch_add(1, Ordering::Relaxed);
            let result = self.match_ip_uncached(ip, &ip_str);
            cache.insert(key, result);
            return result;
        }
        self.match_ip_uncached(ip, &ip_str)
    }

    /// Internal uncached IP matching logic.
    fn match_ip_uncached(&self, ip: IpAddr, ip_str: &str) -> Target {
        // Check dynamic IP rules
        {
            let direct = self.direct_ip.read();
            if direct.match_input(Some(ip), ip_str) {
                return Target::Direct;
            }
        }
        {
            let proxy = self.proxy_ip.read();
            if proxy.match_input(Some(ip), ip_str) {
                return Target::Proxy;
            }
        }
        // Check CIDR rules
        {
            let direct = self.direct_cidr.read();
            if direct.match_input(Some(ip), ip_str) {
                return Target::Direct;
            }
        }
        {
            let proxy = self.proxy_cidr.read();
            if proxy.match_input(Some(ip), ip_str) {
                return Target::Proxy;
            }
        }
        // Static rules (IP and CIDR types)
        {
            let rules = self.rules.read();
            for rule in rules.iter() {
                match rule.rule_type() {
                    RuleType::IpCidr | RuleType::IpMatch | RuleType::GeoIP => {
                        if rule.match_input(Some(ip), ip_str) {
                            return rule.target();
                        }
                    }
                    _ => {}
                }
            }
        }
        self.config.fallback_target
    }

    /// Returns cache hit rates for (domain_cache, ip_cache).
    /// Returns NaN for caches that haven't been used or are disabled.
    pub fn cache_stats(&self) -> (f64, f64) {
        let domain_hits = self.domain_cache_hits.load(Ordering::Relaxed);
        let domain_misses = self.domain_cache_misses.load(Ordering::Relaxed);
        let domain_total = domain_hits + domain_misses;
        let domain_rate = if domain_total == 0 {
            f64::NAN
        } else {
            domain_hits as f64 / domain_total as f64
        };

        let ip_hits = self.ip_cache_hits.load(Ordering::Relaxed);
        let ip_misses = self.ip_cache_misses.load(Ordering::Relaxed);
        let ip_total = ip_hits + ip_misses;
        let ip_rate = if ip_total == 0 {
            f64::NAN
        } else {
            ip_hits as f64 / ip_total as f64
        };

        (domain_rate, ip_rate)
    }

    /// Clears all caches and resets hit/miss counters.
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

    /// Returns the total number of rules across all rule types.
    pub fn rule_count(&self) -> usize {
        let direct_domain = self.direct_domain.read().pattern_count();
        let proxy_domain = self.proxy_domain.read().pattern_count();
        let reject_domain = self.reject_domain.read().pattern_count();
        let direct_ip = self.direct_ip.read().count();
        let proxy_ip = self.proxy_ip.read().count();
        let direct_cidr = self.direct_cidr.read().pattern_count();
        let proxy_cidr = self.proxy_cidr.read().pattern_count();
        let static_rules = self.rules.read().len();

        direct_domain
            + proxy_domain
            + reject_domain
            + direct_ip
            + proxy_ip
            + direct_cidr
            + proxy_cidr
            + static_rules
    }

    /// Clears the domain cache (used after adding domain rules).
    fn clear_domain_cache(&self) {
        if let Some(ref cache) = self.domain_cache {
            cache.clear();
        }
    }

    /// Clears the IP cache (used after adding IP/CIDR rules).
    fn clear_ip_cache(&self) {
        if let Some(ref cache) = self.ip_cache {
            cache.clear();
        }
    }
}

/// Compute a hash key for cache lookup using ahash.
fn hash_key(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Parse header parameters from a string like "name=foo,rule=DOMAIN,target=PROXY"
fn parse_header_params(content: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    for part in content.split(',') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim().to_string();
            params.insert(key, value);
        } else {
            // Key without value (like "disable")
            params.insert(part.to_lowercase(), String::new());
        }
    }

    params
}

/// Helper trait for type-erased dynamic rule operations
trait DynamicRuleAny: Send {
    fn add_pattern_any(&mut self, pattern: &str) -> bool;
    fn into_rule(self: Box<Self>) -> Arc<dyn Rule>;
}

impl DynamicRuleAny for DomainRule {
    fn add_pattern_any(&mut self, pattern: &str) -> bool {
        self.add_pattern(pattern).is_ok()
    }

    fn into_rule(self: Box<Self>) -> Arc<dyn Rule> {
        Arc::new(*self)
    }
}

impl DynamicRuleAny for CidrRule {
    fn add_pattern_any(&mut self, pattern: &str) -> bool {
        self.add_pattern(pattern).is_ok()
    }

    fn into_rule(self: Box<Self>) -> Arc<dyn Rule> {
        Arc::new(*self)
    }
}

impl DynamicRuleAny for GeoIpRule {
    fn add_pattern_any(&mut self, pattern: &str) -> bool {
        self.add_pattern(pattern).is_ok()
    }

    fn into_rule(self: Box<Self>) -> Arc<dyn Rule> {
        Arc::new(*self)
    }
}

impl DynamicRuleAny for IpRule {
    fn add_pattern_any(&mut self, pattern: &str) -> bool {
        self.add_pattern(pattern).is_ok()
    }

    fn into_rule(self: Box<Self>) -> Arc<dyn Rule> {
        Arc::new(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_ruleset() {
        let config = RuleConfig::new("test", "Test", Target::Direct);
        let ruleset = RuleSet::new(config);

        // Should have no static rules initially
        assert_eq!(ruleset.len(), 0);
    }

    #[test]
    fn test_parse_rules() {
        let rules_text = r#"
# Comment
[name=test,rule=DOMAIN,target=PROXY]
google.com
.youtube.com

[name=local,rule=IP-CIDR,target=DIRECT]
192.168.0.0/16
10.0.0.0/8
"#;

        let config = RuleConfig::new("test", "Test", Target::Direct);
        let ruleset = RuleSet::from_reader(rules_text.as_bytes(), config);

        // Should have 2 parsed rules
        assert_eq!(ruleset.len(), 2);

        // Test matching
        assert_eq!(ruleset.match_input("google.com"), Target::Proxy);
        assert_eq!(ruleset.match_input("www.youtube.com"), Target::Proxy);
        assert_eq!(ruleset.match_input("192.168.1.1"), Target::Direct);
        assert_eq!(ruleset.match_input("10.0.0.1"), Target::Direct);
        assert_eq!(ruleset.match_input("8.8.8.8"), Target::Direct); // Fallback
    }

    #[test]
    fn test_dynamic_rules_priority() {
        let config = RuleConfig::new("test", "Test", Target::Proxy);
        let ruleset = RuleSet::new(config);

        // Add a static rule for google.com -> PROXY
        let mut domain_rule = DomainRule::new(Target::Proxy);
        domain_rule.add_pattern("google.com").unwrap();
        ruleset.add_rule(Arc::new(domain_rule));

        // Add dynamic rule for google.com -> DIRECT
        ruleset.add_direct_domains(&["google.com"]);

        // Dynamic rule should have higher priority
        assert_eq!(ruleset.match_input("google.com"), Target::Direct);
    }

    #[test]
    fn test_disabled_rules() {
        let rules_text = r#"
[name=disabled,rule=DOMAIN,target=PROXY,disable]
google.com

[name=enabled,rule=DOMAIN,target=DIRECT]
example.com
"#;

        let config = RuleConfig::new("test", "Test", Target::Proxy);
        let ruleset = RuleSet::from_reader(rules_text.as_bytes(), config);

        // Only the enabled rule should be active
        assert_eq!(ruleset.match_input("google.com"), Target::Proxy); // Fallback
        assert_eq!(ruleset.match_input("example.com"), Target::Direct);
    }

    #[test]
    fn test_fallback_target() {
        let config = RuleConfig::new("test", "Test", Target::Reject);
        let ruleset = RuleSet::new(config);

        assert_eq!(ruleset.match_input("unknown.com"), Target::Reject);
        assert_eq!(ruleset.match_input(""), Target::Reject);
    }

    #[test]
    fn test_with_fallback_constructor() {
        let ruleset = RuleSet::with_fallback(Target::Direct);
        assert_eq!(ruleset.config.fallback_target, Target::Direct);

        let ruleset = RuleSet::with_fallback(Target::Proxy);
        assert_eq!(ruleset.config.fallback_target, Target::Proxy);

        let ruleset = RuleSet::with_fallback(Target::Reject);
        assert_eq!(ruleset.config.fallback_target, Target::Reject);
    }

    #[test]
    fn test_single_item_domain_methods() {
        let ruleset = RuleSet::with_fallback(Target::Direct);

        // Test add_direct_domain (single, kaitu-rules compatible)
        ruleset.add_direct_domain("example.com");
        assert_eq!(ruleset.match_input("example.com"), Target::Direct);

        // Test add_proxy_domain (single, kaitu-rules compatible)
        ruleset.add_proxy_domain("proxy.com");
        assert_eq!(ruleset.match_input("proxy.com"), Target::Proxy);

        // Test add_reject_domain (kaitu-rules compatible)
        ruleset.add_reject_domain("blocked.com");
        assert_eq!(ruleset.match_input("blocked.com"), Target::Reject);
    }

    #[test]
    fn test_single_item_ip_methods() {
        let ruleset = RuleSet::with_fallback(Target::Proxy);

        // Test add_direct_ip (single)
        ruleset.add_direct_ip("192.168.1.1");
        assert_eq!(ruleset.match_input("192.168.1.1"), Target::Direct);

        // Test add_proxy_ip (single)
        ruleset.add_proxy_ip("10.0.0.1");
        assert_eq!(ruleset.match_input("10.0.0.1"), Target::Proxy);
    }

    #[test]
    fn test_single_item_cidr_methods() {
        let ruleset = RuleSet::with_fallback(Target::Proxy);

        // Test add_direct_cidr
        ruleset.add_direct_cidr("192.168.0.0/16");
        assert_eq!(ruleset.match_input("192.168.1.100"), Target::Direct);

        // Test add_proxy_cidr
        ruleset.add_proxy_cidr("10.0.0.0/8");
        assert_eq!(ruleset.match_input("10.1.2.3"), Target::Proxy);
    }

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
        assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);
        assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);
        let (domain_hit_rate, _ip_hit_rate) = ruleset.cache_stats();
        assert!(domain_hit_rate > 0.0);
        ruleset.clear_cache();
        // After clear, stats should be reset
        let (domain_hit_rate_after, _) = ruleset.cache_stats();
        assert!(domain_hit_rate_after.is_nan());
    }

    #[test]
    fn test_rule_count() {
        let ruleset = RuleSet::with_fallback(Target::Proxy);
        assert_eq!(ruleset.rule_count(), 0);
        ruleset.add_direct_domain("a.com");
        ruleset.add_proxy_domain("b.com");
        ruleset.add_direct_ip("1.1.1.1");
        assert!(ruleset.rule_count() >= 3);
    }

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
        ruleset.match_domain("test.com"); // miss
        let (hit_rate, _) = ruleset.cache_stats();
        assert_eq!(hit_rate, 0.0);
        ruleset.match_domain("test.com"); // hit
        let (hit_rate, _) = ruleset.cache_stats();
        assert_eq!(hit_rate, 0.5);
        ruleset.match_domain("test.com"); // hit
        let (hit_rate, _) = ruleset.cache_stats();
        assert!((hit_rate - 0.666).abs() < 0.01);
    }

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
        assert_eq!(ruleset.match_domain("test.com"), Target::Proxy);
        ruleset.add_direct_domain("test.com");
        assert_eq!(ruleset.match_domain("test.com"), Target::Direct);
    }

    #[test]
    fn test_default_ruleset_no_cache() {
        let ruleset = RuleSet::with_fallback(Target::Proxy);
        ruleset.match_domain("test.com");
        ruleset.match_domain("test.com");
        let (domain_rate, ip_rate) = ruleset.cache_stats();
        assert!(domain_rate.is_nan());
        assert!(ip_rate.is_nan());
    }
}
