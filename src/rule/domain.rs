//! Domain-based rule implementation.

use ahash::AHashMap;
use parking_lot::RwLock;
use std::net::IpAddr;

use super::{DynamicRule, Rule};
use crate::error::DomainRuleError;
use crate::{RuleType, Target};

/// DomainRule matches domain names using exact or suffix matching.
///
/// # Pattern Formats
/// - Exact match: `example.com` - matches only `example.com`
/// - Suffix match: `.example.com` - matches `example.com`, `www.example.com`, etc.
/// - TLD suffix: `.cn`, `.local` - matches any domain with that TLD (e.g., `example.cn`)
///
/// # Examples
/// ```
/// use k2rule::{Target, rule::DomainRule};
/// use k2rule::rule::DynamicRule;
///
/// let mut rule = DomainRule::new(Target::Proxy);
/// rule.add_pattern("google.com").unwrap();      // Exact match
/// rule.add_pattern(".youtube.com").unwrap();    // Suffix match
/// rule.add_pattern(".cn").unwrap();             // TLD suffix match
/// ```
pub struct DomainRule {
    target: Target,
    /// Exact match domains (lowercase)
    exacts: RwLock<AHashMap<String, ()>>,
    /// Suffix match domains (stored without leading dot, lowercase)
    suffixes: RwLock<AHashMap<String, ()>>,
}

impl DomainRule {
    /// Create a new DomainRule with the specified target.
    pub fn new(target: Target) -> Self {
        Self {
            target,
            exacts: RwLock::new(AHashMap::new()),
            suffixes: RwLock::new(AHashMap::new()),
        }
    }

    /// Get the number of exact match patterns.
    pub fn exact_count(&self) -> usize {
        self.exacts.read().len()
    }

    /// Get the number of suffix match patterns.
    pub fn suffix_count(&self) -> usize {
        self.suffixes.read().len()
    }

    /// Get the total number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.exact_count() + self.suffix_count()
    }

    /// Get the total number of patterns (alias for pattern_count).
    pub fn len(&self) -> usize {
        self.pattern_count()
    }

    /// Check if there are no patterns in this rule.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if a domain matches any exact pattern.
    fn match_exact(&self, domain: &str) -> bool {
        self.exacts.read().contains_key(domain)
    }

    /// Check if a domain matches any suffix pattern.
    fn match_suffix(&self, domain: &str) -> bool {
        let suffixes = self.suffixes.read();

        // Check if domain itself is a registered suffix
        if suffixes.contains_key(domain) {
            return true;
        }

        // Check parent domains
        let mut current = domain;
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if suffixes.contains_key(current) {
                return true;
            }
        }

        false
    }
}

impl Rule for DomainRule {
    fn match_input(&self, ip: Option<IpAddr>, domain: &str) -> bool {
        // Only match domains, not IPs
        if ip.is_some() || domain.is_empty() {
            return false;
        }

        let domain_lower = domain.to_lowercase();

        // Check exact match first (O(1))
        if self.match_exact(&domain_lower) {
            return true;
        }

        // Check suffix match
        self.match_suffix(&domain_lower)
    }

    fn target(&self) -> Target {
        self.target
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Domain
    }
}

impl DynamicRule for DomainRule {
    type Error = DomainRuleError;

    fn add_pattern(&mut self, pattern: &str) -> Result<(), Self::Error> {
        let pattern = pattern.trim().to_lowercase();

        if pattern.is_empty() {
            return Err(DomainRuleError::EmptyPattern);
        }

        // Validate: must contain at least one dot
        if !pattern.contains('.') && !pattern.starts_with('.') {
            return Err(DomainRuleError::InvalidPattern(pattern));
        }

        if let Some(suffix) = pattern.strip_prefix('.') {
            // Suffix match: store without leading dot
            if suffix.is_empty() {
                return Err(DomainRuleError::InvalidPattern(pattern));
            }
            // Both multi-level suffixes (.example.com) and TLDs (.cn, .local) are supported
            self.suffixes.write().insert(suffix.to_string(), ());
        } else {
            // Exact match
            self.exacts.write().insert(pattern, ());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut rule = DomainRule::new(Target::Proxy);
        rule.add_pattern("google.com").unwrap();

        assert!(rule.match_input(None, "google.com"));
        assert!(rule.match_input(None, "GOOGLE.COM"));
        assert!(rule.match_input(None, "Google.Com"));
        assert!(!rule.match_input(None, "www.google.com"));
        assert!(!rule.match_input(None, "mail.google.com"));
    }

    #[test]
    fn test_suffix_match() {
        let mut rule = DomainRule::new(Target::Proxy);
        rule.add_pattern(".google.com").unwrap();

        assert!(rule.match_input(None, "google.com"));
        assert!(rule.match_input(None, "www.google.com"));
        assert!(rule.match_input(None, "mail.google.com"));
        assert!(rule.match_input(None, "a.b.c.google.com"));
        assert!(!rule.match_input(None, "notgoogle.com"));
    }

    #[test]
    fn test_mixed_patterns() {
        let mut rule = DomainRule::new(Target::Direct);
        rule.add_pattern("example.com").unwrap();
        rule.add_pattern(".google.com").unwrap();

        assert!(rule.match_input(None, "example.com"));
        assert!(!rule.match_input(None, "www.example.com"));
        assert!(rule.match_input(None, "google.com"));
        assert!(rule.match_input(None, "www.google.com"));
    }

    #[test]
    fn test_invalid_patterns() {
        let mut rule = DomainRule::new(Target::Proxy);

        assert!(rule.add_pattern("").is_err());
        assert!(rule.add_pattern("localhost").is_err());
        assert!(rule.add_pattern(".").is_err());
    }

    #[test]
    fn test_ip_not_matched() {
        let mut rule = DomainRule::new(Target::Proxy);
        rule.add_pattern(".google.com").unwrap();

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!rule.match_input(Some(ip), ""));
    }

    #[test]
    fn test_target_and_type() {
        let rule = DomainRule::new(Target::Reject);
        assert_eq!(rule.target(), Target::Reject);
        assert_eq!(rule.rule_type(), RuleType::Domain);
    }

    #[test]
    fn test_tld_patterns() {
        let mut rule = DomainRule::new(Target::Direct);
        rule.add_pattern(".cn").unwrap();
        rule.add_pattern(".local").unwrap();

        // Single-level TLDs should match
        assert!(rule.match_input(None, "example.cn"));
        assert!(rule.match_input(None, "test.com.cn"));
        assert!(rule.match_input(None, "a.b.c.cn"));
        assert!(rule.match_input(None, "mypc.local"));
        assert!(rule.match_input(None, "printer.local"));

        // Should not match other TLDs
        assert!(!rule.match_input(None, "example.com"));
        assert!(!rule.match_input(None, "example.org"));

        // Case insensitivity
        assert!(rule.match_input(None, "EXAMPLE.CN"));
        assert!(rule.match_input(None, "MyPC.LOCAL"));
    }

    #[test]
    fn test_regional_tlds() {
        let mut rule = DomainRule::new(Target::Proxy);
        rule.add_pattern(".hk").unwrap();
        rule.add_pattern(".tw").unwrap();
        rule.add_pattern(".jp").unwrap();

        assert!(rule.match_input(None, "example.hk"));
        assert!(rule.match_input(None, "test.tw"));
        assert!(rule.match_input(None, "site.jp"));
        assert!(rule.match_input(None, "sub.domain.jp"));
    }

    #[test]
    fn test_local_network_tlds() {
        let mut rule = DomainRule::new(Target::Direct);
        rule.add_pattern(".lan").unwrap();
        rule.add_pattern(".home.arpa").unwrap();

        assert!(rule.match_input(None, "router.lan"));
        assert!(rule.match_input(None, "nas.lan"));
        assert!(rule.match_input(None, "device.home.arpa"));
        assert!(rule.match_input(None, "sub.device.home.arpa"));
    }

    #[test]
    fn test_mixed_tld_and_suffix_patterns() {
        let mut rule = DomainRule::new(Target::Proxy);
        rule.add_pattern(".cn").unwrap();           // TLD
        rule.add_pattern(".google.com").unwrap();   // Multi-level suffix
        rule.add_pattern("example.org").unwrap();   // Exact match

        // TLD matches
        assert!(rule.match_input(None, "baidu.cn"));
        assert!(rule.match_input(None, "test.cn"));

        // Suffix matches
        assert!(rule.match_input(None, "www.google.com"));
        assert!(rule.match_input(None, "mail.google.com"));

        // Exact matches
        assert!(rule.match_input(None, "example.org"));
        assert!(!rule.match_input(None, "www.example.org"));

        // Non-matches
        assert!(!rule.match_input(None, "example.com"));
    }
}
