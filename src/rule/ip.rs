//! Exact IP address matching rule implementation.

use ahash::AHashSet;
use parking_lot::RwLock;
use std::net::IpAddr;

use super::{DynamicRule, Rule};
use crate::error::IpRuleError;
use crate::{RuleType, Target};

/// IpRule matches exact IP addresses.
///
/// This is useful for dynamically adding specific IPs that should
/// be routed directly or through proxy.
///
/// # Examples
/// ```
/// use k2rule::{Target, rule::IpRule};
/// use k2rule::rule::DynamicRule;
///
/// let mut rule = IpRule::new(Target::Direct);
/// rule.add_pattern("8.8.8.8").unwrap();
/// rule.add_pattern("2001:4860:4860::8888").unwrap();
/// ```
pub struct IpRule {
    target: Target,
    /// Set of IP addresses (stored as strings for simplicity)
    ips: RwLock<AHashSet<String>>,
}

impl IpRule {
    /// Create a new IpRule with the specified target.
    pub fn new(target: Target) -> Self {
        Self {
            target,
            ips: RwLock::new(AHashSet::new()),
        }
    }

    /// Get the number of IP addresses in this rule.
    pub fn count(&self) -> usize {
        self.ips.read().len()
    }

    /// Get the number of IP addresses in this rule (alias for count).
    pub fn len(&self) -> usize {
        self.count()
    }

    /// Check if there are no IP addresses in this rule.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all IP addresses from this rule.
    pub fn clear(&self) {
        self.ips.write().clear();
    }

    /// Add an IP address to this rule.
    ///
    /// This is a convenience method that doesn't return an error.
    pub fn add_ip(&self, ip: &str) {
        let ip = ip.trim().to_lowercase();
        if !ip.is_empty() {
            self.ips.write().insert(ip);
        }
    }

    /// Check if an IP address is in this rule.
    pub fn contains(&self, ip: &str) -> bool {
        self.ips.read().contains(&ip.to_lowercase())
    }
}

impl Rule for IpRule {
    fn match_input(&self, ip: Option<IpAddr>, _domain: &str) -> bool {
        match ip {
            Some(addr) => self.contains(&addr.to_string()),
            None => false,
        }
    }

    fn target(&self) -> Target {
        self.target
    }

    fn rule_type(&self) -> RuleType {
        RuleType::IpMatch
    }
}

impl DynamicRule for IpRule {
    type Error = IpRuleError;

    fn add_pattern(&mut self, pattern: &str) -> Result<(), Self::Error> {
        let pattern = pattern.trim();

        // Validate that it's a valid IP address
        if pattern.parse::<IpAddr>().is_err() {
            return Err(IpRuleError::InvalidIp(pattern.to_string()));
        }

        self.ips.write().insert(pattern.to_lowercase());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_match() {
        let mut rule = IpRule::new(Target::Direct);
        rule.add_pattern("8.8.8.8").unwrap();
        rule.add_pattern("1.1.1.1").unwrap();

        let ip1: IpAddr = "8.8.8.8".parse().unwrap();
        let ip2: IpAddr = "1.1.1.1".parse().unwrap();
        let ip3: IpAddr = "8.8.4.4".parse().unwrap();

        assert!(rule.match_input(Some(ip1), ""));
        assert!(rule.match_input(Some(ip2), ""));
        assert!(!rule.match_input(Some(ip3), ""));
    }

    #[test]
    fn test_ipv6_match() {
        let mut rule = IpRule::new(Target::Proxy);
        rule.add_pattern("2001:4860:4860::8888").unwrap();

        let ip1: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        let ip2: IpAddr = "2001:4860:4860::8844".parse().unwrap();

        assert!(rule.match_input(Some(ip1), ""));
        assert!(!rule.match_input(Some(ip2), ""));
    }

    #[test]
    fn test_add_ip_convenience() {
        let rule = IpRule::new(Target::Direct);
        rule.add_ip("8.8.8.8");
        rule.add_ip("1.1.1.1");

        assert_eq!(rule.count(), 2);
        assert!(rule.contains("8.8.8.8"));
        assert!(rule.contains("1.1.1.1"));
    }

    #[test]
    fn test_clear() {
        let rule = IpRule::new(Target::Direct);
        rule.add_ip("8.8.8.8");
        rule.add_ip("1.1.1.1");

        assert_eq!(rule.count(), 2);
        rule.clear();
        assert_eq!(rule.count(), 0);
    }

    #[test]
    fn test_invalid_ip() {
        let mut rule = IpRule::new(Target::Direct);

        assert!(rule.add_pattern("invalid").is_err());
        assert!(rule.add_pattern("256.256.256.256").is_err());
    }

    #[test]
    fn test_domain_not_matched() {
        let mut rule = IpRule::new(Target::Direct);
        rule.add_pattern("8.8.8.8").unwrap();

        assert!(!rule.match_input(None, "example.com"));
    }

    #[test]
    fn test_target_and_type() {
        let rule = IpRule::new(Target::Reject);
        assert_eq!(rule.target(), Target::Reject);
        assert_eq!(rule.rule_type(), RuleType::IpMatch);
    }
}
