//! IP CIDR range rule implementation.

use ipnet::{Ipv4Net, Ipv6Net};
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::CidrRuleError;
use crate::{RuleType, Target};
use super::{DynamicRule, Rule};

/// CidrRule matches IP addresses against CIDR network ranges.
///
/// Supports both IPv4 and IPv6 CIDR notation.
///
/// # Examples
/// ```
/// use k2rule::{Target, rule::CidrRule};
/// use k2rule::rule::DynamicRule;
///
/// let mut rule = CidrRule::new(Target::Direct);
/// rule.add_pattern("192.168.0.0/16").unwrap();
/// rule.add_pattern("10.0.0.0/8").unwrap();
/// rule.add_pattern("fc00::/7").unwrap();
/// ```
pub struct CidrRule {
    target: Target,
    /// IPv4 CIDR ranges (sorted by network address for binary search)
    v4_cidrs: RwLock<Vec<Ipv4Net>>,
    /// IPv6 CIDR ranges (sorted by network address for binary search)
    v6_cidrs: RwLock<Vec<Ipv6Net>>,
}

impl CidrRule {
    /// Create a new CidrRule with the specified target.
    pub fn new(target: Target) -> Self {
        Self {
            target,
            v4_cidrs: RwLock::new(Vec::new()),
            v6_cidrs: RwLock::new(Vec::new()),
        }
    }

    /// Get the number of IPv4 CIDR patterns.
    pub fn v4_count(&self) -> usize {
        self.v4_cidrs.read().len()
    }

    /// Get the number of IPv6 CIDR patterns.
    pub fn v6_count(&self) -> usize {
        self.v6_cidrs.read().len()
    }

    /// Get the total number of CIDR patterns.
    pub fn pattern_count(&self) -> usize {
        self.v4_count() + self.v6_count()
    }

    /// Check if an IPv4 address matches any CIDR range.
    fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        let cidrs = self.v4_cidrs.read();
        cidrs.iter().any(|cidr| cidr.contains(&ip))
    }

    /// Check if an IPv6 address matches any CIDR range.
    fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        let cidrs = self.v6_cidrs.read();
        cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

impl Rule for CidrRule {
    fn match_input(&self, ip: Option<IpAddr>, _domain: &str) -> bool {
        match ip {
            Some(IpAddr::V4(v4)) => self.contains_v4(v4),
            Some(IpAddr::V6(v6)) => self.contains_v6(v6),
            None => false,
        }
    }

    fn target(&self) -> Target {
        self.target
    }

    fn rule_type(&self) -> RuleType {
        RuleType::IpCidr
    }
}

impl DynamicRule for CidrRule {
    type Error = CidrRuleError;

    fn add_pattern(&mut self, pattern: &str) -> Result<(), Self::Error> {
        let pattern = pattern.trim();

        // Try parsing as IPv4 CIDR
        if let Ok(v4net) = pattern.parse::<Ipv4Net>() {
            let mut cidrs = self.v4_cidrs.write();
            // Insert maintaining sorted order
            let pos = cidrs
                .binary_search_by_key(&v4net.network(), |n| n.network())
                .unwrap_or_else(|e| e);
            cidrs.insert(pos, v4net);
            return Ok(());
        }

        // Try parsing as IPv6 CIDR
        if let Ok(v6net) = pattern.parse::<Ipv6Net>() {
            let mut cidrs = self.v6_cidrs.write();
            // Insert maintaining sorted order
            let pos = cidrs
                .binary_search_by_key(&v6net.network(), |n| n.network())
                .unwrap_or_else(|e| e);
            cidrs.insert(pos, v6net);
            return Ok(());
        }

        Err(CidrRuleError::InvalidCidr(pattern.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr_match() {
        let mut rule = CidrRule::new(Target::Direct);
        rule.add_pattern("192.168.0.0/16").unwrap();
        rule.add_pattern("10.0.0.0/8").unwrap();

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.255.255".parse().unwrap();
        let ip3: IpAddr = "10.0.0.1".parse().unwrap();
        let ip4: IpAddr = "8.8.8.8".parse().unwrap();

        assert!(rule.match_input(Some(ip1), ""));
        assert!(rule.match_input(Some(ip2), ""));
        assert!(rule.match_input(Some(ip3), ""));
        assert!(!rule.match_input(Some(ip4), ""));
    }

    #[test]
    fn test_ipv6_cidr_match() {
        let mut rule = CidrRule::new(Target::Proxy);
        rule.add_pattern("fc00::/7").unwrap();
        rule.add_pattern("2001:db8::/32").unwrap();

        let ip1: IpAddr = "fc00::1".parse().unwrap();
        let ip2: IpAddr = "fd00::1".parse().unwrap();
        let ip3: IpAddr = "2001:db8::1".parse().unwrap();
        let ip4: IpAddr = "2001:4860::1".parse().unwrap();

        assert!(rule.match_input(Some(ip1), ""));
        assert!(rule.match_input(Some(ip2), ""));
        assert!(rule.match_input(Some(ip3), ""));
        assert!(!rule.match_input(Some(ip4), ""));
    }

    #[test]
    fn test_localhost_cidr() {
        let mut rule = CidrRule::new(Target::Direct);
        rule.add_pattern("127.0.0.0/8").unwrap();
        rule.add_pattern("::1/128").unwrap();

        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.255.255.255".parse().unwrap();
        let ip3: IpAddr = "::1".parse().unwrap();

        assert!(rule.match_input(Some(ip1), ""));
        assert!(rule.match_input(Some(ip2), ""));
        assert!(rule.match_input(Some(ip3), ""));
    }

    #[test]
    fn test_invalid_cidr() {
        let mut rule = CidrRule::new(Target::Direct);

        assert!(rule.add_pattern("invalid").is_err());
        assert!(rule.add_pattern("192.168.1.1").is_err()); // No prefix
        assert!(rule.add_pattern("192.168.1.1/33").is_err()); // Invalid prefix
    }

    #[test]
    fn test_domain_not_matched() {
        let mut rule = CidrRule::new(Target::Direct);
        rule.add_pattern("192.168.0.0/16").unwrap();

        assert!(!rule.match_input(None, "example.com"));
    }

    #[test]
    fn test_target_and_type() {
        let rule = CidrRule::new(Target::Reject);
        assert_eq!(rule.target(), Target::Reject);
        assert_eq!(rule.rule_type(), RuleType::IpCidr);
    }
}
