//! Rule types and trait definitions.

mod application;
mod cidr;
mod domain;
pub mod geoip;
mod ip;

pub use application::ApplicationRule;
pub use cidr::CidrRule;
pub use domain::DomainRule;
pub use geoip::GeoIpRule;
pub use ip::IpRule;

use crate::{RuleType, Target};
use std::net::IpAddr;

/// Rule trait defines the interface for all rule types.
///
/// Rules are used to match IP addresses or domain names and determine
/// the routing target (DIRECT, PROXY, or REJECT).
pub trait Rule: Send + Sync {
    /// Match an IP address or domain against this rule.
    ///
    /// # Arguments
    /// * `ip` - Optional IP address to match
    /// * `domain` - Domain name to match (empty string if matching IP)
    ///
    /// # Returns
    /// `true` if the input matches this rule, `false` otherwise.
    fn match_input(&self, ip: Option<IpAddr>, domain: &str) -> bool;

    /// Get the target action for this rule.
    fn target(&self) -> Target;

    /// Get the type of this rule.
    fn rule_type(&self) -> RuleType;
}

/// Trait for rules that can have patterns added dynamically.
pub trait DynamicRule: Rule {
    /// Error type for pattern addition
    type Error;

    /// Add a pattern to this rule.
    ///
    /// The pattern format depends on the rule type:
    /// - Domain: `example.com` (exact) or `.example.com` (suffix)
    /// - CIDR: `192.168.0.0/16` or `2001:db8::/32`
    /// - GeoIP: `CN`, `US`, etc.
    /// - IP: `192.168.1.1` or `2001:db8::1`
    fn add_pattern(&mut self, pattern: &str) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_trait_object() {
        let domain_rule = DomainRule::new(Target::Proxy);
        let rule: &dyn Rule = &domain_rule;
        assert_eq!(rule.target(), Target::Proxy);
        assert_eq!(rule.rule_type(), RuleType::Domain);
    }
}
