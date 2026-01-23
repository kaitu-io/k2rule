//! Rule type definitions.

use std::fmt;

/// RuleType represents the type of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleType {
    /// Domain-based rules (exact and suffix matching)
    Domain,
    /// IP CIDR range matching (supports both IPv4 and IPv6)
    IpCidr,
    /// GeoIP-based rules (country code matching)
    GeoIP,
    /// Exact IP address matching
    IpMatch,
    /// Application-based rules (placeholder)
    Application,
}

impl RuleType {
    /// Parse a rule type from a string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "DOMAIN" => Some(RuleType::Domain),
            "IP-CIDR" | "IPCIDR" => Some(RuleType::IpCidr),
            "GEOIP" => Some(RuleType::GeoIP),
            "IP-MATCH" | "IPMATCH" | "IP" => Some(RuleType::IpMatch),
            "APPLICATION" | "APP" => Some(RuleType::Application),
            _ => None,
        }
    }

    /// Get the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleType::Domain => "DOMAIN",
            RuleType::IpCidr => "IP-CIDR",
            RuleType::GeoIP => "GEOIP",
            RuleType::IpMatch => "IP-MATCH",
            RuleType::Application => "APPLICATION",
        }
    }

    /// Convert to a u8 value for binary serialization.
    pub fn as_u8(&self) -> u8 {
        match self {
            RuleType::Domain => 0,
            RuleType::IpCidr => 1,
            RuleType::GeoIP => 2,
            RuleType::IpMatch => 3,
            RuleType::Application => 4,
        }
    }

    /// Convert from a u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RuleType::Domain),
            1 => Some(RuleType::IpCidr),
            2 => Some(RuleType::GeoIP),
            3 => Some(RuleType::IpMatch),
            4 => Some(RuleType::Application),
            _ => None,
        }
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Information about a rule type (for API responses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTypeInfo {
    /// Internal name of the rule type
    pub name: String,
    /// Display name for UI
    pub display_name: String,
}

impl RuleTypeInfo {
    /// Create a new RuleTypeInfo.
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_type_from_str() {
        assert_eq!(RuleType::parse("DOMAIN"), Some(RuleType::Domain));
        assert_eq!(RuleType::parse("domain"), Some(RuleType::Domain));
        assert_eq!(RuleType::parse("IP-CIDR"), Some(RuleType::IpCidr));
        assert_eq!(RuleType::parse("IPCIDR"), Some(RuleType::IpCidr));
        assert_eq!(RuleType::parse("GEOIP"), Some(RuleType::GeoIP));
        assert_eq!(RuleType::parse("IP-MATCH"), Some(RuleType::IpMatch));
        assert_eq!(RuleType::parse("APPLICATION"), Some(RuleType::Application));
        assert_eq!(RuleType::parse("UNKNOWN"), None);
    }

    #[test]
    fn test_rule_type_roundtrip() {
        for rule_type in [
            RuleType::Domain,
            RuleType::IpCidr,
            RuleType::GeoIP,
            RuleType::IpMatch,
            RuleType::Application,
        ] {
            let u8_val = rule_type.as_u8();
            assert_eq!(RuleType::from_u8(u8_val), Some(rule_type));
        }
    }
}
