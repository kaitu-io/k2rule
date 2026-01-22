//! GeoIP-based rule implementation.

use ahash::AHashSet;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::error::GeoIpRuleError;
use crate::{RuleType, Target};
use super::{DynamicRule, Rule};

/// Global GeoIP database reader.
static GEOIP_READER: once_cell::sync::OnceCell<Arc<maxminddb::Reader<Vec<u8>>>> =
    once_cell::sync::OnceCell::new();

/// Initialize the global GeoIP database from a file path.
///
/// This should be called once at startup.
pub fn init_geoip_database(path: &Path) -> Result<(), crate::Error> {
    let reader = maxminddb::Reader::open_readfile(path)
        .map_err(|e| crate::Error::GeoIp(e.to_string()))?;

    GEOIP_READER
        .set(Arc::new(reader))
        .map_err(|_| crate::Error::GeoIp("GeoIP database already initialized".to_string()))?;

    Ok(())
}

/// Initialize the global GeoIP database from bytes.
pub fn init_geoip_database_from_bytes(data: Vec<u8>) -> Result<(), crate::Error> {
    let reader = maxminddb::Reader::from_source(data)
        .map_err(|e| crate::Error::GeoIp(e.to_string()))?;

    GEOIP_READER
        .set(Arc::new(reader))
        .map_err(|_| crate::Error::GeoIp("GeoIP database already initialized".to_string()))?;

    Ok(())
}

/// Look up the country code for an IP address.
pub fn lookup_country(ip: IpAddr) -> Option<String> {
    let reader = GEOIP_READER.get()?;

    #[derive(serde::Deserialize)]
    struct Country {
        iso_code: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct GeoIpResponse {
        country: Option<Country>,
    }

    let result: GeoIpResponse = reader.lookup(ip).ok()?;
    result.country?.iso_code
}

/// GeoIpRule matches IP addresses based on their geographic location (country code).
///
/// Requires a GeoIP database to be initialized via `init_geoip_database`.
///
/// # Examples
/// ```ignore
/// use k2rule::{Target, rule::GeoIpRule};
/// use k2rule::rule::DynamicRule;
///
/// // First initialize the GeoIP database
/// k2rule::rule::geoip::init_geoip_database(Path::new("/path/to/GeoLite2-Country.mmdb")).unwrap();
///
/// let mut rule = GeoIpRule::new(Target::Direct);
/// rule.add_pattern("CN").unwrap();
/// rule.add_pattern("US").unwrap();
/// ```
pub struct GeoIpRule {
    target: Target,
    /// Set of 2-letter ISO country codes (uppercase)
    countries: RwLock<AHashSet<String>>,
}

impl GeoIpRule {
    /// Create a new GeoIpRule with the specified target.
    pub fn new(target: Target) -> Self {
        Self {
            target,
            countries: RwLock::new(AHashSet::new()),
        }
    }

    /// Get the number of country codes in this rule.
    pub fn count(&self) -> usize {
        self.countries.read().len()
    }

    /// Check if a country code is in this rule.
    pub fn contains(&self, country: &str) -> bool {
        self.countries.read().contains(&country.to_uppercase())
    }
}

impl Rule for GeoIpRule {
    fn match_input(&self, ip: Option<IpAddr>, _domain: &str) -> bool {
        let ip = match ip {
            Some(ip) => ip,
            None => return false,
        };

        // Look up the country code
        let country = match lookup_country(ip) {
            Some(c) => c,
            None => return false,
        };

        self.countries.read().contains(&country)
    }

    fn target(&self) -> Target {
        self.target
    }

    fn rule_type(&self) -> RuleType {
        RuleType::GeoIP
    }
}

impl DynamicRule for GeoIpRule {
    type Error = GeoIpRuleError;

    fn add_pattern(&mut self, pattern: &str) -> Result<(), Self::Error> {
        let code = pattern.trim().to_uppercase();

        // Validate: must be exactly 2 characters
        if code.len() != 2 {
            return Err(GeoIpRuleError::InvalidCountryCode(code));
        }

        // Validate: must be ASCII letters
        if !code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(GeoIpRuleError::InvalidCountryCode(code));
        }

        self.countries.write().insert(code);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_code_validation() {
        let mut rule = GeoIpRule::new(Target::Direct);

        // Valid country codes
        assert!(rule.add_pattern("CN").is_ok());
        assert!(rule.add_pattern("us").is_ok()); // Lowercase should work
        assert!(rule.add_pattern("JP").is_ok());

        // Invalid country codes
        assert!(rule.add_pattern("").is_err());
        assert!(rule.add_pattern("A").is_err()); // Too short
        assert!(rule.add_pattern("ABC").is_err()); // Too long
        assert!(rule.add_pattern("12").is_err()); // Not letters
    }

    #[test]
    fn test_contains() {
        let mut rule = GeoIpRule::new(Target::Direct);
        rule.add_pattern("CN").unwrap();
        rule.add_pattern("US").unwrap();

        assert!(rule.contains("CN"));
        assert!(rule.contains("cn")); // Case insensitive
        assert!(rule.contains("US"));
        assert!(!rule.contains("JP"));
    }

    #[test]
    fn test_count() {
        let mut rule = GeoIpRule::new(Target::Direct);
        assert_eq!(rule.count(), 0);

        rule.add_pattern("CN").unwrap();
        assert_eq!(rule.count(), 1);

        rule.add_pattern("US").unwrap();
        assert_eq!(rule.count(), 2);

        // Adding duplicate should not increase count
        rule.add_pattern("CN").unwrap();
        assert_eq!(rule.count(), 2);
    }

    #[test]
    fn test_domain_not_matched() {
        let mut rule = GeoIpRule::new(Target::Direct);
        rule.add_pattern("CN").unwrap();

        assert!(!rule.match_input(None, "example.com"));
    }

    #[test]
    fn test_target_and_type() {
        let rule = GeoIpRule::new(Target::Reject);
        assert_eq!(rule.target(), Target::Reject);
        assert_eq!(rule.rule_type(), RuleType::GeoIP);
    }
}
