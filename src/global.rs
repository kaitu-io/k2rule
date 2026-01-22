//! Global state and public API.

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::Once;

use crate::error::{Error, Result};
use crate::rule_type::RuleTypeInfo;
use crate::ruleset::{RuleConfig, RuleSet, RuleSetType};
use crate::Target;

/// Global rule set
static GLOBAL_RULESET: Lazy<RwLock<Option<RuleSet>>> = Lazy::new(|| RwLock::new(None));

/// Initialization flag
static INIT: Once = Once::new();

/// Ensure the global rule set is initialized.
///
/// This is called lazily when needed, but can be called explicitly
/// to initialize the rule set proactively.
pub fn ensure_initialized() {
    INIT.call_once(|| {
        if let Err(e) = reload_ruleset() {
            log::error!("Failed to initialize rule set: {}", e);
        }
    });
}

/// Check if the global rule set is initialized.
pub fn is_initialized() -> bool {
    GLOBAL_RULESET.read().is_some()
}

/// Reload the global rule set.
///
/// This will create a new rule set with the default configuration.
pub fn reload_ruleset() -> Result<()> {
    reload_ruleset_with_type(RuleSetType::Global)
}

/// Reload the global rule set with a specific type.
pub fn reload_ruleset_with_type(rule_type: RuleSetType) -> Result<()> {
    let config = rule_type.config();
    let ruleset = RuleSet::new(config);

    // Add default local IP rules
    add_local_ip_rules(&ruleset);

    let mut guard = GLOBAL_RULESET.write();
    *guard = Some(ruleset);

    log::debug!("Reloaded rule set: {}", rule_type.name());

    Ok(())
}

/// Reload the global rule set from a reader.
pub fn reload_ruleset_from_reader<R: std::io::Read>(
    reader: R,
    config: RuleConfig,
) -> Result<()> {
    let ruleset = RuleSet::from_reader(reader, config);

    // Add default local IP rules
    add_local_ip_rules(&ruleset);

    let mut guard = GLOBAL_RULESET.write();
    *guard = Some(ruleset);

    Ok(())
}

/// Add default local IP CIDR rules.
fn add_local_ip_rules(ruleset: &RuleSet) {
    use crate::rule::{CidrRule, DynamicRule};
    use std::sync::Arc;

    let mut local_ip_rule = CidrRule::new(Target::Direct);

    // Local/private IP ranges
    let _ = local_ip_rule.add_pattern("127.0.0.0/8"); // Loopback
    let _ = local_ip_rule.add_pattern("10.0.0.0/8"); // Private
    let _ = local_ip_rule.add_pattern("172.16.0.0/12"); // Private
    let _ = local_ip_rule.add_pattern("192.168.0.0/16"); // Private
    let _ = local_ip_rule.add_pattern("169.254.0.0/16"); // Link-local

    // IPv6 equivalents
    let _ = local_ip_rule.add_pattern("::1/128"); // Loopback
    let _ = local_ip_rule.add_pattern("fc00::/7"); // Unique local
    let _ = local_ip_rule.add_pattern("fe80::/10"); // Link-local

    ruleset.add_rule(Arc::new(local_ip_rule));
}

/// Match an IP or domain against the global rule set.
///
/// Returns the target from the first matching rule,
/// or the fallback target if no rules match.
///
/// # Examples
/// ```ignore
/// use k2rule::match_rule;
///
/// let target = match_rule("www.google.com");
/// println!("Target: {}", target);
/// ```
pub fn match_rule(ip_or_domain: &str) -> Target {
    ensure_initialized();

    let guard = GLOBAL_RULESET.read();
    match guard.as_ref() {
        Some(ruleset) => ruleset.match_input(ip_or_domain),
        None => Target::Proxy, // Fallback if not initialized
    }
}

/// Add IP addresses that should route directly.
pub fn add_direct_ip(ips: &[&str]) {
    ensure_initialized();

    let guard = GLOBAL_RULESET.read();
    if let Some(ruleset) = guard.as_ref() {
        ruleset.add_direct_ip(ips);
    }
}

/// Add domains that should route directly.
pub fn add_direct_domain(domains: &[&str]) {
    ensure_initialized();

    let guard = GLOBAL_RULESET.read();
    if let Some(ruleset) = guard.as_ref() {
        ruleset.add_direct_domain(domains);
    }
}

/// Add IP addresses that should route through proxy.
pub fn add_proxy_ip(ips: &[&str]) {
    ensure_initialized();

    let guard = GLOBAL_RULESET.read();
    if let Some(ruleset) = guard.as_ref() {
        ruleset.add_proxy_ip(ips);
    }
}

/// Add domains that should route through proxy.
pub fn add_proxy_domain(domains: &[&str]) {
    ensure_initialized();

    let guard = GLOBAL_RULESET.read();
    if let Some(ruleset) = guard.as_ref() {
        ruleset.add_proxy_domain(domains);
    }
}

/// Validate a rule set type name.
pub fn validate_rule_type(rule_type: &str) -> Result<()> {
    if RuleSetType::from_str(rule_type).is_none() {
        return Err(Error::InvalidRuleType(rule_type.to_string()));
    }
    Ok(())
}

/// Get information about all available rule set types.
pub fn get_available_rule_types() -> Vec<RuleTypeInfo> {
    vec![
        RuleTypeInfo::new(
            RuleSetType::Global.name(),
            RuleSetType::Global.display_name(),
        ),
        RuleTypeInfo::new(
            RuleSetType::CnBlacklist.name(),
            RuleSetType::CnBlacklist.display_name(),
        ),
        RuleTypeInfo::new(
            RuleSetType::CnWhitelist.name(),
            RuleSetType::CnWhitelist.display_name(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rule_type() {
        assert!(validate_rule_type("global").is_ok());
        assert!(validate_rule_type("cn_blacklist").is_ok());
        assert!(validate_rule_type("cn_whitelist").is_ok());
        assert!(validate_rule_type("unknown").is_err());
    }

    #[test]
    fn test_get_available_rule_types() {
        let types = get_available_rule_types();
        assert_eq!(types.len(), 3);
        assert_eq!(types[0].name, "global");
        assert_eq!(types[1].name, "cn_blacklist");
        assert_eq!(types[2].name, "cn_whitelist");
    }
}
