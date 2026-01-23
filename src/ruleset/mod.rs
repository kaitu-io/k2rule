//! RuleSet management and configuration.

mod config;

pub use config::{RuleConfig, RuleSetType};

use parking_lot::RwLock;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::sync::Arc;

use crate::rule::{CidrRule, DomainRule, DynamicRule, GeoIpRule, IpRule, Rule};
use crate::{RuleType, Target};

/// RuleSet manages a collection of rules for matching IP addresses and domains.
///
/// Rules are matched in priority order:
/// 1. Dynamic rules (Direct IP → Direct Domain → Proxy IP → Proxy Domain)
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
    /// Dynamic proxy domain rule
    proxy_domain: RwLock<DomainRule>,
    /// Dynamic proxy IP rule
    proxy_ip: RwLock<IpRule>,
}

impl RuleSet {
    /// Create a new RuleSet with the specified configuration.
    pub fn new(config: RuleConfig) -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
            config,
            direct_domain: RwLock::new(DomainRule::new(Target::Direct)),
            direct_ip: RwLock::new(IpRule::new(Target::Direct)),
            proxy_domain: RwLock::new(DomainRule::new(Target::Proxy)),
            proxy_ip: RwLock::new(IpRule::new(Target::Proxy)),
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

                let rule_type = params.get("rule").and_then(|s| RuleType::from_str(s));
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
        // Order: Direct IP -> Direct Domain -> Proxy IP -> Proxy Domain
        if self.direct_ip.read().match_input(ip, domain) {
            return Target::Direct;
        }
        if self.direct_domain.read().match_input(ip, domain) {
            return Target::Direct;
        }
        if self.proxy_ip.read().match_input(ip, domain) {
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

    /// Add domains that should route directly.
    pub fn add_direct_domain(&self, domains: &[&str]) {
        let mut rule = self.direct_domain.write();
        for domain in domains {
            let _ = rule.add_pattern(domain);
        }
    }

    /// Add domains that should route through proxy.
    pub fn add_proxy_domain(&self, domains: &[&str]) {
        let mut rule = self.proxy_domain.write();
        for domain in domains {
            let _ = rule.add_pattern(domain);
        }
    }

    /// Add IP addresses that should route directly.
    pub fn add_direct_ip(&self, ips: &[&str]) {
        let rule = self.direct_ip.read();
        for ip in ips {
            rule.add_ip(ip);
        }
    }

    /// Add IP addresses that should route through proxy.
    pub fn add_proxy_ip(&self, ips: &[&str]) {
        let rule = self.proxy_ip.read();
        for ip in ips {
            rule.add_ip(ip);
        }
    }
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
        ruleset.add_direct_domain(&["google.com"]);

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
}
