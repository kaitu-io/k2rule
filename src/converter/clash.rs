//! Clash YAML rule format converter.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::binary::writer::IntermediateRules;
use crate::{Result, Target};

/// Clash configuration structure.
#[derive(Debug, Deserialize)]
pub struct ClashConfig {
    /// Rule list
    #[serde(default)]
    pub rules: Vec<String>,
    /// Rule providers
    #[serde(rename = "rule-providers", default)]
    pub rule_providers: HashMap<String, RuleProvider>,
}

/// Clash rule provider configuration.
#[derive(Debug, Deserialize)]
pub struct RuleProvider {
    /// Provider type (http, file)
    #[serde(rename = "type")]
    pub provider_type: String,
    /// Behavior (domain, ipcidr, classical)
    pub behavior: String,
    /// URL for HTTP providers
    pub url: Option<String>,
    /// Local path
    pub path: Option<String>,
    /// Update interval in seconds
    pub interval: Option<u64>,
    /// Inline rules (for testing)
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Rule provider payload structure.
#[derive(Debug, Deserialize)]
struct ProviderPayload {
    #[serde(default)]
    payload: Vec<String>,
}

/// Clash rule converter.
pub struct ClashConverter {
    /// Loaded provider rules
    provider_rules: HashMap<String, Vec<String>>,
}

impl ClashConverter {
    /// Create a new converter.
    pub fn new() -> Self {
        Self {
            provider_rules: HashMap::new(),
        }
    }

    /// Load provider rules from YAML content.
    pub fn load_provider(&mut self, name: &str, content: &str) -> Result<()> {
        let payload: ProviderPayload = serde_yaml::from_str(content)?;
        self.provider_rules.insert(name.to_string(), payload.payload);
        Ok(())
    }

    /// Set provider rules directly.
    pub fn set_provider_rules(&mut self, name: &str, rules: Vec<String>) {
        self.provider_rules.insert(name.to_string(), rules);
    }

    /// Convert Clash config to intermediate rules.
    pub fn convert(&self, yaml_content: &str) -> Result<IntermediateRules> {
        let config: ClashConfig = serde_yaml::from_str(yaml_content)?;
        let mut intermediate = IntermediateRules::new();

        for rule_str in &config.rules {
            let parts: Vec<&str> = rule_str.split(',').collect();
            if parts.len() < 2 {
                continue;
            }

            let rule_type = parts[0].trim();
            let target = Target::from_str_lossy(parts.last().unwrap_or(&"PROXY"));

            match rule_type {
                "RULE-SET" => {
                    if parts.len() < 3 {
                        continue;
                    }
                    let provider_name = parts[1].trim();

                    // Get provider behavior from config
                    let behavior = config
                        .rule_providers
                        .get(provider_name)
                        .map(|p| p.behavior.as_str())
                        .unwrap_or("domain");

                    // Get rules from loaded providers or inline
                    let rules = self
                        .provider_rules
                        .get(provider_name)
                        .cloned()
                        .or_else(|| {
                            config
                                .rule_providers
                                .get(provider_name)
                                .map(|p| p.rules.clone())
                        })
                        .unwrap_or_default();

                    self.add_provider_rules(&mut intermediate, behavior, &rules, target);
                }
                "GEOIP" => {
                    if parts.len() >= 3 {
                        let country = parts[1].trim();
                        if country == "LAN" {
                            // Add LAN CIDRs
                            add_lan_cidrs(&mut intermediate, target);
                        } else {
                            intermediate.add_geoip(country, target);
                        }
                    }
                }
                "DOMAIN" => {
                    if parts.len() >= 3 {
                        let domain = parts[1].trim();
                        intermediate.add_domain(domain, target);
                    }
                }
                "DOMAIN-SUFFIX" => {
                    if parts.len() >= 3 {
                        let suffix = parts[1].trim();
                        intermediate.add_domain(&format!(".{}", suffix), target);
                    }
                }
                "DOMAIN-KEYWORD" => {
                    // Domain keyword matching is not directly supported
                    // Skip for now
                }
                "IP-CIDR" | "IP-CIDR6" => {
                    if parts.len() >= 3 {
                        let cidr = parts[1].trim();
                        if let Some((network, prefix_len)) = parse_cidr(cidr) {
                            match network {
                                CidrNetwork::V4(n) => {
                                    intermediate.add_v4_cidr(n, prefix_len, target);
                                }
                                CidrNetwork::V6(n) => {
                                    intermediate.add_v6_cidr(n, prefix_len, target);
                                }
                            }
                        }
                    }
                }
                "MATCH" => {
                    intermediate.set_fallback(target);
                }
                _ => {
                    // Unknown rule type, skip
                }
            }
        }

        Ok(intermediate)
    }

    fn add_provider_rules(
        &self,
        intermediate: &mut IntermediateRules,
        behavior: &str,
        rules: &[String],
        target: Target,
    ) {
        match behavior {
            "domain" => {
                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }

                    // Convert Clash suffix format to our format
                    let domain = if rule.starts_with("+.") {
                        format!(".{}", &rule[2..])
                    } else if rule.starts_with('.') {
                        rule.to_string()
                    } else {
                        rule.to_string()
                    };

                    intermediate.add_domain(&domain, target);
                }
            }
            "ipcidr" => {
                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }

                    if let Some((network, prefix_len)) = parse_cidr(rule) {
                        match network {
                            CidrNetwork::V4(n) => {
                                intermediate.add_v4_cidr(n, prefix_len, target);
                            }
                            CidrNetwork::V6(n) => {
                                intermediate.add_v6_cidr(n, prefix_len, target);
                            }
                        }
                    }
                }
            }
            "classical" => {
                // Parse classical format rules
                for rule in rules {
                    self.parse_classical_rule(intermediate, rule, target);
                }
            }
            _ => {}
        }
    }

    fn parse_classical_rule(
        &self,
        intermediate: &mut IntermediateRules,
        rule: &str,
        target: Target,
    ) {
        let parts: Vec<&str> = rule.split(',').collect();
        if parts.len() < 2 {
            return;
        }

        let rule_type = parts[0].trim();
        let value = parts[1].trim();

        match rule_type {
            "DOMAIN" => {
                intermediate.add_domain(value, target);
            }
            "DOMAIN-SUFFIX" => {
                intermediate.add_domain(&format!(".{}", value), target);
            }
            "IP-CIDR" | "IP-CIDR6" => {
                if let Some((network, prefix_len)) = parse_cidr(value) {
                    match network {
                        CidrNetwork::V4(n) => {
                            intermediate.add_v4_cidr(n, prefix_len, target);
                        }
                        CidrNetwork::V6(n) => {
                            intermediate.add_v6_cidr(n, prefix_len, target);
                        }
                    }
                }
            }
            "GEOIP" => {
                if value == "LAN" {
                    add_lan_cidrs(intermediate, target);
                } else {
                    intermediate.add_geoip(value, target);
                }
            }
            _ => {}
        }
    }
}

impl Default for ClashConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// CIDR network type.
enum CidrNetwork {
    V4(u32),
    V6([u8; 16]),
}

/// Parse a CIDR string into network and prefix length.
fn parse_cidr(cidr: &str) -> Option<(CidrNetwork, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix_len: u8 = parts[1].parse().ok()?;

    // Try IPv4
    if let Ok(addr) = parts[0].parse::<Ipv4Addr>() {
        return Some((CidrNetwork::V4(u32::from(addr)), prefix_len));
    }

    // Try IPv6
    if let Ok(addr) = parts[0].parse::<std::net::Ipv6Addr>() {
        return Some((CidrNetwork::V6(addr.octets()), prefix_len));
    }

    None
}

/// Add LAN CIDR ranges.
fn add_lan_cidrs(intermediate: &mut IntermediateRules, target: Target) {
    // IPv4 private ranges
    intermediate.add_v4_cidr(0x7F000000, 8, target); // 127.0.0.0/8
    intermediate.add_v4_cidr(0x0A000000, 8, target); // 10.0.0.0/8
    intermediate.add_v4_cidr(0xAC100000, 12, target); // 172.16.0.0/12
    intermediate.add_v4_cidr(0xC0A80000, 16, target); // 192.168.0.0/16
    intermediate.add_v4_cidr(0xA9FE0000, 16, target); // 169.254.0.0/16

    // IPv6 private ranges
    let fc00: [u8; 16] = [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let fe80: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let localhost: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    intermediate.add_v6_cidr(fc00, 7, target); // fc00::/7
    intermediate.add_v6_cidr(fe80, 10, target); // fe80::/10
    intermediate.add_v6_cidr(localhost, 128, target); // ::1/128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clash_config() {
        let yaml = r#"
rules:
  - DOMAIN,google.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;

        let converter = ClashConverter::new();
        let rules = converter.convert(yaml).unwrap();

        assert!(!rules.exact_domains.is_empty());
        assert!(!rules.suffix_domains.is_empty());
        assert!(!rules.geoip_countries.is_empty());
        assert_eq!(rules.fallback_target, Target::Proxy);
    }

    #[test]
    fn test_parse_cidr() {
        let (network, prefix) = parse_cidr("192.168.0.0/16").unwrap();
        assert!(matches!(network, CidrNetwork::V4(_)));
        assert_eq!(prefix, 16);

        let (network, prefix) = parse_cidr("fc00::/7").unwrap();
        assert!(matches!(network, CidrNetwork::V6(_)));
        assert_eq!(prefix, 7);
    }

    #[test]
    fn test_lan_geoip() {
        let yaml = r#"
rules:
  - GEOIP,LAN,DIRECT
"#;

        let converter = ClashConverter::new();
        let rules = converter.convert(yaml).unwrap();

        // Should have LAN CIDRs added
        assert!(!rules.v4_cidrs.is_empty());
        assert!(!rules.v6_cidrs.is_empty());
    }
}
