//! Converter from Clash config to slice-based format.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::{Result, Target};

use super::SliceWriter;

/// Intermediate representation of a slice.
#[derive(Debug, Clone)]
enum SliceData {
    Domains(Vec<String>, Target),
    CidrV4(Vec<(u32, u8)>, Target),
    CidrV6(Vec<([u8; 16], u8)>, Target),
    GeoIp(Vec<String>, Target),
}

impl SliceData {
    fn target(&self) -> Target {
        match self {
            SliceData::Domains(_, t) => *t,
            SliceData::CidrV4(_, t) => *t,
            SliceData::CidrV6(_, t) => *t,
            SliceData::GeoIp(_, t) => *t,
        }
    }

    fn slice_type(&self) -> SliceType {
        match self {
            SliceData::Domains(_, _) => SliceType::Domain,
            SliceData::CidrV4(_, _) => SliceType::CidrV4,
            SliceData::CidrV6(_, _) => SliceType::CidrV6,
            SliceData::GeoIp(_, _) => SliceType::GeoIp,
        }
    }

    fn can_merge(&self, other: &SliceData) -> bool {
        self.slice_type() == other.slice_type() && self.target() == other.target()
    }

    fn merge(&mut self, other: SliceData) {
        match (self, other) {
            (SliceData::Domains(a, _), SliceData::Domains(b, _)) => a.extend(b),
            (SliceData::CidrV4(a, _), SliceData::CidrV4(b, _)) => a.extend(b),
            (SliceData::CidrV6(a, _), SliceData::CidrV6(b, _)) => a.extend(b),
            (SliceData::GeoIp(a, _), SliceData::GeoIp(b, _)) => a.extend(b),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SliceType {
    Domain,
    CidrV4,
    CidrV6,
    GeoIp,
}

/// Clash configuration structure for deserialization.
#[derive(Debug, serde::Deserialize)]
struct ClashConfig {
    #[serde(default)]
    rules: Vec<String>,
    #[serde(rename = "rule-providers", default)]
    rule_providers: HashMap<String, RuleProvider>,
}

/// Clash rule provider configuration.
#[derive(Debug, serde::Deserialize)]
struct RuleProvider {
    behavior: String,
    #[serde(default)]
    rules: Vec<String>,
}

/// Converter from Clash config to slice-based format.
pub struct SliceConverter {
    provider_rules: HashMap<String, Vec<String>>,
}

impl SliceConverter {
    /// Create a new converter.
    pub fn new() -> Self {
        Self {
            provider_rules: HashMap::new(),
        }
    }

    /// Set provider rules directly (for testing or preloaded providers).
    pub fn set_provider_rules(&mut self, name: &str, rules: Vec<String>) {
        self.provider_rules.insert(name.to_string(), rules);
    }

    /// Load provider rules from YAML content.
    pub fn load_provider(&mut self, name: &str, content: &str) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct Payload {
            #[serde(default)]
            payload: Vec<String>,
        }
        let payload: Payload = serde_yaml::from_str(content)?;
        self.provider_rules.insert(name.to_string(), payload.payload);
        Ok(())
    }

    /// Convert Clash config to slice-based binary format.
    ///
    /// Returns the binary data. The fallback target is embedded in the header.
    pub fn convert(&self, yaml_content: &str) -> Result<Vec<u8>> {
        let config: ClashConfig = serde_yaml::from_str(yaml_content)?;

        // Collect slices in rule order
        let mut slices: Vec<SliceData> = Vec::new();
        let mut fallback = Target::Direct;

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

                    self.add_provider_slices(&mut slices, behavior, &rules, target);
                }
                "GEOIP" => {
                    if parts.len() >= 3 {
                        let country = parts[1].trim();
                        if country == "LAN" {
                            add_lan_slices(&mut slices, target);
                        } else {
                            slices.push(SliceData::GeoIp(vec![country.to_string()], target));
                        }
                    }
                }
                "DOMAIN" => {
                    if parts.len() >= 3 {
                        let domain = parts[1].trim();
                        slices.push(SliceData::Domains(vec![domain.to_string()], target));
                    }
                }
                "DOMAIN-SUFFIX" => {
                    if parts.len() >= 3 {
                        let suffix = parts[1].trim();
                        slices.push(SliceData::Domains(vec![suffix.to_string()], target));
                    }
                }
                "IP-CIDR" => {
                    if parts.len() >= 3 {
                        let cidr = parts[1].trim();
                        if let Some((network, prefix_len)) = parse_cidr_v4(cidr) {
                            slices.push(SliceData::CidrV4(vec![(network, prefix_len)], target));
                        }
                    }
                }
                "IP-CIDR6" => {
                    if parts.len() >= 3 {
                        let cidr = parts[1].trim();
                        if let Some((network, prefix_len)) = parse_cidr_v6(cidr) {
                            slices.push(SliceData::CidrV6(vec![(network, prefix_len)], target));
                        }
                    }
                }
                "MATCH" => {
                    fallback = target;
                }
                _ => {}
            }
        }

        // Merge adjacent same-type same-target slices
        let merged_slices = merge_adjacent_slices(slices);

        // Build binary using SliceWriter
        let mut writer = SliceWriter::new(fallback);

        for slice in merged_slices {
            match slice {
                SliceData::Domains(domains, target) => {
                    let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
                    writer.add_domain_slice(&domain_refs, target)?;
                }
                SliceData::CidrV4(cidrs, target) => {
                    writer.add_cidr_v4_slice(&cidrs, target)?;
                }
                SliceData::CidrV6(cidrs, target) => {
                    writer.add_cidr_v6_slice(&cidrs, target)?;
                }
                SliceData::GeoIp(countries, target) => {
                    let country_refs: Vec<&str> = countries.iter().map(|s| s.as_str()).collect();
                    writer.add_geoip_slice(&country_refs, target)?;
                }
            }
        }

        writer.build()
    }

    fn add_provider_slices(
        &self,
        slices: &mut Vec<SliceData>,
        behavior: &str,
        rules: &[String],
        target: Target,
    ) {
        match behavior {
            "domain" => {
                let mut domains = Vec::new();
                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }

                    // Convert Clash suffix format to our format
                    let domain = if rule.starts_with("+.") {
                        rule[2..].to_string()
                    } else if rule.starts_with('.') {
                        rule[1..].to_string()
                    } else {
                        rule.to_string()
                    };

                    domains.push(domain);
                }
                if !domains.is_empty() {
                    slices.push(SliceData::Domains(domains, target));
                }
            }
            "ipcidr" => {
                let mut v4_cidrs = Vec::new();
                let mut v6_cidrs = Vec::new();

                for rule in rules {
                    let rule = rule.trim();
                    if rule.is_empty() || rule.starts_with('#') {
                        continue;
                    }

                    if let Some((network, prefix_len)) = parse_cidr_v4(rule) {
                        v4_cidrs.push((network, prefix_len));
                    } else if let Some((network, prefix_len)) = parse_cidr_v6(rule) {
                        v6_cidrs.push((network, prefix_len));
                    }
                }

                if !v4_cidrs.is_empty() {
                    slices.push(SliceData::CidrV4(v4_cidrs, target));
                }
                if !v6_cidrs.is_empty() {
                    slices.push(SliceData::CidrV6(v6_cidrs, target));
                }
            }
            "classical" => {
                for rule in rules {
                    self.parse_classical_rule(slices, rule, target);
                }
            }
            _ => {}
        }
    }

    fn parse_classical_rule(&self, slices: &mut Vec<SliceData>, rule: &str, target: Target) {
        let parts: Vec<&str> = rule.split(',').collect();
        if parts.len() < 2 {
            return;
        }

        let rule_type = parts[0].trim();
        let value = parts[1].trim();

        match rule_type {
            "DOMAIN" | "DOMAIN-SUFFIX" => {
                slices.push(SliceData::Domains(vec![value.to_string()], target));
            }
            "IP-CIDR" => {
                if let Some((network, prefix_len)) = parse_cidr_v4(value) {
                    slices.push(SliceData::CidrV4(vec![(network, prefix_len)], target));
                }
            }
            "IP-CIDR6" => {
                if let Some((network, prefix_len)) = parse_cidr_v6(value) {
                    slices.push(SliceData::CidrV6(vec![(network, prefix_len)], target));
                }
            }
            "GEOIP" => {
                if value == "LAN" {
                    add_lan_slices(slices, target);
                } else {
                    slices.push(SliceData::GeoIp(vec![value.to_string()], target));
                }
            }
            _ => {}
        }
    }
}

impl Default for SliceConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// Merge adjacent slices with same type and target.
fn merge_adjacent_slices(slices: Vec<SliceData>) -> Vec<SliceData> {
    if slices.is_empty() {
        return slices;
    }

    let mut result: Vec<SliceData> = Vec::new();

    for slice in slices {
        if let Some(last) = result.last_mut() {
            if last.can_merge(&slice) {
                last.merge(slice);
                continue;
            }
        }
        result.push(slice);
    }

    result
}

/// Add LAN CIDR slices.
fn add_lan_slices(slices: &mut Vec<SliceData>, target: Target) {
    // IPv4 private ranges
    slices.push(SliceData::CidrV4(
        vec![
            (0x7F000000, 8),  // 127.0.0.0/8
            (0x0A000000, 8),  // 10.0.0.0/8
            (0xAC100000, 12), // 172.16.0.0/12
            (0xC0A80000, 16), // 192.168.0.0/16
            (0xA9FE0000, 16), // 169.254.0.0/16
        ],
        target,
    ));

    // IPv6 private ranges
    let fc00: [u8; 16] = [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let fe80: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let localhost: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    slices.push(SliceData::CidrV6(
        vec![(fc00, 7), (fe80, 10), (localhost, 128)],
        target,
    ));
}

/// Parse IPv4 CIDR string.
fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    Some((u32::from(addr), prefix_len))
}

/// Parse IPv6 CIDR string.
fn parse_cidr_v6(cidr: &str) -> Option<([u8; 16], u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: std::net::Ipv6Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    Some((addr.octets(), prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slice::SliceReader;

    #[test]
    fn test_simple_rules() {
        let yaml = r#"
rules:
  - DOMAIN,google.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();
        assert_eq!(reader.fallback(), Target::Proxy);
        assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("youtube.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("www.youtube.com"), Some(Target::Proxy));
        assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));
    }

    #[test]
    fn test_rule_providers() {
        let yaml = r#"
rule-providers:
  proxy-domains:
    type: http
    behavior: domain
    rules:
      - google.com
      - "+.googleapis.com"

rules:
  - RULE-SET,proxy-domains,PROXY
  - MATCH,DIRECT
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();
        assert_eq!(reader.fallback(), Target::Direct);
        assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
        assert_eq!(
            reader.match_domain("www.googleapis.com"),
            Some(Target::Proxy)
        );
    }

    #[test]
    fn test_merge_adjacent_slices() {
        let yaml = r#"
rules:
  - DOMAIN,a.com,PROXY
  - DOMAIN,b.com,PROXY
  - DOMAIN,c.com,DIRECT
  - DOMAIN,d.com,PROXY
  - MATCH,DIRECT
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();
        // a.com and b.com should be merged (same type, same target)
        // c.com is separate (different target)
        // d.com is separate (not adjacent to b.com after c.com)
        assert_eq!(reader.slice_count(), 3);

        assert_eq!(reader.match_domain("a.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("b.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("c.com"), Some(Target::Direct));
        assert_eq!(reader.match_domain("d.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_ordering_preserved() {
        // cn.bing.com -> Direct first, then bing.com -> Proxy
        let yaml = r#"
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - MATCH,DIRECT
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        // cn.bing.com should match first slice (Direct)
        assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
        assert_eq!(
            reader.match_domain("www.cn.bing.com"),
            Some(Target::Direct)
        );

        // bing.com should match second slice (Proxy)
        assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_cidr_rules() {
        let yaml = r#"
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR6,fc00::/7,DIRECT
  - MATCH,PROXY
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        assert_eq!(
            reader.match_ip("10.1.2.3".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(
            reader.match_ip("fc00::1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(reader.match_ip("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn test_lan_geoip() {
        let yaml = r#"
rules:
  - GEOIP,LAN,DIRECT
  - MATCH,PROXY
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();

        // LAN IPs should match
        assert_eq!(
            reader.match_ip("10.0.0.1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(
            reader.match_ip("192.168.1.1".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(
            reader.match_ip("fc00::1".parse().unwrap()),
            Some(Target::Direct)
        );
    }

    #[test]
    fn test_external_provider() {
        let yaml = r#"
rule-providers:
  external:
    type: http
    behavior: domain
    url: https://example.com/rules.yaml

rules:
  - RULE-SET,external,PROXY
  - MATCH,DIRECT
"#;

        let mut converter = SliceConverter::new();
        converter.set_provider_rules(
            "external",
            vec!["google.com".to_string(), "youtube.com".to_string()],
        );

        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();
        assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
        assert_eq!(reader.match_domain("youtube.com"), Some(Target::Proxy));
    }

    #[test]
    fn test_ipcidr_provider() {
        let yaml = r#"
rule-providers:
  private:
    type: http
    behavior: ipcidr
    rules:
      - 10.0.0.0/8
      - 172.16.0.0/12

rules:
  - RULE-SET,private,DIRECT
  - MATCH,PROXY
"#;

        let converter = SliceConverter::new();
        let data = converter.convert(yaml).unwrap();

        let reader = SliceReader::from_bytes(&data).unwrap();
        assert_eq!(
            reader.match_ip("10.1.2.3".parse().unwrap()),
            Some(Target::Direct)
        );
        assert_eq!(
            reader.match_ip("172.20.0.1".parse().unwrap()),
            Some(Target::Direct)
        );
    }
}
