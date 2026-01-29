//! K2Rule text format parser.

use std::io::{BufRead, BufReader, Read};

use crate::binary::writer::IntermediateRules;
use crate::{Result, RuleType, Target};

/// K2Rule text format parser.
pub struct TextParser;

impl TextParser {
    /// Parse rules from a reader.
    pub fn parse<R: Read>(reader: R) -> Result<IntermediateRules> {
        let mut rules = IntermediateRules::new();
        let buf_reader = BufReader::new(reader);

        let mut current_rule_type: Option<RuleType> = None;
        let mut current_target = Target::Proxy;

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

            // Try to parse as rule header
            if line.starts_with('[') && line.ends_with(']') {
                let content = &line[1..line.len() - 1];
                let params = parse_params(content);

                let rule_type = params.get("rule").and_then(|s| RuleType::parse(s));
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
                    current_rule_type = None;
                    continue;
                }

                current_rule_type = rule_type;
                current_target = target;
                continue;
            }

            // Add pattern based on current rule type
            if let Some(rule_type) = current_rule_type {
                match rule_type {
                    RuleType::Domain => {
                        rules.add_domain(line, current_target);
                    }
                    RuleType::IpCidr => {
                        if let Some((network, prefix_len)) = parse_cidr(line) {
                            match network {
                                CidrNetwork::V4(n) => {
                                    rules.add_v4_cidr(n, prefix_len, current_target);
                                }
                                CidrNetwork::V6(n) => {
                                    rules.add_v6_cidr(n, prefix_len, current_target);
                                }
                            }
                        }
                    }
                    RuleType::GeoIP => {
                        rules.add_geoip(line, current_target);
                    }
                    RuleType::IpMatch => {
                        if let Ok(ip) = line.parse::<std::net::Ipv4Addr>() {
                            rules.exact_v4_ips.push((u32::from(ip), current_target));
                        } else if let Ok(ip) = line.parse::<std::net::Ipv6Addr>() {
                            rules.exact_v6_ips.push((ip.octets(), current_target));
                        }
                    }
                    RuleType::Application => {
                        // Skip application rules for now
                    }
                }
            }
        }

        Ok(rules)
    }
}

/// Parse header parameters.
fn parse_params(content: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();

    for part in content.split(',') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_lowercase();
            let value = part[eq_pos + 1..].trim().to_string();
            params.insert(key, value);
        } else {
            params.insert(part.to_lowercase(), String::new());
        }
    }

    params
}

/// CIDR network type.
enum CidrNetwork {
    V4(u32),
    V6([u8; 16]),
}

/// Parse a CIDR string.
fn parse_cidr(cidr: &str) -> Option<(CidrNetwork, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix_len: u8 = parts[1].parse().ok()?;

    if let Ok(addr) = parts[0].parse::<std::net::Ipv4Addr>() {
        return Some((CidrNetwork::V4(u32::from(addr)), prefix_len));
    }

    if let Ok(addr) = parts[0].parse::<std::net::Ipv6Addr>() {
        return Some((CidrNetwork::V6(addr.octets()), prefix_len));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_rules() {
        let text = r#"
# Comment
[name=test,rule=DOMAIN,target=PROXY]
google.com
.youtube.com

[name=local,rule=IP-CIDR,target=DIRECT]
192.168.0.0/16
10.0.0.0/8

[name=disabled,rule=DOMAIN,target=REJECT,disable]
blocked.com
"#;

        let rules = TextParser::parse(text.as_bytes()).unwrap();

        assert!(!rules.exact_domains.is_empty());
        assert!(!rules.suffix_domains.is_empty());
        assert!(!rules.v4_cidrs.is_empty());
    }
}
