//! Integration tests for slice-based rule format (k2r v2).

use k2rule::{SliceConverter, SliceReader, SliceWriter, Target};
use std::net::IpAddr;

#[test]
fn test_full_roundtrip_with_writer_reader() {
    // Build a complex rule set using SliceWriter
    let mut writer = SliceWriter::new(Target::Proxy);

    // Add domains with different targets
    writer
        .add_domain_slice(&["cn.bing.com"], Target::Direct)
        .unwrap();
    writer
        .add_domain_slice(&["bing.com", "google.com"], Target::Proxy)
        .unwrap();

    // Add CIDR rules
    writer
        .add_cidr_v4_slice(&[(0x0A000000, 8), (0xC0A80000, 16)], Target::Direct)
        .unwrap();

    // Add GeoIP rules
    writer.add_geoip_slice(&["CN", "HK"], Target::Direct).unwrap();

    let data = writer.build().unwrap();

    // Read and verify
    let reader = SliceReader::from_bytes(&data).unwrap();

    // Verify fallback
    assert_eq!(reader.fallback(), Target::Proxy);

    // Verify domain ordering (cn.bing.com should match Direct first)
    assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("www.cn.bing.com"), Some(Target::Direct));

    // bing.com matches the second slice (Proxy)
    assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));

    // google.com matches Proxy
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));

    // Unknown domain returns None (caller uses fallback)
    assert_eq!(reader.match_domain("unknown.com"), None);

    // CIDR matching
    assert_eq!(
        reader.match_ip("10.0.0.1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("192.168.1.1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("8.8.8.8".parse::<IpAddr>().unwrap()),
        None
    );

    // GeoIP matching
    assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("HK"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("US"), None);
}

#[test]
fn test_converter_complex_config() {
    // A realistic Clash config with multiple rule types
    let yaml = r#"
rule-providers:
  direct-domains:
    type: http
    behavior: domain
    rules:
      - cn.bing.com
      - "+.baidu.com"
  proxy-domains:
    type: http
    behavior: domain
    rules:
      - google.com
      - "+.googleapis.com"
      - youtube.com
  private-ips:
    type: http
    behavior: ipcidr
    rules:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16

rules:
  - RULE-SET,direct-domains,DIRECT
  - RULE-SET,proxy-domains,PROXY
  - RULE-SET,private-ips,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;

    let converter = SliceConverter::new();
    let data = converter.convert(yaml).unwrap();

    let reader = SliceReader::from_bytes(&data).unwrap();

    // Fallback is PROXY (from MATCH rule)
    assert_eq!(reader.fallback(), Target::Proxy);

    // Direct domains
    assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("baidu.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("www.baidu.com"), Some(Target::Direct));

    // Proxy domains
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("apis.googleapis.com"),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_domain("youtube.com"), Some(Target::Proxy));

    // Private IPs
    assert_eq!(
        reader.match_ip("10.1.2.3".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("172.20.0.1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("192.168.100.1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );

    // GeoIP
    assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));

    // Unknown should return None
    assert_eq!(reader.match_domain("unknown.example.org"), None);
    assert_eq!(reader.match_geoip("JP"), None);
}

#[test]
fn test_ordering_priority() {
    // This tests the critical ordering behavior:
    // cn.bing.com -> DIRECT
    // bing.com -> PROXY
    // First match wins!
    let yaml = r#"
rules:
  - DOMAIN-SUFFIX,cn.bing.com,DIRECT
  - DOMAIN-SUFFIX,bing.com,PROXY
  - MATCH,DIRECT
"#;

    let converter = SliceConverter::new();
    let data = converter.convert(yaml).unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // cn.bing.com and subdomains should match DIRECT (first rule)
    assert_eq!(reader.match_domain("cn.bing.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("www.cn.bing.com"), Some(Target::Direct));
    assert_eq!(
        reader.match_domain("api.cn.bing.com"),
        Some(Target::Direct)
    );

    // bing.com and other subdomains should match PROXY (second rule)
    assert_eq!(reader.match_domain("bing.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.bing.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("api.bing.com"), Some(Target::Proxy));
}

#[test]
fn test_slice_count_after_merging() {
    // Test that adjacent same-type same-target slices get merged
    let yaml = r#"
rules:
  - DOMAIN,a.com,PROXY
  - DOMAIN,b.com,PROXY
  - DOMAIN,c.com,PROXY
  - DOMAIN,x.com,DIRECT
  - DOMAIN,y.com,DIRECT
  - MATCH,PROXY
"#;

    let converter = SliceConverter::new();
    let data = converter.convert(yaml).unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // Should be 2 slices: [a.com, b.com, c.com] -> PROXY, [x.com, y.com] -> DIRECT
    assert_eq!(reader.slice_count(), 2);

    // All domains should still match correctly
    assert_eq!(reader.match_domain("a.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("b.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("c.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("x.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("y.com"), Some(Target::Direct));
}

#[test]
fn test_ipv6_cidr_matching() {
    let mut writer = SliceWriter::new(Target::Proxy);

    // fc00::/7 - unique local addresses
    let fc00: [u8; 16] = [0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // fe80::/10 - link-local addresses
    let fe80: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    writer
        .add_cidr_v6_slice(&[(fc00, 7), (fe80, 10)], Target::Direct)
        .unwrap();

    let data = writer.build().unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // fc00::/7 includes fc00:: and fd00::
    assert_eq!(
        reader.match_ip("fc00::1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("fd00::1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );

    // fe80::/10
    assert_eq!(
        reader.match_ip("fe80::1".parse::<IpAddr>().unwrap()),
        Some(Target::Direct)
    );

    // Public IPv6 should not match
    assert_eq!(
        reader.match_ip("2001:db8::1".parse::<IpAddr>().unwrap()),
        None
    );
}

#[test]
fn test_empty_rules() {
    let yaml = r#"
rules:
  - MATCH,DIRECT
"#;

    let converter = SliceConverter::new();
    let data = converter.convert(yaml).unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    assert_eq!(reader.slice_count(), 0);
    assert_eq!(reader.fallback(), Target::Direct);
    assert_eq!(reader.match_domain("any.com"), None);
}

#[test]
fn test_case_insensitive_domain_matching() {
    let mut writer = SliceWriter::new(Target::Direct);
    writer
        .add_domain_slice(&["Google.COM", "YOUTUBE.com"], Target::Proxy)
        .unwrap();

    let data = writer.build().unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // Should match regardless of case
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("GOOGLE.COM"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("Google.Com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("youtube.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("YOUTUBE.COM"), Some(Target::Proxy));
}

#[test]
fn test_case_insensitive_geoip_matching() {
    let mut writer = SliceWriter::new(Target::Proxy);
    writer.add_geoip_slice(&["cn", "us"], Target::Direct).unwrap();

    let data = writer.build().unwrap();
    let reader = SliceReader::from_bytes(&data).unwrap();

    // Should match regardless of case
    assert_eq!(reader.match_geoip("CN"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("cn"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("Cn"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("US"), Some(Target::Direct));
    assert_eq!(reader.match_geoip("us"), Some(Target::Direct));
}
