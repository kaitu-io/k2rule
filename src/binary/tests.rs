//! Comprehensive tests for binary rule format.
//!
//! These tests verify the complete write-read round-trip for all rule types
//! and ensure the binary format works correctly in various scenarios.

use super::format::*;
use super::reader::BinaryRuleReader;
use super::writer::{BinaryRuleWriter, IntermediateRules};
use crate::Target;

/// Helper to create a reader from rules
fn write_and_read(rules: &IntermediateRules) -> BinaryRuleReader {
    let mut writer = BinaryRuleWriter::new();
    let data = writer.write(rules).expect("Failed to write rules");
    BinaryRuleReader::from_bytes(data).expect("Failed to read rules")
}

// ============================================================================
// Header and Format Tests
// ============================================================================

#[test]
fn test_empty_rules_produces_valid_binary() {
    let rules = IntermediateRules::new();
    let mut writer = BinaryRuleWriter::new();
    let data = writer.write(&rules).unwrap();

    // Should have at least header size
    assert!(data.len() >= HEADER_SIZE);

    // Magic bytes should be correct
    assert_eq!(&data[0..8], &MAGIC);

    // Version should be correct
    let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    assert_eq!(version, FORMAT_VERSION);
}

#[test]
fn test_header_validation_with_valid_data() {
    let rules = IntermediateRules::new();
    let reader = write_and_read(&rules);
    let header = reader.header();

    assert!(header.validate().is_ok());
    assert_eq!(header.magic, MAGIC);
    assert_eq!(header.version, FORMAT_VERSION);
}

#[test]
fn test_header_validation_with_invalid_magic() {
    let rules = IntermediateRules::new();
    let mut writer = BinaryRuleWriter::new();
    let mut data = writer.write(&rules).unwrap();

    // Corrupt magic bytes
    data[0] = 0xFF;

    let result = BinaryRuleReader::from_bytes(data);
    assert!(result.is_err());
}

#[test]
fn test_header_counts_are_correct() {
    let mut rules = IntermediateRules::new();

    // Add 3 exact domains
    rules.add_domain("example.com", Target::Direct);
    rules.add_domain("test.com", Target::Proxy);
    rules.add_domain("foo.com", Target::Reject);

    // Add 2 suffix domains
    rules.add_domain(".google.com", Target::Proxy);
    rules.add_domain(".youtube.com", Target::Proxy);

    // Add 2 IPv4 CIDRs
    rules.add_v4_cidr(0xC0A80000, 16, Target::Direct); // 192.168.0.0/16
    rules.add_v4_cidr(0x0A000000, 8, Target::Direct); // 10.0.0.0/8

    // Add 1 IPv6 CIDR
    rules.add_v6_cidr([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7, Target::Direct);

    let reader = write_and_read(&rules);
    let header = reader.header();

    assert_eq!(header.domain_count, 5); // 3 exact + 2 suffix
    assert_eq!(header.cidr_count, 3); // 2 v4 + 1 v6
}

// ============================================================================
// Domain Exact Match Tests
// ============================================================================

#[test]
fn test_exact_domain_match() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("google.com", Target::Proxy);
    rules.add_domain("example.com", Target::Direct);
    rules.add_domain("blocked.com", Target::Reject);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("example.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("blocked.com"), Some(Target::Reject));
}

#[test]
fn test_exact_domain_case_insensitive() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("Google.Com", Target::Proxy);

    let reader = write_and_read(&rules);

    // All case variations should match
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("GOOGLE.COM"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("GoOgLe.CoM"), Some(Target::Proxy));
}

#[test]
fn test_exact_domain_no_match() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("google.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // Subdomain should not match exact pattern
    assert_eq!(reader.match_domain("www.google.com"), None);
    assert_eq!(reader.match_domain("mail.google.com"), None);

    // Different domain should not match
    assert_eq!(reader.match_domain("notgoogle.com"), None);
    assert_eq!(reader.match_domain("google.org"), None);
}

#[test]
fn test_many_exact_domains() {
    let mut rules = IntermediateRules::new();

    // Add 1000 domains to test hash table performance
    for i in 0..1000 {
        let target = match i % 3 {
            0 => Target::Direct,
            1 => Target::Proxy,
            _ => Target::Reject,
        };
        rules.add_domain(&format!("domain{}.com", i), target);
    }

    let reader = write_and_read(&rules);

    // Verify some samples
    assert_eq!(reader.match_domain("domain0.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("domain1.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("domain2.com"), Some(Target::Reject));
    assert_eq!(reader.match_domain("domain999.com"), Some(Target::Direct));

    // Non-existent should return None
    assert_eq!(reader.match_domain("domain1000.com"), None);
}

// ============================================================================
// Domain Suffix Match Tests
// ============================================================================

#[test]
fn test_suffix_domain_match() {
    let mut rules = IntermediateRules::new();
    rules.add_domain(".google.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // Suffix should match the domain itself and all subdomains
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("mail.google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("a.b.c.google.com"), Some(Target::Proxy));
}

#[test]
fn test_suffix_domain_no_partial_match() {
    let mut rules = IntermediateRules::new();
    rules.add_domain(".google.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // Should NOT match domains that merely contain "google.com"
    assert_eq!(reader.match_domain("notgoogle.com"), None);
    assert_eq!(reader.match_domain("fakegoogle.com"), None);
}

#[test]
fn test_multiple_suffix_domains() {
    let mut rules = IntermediateRules::new();
    rules.add_domain(".google.com", Target::Proxy);
    rules.add_domain(".youtube.com", Target::Proxy);
    rules.add_domain(".facebook.com", Target::Proxy);
    rules.add_domain(".cn", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("www.google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.youtube.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("m.facebook.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("baidu.cn"), Some(Target::Direct));
    assert_eq!(reader.match_domain("example.org"), None);
}

// ============================================================================
// Mixed Domain Tests (Exact + Suffix)
// ============================================================================

#[test]
fn test_mixed_exact_and_suffix() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("example.com", Target::Direct); // Exact
    rules.add_domain(".google.com", Target::Proxy); // Suffix

    let reader = write_and_read(&rules);

    // Exact match
    assert_eq!(reader.match_domain("example.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("www.example.com"), None); // No suffix rule

    // Suffix match
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("www.google.com"), Some(Target::Proxy));
}

#[test]
fn test_exact_takes_priority_over_suffix() {
    let mut rules = IntermediateRules::new();
    // Add exact match for specific subdomain
    rules.add_domain("api.google.com", Target::Direct);
    // Add suffix match for all google.com
    rules.add_domain(".google.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // Exact match should be found first
    assert_eq!(reader.match_domain("api.google.com"), Some(Target::Direct));

    // Other subdomains should use suffix
    assert_eq!(reader.match_domain("www.google.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));
}

// ============================================================================
// IPv4 CIDR Tests
// ============================================================================

#[test]
fn test_ipv4_cidr_match() {
    let mut rules = IntermediateRules::new();
    // 192.168.0.0/16
    rules.add_v4_cidr(
        u32::from_be_bytes([192, 168, 0, 0]),
        16,
        Target::Direct,
    );

    let reader = write_and_read(&rules);

    // Should match
    assert_eq!(
        reader.match_ip("192.168.0.1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("192.168.255.255".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("192.168.100.50".parse().unwrap()),
        Some(Target::Direct)
    );

    // Should not match
    assert_eq!(reader.match_ip("192.169.0.1".parse().unwrap()), None);
    assert_eq!(reader.match_ip("10.0.0.1".parse().unwrap()), None);
}

#[test]
fn test_ipv4_cidr_private_ranges() {
    let mut rules = IntermediateRules::new();
    // Common private ranges
    rules.add_v4_cidr(u32::from_be_bytes([10, 0, 0, 0]), 8, Target::Direct);
    rules.add_v4_cidr(u32::from_be_bytes([172, 16, 0, 0]), 12, Target::Direct);
    rules.add_v4_cidr(u32::from_be_bytes([192, 168, 0, 0]), 16, Target::Direct);
    rules.add_v4_cidr(u32::from_be_bytes([127, 0, 0, 0]), 8, Target::Direct);

    let reader = write_and_read(&rules);

    // Private addresses
    assert_eq!(
        reader.match_ip("10.0.0.1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("172.16.0.1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("172.31.255.255".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("192.168.1.1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("127.0.0.1".parse().unwrap()),
        Some(Target::Direct)
    );

    // Public addresses
    assert_eq!(reader.match_ip("8.8.8.8".parse().unwrap()), None);
    assert_eq!(reader.match_ip("1.1.1.1".parse().unwrap()), None);
}

#[test]
fn test_ipv4_cidr_most_specific_match() {
    let mut rules = IntermediateRules::new();
    // Add overlapping ranges with different targets
    rules.add_v4_cidr(u32::from_be_bytes([10, 0, 0, 0]), 8, Target::Direct); // /8
    rules.add_v4_cidr(u32::from_be_bytes([10, 1, 0, 0]), 16, Target::Proxy); // /16 more specific
    rules.add_v4_cidr(u32::from_be_bytes([10, 1, 1, 0]), 24, Target::Reject); // /24 most specific

    let reader = write_and_read(&rules);

    // Most specific should win
    assert_eq!(
        reader.match_ip("10.1.1.1".parse().unwrap()),
        Some(Target::Reject)
    ); // Matches /24
    assert_eq!(
        reader.match_ip("10.1.2.1".parse().unwrap()),
        Some(Target::Proxy)
    ); // Matches /16
    assert_eq!(
        reader.match_ip("10.2.0.1".parse().unwrap()),
        Some(Target::Direct)
    ); // Matches /8
}

#[test]
fn test_ipv4_cidr_single_host() {
    let mut rules = IntermediateRules::new();
    // /32 means single host
    rules.add_v4_cidr(u32::from_be_bytes([8, 8, 8, 8]), 32, Target::Reject);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_ip("8.8.8.8".parse().unwrap()),
        Some(Target::Reject)
    );
    assert_eq!(reader.match_ip("8.8.8.9".parse().unwrap()), None);
}

// ============================================================================
// IPv6 CIDR Tests
// ============================================================================

#[test]
fn test_ipv6_cidr_match() {
    let mut rules = IntermediateRules::new();
    // fc00::/7 (Unique Local Addresses)
    let mut network = [0u8; 16];
    network[0] = 0xfc;
    rules.add_v6_cidr(network, 7, Target::Direct);

    let reader = write_and_read(&rules);

    // Should match fc00::/7 range
    assert_eq!(
        reader.match_ip("fc00::1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("fd00::1".parse().unwrap()),
        Some(Target::Direct)
    );

    // Should not match
    assert_eq!(reader.match_ip("fe80::1".parse().unwrap()), None);
    assert_eq!(reader.match_ip("2001:db8::1".parse().unwrap()), None);
}

#[test]
fn test_ipv6_cidr_documentation_range() {
    let mut rules = IntermediateRules::new();
    // 2001:db8::/32 (Documentation range)
    let mut network = [0u8; 16];
    network[0] = 0x20;
    network[1] = 0x01;
    network[2] = 0x0d;
    network[3] = 0xb8;
    rules.add_v6_cidr(network, 32, Target::Reject);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_ip("2001:db8::1".parse().unwrap()),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_ip("2001:db8:ffff::1".parse().unwrap()),
        Some(Target::Reject)
    );
    assert_eq!(reader.match_ip("2001:db9::1".parse().unwrap()), None);
}

#[test]
fn test_ipv6_cidr_loopback() {
    let mut rules = IntermediateRules::new();
    // ::1/128 (loopback)
    let mut network = [0u8; 16];
    network[15] = 1;
    rules.add_v6_cidr(network, 128, Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_ip("::1".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(reader.match_ip("::2".parse().unwrap()), None);
}

// ============================================================================
// Mixed IPv4 and IPv6 CIDR Tests
// ============================================================================

#[test]
fn test_mixed_ipv4_and_ipv6_cidrs() {
    let mut rules = IntermediateRules::new();

    // IPv4
    rules.add_v4_cidr(u32::from_be_bytes([192, 168, 0, 0]), 16, Target::Direct);

    // IPv6
    let mut v6_network = [0u8; 16];
    v6_network[0] = 0xfc;
    rules.add_v6_cidr(v6_network, 7, Target::Direct);

    let reader = write_and_read(&rules);

    // IPv4 match
    assert_eq!(
        reader.match_ip("192.168.1.1".parse().unwrap()),
        Some(Target::Direct)
    );

    // IPv6 match
    assert_eq!(
        reader.match_ip("fc00::1".parse().unwrap()),
        Some(Target::Direct)
    );

    // No cross-matching
    assert_eq!(reader.match_ip("8.8.8.8".parse().unwrap()), None);
    assert_eq!(reader.match_ip("2001:db8::1".parse().unwrap()), None);
}

// ============================================================================
// Input Matching Tests (Domain or IP)
// ============================================================================

#[test]
fn test_match_input_auto_detect() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("google.com", Target::Proxy);
    rules.add_v4_cidr(u32::from_be_bytes([8, 8, 8, 0]), 24, Target::Direct);

    let reader = write_and_read(&rules);

    // Domain input
    assert_eq!(reader.match_input("google.com"), Some(Target::Proxy));

    // IP input
    assert_eq!(reader.match_input("8.8.8.8"), Some(Target::Direct));

    // Unknown
    assert_eq!(reader.match_input("unknown.com"), None);
    assert_eq!(reader.match_input("1.1.1.1"), None);
}

// ============================================================================
// GeoIP Tests
// ============================================================================

#[test]
fn test_geoip_rules_written() {
    let mut rules = IntermediateRules::new();
    rules.add_geoip("CN", Target::Direct);
    rules.add_geoip("US", Target::Proxy);

    let reader = write_and_read(&rules);
    let header = reader.header();

    assert_eq!(header.geoip_count, 2);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_domain_no_match() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("google.com", Target::Proxy);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain(""), None);
}

#[test]
fn test_unicode_domain_lowercased() {
    let mut rules = IntermediateRules::new();
    // Add domain with mixed case
    rules.add_domain("EXAMPLE.COM", Target::Direct);

    let reader = write_and_read(&rules);

    // Should match regardless of case
    assert_eq!(reader.match_domain("example.com"), Some(Target::Direct));
    assert_eq!(reader.match_domain("EXAMPLE.COM"), Some(Target::Direct));
}

#[test]
fn test_domain_with_numbers() {
    let mut rules = IntermediateRules::new();
    rules.add_domain("123.example.com", Target::Direct);
    rules.add_domain(".456.com", Target::Proxy);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("123.example.com"),
        Some(Target::Direct)
    );
    assert_eq!(reader.match_domain("sub.456.com"), Some(Target::Proxy));
}

#[test]
fn test_very_long_domain() {
    let mut rules = IntermediateRules::new();
    let long_domain = format!(
        "{}.{}.{}.example.com",
        "a".repeat(50),
        "b".repeat(50),
        "c".repeat(50)
    );
    rules.add_domain(&long_domain, Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain(&long_domain), Some(Target::Direct));
}

#[test]
fn test_cidr_edge_prefix_lengths() {
    let mut rules = IntermediateRules::new();

    // /0 (match everything)
    rules.add_v4_cidr(0, 0, Target::Direct);

    let reader = write_and_read(&rules);

    // Everything should match
    assert_eq!(
        reader.match_ip("0.0.0.0".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("255.255.255.255".parse().unwrap()),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_ip("8.8.8.8".parse().unwrap()),
        Some(Target::Direct)
    );
}

#[test]
fn test_reader_from_bytes_too_small() {
    let small_data = vec![0u8; 64]; // Less than HEADER_SIZE
    let result = BinaryRuleReader::from_bytes(small_data);
    assert!(result.is_err());
}

#[test]
fn test_checksum_is_computed() {
    let rules = IntermediateRules::new();
    let mut writer = BinaryRuleWriter::new();
    let data = writer.write(&rules).unwrap();

    // Checksum field (bytes 0x18-0x38) should not be all zeros
    let checksum = &data[0x18..0x38];
    let all_zeros = checksum.iter().all(|&b| b == 0);
    assert!(!all_zeros, "Checksum should be computed, not all zeros");
}

#[test]
fn test_timestamp_is_set() {
    let rules = IntermediateRules::new();
    let reader = write_and_read(&rules);
    let header = reader.header();

    // Timestamp should be reasonably recent (after 2020)
    let year_2020_unix = 1577836800i64;
    assert!(
        header.timestamp > year_2020_unix,
        "Timestamp should be after 2020"
    );
}

// ============================================================================
// Performance / Large Dataset Tests
// ============================================================================

#[test]
fn test_large_domain_set() {
    let mut rules = IntermediateRules::new();

    // Add 10,000 domains
    for i in 0..10_000 {
        rules.add_domain(&format!("domain{}.example.com", i), Target::Proxy);
    }

    let reader = write_and_read(&rules);
    let header = reader.header();

    assert_eq!(header.domain_count, 10_000);

    // Verify some lookups still work
    assert_eq!(
        reader.match_domain("domain0.example.com"),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_domain("domain9999.example.com"),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_domain("domain10000.example.com"), None);
}

#[test]
fn test_large_cidr_set() {
    let mut rules = IntermediateRules::new();

    // Add 1000 IPv4 CIDRs
    for i in 0..250u8 {
        rules.add_v4_cidr(u32::from_be_bytes([i, 0, 0, 0]), 8, Target::Direct);
    }

    let reader = write_and_read(&rules);
    let header = reader.header();

    assert_eq!(header.cidr_count, 250);

    // Verify lookup
    assert_eq!(
        reader.match_ip("100.0.0.1".parse().unwrap()),
        Some(Target::Direct)
    );
}

// ============================================================================
// Real-world Clash Rule Pattern Tests
// These tests are derived from actual Loyalsoldier/clash-rules patterns
// ============================================================================

#[test]
fn test_clash_domain_starting_with_number() {
    // From reject.txt: '+.0.avmarket.rs', '+.000webhost.com'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".0.avmarket.rs", Target::Reject);
    rules.add_domain(".000webhost.com", Target::Reject);
    rules.add_domain("123rf.com", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("0.avmarket.rs"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("sub.0.avmarket.rs"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("000webhost.com"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("123rf.com"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_tld_only_suffix() {
    // From tld-not-cn.txt: '+.gov', '+.mil', '+.edu'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".gov", Target::Proxy);
    rules.add_domain(".mil", Target::Proxy);
    rules.add_domain(".edu", Target::Proxy);

    let reader = write_and_read(&rules);

    // TLD suffix should match any domain ending with that TLD
    assert_eq!(reader.match_domain("whitehouse.gov"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("www.army.mil"),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_domain("mit.edu"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("cs.stanford.edu"),
        Some(Target::Proxy)
    );

    // Should not match unrelated domains
    assert_eq!(reader.match_domain("example.com"), None);
}

#[test]
fn test_clash_country_code_tld() {
    // From tld-not-cn.txt: '+.ac', '+.ad', '+.ae', '+.jp', '+.uk'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".jp", Target::Proxy);
    rules.add_domain(".uk", Target::Proxy);
    rules.add_domain(".de", Target::Proxy);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("google.jp"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("bbc.co.uk"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("amazon.de"),
        Some(Target::Proxy)
    );
}

#[test]
fn test_clash_special_tld() {
    // From private.txt: '+.internal', '+.localdomain', '+.localhost', '+.local', '+.lan'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".internal", Target::Direct);
    rules.add_domain(".localdomain", Target::Direct);
    rules.add_domain(".localhost", Target::Direct);
    rules.add_domain(".local", Target::Direct);
    rules.add_domain(".lan", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("server.internal"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("mypc.localdomain"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("app.localhost"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("printer.local"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("nas.lan"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_reverse_dns_arpa() {
    // From private.txt: '+.in-addr.arpa', '+.ip6.arpa'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".in-addr.arpa", Target::Direct);
    rules.add_domain(".ip6.arpa", Target::Direct);
    rules.add_domain(".127.in-addr.arpa", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("1.0.0.127.in-addr.arpa"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("168.192.in-addr.arpa"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("8.b.d.0.1.0.0.2.ip6.arpa"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_domain_with_hyphens() {
    // From private.txt: '+.my.router', from gfw.txt: '+.2-hand.info'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".my.router", Target::Direct);
    rules.add_domain("2-hand.info", Target::Proxy);
    rules.add_domain(".app-measurement.com", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("my.router"), Some(Target::Direct));
    assert_eq!(reader.match_domain("2-hand.info"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("sub.app-measurement.com"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_deep_subdomain_chain() {
    // From direct.txt: 'cl1-cdn.origin-apple.com.akadns.net'
    let mut rules = IntermediateRules::new();
    rules.add_domain("cl1-cdn.origin-apple.com.akadns.net", Target::Direct);
    rules.add_domain(".akadns.net", Target::Proxy);

    let reader = write_and_read(&rules);

    // Exact match should take priority
    assert_eq!(
        reader.match_domain("cl1-cdn.origin-apple.com.akadns.net"),
        Some(Target::Direct)
    );

    // Other subdomains should match suffix
    assert_eq!(
        reader.match_domain("other.akadns.net"),
        Some(Target::Proxy)
    );
}

#[test]
fn test_clash_cdn_numbered_subdomains() {
    // From direct.txt: 'a1.mzstatic.com', 'a2.mzstatic.com', etc.
    let mut rules = IntermediateRules::new();
    rules.add_domain("a1.mzstatic.com", Target::Direct);
    rules.add_domain("a2.mzstatic.com", Target::Direct);
    rules.add_domain("a3.mzstatic.com", Target::Direct);
    rules.add_domain(".mzstatic.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // Exact matches
    assert_eq!(
        reader.match_domain("a1.mzstatic.com"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("a2.mzstatic.com"),
        Some(Target::Direct)
    );

    // Suffix match for others
    assert_eq!(
        reader.match_domain("a99.mzstatic.com"),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_domain("apps.mzstatic.com"),
        Some(Target::Proxy)
    );
}

#[test]
fn test_clash_localhost_subdomains() {
    // From private.txt: '+.localhost.ptlogin2.qq.com', '+.localhost.sec.qq.com'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".localhost.ptlogin2.qq.com", Target::Direct);
    rules.add_domain(".localhost.sec.qq.com", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("localhost.ptlogin2.qq.com"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("sub.localhost.ptlogin2.qq.com"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("localhost.sec.qq.com"),
        Some(Target::Direct)
    );

    // Non-localhost subdomains should not match
    assert_eq!(reader.match_domain("ptlogin2.qq.com"), None);
    assert_eq!(reader.match_domain("other.ptlogin2.qq.com"), None);
}

#[test]
fn test_clash_telegram_cidr() {
    // From telegramcidr.txt
    let mut rules = IntermediateRules::new();
    // 91.105.192.0/23
    rules.add_v4_cidr(u32::from_be_bytes([91, 105, 192, 0]), 23, Target::Proxy);
    // 91.108.4.0/22
    rules.add_v4_cidr(u32::from_be_bytes([91, 108, 4, 0]), 22, Target::Proxy);
    // 149.154.160.0/20
    rules.add_v4_cidr(u32::from_be_bytes([149, 154, 160, 0]), 20, Target::Proxy);

    let reader = write_and_read(&rules);

    // Should match Telegram IPs
    assert_eq!(
        reader.match_ip("91.105.192.1".parse().unwrap()),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_ip("91.108.4.1".parse().unwrap()),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_ip("149.154.167.50".parse().unwrap()),
        Some(Target::Proxy)
    );

    // Should not match non-Telegram IPs
    assert_eq!(reader.match_ip("91.105.194.1".parse().unwrap()), None);
}

#[test]
fn test_clash_telegram_ipv6_cidr() {
    // From telegramcidr.txt: '2001:67c:4e8::/48', '2a0a:f280::/32'
    let mut rules = IntermediateRules::new();

    // 2001:67c:4e8::/48
    let mut network1 = [0u8; 16];
    network1[0] = 0x20;
    network1[1] = 0x01;
    network1[2] = 0x06;
    network1[3] = 0x7c;
    network1[4] = 0x04;
    network1[5] = 0xe8;
    rules.add_v6_cidr(network1, 48, Target::Proxy);

    // 2a0a:f280::/32
    let mut network2 = [0u8; 16];
    network2[0] = 0x2a;
    network2[1] = 0x0a;
    network2[2] = 0xf2;
    network2[3] = 0x80;
    rules.add_v6_cidr(network2, 32, Target::Proxy);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_ip("2001:67c:4e8::1".parse().unwrap()),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_ip("2a0a:f280::1".parse().unwrap()),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_ip("2001:db8::1".parse().unwrap()), None);
}

#[test]
fn test_clash_long_random_subdomain() {
    // From reject.txt: '+.00cae06d30.720df8c8c9.com' (random hash-like subdomains)
    let mut rules = IntermediateRules::new();
    rules.add_domain(".00cae06d30.720df8c8c9.com", Target::Reject);
    rules.add_domain(
        ".079301eaff0975107716716fd1cb0dcd.com",
        Target::Reject,
    );

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("00cae06d30.720df8c8c9.com"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("sub.00cae06d30.720df8c8c9.com"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("079301eaff0975107716716fd1cb0dcd.com"),
        Some(Target::Reject)
    );
}

#[test]
fn test_clash_mixed_numeric_alpha_domain() {
    // From gfw.txt: '+.1e100.net', '+.1point3acres.com', '+.4chan.com'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".1e100.net", Target::Proxy); // Google's domain
    rules.add_domain(".1point3acres.com", Target::Proxy);
    rules.add_domain(".4chan.com", Target::Proxy);
    rules.add_domain(".500px.com", Target::Proxy);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("1e100.net"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("www.1e100.net"),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_domain("1point3acres.com"),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_domain("4chan.com"), Some(Target::Proxy));
    assert_eq!(reader.match_domain("500px.com"), Some(Target::Proxy));
}

#[test]
fn test_clash_router_domains() {
    // From private.txt
    let mut rules = IntermediateRules::new();
    rules.add_domain("router.asus.com", Target::Direct);
    rules.add_domain("tplogin.cn", Target::Direct);
    rules.add_domain("miwifi.com", Target::Direct);
    rules.add_domain(".routerlogin.com", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("router.asus.com"),
        Some(Target::Direct)
    );
    assert_eq!(reader.match_domain("tplogin.cn"), Some(Target::Direct));
    assert_eq!(reader.match_domain("miwifi.com"), Some(Target::Direct));
    assert_eq!(
        reader.match_domain("routerlogin.com"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("www.routerlogin.com"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_app_subdomain_variations() {
    // From reject.txt: '+.0186141170.apps.iocnt.de'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".0186141170.apps.iocnt.de", Target::Reject);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("0186141170.apps.iocnt.de"),
        Some(Target::Reject)
    );
    assert_eq!(
        reader.match_domain("sub.0186141170.apps.iocnt.de"),
        Some(Target::Reject)
    );

    // Parent domains should not match
    assert_eq!(reader.match_domain("apps.iocnt.de"), None);
    assert_eq!(reader.match_domain("iocnt.de"), None);
}

#[test]
fn test_clash_plex_direct() {
    // From private.txt: '+.plex.direct'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".plex.direct", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(
        reader.match_domain("plex.direct"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("192-168-1-100.abc123.plex.direct"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_co_uk_style_domain() {
    // Testing second-level TLD patterns
    let mut rules = IntermediateRules::new();
    rules.add_domain(".co.uk", Target::Proxy);
    rules.add_domain(".com.cn", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("bbc.co.uk"), Some(Target::Proxy));
    assert_eq!(
        reader.match_domain("www.bbc.co.uk"),
        Some(Target::Proxy)
    );
    assert_eq!(
        reader.match_domain("taobao.com.cn"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("www.taobao.com.cn"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_overlapping_suffixes() {
    // Test when multiple suffixes could match - more specific should be checked first
    let mut rules = IntermediateRules::new();
    rules.add_domain(".google.com", Target::Proxy);
    rules.add_domain(".com", Target::Direct); // Very broad

    let reader = write_and_read(&rules);

    // More specific suffix ".google.com" should match first
    assert_eq!(
        reader.match_domain("www.google.com"),
        Some(Target::Proxy)
    );
    assert_eq!(reader.match_domain("google.com"), Some(Target::Proxy));

    // Other .com domains should match ".com"
    assert_eq!(reader.match_domain("example.com"), Some(Target::Direct));
}

#[test]
fn test_clash_ts_net_tailscale() {
    // From private.txt: '+.ts.net' (Tailscale MagicDNS)
    let mut rules = IntermediateRules::new();
    rules.add_domain(".ts.net", Target::Direct);

    let reader = write_and_read(&rules);

    assert_eq!(reader.match_domain("ts.net"), Some(Target::Direct));
    assert_eq!(
        reader.match_domain("mydevice.tail1234.ts.net"),
        Some(Target::Direct)
    );
}

#[test]
fn test_clash_steam_domains() {
    // From private.txt: '+.test.steampowered.com'
    let mut rules = IntermediateRules::new();
    rules.add_domain(".test.steampowered.com", Target::Direct);
    rules.add_domain(".steampowered.com", Target::Proxy);

    let reader = write_and_read(&rules);

    // More specific should match
    assert_eq!(
        reader.match_domain("test.steampowered.com"),
        Some(Target::Direct)
    );
    assert_eq!(
        reader.match_domain("api.test.steampowered.com"),
        Some(Target::Direct)
    );

    // General steampowered.com
    assert_eq!(
        reader.match_domain("store.steampowered.com"),
        Some(Target::Proxy)
    );
}
