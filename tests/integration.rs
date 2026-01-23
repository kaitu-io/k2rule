//! Integration tests for kaitu-rules compatibility.

use k2rule::{RuleConfig, RuleSet, Target};
use std::net::IpAddr;

#[test]
fn test_ruleset_kaitu_rules_compatibility() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Single-item adds
    ruleset.add_direct_domain("direct.com");
    ruleset.add_proxy_domain("proxy.com");
    ruleset.add_reject_domain("blocked.com");
    ruleset.add_direct_ip("192.168.1.1");
    ruleset.add_proxy_ip("10.0.0.1");
    ruleset.add_direct_cidr("172.16.0.0/12");
    ruleset.add_proxy_cidr("100.64.0.0/10");

    // Match methods
    assert_eq!(ruleset.match_host("direct.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("proxy.com"), Target::Proxy);
    assert_eq!(ruleset.match_domain("blocked.com"), Target::Reject);

    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(ruleset.match_ip(ip), Target::Direct);

    let cidr_ip: IpAddr = "172.16.5.5".parse().unwrap();
    assert_eq!(ruleset.match_ip(cidr_ip), Target::Direct);

    // Stats
    assert!(ruleset.rule_count() >= 7);
}

#[test]
fn test_ruleset_with_cache() {
    let config = RuleConfig {
        name: "test".to_string(),
        display_name: "Test".to_string(),
        fallback_target: Target::Proxy,
    };
    let ruleset = RuleSet::with_cache_size(config, 1000);

    ruleset.add_direct_domain("cached.com");

    // Multiple queries
    for _ in 0..10 {
        assert_eq!(ruleset.match_domain("cached.com"), Target::Direct);
    }

    let (hit_rate, _) = ruleset.cache_stats();
    assert!(hit_rate > 0.8); // Should have ~90% hit rate

    ruleset.clear_cache();
}

#[test]
fn test_ruleset_fallback_targets() {
    // Test Direct fallback
    let ruleset = RuleSet::with_fallback(Target::Direct);
    assert_eq!(ruleset.match_host("unknown.com"), Target::Direct);

    // Test Proxy fallback
    let ruleset = RuleSet::with_fallback(Target::Proxy);
    assert_eq!(ruleset.match_host("unknown.com"), Target::Proxy);

    // Test Reject fallback
    let ruleset = RuleSet::with_fallback(Target::Reject);
    assert_eq!(ruleset.match_host("unknown.com"), Target::Reject);
}

#[test]
fn test_domain_suffix_matching() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Add suffix pattern
    ruleset.add_direct_domain(".google.com");

    // Should match the domain itself and all subdomains
    assert_eq!(ruleset.match_domain("google.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("www.google.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("mail.google.com"), Target::Direct);
    assert_eq!(ruleset.match_domain("a.b.c.google.com"), Target::Direct);

    // Should not match unrelated domains
    assert_eq!(ruleset.match_domain("notgoogle.com"), Target::Proxy);
}

#[test]
fn test_ipv6_support() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Add IPv6 addresses and CIDRs
    ruleset.add_direct_ip("2001:4860:4860::8888");
    ruleset.add_proxy_cidr("fc00::/7");

    // Test exact IPv6 match
    let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    assert_eq!(ruleset.match_ip(ipv6), Target::Direct);

    // Test IPv6 CIDR match
    let fc_ip: IpAddr = "fc00::1".parse().unwrap();
    assert_eq!(ruleset.match_ip(fc_ip), Target::Proxy);

    let fd_ip: IpAddr = "fd00::1".parse().unwrap();
    assert_eq!(ruleset.match_ip(fd_ip), Target::Proxy);
}

#[test]
fn test_rule_priority() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Add a domain to both direct and proxy
    // Direct should have higher priority
    ruleset.add_direct_domain("example.com");
    ruleset.add_proxy_domain("example.com");

    assert_eq!(ruleset.match_domain("example.com"), Target::Direct);
}

#[test]
fn test_reject_domain_priority() {
    let ruleset = RuleSet::with_fallback(Target::Proxy);

    // Add a domain to direct and reject
    // Direct should have higher priority than reject
    ruleset.add_reject_domain("blocked.com");

    assert_eq!(ruleset.match_domain("blocked.com"), Target::Reject);

    // But adding it to direct should override
    ruleset.add_direct_domain("blocked.com");
    assert_eq!(ruleset.match_domain("blocked.com"), Target::Direct);
}
