//! K2Rule - A high-performance rule-based routing/filtering system.
//!
//! This crate provides a rule engine for determining how network traffic
//! (domains and IPs) should be routed based on configurable rules.
//!
//! # Features
//!
//! - **Domain matching**: Exact and suffix matching for domain names
//! - **IP-CIDR matching**: IPv4 and IPv6 CIDR range matching
//! - **GeoIP matching**: Country-based IP routing (requires GeoIP database)
//! - **Dynamic rules**: Add rules at runtime without reloading
//! - **Thread-safe**: All operations are thread-safe
//! - **Memory-mapped binary format**: Efficient loading of large rule sets
//! - **Remote rule management**: Download, cache, and hot-reload rules from URLs
//!
//! # Quick Start
//!
//! ```ignore
//! use k2rule::{match_rule, add_direct_domain, add_proxy_domain, Target};
//!
//! // Match a domain or IP
//! let target = match_rule("www.google.com");
//! assert_eq!(target, Target::Proxy);
//!
//! // Add dynamic rules
//! add_direct_domain(&["example.com"]);
//! add_proxy_domain(&["api.example.com"]);
//! ```
//!
//! # Remote Rules
//!
//! For applications that need to download and cache rules from a remote server,
//! use [`RemoteRuleManager`]:
//!
//! ```ignore
//! use k2rule::{RemoteRuleManager, Target};
//! use std::path::Path;
//!
//! // Create manager with remote URL and local cache directory
//! let mut manager = RemoteRuleManager::new(
//!     "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/cn_blacklist.k2r.gz",
//!     Path::new("/tmp/k2rule-cache"),
//!     Target::Direct, // fallback when no rule matches
//! );
//!
//! // Initialize: loads from cache or downloads
//! manager.init()?;
//!
//! // Query rules
//! let target = manager.match_domain("google.com");
//!
//! // Check for updates (uses ETag for efficiency)
//! if manager.update()? {
//!     println!("Rules updated!");
//! }
//! ```
//!
//! The remote manager supports:
//! - Automatic gzip decompression (`.k2r.gz` files)
//! - ETag-based conditional requests (304 Not Modified)
//! - Atomic cache updates
//! - Hot reload without restarting
//!
//! # Porn Domain Detection
//!
//! For applications that need to detect adult content domains,
//! use [`PornDomainChecker`]:
//!
//! ```ignore
//! use k2rule::PornDomainChecker;
//! use std::path::Path;
//!
//! // Create checker with remote URL and local cache directory
//! let mut checker = PornDomainChecker::new(
//!     "https://cdn.jsdelivr.net/gh/kaitu-io/k2rule@release/porn_domains.k2r.gz",
//!     Path::new("/tmp/k2rule-porn-cache"),
//! );
//!
//! // Initialize: loads from cache or downloads
//! checker.init()?;
//!
//! // Check if a domain is porn
//! if checker.is_porn("example-adult-site.com") {
//!     println!("Blocked!");
//! }
//! ```
//!
//! # Rule Types
//!
//! - **DOMAIN**: Domain name matching (exact or suffix)
//! - **IP-CIDR**: IP address range matching
//! - **GEOIP**: Geographic location-based matching
//! - **IP-MATCH**: Exact IP address matching
//! - **APPLICATION**: Application-based matching (placeholder)
//!
//! # Matching Priority
//!
//! Rules are matched in the following order:
//! 1. Dynamic rules (Direct IP → Direct Domain → Proxy IP → Proxy Domain)
//! 2. Static rules (in configuration order)
//! 3. Fallback target (when no rules match)

mod error;
mod global;
mod rule_type;
mod target;

pub mod binary;
pub mod converter;
pub mod porn;
pub mod porn_heuristic;
pub mod remote;
pub mod rule;
pub mod ruleset;

// Re-export core types
pub use error::{Error, Result};
pub use rule_type::{RuleType, RuleTypeInfo};
pub use target::Target;

// Re-export ruleset types
pub use ruleset::{RuleConfig, RuleSet, RuleSetType};

// Re-export global API functions
pub use global::{
    add_direct_domain, add_direct_ip, add_proxy_domain, add_proxy_ip, ensure_initialized,
    get_available_rule_types, is_initialized, match_rule, reload_ruleset,
    reload_ruleset_from_reader, reload_ruleset_with_type, validate_rule_type,
};

// Re-export GeoIP initialization
pub use rule::geoip::{init_geoip_database, init_geoip_database_from_bytes, lookup_country};

// Re-export remote rule management
pub use remote::RemoteRuleManager;

// Re-export porn domain checker
pub use porn::PornDomainChecker;

// Re-export binary reader types for advanced usage
pub use binary::{CachedBinaryReader, CachedReaderConfig};
