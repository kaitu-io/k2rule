//! Error types for k2rule.

use thiserror::Error;

/// Error type for k2rule operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid binary file magic bytes
    #[error("invalid magic bytes: expected K2RULE header")]
    InvalidMagic,

    /// Unsupported binary format version
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u32),

    /// Checksum mismatch
    #[error("checksum mismatch")]
    ChecksumMismatch,

    /// Invalid header size
    #[error("invalid header size: expected {expected}, got {actual}")]
    InvalidHeaderSize { expected: usize, actual: usize },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing error
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Invalid domain pattern
    #[error("invalid domain pattern: {0}")]
    InvalidDomainPattern(String),

    /// Invalid CIDR pattern
    #[error("invalid CIDR pattern: {0}")]
    InvalidCidrPattern(String),

    /// Invalid country code
    #[error("invalid country code: {0}")]
    InvalidCountryCode(String),

    /// Invalid IP address
    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// Invalid rule type
    #[error("invalid rule type: {0}")]
    InvalidRuleType(String),

    /// GeoIP database error
    #[error("GeoIP error: {0}")]
    GeoIp(String),

    /// Rule set not initialized
    #[error("rule set not initialized")]
    NotInitialized,

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Download error
    #[error("download error: {0}")]
    Download(#[from] reqwest::Error),
}

/// Result type alias for k2rule operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for domain rule operations.
#[derive(Error, Debug)]
pub enum DomainRuleError {
    /// Empty pattern
    #[error("empty domain pattern")]
    EmptyPattern,

    /// Invalid pattern (missing dot)
    #[error("invalid domain pattern (must contain at least one dot): {0}")]
    InvalidPattern(String),
}

/// Error type for CIDR rule operations.
#[derive(Error, Debug)]
pub enum CidrRuleError {
    /// Invalid CIDR notation
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
}

/// Error type for GeoIP rule operations.
#[derive(Error, Debug)]
pub enum GeoIpRuleError {
    /// Invalid country code (must be 2 characters)
    #[error("invalid country code (must be 2 characters): {0}")]
    InvalidCountryCode(String),
}

/// Error type for IP rule operations.
#[derive(Error, Debug)]
pub enum IpRuleError {
    /// Invalid IP address
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
}
