//! RuleSet configuration types.

use crate::Target;

/// Pre-defined rule set types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleSetType {
    /// Global mode: all traffic through proxy
    Global,
    /// CN Blacklist: Chinese sites direct, others through proxy
    CnBlacklist,
    /// CN Whitelist: Most traffic direct, exceptions through proxy
    CnWhitelist,
}

impl RuleSetType {
    /// Get the internal name of this rule set type.
    pub fn name(&self) -> &'static str {
        match self {
            RuleSetType::Global => "global",
            RuleSetType::CnBlacklist => "cn_blacklist",
            RuleSetType::CnWhitelist => "cn_whitelist",
        }
    }

    /// Get the display name of this rule set type.
    pub fn display_name(&self) -> &'static str {
        match self {
            RuleSetType::Global => "全局",
            RuleSetType::CnBlacklist => "智能",
            RuleSetType::CnWhitelist => "轻量",
        }
    }

    /// Get the default fallback target for this rule set type.
    pub fn fallback_target(&self) -> Target {
        match self {
            RuleSetType::Global => Target::Proxy,
            RuleSetType::CnBlacklist => Target::Direct,
            RuleSetType::CnWhitelist => Target::Proxy,
        }
    }

    /// Parse a rule set type from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "global" => Some(RuleSetType::Global),
            "cn_blacklist" | "cnblacklist" => Some(RuleSetType::CnBlacklist),
            "cn_whitelist" | "cnwhitelist" => Some(RuleSetType::CnWhitelist),
            _ => None,
        }
    }

    /// Get the RuleConfig for this rule set type.
    pub fn config(&self) -> RuleConfig {
        RuleConfig {
            name: self.name().to_string(),
            display_name: self.display_name().to_string(),
            fallback_target: self.fallback_target(),
        }
    }
}

/// Configuration for a RuleSet.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    /// Internal name of the rule set
    pub name: String,
    /// Display name for UI
    pub display_name: String,
    /// Default target when no rules match
    pub fallback_target: Target,
}

impl RuleConfig {
    /// Create a new RuleConfig.
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        fallback_target: Target,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            fallback_target,
        }
    }

    /// Create a RuleConfig from a RuleSetType.
    pub fn from_type(rule_type: RuleSetType) -> Self {
        rule_type.config()
    }
}

impl Default for RuleConfig {
    fn default() -> Self {
        RuleSetType::Global.config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_set_type() {
        assert_eq!(RuleSetType::Global.name(), "global");
        assert_eq!(RuleSetType::CnBlacklist.name(), "cn_blacklist");
        assert_eq!(RuleSetType::CnWhitelist.name(), "cn_whitelist");
    }

    #[test]
    fn test_fallback_targets() {
        assert_eq!(RuleSetType::Global.fallback_target(), Target::Proxy);
        assert_eq!(RuleSetType::CnBlacklist.fallback_target(), Target::Direct);
        assert_eq!(RuleSetType::CnWhitelist.fallback_target(), Target::Proxy);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(RuleSetType::from_str("global"), Some(RuleSetType::Global));
        assert_eq!(
            RuleSetType::from_str("cn_blacklist"),
            Some(RuleSetType::CnBlacklist)
        );
        assert_eq!(RuleSetType::from_str("unknown"), None);
    }
}
