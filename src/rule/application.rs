//! Application-based rule implementation (placeholder).

use std::net::IpAddr;

use super::Rule;
use crate::{RuleType, Target};

/// ApplicationRule matches based on application type.
///
/// This is currently a placeholder implementation that always returns false.
/// Future versions may implement actual application detection.
pub struct ApplicationRule {
    target: Target,
}

impl ApplicationRule {
    /// Create a new ApplicationRule with the specified target.
    pub fn new(target: Target) -> Self {
        Self { target }
    }
}

impl Rule for ApplicationRule {
    fn match_input(&self, _ip: Option<IpAddr>, _domain: &str) -> bool {
        // Placeholder: always returns false
        false
    }

    fn target(&self) -> Target {
        self.target
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Application
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_never_matches() {
        let rule = ApplicationRule::new(Target::Direct);

        assert!(!rule.match_input(None, ""));
        assert!(!rule.match_input(None, "example.com"));

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!rule.match_input(Some(ip), ""));
    }

    #[test]
    fn test_target_and_type() {
        let rule = ApplicationRule::new(Target::Proxy);
        assert_eq!(rule.target(), Target::Proxy);
        assert_eq!(rule.rule_type(), RuleType::Application);
    }
}
