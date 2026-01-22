//! Target action types for rule matching.

use std::fmt;

/// Target represents the action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Target {
    /// Route directly without proxy
    Direct = 0,
    /// Route through proxy
    #[default]
    Proxy = 1,
    /// Reject the connection
    Reject = 2,
}

impl Target {
    /// Parse a target from a string (case-insensitive).
    ///
    /// Returns `Proxy` as the default for unknown values.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DIRECT" => Target::Direct,
            "REJECT" => Target::Reject,
            _ => Target::Proxy,
        }
    }

    /// Convert from a u8 value.
    ///
    /// Returns `None` for invalid values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Target::Direct),
            1 => Some(Target::Proxy),
            2 => Some(Target::Reject),
            _ => None,
        }
    }

    /// Convert to a u8 value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Target::Direct => "DIRECT",
            Target::Proxy => "PROXY",
            Target::Reject => "REJECT",
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Target {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "DIRECT" => Ok(Target::Direct),
            "PROXY" => Ok(Target::Proxy),
            "REJECT" => Ok(Target::Reject),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_from_str() {
        assert_eq!(Target::from_str_lossy("DIRECT"), Target::Direct);
        assert_eq!(Target::from_str_lossy("direct"), Target::Direct);
        assert_eq!(Target::from_str_lossy("Direct"), Target::Direct);
        assert_eq!(Target::from_str_lossy("PROXY"), Target::Proxy);
        assert_eq!(Target::from_str_lossy("REJECT"), Target::Reject);
        assert_eq!(Target::from_str_lossy("unknown"), Target::Proxy);
    }

    #[test]
    fn test_target_from_u8() {
        assert_eq!(Target::from_u8(0), Some(Target::Direct));
        assert_eq!(Target::from_u8(1), Some(Target::Proxy));
        assert_eq!(Target::from_u8(2), Some(Target::Reject));
        assert_eq!(Target::from_u8(3), None);
    }

    #[test]
    fn test_target_display() {
        assert_eq!(Target::Direct.to_string(), "DIRECT");
        assert_eq!(Target::Proxy.to_string(), "PROXY");
        assert_eq!(Target::Reject.to_string(), "REJECT");
    }
}
