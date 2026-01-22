//! Format converters for rule files.

mod clash;
mod text;

pub use clash::{ClashConfig, ClashConverter, RuleProvider};
pub use text::TextParser;
