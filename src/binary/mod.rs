//! Binary file format for efficient rule storage and loading.
//!
//! The binary format uses a header + index + payload structure for
//! O(log n) or O(1) lookups and memory-mapped file support.
//!
//! # File Structure
//!
//! ```text
//! +------------------+
//! |     HEADER       |  128 bytes (fixed)
//! +------------------+
//! |   DOMAIN INDEX   |  variable
//! +------------------+
//! |    CIDR INDEX    |  variable
//! +------------------+
//! |   GEOIP INDEX    |  variable
//! +------------------+
//! |     IP INDEX     |  variable
//! +------------------+
//! |     PAYLOAD      |  variable
//! +------------------+
//! ```

mod cached_reader;
mod format;
mod reader;
pub mod writer;

#[cfg(test)]
mod tests;

pub use cached_reader::{CacheStats, CachedBinaryReader, CachedReaderConfig};
pub use format::*;
pub use reader::BinaryRuleReader;
pub use writer::{BinaryRuleWriter, IntermediateRules};
