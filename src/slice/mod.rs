//! Slice-based rule format (k2r v2).
//!
//! This module provides a new binary format that preserves rule ordering
//! and uses optimal data structures (FST for domains) per slice.

pub mod converter;
pub mod format;
pub mod reader;
pub mod writer;

pub use converter::SliceConverter;
pub use format::*;
pub use reader::SliceReader;
pub use writer::SliceWriter;
