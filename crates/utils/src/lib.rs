//! Utilities library.
//!
//! This crate provides utility functions for file operations, device information retrieval,
//! and other helpers used throughout the crash upload system.

mod command;
mod device_info;

/// Utilities library version.
pub const UTILS_LIB_VER: &str = "v1.0";

// Re-export file operation helpers.
pub use command::*;

// Re-export all device information utilities.
pub use device_info::*;
