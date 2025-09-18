//! Utilities library for the crash upload system.
//!
//! This crate provides various utility functions and helpers used throughout the crash upload system:
//!
//! - **File operations**: Functions for creating files, removing files/directories, and other
//!   filesystem operations (see the [`command`] module)
//!
//! - **Device information**: Utilities for retrieving device properties such as MAC address,
//!   version information, and config values from property files (see the [`device_info`] module)
//!
//! Most commonly used functions are re-exported at the crate root for convenience.

pub mod command;
pub mod device_info;

/// Utilities library version.
pub const UTILS_LIB_VER: &str = "v1.0";

// Re-export file operation helpers.
pub use command::*;

// Re-export all device information utilities.
pub use device_info::*;
