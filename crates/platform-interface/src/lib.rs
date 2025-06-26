//! Platform interface library.
//!
//! This crate provides APIs for interacting with platform features such as RFC (TR-181) and Telemetry2 (T2).
//! It serves as an abstraction layer between the application and underlying platform-specific mechanisms.
//!
//! ## Modules
//!
//! - [`rfc_api`]: Functions for interacting with TR-181 parameters through Remote Feature Control (RFC)
//!   Used for reading and writing device configuration values at runtime.
//!
//! - [`t2_api`]: Functions for sending telemetry markers to the Telemetry2 system
//!   Used for reporting events and metrics to the telemetry collection service.
//!
//! ## Usage
//!
//! This library re-exports all functions from its modules at the crate root for convenience.
//! This allows for simpler imports like `use platform_interface::set_rfc_param` instead of
//! `use platform_interface::rfc_api::set_rfc_param`.
pub mod rfc_api;
pub mod t2_api;

/// Platform interface library version.
pub const PLATFORM_LIB_VER: &str = "v1.0";

// Re-export RFC API functions for external use.
pub use rfc_api::*;

// Re-export T2 API functions for external use.
pub use t2_api::*;
