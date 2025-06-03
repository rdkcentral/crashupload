//! Platform interface library.
//!
//! This crate provides APIs for interacting with platform features such as RFC (TR-181) and Telemetry2 (T2).
//! It exposes convenient functions for RFC parameter access and telemetry marker notification.

mod rfc_api;
mod t2_api;

/// Platform interface library version.
pub const PLATFORM_LIB_VER: &str = "v1.0";

// Re-export RFC API functions for external use.
pub use rfc_api::{get_rfc_param, set_rfc_param};

// Re-export T2 API functions for external use.
pub use t2_api::{t2_count_notify, t2_val_notify};
