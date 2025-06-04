//! Telemetry2 (T2) API integration for sending telemetry markers to the platform.
//!
//! This module provides functions to notify T2 markers with count or value semantics
//! by invoking the `telemetry2_0_client` binary if present on the system.

use std::path::Path;
use std::process::Command;

/// Path to the Telemetry2 client binary.
const T2_MSG_CLIENT_PATH: &str = "/usr/bin/telemetry2_0_client";

/// Returns the path to the Telemetry2 client as a `Path`.
#[inline]
fn t2_msg_client_path() -> &'static Path {
    Path::new(T2_MSG_CLIENT_PATH)
}

/// Notify a telemetry marker with a count value.
///
/// This function invokes the T2 client with the given marker and count.
/// If `count` is `None`, a default value of `"1"` is used.
///
/// # Arguments
/// * `marker` - The telemetry marker name.
/// * `count` - Optional count value as a string (defaults to `"1"`).
///
/// # Returns
/// * `true` if the notification was successfully sent, `false` otherwise.
///
/// # Example
/// ```
/// use platform_interface::t2_api::t2_count_notify;
/// t2_count_notify("SYST_INFO_minidumpUpld", None);
/// ```
pub fn t2_count_notify<M: AsRef<str>, C: AsRef<str>>(marker: M, count: Option<C>) -> bool {
    let t2_client = t2_msg_client_path();
    if t2_client.exists() {
        let count_val = count.as_ref().map(|c| c.as_ref()).unwrap_or("1");
        match Command::new(t2_client)
            .arg(marker.as_ref())
            .arg(count_val)
            .spawn()
        {
            Ok(_) => true,
            Err(err) => {
                println!("{} execution failed with {}", t2_client.display(), err);
                false
            }
        }
    } else {
        false
    }
}

/// Notify a telemetry marker with one or more values (comma-separated).
///
/// # Arguments
/// * `marker` - The telemetry marker name.
/// * `values` - The values to associate with the marker (comma-separated).
///
/// # Returns
/// * `true` if the notification was successfully sent, `false` otherwise.
pub fn t2_val_notify<M: AsRef<str>>(marker: M, values: &[&str]) -> bool {
    let t2_client = t2_msg_client_path();
    if t2_client.exists() {
        let joined = values.join(", ");
        match Command::new(t2_client)
            .arg(marker.as_ref())
            .arg(&joined)
            .spawn()
        {
            Ok(_) => true,
            Err(err) => {
                println!("{} execution failed with {}", t2_client.display(), err);
                false
            }
        }
    } else {
        false
    }
}
