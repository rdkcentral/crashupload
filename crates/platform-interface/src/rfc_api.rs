//! RFC (Remote Feature Control) API integration for TR-181 parameter access.
//!
//! This module provides functions to get and set TR-181 parameters using the `tr181` binary.
//! It is used for interacting with device configuration at runtime.

use std::path::Path;
use std::process::Command;

/// Path to the TR-181 binary used for RFC parameter access.
const TR181_BIN: &str = "tr181";
// const TR181_SET_BIN: &str = "tr181Set"; // TODO: Implement if needed

/// Returns the path to the TR-181 binary as a `Path`.
#[inline]
fn rfc_bin_path() -> &'static Path {
    Path::new(TR181_BIN)
}

/// Sets a TR-181 RFC parameter to a specified value.
///
/// This function invokes the `tr181` binary with the `-s` (set) and `-v` (value) flags
/// to set the given RFC parameter to the provided value.
///
/// # Arguments
/// * `rfc` - The TR-181 parameter name.
/// * `value` - The value to set for the parameter.
///
/// # Returns
/// * `true` if the parameter was successfully set, `false` otherwise.
///
/// # Example
/// ```
/// use platform_interface::rfc_api::set_rfc_param;
/// let success = set_rfc_param("Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.Foo.Enable", "true");
/// ```
pub fn set_rfc_param<R: AsRef<str>, V: AsRef<str>>(rfc: R, value: V) -> bool {
    let rfc_bin = rfc_bin_path();
    if rfc_bin.exists() {
        match Command::new(rfc_bin)
            .arg("-s")
            .arg("-v")
            .arg(value.as_ref())
            .arg(rfc.as_ref())
            .spawn()
        {
            Ok(_) => true,
            Err(err) => {
                println!("{} set failed with {}", rfc_bin.display(), err);
                false
            }
        }
    } else {
        false
    }
}

/// Gets a TR-181 RFC parameter value into a mutable string.
///
/// This function invokes the `tr181` binary with the `-g` (get) flag to retrieve
/// the value of the given RFC parameter and stores it in the provided mutable string reference.
///
/// # Arguments
/// * `rfc` - The TR-181 parameter name.
/// * `res` - Mutable reference to a string to store the retrieved value.
///
/// # Returns
/// * `true` if the parameter was successfully retrieved, `false` otherwise.
///
/// # Example
/// ```
/// use platform_interface::rfc_api::get_rfc_param;
/// let mut value = String::new();
/// if get_rfc_param("Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.Foo.Enable", &mut value) {
///     println!("RFC value: {}", value);
/// }
/// ```
pub fn get_rfc_param<R: AsRef<str>>(rfc: R, res: &mut String) -> bool {
    let rfc_bin = rfc_bin_path();
    if rfc_bin.exists() {
        match Command::new(rfc_bin).arg("-g").arg(rfc.as_ref()).output() {
            Ok(output) => {
                if output.status.success() {
                    // Convert command output to string and update res
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    *res = output_str.trim().to_string(); // Update the mutable reference
                    true
                } else {
                    false
                }
            }
            Err(err) => {
                println!("{} get failed with {}", TR181_BIN, err);
                false
            }
        }
    } else {
        false
    }
}


pub fn dmcli_get(param: &str, result: &mut String) {
    let output = Command::new("dmcli")
        .args(["eRT", "getv", param])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Faithfully mimic: grep string | cut -d":" -f3- | cut -d" " -f2- | tr -d ' '
            for line in stdout.lines() {
                if line.contains("string") {
                    // Split by ':' and get the 3rd field onward
                    let after_colon = line.splitn(4, ':').nth(3).unwrap_or("").trim();
                    // Split by space and get the 2nd field onward
                    let after_space = after_colon.splitn(2, ' ').nth(1).unwrap_or("").trim();
                    // Remove all spaces
                    let cleaned = after_space.replace(' ', "");
                    *result = cleaned;
                    return;
                }
            }
        } else {
            eprintln!("dmcli_get: dmcli command failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    } else {
        eprintln!("dmcli_get: failed to execute dmcli command");
    }
}
