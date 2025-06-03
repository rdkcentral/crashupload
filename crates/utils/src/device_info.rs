//! Device information utilities.
//!
//! This module provides functions to retrieve device properties such as the MAC address,
//! version file SHA1, and arbitrary property values from property files.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::Command;

/// Path to the file containing the device MAC address.
pub const DEVICE_MAC_FILE: &str = "/tmp/.macAddress";

/// Path to the file containing the image version.
pub const VERSION_FILE: &str = "/version.txt";

/// Retrieves the value for a given key from a property file.
///
/// # Arguments
/// * `path` - Path to the property file.
/// * `key` - The property key to search for.
/// * `val` - Mutable reference to a string to store the value if found.
///
/// # Returns
/// * `true` if the key is found and value is non-empty, `false` otherwise.
///
/// # Example
/// ```
/// let mut value = String::new();
/// let found = get_property_value_from_file("/opt/device.properties", "MODEL_NUM", &mut value);
/// if found {
///     println!("Model number: {}", value);
/// }
/// ```
pub fn get_property_value_from_file<P: AsRef<Path>, K: AsRef<str>>(path: P, key: K, val: &mut String) -> bool {
    let key = key.as_ref().trim();
    *val = String::new();
    let prop_file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let reader = BufReader::new(prop_file);
    for line in reader.lines().flatten() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let value = v.trim();
                if !value.is_empty() {
                    val.push_str(value);
                    return true;
                } else {
                    return false;
                }
            }
        }
    }
    false
}

/// Calculates the SHA1 hash of the version file and stores it in `sha1_val`.
///
/// # Arguments
/// * `sha1_val` - Mutable reference to a string to store the SHA1 hash.
///
/// # Returns
/// * `true` if the SHA1 hash was successfully calculated, `false` otherwise.
///
/// # Example
/// ```
/// let mut sha1 = String::new();
/// if get_sha1_value(&mut sha1) {
///     println!("SHA1: {}", sha1);
/// }
/// ```
pub fn get_sha1_value(sha1_val: &mut String) -> bool {
    let output = match Command::new("sha1sum").arg(VERSION_FILE).output() {
        Ok(output) => output,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha1_hash = stdout.split_whitespace().next().unwrap_or("").to_string();
    *sha1_val = sha1_hash;
    true
}

/// Reads the device MAC address from the device MAC file and stores it in `mac`.
///
/// # Arguments
/// * `mac` - Mutable reference to a string to store the MAC address (colons removed).
///
/// # Returns
/// * `Ok(())` if the MAC address was successfully read, or an `io::Error` otherwise.
///
/// # Example
/// ```
/// let mut mac = String::new();
/// if get_device_mac(&mut mac).is_ok() {
///     println!("MAC: {}", mac);
/// }
/// ```
pub fn get_device_mac(mac: &mut String) -> io::Result<()> {
    let mut mac_val = String::new();
    let mut file = File::open(DEVICE_MAC_FILE)?;

    file.read_to_string(&mut mac_val)?;

    *mac = mac_val.trim().replace(":", "");
    Ok(())
}
