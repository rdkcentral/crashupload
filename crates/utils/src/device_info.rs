//! Device information utilities.
//!
//! This module provides functions to retrieve device properties such as the MAC address,
//! version file SHA1, and arbitrary property values from property files. These utilities
//! are essential for device identification and configuration in the crash upload system.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::Command;

/// Path to the file containing the device MAC address.
/// This file is expected to contain the device's MAC address in colon-separated format.
pub const DEVICE_MAC_FILE: &str = "/tmp/.macAddress";

/// Path to the file containing the image version.
/// This file contains version information for the device firmware/software.
pub const VERSION_FILE: &str = "/version.txt";

/// Retrieves the value for a given key from a property file.
///
/// Property files are expected to contain key-value pairs in the format `KEY=VALUE`.
/// This function searches for the specified key and returns its associated value.
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
    for line in reader.lines().map_while(Result::ok) {
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
/// This function executes the `sha1sum` command on the VERSION_FILE constant
/// and parses the output to extract the hash.
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
/// This function opens the file located at `DEVICE_MAC_FILE` ("/tmp/.macAddress"),
/// reads its contents, and processes the MAC address by removing any colons.
/// The processed MAC address is then stored in the provided string reference.
///
/// # Arguments
/// * `mac` - Mutable reference to a string where the processed MAC address will be stored.
///           The function will clear any existing content in this string.
///
/// # Returns
/// * `Ok(())` if the MAC address was successfully read and processed
/// * `Err(io::Error)` if the file cannot be opened or read
///
/// # Example
/// ```
/// use utils::device_info::get_device_mac;
/// 
/// let mut mac = String::new();
/// match get_device_mac(&mut mac) {
///     Ok(()) => println!("Device MAC: {}", mac),
///     Err(e) => eprintln!("Failed to get MAC address: {}", e),
/// }
/// ```
///
/// # Note
/// The function removes all colons from the MAC address, converting a format
/// like "00:11:22:33:44:55" to "001122334455".
pub fn get_device_mac(mac: &mut String) -> io::Result<()> {
    let mut mac_val = String::new();
    let mut file = File::open(DEVICE_MAC_FILE)?;

    file.read_to_string(&mut mac_val)?;

    *mac = mac_val.trim().replace(":", "");
    Ok(())
}
