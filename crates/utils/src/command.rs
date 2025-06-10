//! File operation helpers.
//!
//! This module provides utility functions for common file operations such as
//! creating files (touch), removing files, and recursively removing directories.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::Command;

use crate::get_property_value_from_file;

/// Creates a file if it does not exist, or updates its modification time if it does (like Unix `touch`).
///
/// # Arguments
/// * `path` - Path to the file to touch.
///
/// # Example
/// ```
/// use utils::touch;
/// touch("/tmp/somefile");
/// ```
pub fn touch<P: AsRef<Path>>(path: P) {
    let _ = OpenOptions::new().create(true).truncate(true).write(true).open(path);
}

/// Recursively removes a directory and its contents, or removes a file if the path is not a directory.
/// Ignores errors if the path does not exist.
///
/// # Arguments
/// * `path` - Path to the directory or file to remove.
///
/// # Example
/// ```
/// use utils::rm_rf;
/// rm_rf("/tmp/somedir");
/// rm_rf("/tmp/somefile");
/// ```
pub fn rm_rf<P: AsRef<Path>>(path: P) {
    let path_ref = path.as_ref();
    let _ = if path_ref.is_dir() {
        fs::remove_dir_all(path_ref)
    } else {
        let _ = fs::remove_file(path);
        Ok(())
    };
}

/// Flushes system logs, mimicking the flushLogger shell function.
///
/// - Logs a message using println!().
/// - Flushes journald buffers if available.
/// - Calls dumpLogs.sh if SYSLOG_NG_ENABLED is not true in device.properties.
pub fn flush_logger() {
    println!("flush_logger is called");

    // Flush journald if available
    if Path::new("/etc/os-release").exists() && Command::new("which").arg("journalctl").output().is_ok() {
        let _ = Command::new("journalctl").args(["--sync", "--flush"]).status();
    }

    // Check SYSLOG_NG_ENABLED from device.properties
    let mut syslog_ng_enabled = String::new();
    let _ = get_property_value_from_file("/etc/device.properties", "SYSLOG_NG_ENABLED", &mut syslog_ng_enabled);
    if syslog_ng_enabled.trim() != "true" {
        let _ = Command::new("nice")
            .args(["-n", "19", "/lib/rdk/dumpLogs.sh"])
            .status();
    }
}
