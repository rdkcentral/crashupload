//! Crash upload utility functions and implementation.
//!
//! This module provides the core functionality for the crash upload system, including:
//!
//! - **Dump file detection and processing**: Functions to identify, sanitize, and process
//!   various types of crash dumps (minidumps and coredumps)
//!
//! - **Tarball creation and management**: Utilities to compress dump files with relevant
//!   logs into tarballs for upload
//!
//! - **Upload control and rate limiting**: Functions to manage upload rates, recovery time,
//!   and crash loop detection
//!
//! - **Security and privacy controls**: Implementation of secure dump handling and privacy
//!   mode checks
//!
//! - **Lock management**: Mutex-like functionality to prevent concurrent execution of
//!   critical sections
//!
//! - **File and path utilities**: Specialized functions for file manipulation, path handling,
//!   and directory management
//!
//! - **Telemetry integration**: Functions to report crash events and upload status to the
//!   Telemetry2 (T2) system
//!
//! ## Key Workflows
//!
//! The main workflow in this module is the dump processing pipeline:
//! 1. Detecting crash dumps in configured directories
//! 2. Sanitizing file names and paths
//! 3. Collecting relevant log files and device information
//! 4. Creating compressed archives (tarballs) containing dumps and logs
//! 5. Uploading archives to cloud storage (S3) with retries
//! 6. Managing cleanup and retention of local dumps
//!
//! ## Integration Points
//!
//! This module integrates with several platform components:
//! - **TR-181/RFC system** (via platform-interface): For configuration parameters
//! - **Telemetry2 (T2)**: For reporting crash and upload events
//! - **S3 storage**: For uploading crash dumps to the cloud
//! - **Device property system**: For obtaining device metadata
//!
//! Most functions in this module are designed to be self-contained and follow
//! the single responsibility principle for maintainability.

// crashupload/src/crashupload_utils.rs
use chrono::{DateTime, Local};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::process;
use std::{thread, time};

use crate::constants::*;
use platform_interface::*;
use utils::*;

/// Determines if a file is a minidump based on its name.
///
/// Checks if the filename contains the substring ".dmp" anywhere in the string,
/// which matches the shell pattern "*.dmp*".
///
/// # Arguments
/// * `name` - The filename to check.
///
/// # Returns
/// * `true` if the filename contains ".dmp", `false` otherwise.
#[inline]
fn is_minidump_file(name: &str) -> bool {
    // *.dmp* matches any file with ".dmp" after the first character
    name.find(".dmp").is_some()
}

/// Determines if a file is a core pattern file based on its name.
///
/// A file is considered a core pattern file if it contains "_core" followed by
/// a dot somewhere after the "_core" substring. This matches the shell pattern
/// "*_core*.*".
///
/// # Arguments
/// * `name` - The filename to check.
///
/// # Returns
/// * `true` if the filename matches the core pattern format, `false` otherwise.
pub fn is_core_pattern_file(name: &str) -> bool {
    if let Some(core_idx) = name.find("_core") {
        // There must be a '.' after the '_core'
        let after_core = &name[core_idx + 5..]; // 5 = len("_core")
        after_core.contains('.')
    } else {
        false
    }
}

/// Checks if a directory is empty or cannot be read.
///
/// This function tries to read the directory entries. If the directory cannot be read
/// (due to permissions or other issues), it's treated as if it were empty.
///
/// # Arguments
/// * `dir` - Path to the directory to check.
///
/// # Returns
/// * `true` if the directory is empty or unreadable, `false` otherwise.
pub fn is_dir_empty_or_unreadable<P: AsRef<Path>>(dir: P) -> bool {
    match fs::read_dir(dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => true, // treat unreadable as empty
    }
}

/// Safely renames a file, with fallback to copy-and-delete if rename fails with EXDEV error.
///
/// This function attempts to rename a file from `src` to `dst`. If the rename fails with
/// error code 18 (EXDEV, "Cross-device link"), it falls back to copying the file and then
/// deleting the original. This handles cases where the source and destination are on
/// different filesystems.
///
/// # Arguments
/// * `src` - Source path.
/// * `dst` - Destination path. If relative, it's resolved relative to `src`'s parent.
///
/// # Returns
/// * `Ok(())` on success, or an error if both rename and copy-delete fail.
pub fn safe_rename<S: AsRef<Path>, D: AsRef<Path>>(src: S, dst: D) -> io::Result<()> {
    let src_path = src.as_ref();
    let dst_path = {
        let dst_ref = dst.as_ref();
        if dst_ref.is_absolute() {
            dst_ref.to_path_buf()
        } else {
            src_path.parent().unwrap_or_else(|| Path::new("")).join(dst_ref)
        }
    };
    match fs::rename(&src_path, &dst_path) {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            fs::copy(&src_path, &dst_path)?;
            fs::remove_file(&src_path)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Extracts the basename (filename) from a path.
///
/// This function extracts just the filename portion from a path. If the path doesn't
/// have a valid filename component, returns the entire path as a string.
///
/// # Arguments
/// * `path` - Path to extract the basename from.
///
/// # Returns
/// * A `String` containing the basename (filename without directory components).
#[inline]
pub fn basename<P: AsRef<Path>>(path: P) -> String {
    path.as_ref()
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.as_ref().to_string_lossy().to_string())
}

/// Ensures the core log file exists, creating it with appropriate permissions if needed.
///
/// This function checks if the core log file exists at the path defined by `CORE_LOG`.
/// If not, it creates the file with 0666 permissions (readable and writable by everyone).
/// It then uses `touch` to update the file's timestamp regardless.
///
/// # Side Effects
/// - May create a new file at `CORE_LOG` path.
/// - Updates the file's timestamp.
fn ensure_core_log_exists() {
    if !Path::new(CORE_LOG).exists() {
        if let Ok(f) = OpenOptions::new().create(true).write(true).open(CORE_LOG) {
            let _ = f.set_permissions(fs::Permissions::from_mode(0o666));
        }
    }
    let _ = Command::new("touch").arg(CORE_LOG).status();
}

#[cfg(not(feature = "shared_api"))]
/// Writes parameters for S3 upload to a parameter file for shell script consumption.
///
/// Creates a space-separated parameter string with all necessary arguments for the S3 upload
/// process and writes it to the file specified by `S3_UPLOAD_PARAM_FILE`. Used when the
/// `shared_api` feature is not enabled.
///
/// # Arguments
/// * `dump_paths` - Reference to crash dump path configuration.
/// * `device_data` - Reference to device metadata.
/// * `partner_id` - Partner identifier string.
/// * `enable_ocsp_stapling` - OCSP stapling configuration flag.
/// * `enable_ocsp` - OCSP configuration flag.
/// * `curl_log_option` - Curl logging option string.
///
/// # Returns
/// * `Ok(())` on success, or an error if file write fails.
fn write_uploadtos3params(
    dump_paths: &DumpPaths,
    device_data: &DeviceData,
    partner_id: &str,
    enable_ocsp_stapling: &str,
    enable_ocsp: &str,
    curl_log_option: &str,
) -> std::io::Result<()> {
    let params = format!(
        "{} {} {} {} {} {} {} {} {} {} {} {}",
        dump_paths.get_working_dir(),
        partner_id,
        dump_paths.get_dump_name(),
        device_data.get_device_type(),
        VERSION_FILE,
        if device_data.get_is_encryption_enabled() { "true" } else { "false" },
        enable_ocsp_stapling,
        enable_ocsp,
        device_data.get_is_tls_enabled(),
        device_data.get_build_type(),
        device_data.get_model_num(),
        curl_log_option
    );
    std::fs::write(S3_UPLOAD_PARAM_FILE, params)
}

/// Populates a [`DeviceData`] struct with device properties from system files and TR-181.
/// 
/// This function reads various device properties from multiple sources:
/// - Device properties file (box type, model number, device type, build type)
/// - Version file (SHA1 value)
/// - Network configuration (MAC address)
/// - System files (T2 enablement, TLS configuration, encryption settings)
/// - TR-181 parameters (portal URL)
///
/// The collected information is essential for crash upload identification, processing, and routing.
///
/// # Arguments
/// * `device_data` - Mutable reference to a [`DeviceData`] struct to populate.
///
/// # Side Effects
/// - Reads from filesystem and TR-181 parameters
/// - May set RFC parameters if encryption is enabled
/// - No files are modified
pub fn set_device_data(device_data: &mut DeviceData) {
    // Populate from device.properties
    let mut box_type = String::new();
    let mut model_num = String::new();
    let mut device_type = String::new();
    let mut build_type = String::new();
    get_property_value_from_file(DEVICE_PROP_FILE, "BOX_TYPE", &mut box_type);
    get_property_value_from_file(DEVICE_PROP_FILE, "MODEL_NUM", &mut model_num);
    get_property_value_from_file(DEVICE_PROP_FILE, "DEVICE_TYPE", &mut device_type);
    get_property_value_from_file(DEVICE_PROP_FILE, "BUILD_TYPE", &mut build_type);
    device_data.set_box_type(box_type);
    device_data.set_model_num(model_num);
    device_data.set_device_type(device_type);
    device_data.set_build_type(build_type);

    // SHA1 from version.txt
    let mut sha1 = String::new();
    get_sha1_value(&mut sha1);
    device_data.set_sha1(sha1);

    // MAC address
    let mut mac_addr = String::new();
    let _ = get_device_mac(&mut mac_addr);
    device_data.set_mac_addr(mac_addr);

    // T2 enabled if script exists
    device_data.set_t2_enabled(Path::new(T2_SHARED_SCRIPT).exists()); // TODO: Check T2 Binary instead of script?

    // TLS flag for Yocto
    let tls = if Path::new("/etc/os-release").exists() { "--tlsv1.2" } else { "" };
    device_data.set_tls(tls);

    // Encryption enabled if file exists, and set RFC param
    let encryption_enabled = if Path::new("/etc/os-release").exists() {
        if set_rfc_param(ENCRYPTION_RFC, "true") { true }
        else { false }
    } else {
        false
    };
    device_data.set_encryption_enabled(encryption_enabled);

    // Portal URL from TR-181
    let mut portal_url = String::new();
    get_rfc_param(CRASH_PORTAL_URL_RFC, &mut portal_url);
    device_data.set_portal_url(portal_url);
}

/// Checks if any crash dump files exist in the specified directories.
///
/// This function examines two types of dumps in their respective directories:
/// - Minidumps: Files containing ".dmp" in their name in the minidumps directory
/// - Core dumps: Files matching the "*_core*.*" pattern in the core dump directory
///
/// # Arguments
/// * `minidumps_path` - Directory path to search for minidump files
/// * `core_path` - Directory path to search for core dump files
///
/// # Returns
/// * `true` if at least one dump file (of either type) exists, `false` otherwise
pub fn check_dumps_exist(minidumps_path: &str, core_path: &str) -> bool {
    let minidumps_dir = std::path::Path::new(minidumps_path);
    let core_dir = std::path::Path::new(core_path);

    let minidump_exists = minidumps_dir.is_dir() && std::fs::read_dir(minidumps_dir)
        .map(|iter| iter.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Faithful to *.dmp* shell pattern
            is_minidump_file(&name)
        }))
        .unwrap_or(false);

    let core_exists = core_dir.is_dir() && std::fs::read_dir(core_dir)
        .map(|iter| iter.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Faithful to *_core*.* shell pattern
            is_core_pattern_file(&name)
        }))
        .unwrap_or(false);

    minidump_exists || core_exists
}

/// Configures secure or non-secure dump paths based on SecureDump enablement status.
///
/// This function determines if SecureDump is enabled by checking flag files and TR-181 parameters,
/// then updates the dump paths accordingly:
/// - When enabled: Uses paths under /opt/secure/
/// - When disabled: Uses standard paths under /opt/ and /var/
///
/// It also manages the appropriate flag files to maintain the system's secure dump state.
///
/// # Arguments
/// * `dump_paths` - Mutable reference to a [`DumpPaths`] struct to update with appropriate paths
///
/// # Side Effects
/// - Creates or removes SecureDump enable/disable flag files
/// - Updates all path settings in the provided `dump_paths` struct
/// - Logs the SecureDump status
pub fn get_secure_dump_status(dump_paths: &mut DumpPaths) {
    println!("get_secure_dump_status: Checking SecureDump status...");
    let mut is_sec_dump_enabled = false;
    set_secure_dump_flag(&mut is_sec_dump_enabled);

    if !is_sec_dump_enabled {
        if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            touch(SECUREDUMP_DISABLE_FILE);
            println!("get_secure_dump_status: Disabled");
        }
        if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            let _ = fs::remove_file(SECUREDUMP_ENABLE_FILE);
        }
        dump_paths.set_core_path("/var/lib/systemd/coredump");
        dump_paths.set_minidumps_path("/opt/minidumps");
        dump_paths.set_core_back_path("/opt/corefiles_back");
        dump_paths.set_persistent_sec_path("/opt");
        println!("get_secure_dump_status: Dump location changed /opt.");
    } else {
        if !Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            touch(SECUREDUMP_ENABLE_FILE);
            println!("get_secure_dump_status: Enabled");
        }
        if Path::new(SECUREDUMP_DISABLE_FILE).exists() {
            let _ = fs::remove_file(SECUREDUMP_DISABLE_FILE);
        }
        dump_paths.set_core_path("/opt/secure/corefiles");
        dump_paths.set_minidumps_path("/opt/secure/minidumps");
        dump_paths.set_core_back_path("/opt/secure/corefiles_back");
        dump_paths.set_persistent_sec_path("/opt/secure");
        println!("get_secure_dump_status: Dump location changed /opt/secure.");
    }
}

/// Determines if SecureDump is enabled by checking flag files or TR-181 parameters.
///
/// This function implements a priority-based check for SecureDump enablement:
/// 1. If SECUREDUMP_ENABLE_FILE exists, SecureDump is enabled
/// 2. If SECUREDUMP_DISABLE_FILE exists, SecureDump is disabled
/// 3. Otherwise, check the TR-181 parameter for the setting
///
/// # Arguments
/// * `is_sec_dump_enabled` - Mutable reference to a boolean to set based on the determination
///
/// # Side Effects
/// - Reads from the filesystem and possibly TR-181 configuration
/// - Modifies the passed boolean reference
fn set_secure_dump_flag(is_sec_dump_enabled: &mut bool) {
    if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
        *is_sec_dump_enabled = true;
    } else if Path::new(SECUREDUMP_DISABLE_FILE).exists() {
        *is_sec_dump_enabled = false;
    } else {
        let mut rfc_value = String::new();
        if get_rfc_param(SECUREDUMP_TR181_NAME, &mut rfc_value) {
            *is_sec_dump_enabled = rfc_value.trim().eq_ignore_ascii_case("true");
        }
    }
}

/// Creates a standard lock directory path for a given resource path.
///
/// This function converts any path into a corresponding lock directory path
/// by changing its extension to ".lock.d". This lock directory is used
/// to implement a filesystem-based mutex mechanism.
///
/// # Arguments
/// * `path` - Path to be locked (can be any file or directory path)
///
/// # Returns
/// * `PathBuf` representing the derived lock directory path
#[inline]
fn lock_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut p = path.as_ref().to_path_buf();
    p.set_extension("lock.d");
    p
}

/// Checks if another process instance is running by testing for an existing lock directory.
///
/// This function is used to implement mutual exclusion between process instances.
/// It determines if another instance is running by checking for the existence of
/// a lock directory associated with the given path.
///
/// # Arguments
/// * `path` - Path to check for an existing lock
/// # Returns
/// * `true` if a lock directory exists (another instance is running), `false` otherwise
#[inline]
fn is_another_instance_running<P: AsRef<Path>>(path: P) -> bool {
    lock_path(path).is_dir()
}

/// Creates a lock directory or exits the process if already locked.
///
/// This function implements an "exit on contention" locking strategy:
/// - If another instance is running (lock exists), it logs a message, 
///   potentially sends a T2 notification, and exits the process
/// - Otherwise, it creates the lock directory and returns true on success
///
/// # Arguments
/// * `path` - Path to lock
/// * `is_t2_enabled` - Whether T2 telemetry is enabled (for sending notifications)
///
/// # Returns
/// * `true` if lock was created successfully
/// * `false` if lock creation failed due to filesystem errors
///
/// # Side Effects
/// - May exit the process if lock already exists
/// - May send T2 telemetry notification if enabled
/// - Creates a lock directory on the filesystem if successful
pub fn create_lock_or_exit<P: AsRef<Path>>(path: P, is_t2_enabled: bool) -> bool {
    let lock = lock_path(&path);
    if is_another_instance_running(&path) {
        if is_t2_enabled {
            t2_count_notify("SYST_WARN_NoMinidump", Some("1"));
        }
        println!("create_lock_or_exit: crash-upload is already running. {:?}. Skip launching another instance...", lock);
        // TODO: add wait
        process::exit(0);
    }

    match fs::create_dir(&lock) {
        Ok(_) => true,
        Err(err) => {
            println!("create_lock_or_exit: Error creating {:?}: {}", lock, err);
            false
        }
    }
}

/// Creates a lock directory, waiting and retrying if already locked.
///
/// This function implements a "wait on contention" locking strategy:
/// - If another instance is running (lock exists), it waits and retries every 2 seconds
/// - It continues retrying indefinitely until either the lock is acquired or creation fails
///
/// # Arguments
/// * `path` - Path to lock
///
/// # Returns
/// * `true` if lock was created successfully
/// * `false` if lock creation failed due to filesystem errors
///
/// # Side Effects
/// - May block thread execution while waiting for lock
/// - Creates a lock directory on the filesystem if successful
pub fn create_lock_or_wait<P: AsRef<Path>>(path: P) -> bool {
    let lock = lock_path(&path);
    loop {
        if is_another_instance_running(&path) {
            println!("create_lock_or_wait: crash-upload is already running. {:?}. Waiting to launch another instance...", lock);
            thread::sleep(time::Duration::from_secs(2));
            continue;
        }

        match fs::create_dir(&lock) {
            Ok(_) => return true,
            Err(err) => {
                println!("create_lock_or_wait: Error creating {:?}: {}", lock, err);
                return false;
            }
        }
    }
}

/// Removes a lock directory for the given resource path.
///
/// This function cleans up the lock directory created by `create_lock_or_exit` or
/// `create_lock_or_wait`, effectively releasing the lock. It silently handles the
/// case where the lock directory doesn't exist.
///
/// # Arguments
/// * `path` - Path whose associated lock should be removed
///
/// # Side Effects
/// - Deletes the lock directory from the filesystem if it exists
/// - Logs any errors that occur during removal
pub fn remove_lock<P: AsRef<Path>>(path: P) {
    let lock = lock_path(&path);
    if lock.is_dir() {
        if let Err(err) = fs::remove_dir(&lock) {
            println!("remove_lock: Error deleting {:?}: {}", lock, err);
        }
    }
}

/// Generates a standardized log file name for a crash, or returns the original if already processed.
///
/// If the file name already contains any of the tags `_mac`, `_dat`, `_box`, or `_mod`,
/// it is considered already processed and returned as-is. Otherwise, constructs a new
/// file name using device metadata and the original file name.
///
/// # Arguments
/// * `device_data` - Reference to the device metadata.
/// * `log_mod_ts` - Last modified timestamp string.
/// * `line` - The original file path or name.
///
/// # Returns
/// * A `String` with the new or original file name.
pub fn set_log_file(device_data: &DeviceData, log_mod_ts: &str, line: &str) -> String {
    let file_name = line.split('/').next_back().unwrap_or(line);
    if file_name.contains("_mac")
        || file_name.contains("_dat")
        || file_name.contains("_box")
        || file_name.contains("_mod")
    {
        println!("set_log_file: Core name is already processed: {}", file_name);
        return String::from(file_name);
    }
    format!(
        "{}_mac{}_dat{}_box{}_mod{}_{}",
        device_data.sha1,
        device_data.mac_addr,
        log_mod_ts,
        device_data.box_type,
        device_data.model_num,
        file_name
    )
}

/// Checks if the box is currently rebooting by looking for the reboot flag file.
///
/// If the reboot flag exists, logs a message, sends a T2 notification, and returns `true`.
/// Otherwise, returns `false`.
///
/// # Arguments
/// * `is_t2_enabled` - Whether T2 telemetry is enabled (for sending notifications)
///
/// # Returns
/// * `true` if the box is rebooting (flag file exists), `false` otherwise.
/// # Side Effects
/// - May send T2 telemetry notification if enabled
pub fn is_box_rebooting(is_t2_enabled: bool) -> bool {
    if Path::new(CRASH_UPLOAD_REBOOT_FLAG).exists() {
        println!("is_box_rebooting: Skipping Upload, Since the box is rebooting now...");
        if is_t2_enabled {
            t2_count_notify("SYST_INFO_CoreUpldSkipped", Some("1"));
        }
        println!("is_box_rebooting: Upload will happen on next reboot");
        // TODO: Add wait
        return true;
    }
    false
}

/// Sanitizes a string by removing all characters except a safe set.
///
/// Only allows alphanumeric characters and the following: `/ :+._,=-`
/// This matches the shell's `sed` logic for cleaning file/process names.
///
/// # Arguments
/// * `input` - The input string to sanitize.
///
/// # Returns
/// * A sanitized `String` containing only allowed characters.
pub fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|c| matches!(
            c,
            'a'..='z'
                | 'A'..='Z'
                | '0'..='9'
                | '/'
                | ' '
                | ':'
                | '+'
                | '.'
                | '_'
                | ','
                | '='
                | '-'
        ))
        .collect()
}

/// Checks if the recovery time (upload denial window) has been reached or expired.
///
/// Reads the timestamp from the deny upload file. If the file does not exist or contains
/// invalid data, returns `true` (uploads allowed). If the current time is greater than the
/// stored timestamp, returns `true` (uploads allowed). Otherwise, returns `false`.
///
/// # Returns
/// * `true` if uploads are allowed, `false` if still in the denial window.
///
/// # Side Effects
/// - Reads from the deny upload file on the filesystem
pub fn is_recovery_time_reached() -> bool {
    let path = Path::new(DENY_UPLOAD_FILE);
    if !path.exists() {
        return true;
    }
    let content = match fs::read_to_string(path) {
        Ok(val) => val.trim().to_string(),
        Err(_) => return true,
    };
    let upload_denied_till = match content.parse::<u64>() {
        Ok(val) => val,
        Err(_) => return true,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > upload_denied_till
}

/// Sets the recovery time (upload denial window) to now + 10 minutes.
///
/// Writes the future timestamp to the deny upload file. This prevents further uploads
/// until the specified time has passed.
///
/// # Side Effects
/// - Overwrites the deny upload file with the new timestamp.
pub fn set_recovery_time() {
    const DONT_UPLOAD_FOR_SEC: u64 = 600;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH")
        .as_secs();
    let recovery_time = now + DONT_UPLOAD_FOR_SEC;
    let _ = fs::write(DENY_UPLOAD_FILE, recovery_time.to_string());
}

/// Determines if the upload rate limit has been reached (10 uploads in 10 minutes).
///
/// Checks the timestamp file for the last 10 upload times. If there are fewer than 10,
/// returns `false`. If the 10th newest timestamp is less than 10 minutes ago, returns `true`.
///
/// # Arguments
/// * `ts_file` - Path to the timestamp file.
///
/// # Returns
/// * `true` if the upload rate limit is reached, `false` otherwise.
///
/// # Side Effects
/// - Acquires and releases a lock on the timestamp file
/// - Reads from the timestamp file
pub fn is_upload_limit_reached(ts_file: &str) -> bool {
    create_lock_or_wait(ts_file);

    const LIMIT_SECONDS: u64 = 600;
    let path = Path::new(ts_file);


    if OpenOptions::new().create(true).append(true).open(path).is_err() {
        println!("is_upload_limit_reached: Failed to create or open {}", ts_file);
        remove_lock(ts_file);
        return false;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            remove_lock(ts_file);
            return false;
        }
    };
    let reader = BufReader::new(&file);

    // Collect upto 10 timestamps (oldest first)
    let lines: Vec<u64> = reader
        .lines()
        .filter_map(|line| line.ok()?.split_whitespace().next()?.parse().ok())
        .collect();

    if lines.len() < 10 {
        remove_lock(ts_file);
        return false;
    }

    let tenth_newest_crash_time = lines[0];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH")
        .as_secs();

    let limit_reached = now.saturating_sub(tenth_newest_crash_time) < LIMIT_SECONDS;
    if limit_reached {
        println!("is_upload_limit_reached: Not uploading the dump. Too many dumps.");
    }
    remove_lock(ts_file);
    limit_reached
}

/// Removes the crash loop flag and all relevant lock files for the given dump paths.
///
/// This function is inlined for performance, as it is small and called from multiple places.
///
/// # Arguments
/// * `dump_paths` - Reference to the dump paths struct.
///
/// # Side Effects
/// - Deletes the crash loop flag file if it exists
/// - Removes lock directories associated with the dump paths
#[inline]
fn remove_crash_locks_and_flag(dump_paths: &DumpPaths) {
    let loop_file = Path::new(CRASH_LOOP_FLAG_FILE);
    if loop_file.exists() {
        rm_rf(loop_file);
    }
    remove_lock(dump_paths.get_lock_dir_prefix());
    remove_lock(dump_paths.get_ts_file());
}

/// Finalizes the crash upload process by cleaning up dumps, removing locks, and clearing the crash loop flag.
///
/// This function should be called on normal exit to ensure all resources are released and
/// any temporary files or locks are cleaned up. Uses only getters for `DumpPaths`.
///
/// # Arguments
/// * `dump_paths` - Reference to the dump paths struct.
///
/// # Side Effects
/// - Cleans up dump files in the working directory
/// - Removes lock files and crash loop flags
pub fn finalize(dump_paths: &DumpPaths) {
    println!("finalize: ##DEBUG## Skipping cleanup and removing crash locks and flag for debugging purposes");
    if false {
    let _ = cleanup(
        dump_paths.get_working_dir(),
        dump_paths.get_dump_name(),
        dump_paths.get_dumps_extn(),
    );
    remove_crash_locks_and_flag(dump_paths);
}
}

/// Handles cleanup on receiving a crash-related signal (SIGTERM or SIGKILL).
///
/// Logs the signal type, removes the crash loop flag, and removes all relevant locks.
/// Uses only getters for `DumpPaths`.
///
/// # Arguments
/// * `signal` - The signal type (CrashSignal::Term or CrashSignal::Kill).
/// * `dump_paths` - Reference to the dump paths struct.
///
/// # Side Effects
/// - Logs the signal type
/// - Removes crash loop flag and lock files
pub fn handle_crash_signal(signal: CrashSignal, dump_paths: &DumpPaths) {
    match signal {
        CrashSignal::Term => println!("systemd terminating, Removing the script locks"),
        CrashSignal::Kill => println!("systemd killing, Removing the script locks"),
    }
    remove_crash_locks_and_flag(dump_paths);
}

/// Determines if a dump file should be processed/uploaded based on dump type, device type, and file name.
///
/// - Always returns `true` for minidumps.
/// - For coredumps, returns `true` if not a "prod" build or if the file name does not contain "Receiver".
/// - Otherwise, logs and returns `false`.
///
/// # Arguments
/// * `dump_name` - The dump type ("coredump" or "minidump").
/// * `build_type` - The build type (e.g., "prod").
/// * `file_name` - The file name to check.
///
/// # Returns
/// * `true` if the file should be processed, `false` otherwise.
pub fn should_process_dump(dump_name: &str, build_type: &str, file_name: &str) -> bool {
    if dump_name == "minidump" || build_type != "prod" || !file_name.contains("Receiver") {
        true
    } else {
        println!("should_process_dump: Not processing dump file {}", file_name);
        false
    }
}

/// Determines if a file name matches a specified pattern.
///
/// This function implements shell-like wildcard pattern matching for specific crash-related
/// file patterns. It supports the following patterns:
/// - "*.dmp*": Files containing ".dmp" anywhere in the name
/// - "*.dmp.tgz": Files ending with ".dmp.tgz"
/// - "*core.prog*.gz*": Files containing "core.prog" followed by ".gz" somewhere later
/// - "*.core.tgz": Files ending with ".core.tgz"
///
/// # Arguments
/// * `name` - The file name to check against the pattern.
/// * `pattern` - The pattern to match against (one of the supported patterns above).
///
/// # Returns
/// * `true` if the file name matches the pattern, `false` otherwise.
fn matches_pattern(name: &str, pattern: &str) -> bool {
    match pattern {
        "*.dmp*" => name.contains(".dmp"),
        "*.dmp.tgz" => name.ends_with(".dmp.tgz"),
        "*core.prog*.gz*" => {
            if let Some(core_idx) = name.find("core.prog") {
                name[core_idx + "core.prog".len()..].contains(".gz")
            } else {
                false
            }
        },
        "*.core.tgz" => name.ends_with(".core.tgz"),
        _ => false,
    }
}

/// Counts the number of dump files in a directory matching a given pattern.
///
/// # Arguments
/// * `dir` - Directory path to search.
/// * `pattern` - Pattern to match in file names (e.g., "*.dmp*" or "*.core.tgz").
///
/// # Returns
/// * `Ok(count)` with the number of matching files, or an error if the directory can't be read.
pub fn get_file_count(dir: &str, pattern: &str) -> std::io::Result<usize> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.is_dir() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches_pattern(&name, pattern) {
            count += 1;
        }
    }
    Ok(count)
}

/// Removes pending dump files (matching extension or .tgz) from the given directory.
///
/// This function is used when the upload limit is reached, the build is blacklisted,
/// or TelemetryOptOut is set. It removes all files matching the given extension or `.tgz`.
///
/// # Arguments
/// * `path` - Directory path to search.
/// * `extn` - Extension to match (e.g., "dmp" or "core").
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail.
///
/// # Side Effects
/// - Deletes files from the filesystem that match the criteria
pub fn remove_pending_dumps(path: &str, extn: &str) -> io::Result<()> {
    println!("remove_pending_dumps: ###DEBUG### Skipping pending dumps removal for debugging purposes");
    if false {
    let dir_path = Path::new(path);
    if !dir_path.exists() || !dir_path.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.is_file() {
            let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.ends_with(extn) || file_name.ends_with(".tgz") {
                println!("remove_pending_dumps: Removing {} because upload limit has reached or build is blacklisted or TelemetryOptOut is set", basename(&file_path));
                let _ = fs::remove_file(&file_path);
            }
        }
    }
    }
    Ok(())
}

/// Processes crash telemetry info for a given dump file.
///
/// - Detects if the file is a tarball and logs accordingly.
/// - Extracts container crash info if present in the filename.
/// - Sends T2 notifications for container/app/process info.
/// - Calls `get_crashed_log_file` for further log mapping.
///
/// # Arguments
/// * `file_path` - Path to the crash dump file (as &str).
/// * `is_t2_enabled` - Whether T2 telemetry is enabled (for sending notifications)
///
/// # Side Effects
/// - May send multiple T2 telemetry notifications
/// - Logs crash information
/// - Calls `get_crashed_log_file` which may write to log files
pub fn process_crash_t2_info(file_path: &str, is_t2_enabled: bool) {
    println!("process_crash_t2_info: Processing the crash telemetry info");
    let file = Path::new(file_path);
    let mut file_name_str = file_path.to_string();
    let container_delimiter = "<#=#>";

    // Check if file is a tarball
    if file.extension().and_then(|e| e.to_str()) == Some("tgz") {
        println!("process_crash_t2_info: The File is already a tarball, this might be a retry or crash during shutdown");
        if let Some(pos) = file_name_str.find("_mod_") {
            file_name_str = file_name_str.split_off(pos + "_mod_".len());
        }
        println!("process_crash_t2_info: Original Filename: {}", basename(file));
        println!("process_crash_t2_info: Removing the meta information New Filename: {}", basename(&file_name_str));
        println!("process_crash_t2_info: This could be a retry or crash from previous boot; the appname can be truncated");
        t2_count_notify("SYS_INFO_TGZDUMP", Some("1"));
    }

    // Check for container delimiter in file name
    if file_name_str.contains(container_delimiter) {
        let parts: Vec<&str> = file_name_str.split(container_delimiter).collect();
        println!("process_crash_t2_info: From the file name crashed process is a container");

        if parts.len() >= 2 {
            let container_name = parts[0];
            let container_status = if parts.len() > 2 { parts[1] } else { "unknown" };
            let app_name = container_name.split('_').nth(1).unwrap_or(container_name);
            let process_name = container_name.split('_').next().unwrap_or(container_name);

            t2_count_notify("SYS_INFO_CrashedContainer", Some("1"));

            println!("process_crash_t2_info: Container crash info Basic: {}, {}", app_name, process_name);
            println!("process_crash_t2_info: Container crash info Advanced: {}, {}", container_name, container_status);
            println!("process_crash_t2_info: NEW Appname, Process_Crashed, Status = {}, {}, {}", app_name, process_name, container_status);

            t2_val_notify("APP_ERROR_Crashed_split", &[app_name, process_name, container_status]);
            t2_val_notify("APP_ERROR_Crashed_accum", &[app_name, process_name, container_status]);

            println!("process_crash_t2_info: NEW Processname, App Name, AppState = {}, {}, {}", process_name, app_name, container_status);
            println!("process_crash_t2_info: ContainerName, ContainerStatus = {}, {}", container_name, container_status);
            t2_val_notify("APP_ERROR_CrashInfo_accum", &[container_name, container_status]);
        }
    }
    let _ = get_crashed_log_file(&file_name_str, is_t2_enabled);

}

/// Renames a tarball to mark it as crashlooped and (optionally) uploads it to the crash portal.
///
/// # Arguments
/// * `tgz_file` - Path to the tarball file.
///
/// # Side Effects
/// - Renames the file to `.crashloop.dmp.tgz`.
/// - Logs the rename operation and any errors.
pub fn mark_as_crash_loop_and_upload(tgz_file: &str) { // portal_url: &str, crash_portal_path: &str) {
    let tgz_path = Path::new(tgz_file);
    let new_tgz_name = tgz_path.with_extension("crashloop.dmp.tgz");
    println!("mark_as_crash_loop_and_upload: Renaming {} to {}", tgz_path.display(), new_tgz_name.display());
    if let Err(e) = safe_rename(tgz_path, &new_tgz_name) {
        println!("mark_as_crash_loop_and_upload: Failed to rename crashloop tarball: {}", e);
    }
}

/// Finds the oldest file in a directory.
///
/// Scans a directory for files, sorts them by modification time, and returns the oldest one.
/// This is typically used for retention policies and cleanup of old dumps.
///
/// # Arguments
/// * `dir` - Directory path to search.
///
/// # Returns
/// * `Ok(Some(path))` with the oldest file, or `Ok(None)` if no files found or directory is empty.
/// * `Err` if there was an error reading the directory or file metadata.
pub fn find_oldest_dump(dir: &str) -> io::Result<Option<PathBuf>> {
    let mut files: Vec<_> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();

    files.sort_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).ok());
    Ok(files.into_iter().next())
}

/// Saves a dump file, renaming if needed, and ensures only the most recent 5 minidumps are kept.
///
/// This function has two main responsibilities:
/// 1. Renames the dump file to preserve container information (if `new_name` is provided)
/// 2. Enforces a retention policy by keeping only the 5 most recent dump files
///
/// # Arguments
/// * `minidumps_path` - Directory containing minidumps
/// * `s3_filename` - The current filename of the dump
/// * `new_name` - Optional new name to rename to (to retain container info)
///
/// # Side Effects
/// - May rename files in the minidumps directory
/// - May delete old dump files to maintain the retention limit
pub fn save_dump(minidumps_path: &str, s3_filename: &str, new_name: Option<&str>) {
    if let Some(new_name) = new_name {
        println!("save_dump: Saving dump with original name to retain container info: {}", basename(new_name));
        let original_path = format!("{}/{}", minidumps_path, s3_filename);
        let new_path = format!("{}/{}", minidumps_path, new_name);
        if let Err(e) = safe_rename(&original_path, &new_path) {
            println!("save_dump: Failed to rename file: {}", e);
        }
    }

    let dump_extn = "dmp.tgz";
    let mut count = get_file_count(minidumps_path, dump_extn).unwrap_or(0);

    while count > 5 {
        match find_oldest_dump(minidumps_path) {
            Ok(Some(oldest)) => {
                println!("save_dump: Removing old dump {}", oldest.display());
                if let Err(e) = fs::remove_file(&oldest) {
                    println!("Failed to remove old dump: {}", e);
                }
                count -= 1;
            }
            _ => break,
        }
    }
    println!("save_dump: Total pending Minidumps: {}", count);
}

/// Logs the current upload timestamp to the timestamp file and truncates it to the last 10 entries.
///
/// This function is used to maintain a record of recent uploads for rate limiting purposes.
/// For production builds, it adds the current time to the timestamp file and calls
/// `truncate_timestamp_file()` to keep only the 10 most recent entries.
///
/// # Arguments
/// * `ts_file` - Path to the timestamp file
///
/// # Side Effects
/// - Acquires and releases a lock on the timestamp file
/// - Appends the current timestamp to the file
/// - Truncates the file to keep only the 10 most recent entries
pub fn log_upload_timestamp(ts_file: &str) {
    create_lock_or_wait(ts_file);

    let mut build_type = String::new();
    get_property_value_from_file("/etc/device.properties", "BUILD_TYPE", &mut build_type);
    if build_type == "prod" {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX_EPOCH")
            .as_secs();
        if let Err(e) = OpenOptions::new().append(true).create(true).open(ts_file)
            .and_then(|mut f| writeln!(f, "{}", now)) {
            println!("log_upload_timestamp: Failed to write timestamp: {}", e);
        }
        if let Err(e) = truncate_timestamp_file(ts_file) {
            println!("log_upload_timestamp: Failed to truncate timestamp file: {}", e);
        }
    }
    remove_lock(ts_file);
}

/// Truncates the timestamp file to the last 10 lines.
///
/// This function maintains a fixed-size history of upload timestamps by keeping
/// only the 10 most recent entries. It reads all lines, selects the 10 newest,
/// and overwrites the file with just those lines.
///
/// # Arguments
/// * `ts_file` - Path to the timestamp file
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail
///
/// # Side Effects
/// - Acquires and releases a lock on the timestamp file
/// - Modifies the content of the timestamp file
pub fn truncate_timestamp_file(ts_file: &str) -> io::Result<()> {
    create_lock_or_wait(ts_file);
    let ts_path = Path::new(ts_file);
    let file = File::open(ts_path)?;
    let reader = BufReader::new(file);

    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let last_10_lines = lines.iter().rev().take(10).cloned().collect::<Vec<_>>();
    let mut tmp_file = OpenOptions::new().write(true).truncate(true).open(ts_path)?;

    for line in last_10_lines.into_iter().rev() {
        writeln!(tmp_file, "{}", line)?;
    }

    remove_lock(ts_file);
    Ok(())
}

/// Gets the last modified time of a file as a formatted string.
///
/// Retrieves the file's modification timestamp and formats it as 
/// "YYYY-MM-DD-HH-MM-SS" for use in log file naming and comparisons.
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Some(String)` with the formatted time string, or `None` if:
///   - The path doesn't exist
///   - The path isn't a regular file
///   - The metadata or modification time couldn't be retrieved
pub fn get_last_modified_time_of_file(path: &str) -> Option<String> {
    let path_ref = Path::new(path);
    if !path_ref.is_file() {
        return None;
    }
    let metadata = fs::metadata(path_ref).ok()?;
    let modified_time = metadata.modified().ok()?;
    let datetime: DateTime<Local> = modified_time.into();
    Some(datetime.format("%Y-%m-%d-%H-%M-%S").to_string())
}

/// Maps a crashed process to its log files using the logmapper config and writes them to LOG_FILES.
///
/// This function performs several key operations:
/// 1. Extracts the process name from the crashed file path
/// 2. Sends telemetry notifications about the crashed process
/// 3. Looks up associated log files in the LOGMAPPER_FILE configuration
/// 4. Writes the full paths of those log files to the LOG_FILES file
///
/// # Arguments
/// * `file_path` - Path or name of the crashed file
/// * `is_t2_enabled` - Whether T2 telemetry is enabled (for sending notifications)
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail
///
/// # Side Effects
/// - May send multiple T2 telemetry notifications
/// - Writes to the LOG_FILES file
pub fn get_crashed_log_file(file_path: &str, is_t2_enabled: bool) -> io::Result<()> {
    let basename = basename(file_path);

    let process_name = match basename.rfind('_') {
        Some(idx) => &basename[..idx],
        None => &basename,
    };

    println!("get_crashed_log_file: Process crashed = {}", process_name);

    if is_t2_enabled {
        t2_val_notify("processCrash_split", &[process_name]);
        t2_val_notify("SYST_ERR_Process_Crash_accum", &[process_name]);
        t2_count_notify("SYST_ERR_ProcessCrash", Some("1"));
    }

    let app_name = basename
        .split('_')
        .nth(1)
        .and_then(|s| s.split('-').next())
        .unwrap_or("");

    let breakpad_mapper = BufReader::new(File::open(LOGMAPPER_FILE)?);
    let mut log_files = String::new();
    for line in breakpad_mapper.lines() {
        let line = line?;
        if let Some((key, val)) = line.split_once('=') {
            if key.contains(process_name) {
                log_files = val.to_string();
                break;
            }
        }
    }
    println!("get_crashed_log_file: Crashed process log file(s): {}", log_files);
    if !app_name.is_empty() {
        println!("get_crashed_log_file: Appname, Process_Crashed = {}, {}", app_name, process_name);
    }
    // Write each log file to LOG_FILES
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILES)?;

    for log_file in log_files
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        writeln!(output, "{}/{}", LOG_PATH, log_file)?;
    }

    Ok(())
}

/// Deletes all but the most recent N files in a directory, sorted by modification time (descending).
///
/// This function is used to enforce a retention policy for core/minidump files,
/// keeping only the newest `MAX_CORE_FILES` files and deleting the rest.
///
/// # Arguments
/// * `dir_path` - Directory path as &str
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail
///
/// # Side Effects
/// - Deletes files from the filesystem that exceed the retention limit
/// - Logs the deletion operations or their failure
pub fn delete_all_but_most_recent_files(dir_path: &str) -> io::Result<()> {
    let path = Path::new(dir_path);
    if !path.is_dir() {
        return Ok(());
    }

    // Collect all files with their modification times
    let mut files: Vec<_> = fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let meta = entry.metadata().ok()?;
            let mtime = meta.modified().ok()?;
            if meta.is_file() {
                Some((entry.path(), mtime))
            } else {
                None
            }
        })
        .collect();

    files.sort_by(|a, b| b.1.cmp(&a.1));

    // Calculate number of files to delete
    if files.len() > MAX_CORE_FILES {
        // Delete the oldest files
        for (file_path, _) in files.iter().skip(MAX_CORE_FILES) {
            if let Err(e) = fs::remove_file(file_path) {
                println!("delete_all_but_most_recent_files: Failed to delete file {:?}: {}", file_path, e);
            } else {
                println!("delete_all_but_most_recent_files: Deleted old dump file: {:?}", file_path);
            }
        }
    } else {
        println!("delete_all_but_most_recent_files: No files need to be deleted. Total files: {}", files.len());
    }
    Ok(())
}

/// Cleans up the working directory by removing old, unfinished, and non-dump files,
/// and limits the number of dump files to the configured maximum.
///
/// This function performs several cleanup operations:
/// - Removes files matching `*_mac*_dat*` older than 2 days
/// - On first startup, removes unfinished and non-dump files, and limits dump file count
/// - Removes version.txt if not uploading on startup
///
/// # Arguments
/// * `work_dir` - Working directory path
/// * `dump_name` - Dump type ("coredump" or "minidump")
/// * `dump_extn` - Dump file extension pattern (e.g., "*.dmp*")
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail
///
/// # Side Effects
/// - Deletes files from the filesystem based on various criteria
/// - Creates a flag file to indicate cleanup has been performed
pub fn cleanup(work_dir: &str, dump_name: &str, dump_extn: &str) -> std::io::Result<()> {
    let work_dir_path = Path::new(work_dir);

    // Early exit if directory is missing or empty
    if !work_dir_path.exists() || !work_dir_path.is_dir() || work_dir_path.read_dir()?.next().is_none()
    {
        println!("cleanup: Working directory {} is empty", work_dir);
        return Ok(());
    }

    println!("cleanup: Cleaning up {} directory {}", dump_name, work_dir);

    // Remove files matching '*_mac*_dat*' older than 2 days
    let cutoff = SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 2); // 2 days
    for entry in fs::read_dir(work_dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if fname.contains("_mac") && fname.contains("_dat") {
                if let Ok(meta) = fs::metadata(&path) {
                    if let Ok(modified) = meta.modified() {
                        if modified < cutoff {
                            fs::remove_file(&path)?;
                            println!("cleanup: Removed file: {}", path.display());
                        }
                    }
                }
            }
        }
    }

    // find and while loop logic
    if !Path::new(UPLOAD_ON_STARTUP).exists() {
        let version_txt = Path::new(work_dir).join("version.txt");
        if version_txt.exists() {
            println!("cleanup: Removing version.txt file: {}", version_txt.display());
            let _ = fs::remove_file(&version_txt);
        }

        let on_startup_flag = format!(
            "{}_{}",
            ON_STARTUP_DUMPS_CLEANED_UP_BASE,
            if dump_name == "coredump" { "1" } else { "" }
        );
        let on_startup_flag_path = Path::new(&on_startup_flag);

        if !on_startup_flag_path.exists() {
            // Remove unfinished files: '*_mac*_dat*'
            for entry in fs::read_dir(work_dir_path)? {
                let entry = entry?;
                let path = entry.path();
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if fname.contains("_mac") && fname.contains("_dat") {
                    fs::remove_file(&path)?;
                    println!("cleanup: Deleting unfinished file: {}", path.display());
                }
            }

            // Remove non-dump files (not matching dump_extn)
            for entry in fs::read_dir(work_dir_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !fname.contains(dump_extn.trim_matches('*')) {
                        fs::remove_file(&path)?;
                        println!("cleanup: Deleting non-dump file: {}", path.display());
                    }
                }
            }

            // Limit number of dump files
            let _ = delete_all_but_most_recent_files(work_dir);

            touch(&on_startup_flag);
        }
    } else if dump_name == "coredump" {
        let _ = fs::remove_file(UPLOAD_ON_STARTUP);
    }
    Ok(())
}

/// Returns the usage percent of the /tmp partition by invoking `df`.
///
/// Mimics the shell logic: `df -h /tmp | grep '\tmp' | awk '{print $5}'`
/// This is used to determine if there's enough space to copy log files to /tmp.
///
/// # Returns
/// * `Some(u8)` with the usage percent (0-100), or `None` if:
///   - The `df` command fails to execute
///   - The output doesn't contain expected data
///   - The percentage value cannot be parsed
#[inline]
fn get_tmp_usage_percent() -> Option<u8> {
    let output = Command::new("df")
        .arg("-h")
        .arg("/tmp")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Skip the header, look for the line containing "/tmp"
    for line in stdout.lines().skip(1) {
        if line.contains("/tmp") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if let Some(usage) = fields.get(4) {
                // usage is like "12%"
                return usage.trim_end_matches('%').parse::<u8>().ok();
            }
        }
    }
    None
}

/// Adds crashed log files to the minidump tarball, processing each log file as needed.
///
/// For each log file:
/// 1. Gets the file's last modified timestamp
/// 2. Creates a sanitized process log file name using device metadata
/// 3. Extracts the last N lines (N=500 for prod, 5000 otherwise)
/// 4. Writes those lines to a new file in the working directory
///
/// # Arguments
/// * `device_data` - Reference to device metadata (for log file naming)
/// * `log_files` - Slice of log file paths to process and add
/// * `working_dir` - Directory where processed log files will be written
///
/// # Returns
/// * `Ok(())` on success, or an error if file operations fail
///
/// # Side Effects
/// - Creates new log files in the working directory
/// - Logs each file addition
pub fn add_crashed_log_file(device_data: &DeviceData, log_files:  &[&str], working_dir: &str) -> io::Result<()> {
    let line_count = if device_data.build_type == "prod" { 500 } else { 5000 };

    for file_path in log_files {
        let path = Path::new(file_path);
        if path.is_file() {
            if let Some(log_mod_ts) = get_last_modified_time_of_file(file_path) {
                let process_log_name = set_log_file(device_data, &log_mod_ts, file_path);
                let process_log_path = Path::new(working_dir).join(&process_log_name);

                let file = File::open(path)?;
                let lines: Vec<String> = BufReader::new(file)
                    .lines()
                    .map_while(Result::ok)
                    .collect();

                let start = lines.len().saturating_sub(line_count);
                let mut output = File::create(&process_log_path)?;
                for line in &lines[start..] {
                    writeln!(output, "{}", line)?;
                }

                println!("add_crashed_log_file: Adding File: {} to minidump tarball", process_log_path.display());
            }
        }
    }
    Ok(())
}

/// Copies log files to a temporary directory under /tmp if there is enough free space.
///
/// This function implements a space-aware strategy for log file handling:
/// - If /tmp usage is below 70%, copies each log file to a temp directory
/// - Otherwise, uses the original file paths to avoid filling /tmp
///
/// # Arguments
/// * `tmp_dir_name` - Name for the temporary directory under /tmp
/// * `logfiles` - Slice of log file paths to potentially copy
///
/// # Returns
/// * `Vec<String>` containing paths to use for archiving (either in /tmp or original)
///
/// # Side Effects
/// - May create a directory in /tmp
/// - May copy files to the temporary directory
pub fn copy_log_files_to_tmp(tmp_dir_name: &str, logfiles: &[&str]) -> Vec<String> {
    let tmp_dir = format!("/tmp/{}", tmp_dir_name);
    let usage_percent = get_tmp_usage_percent().unwrap_or(0);
    let limit = 70;
    let mut out_files = Vec::new();

    if usage_percent >= limit {
        println!(
            "copy_log_files_to_tmp: Skipping copying logs to tmp dir due to limited memory (used: {}%, limit: {}%)",
            usage_percent, limit
        );
        for &file in logfiles {
            if Path::new(file).exists() {
                out_files.push(file.to_string());
            }
        }
    } else {
        println!(
            "copy_log_files_to_tmp: Copying logs to tmp dir as memory available (used: {}%, limit: {}%)",
            usage_percent, limit
        );
        if let Err(e) = fs::create_dir_all(&tmp_dir) {
            println!("copy_log_files_to_tmp: Failed to create tmp dir {}: {}", tmp_dir, e);
        }
        for &file in logfiles {
            let src = Path::new(file);
            if src.exists() {
                let dest = Path::new(&tmp_dir).join(src.file_name().unwrap());
                if let Err(e) = fs::copy(src, &dest) {
                    println!("copy_log_files_to_tmp: Failed to copy {:?} to {:?}: {}", src, dest, e);
                } else {
                    out_files.push(dest.to_string_lossy().to_string());
                }
            }
        }
        println!("copy_log_files_to_tmp: Logs copied to {} temporary", tmp_dir);
    }
    out_files
}

/// Uploads a crash dump file to S3 using the Rust implementation from crash-upload-cpc.
///
/// This function is only available when the "shared_api" feature is enabled.
/// It implements the actual upload logic, handling encryption, TLS configuration,
/// and authentication based on device settings.
///
/// # Arguments
/// * `args` - Arguments for the upload, with args[0] being the file to upload
/// * `dump_paths` - Reference to dump paths configuration
/// * `device_data` - Reference to device metadata
/// * `curl_log_option` - Curl logging options string
///
/// # Returns
/// * `Ok(())` on successful upload, or an error if upload fails
///
/// # Side Effects
/// - Creates a backup of the file before uploading
/// - Logs upload status and details
/// - Makes network requests to S3
#[cfg(feature = "shared_api")]
pub fn upload_to_s3_lib(args: &[&str], dump_paths: &DumpPaths, device_data: &DeviceData, curl_log_option: &str) -> std::io::Result<()> {
    // Call the Rust implementation from crash-upload-cpc
    println!("upload_to_s3_lib: Uploading to S3 using Rust implementation");
    println!("upload_to_s3_lib: Tars to be uploaded: {:#?}", args);
    let file = args.get(0).copied().unwrap_or("");
    println!("upload_to_s3_lib: ###DEBUG### File to upload: {:#?}", file);
    if !file.is_empty() {
        let backup_path = format!("{}.backup", file);
        println!("upload_to_s3_lib: ###DEBUG### Backing up file to: {}", backup_path);
        if let Err(e) = std::fs::copy(file, &backup_path) {
            println!("upload_to_s3_lib: Warning - Failed to create backup: {}", e);
            // Continue with upload even if backup fails
        }
    }
    let mut force_mtls = String::new();
    let _ = utils::get_property_value_from_file(DEVICE_PROP_FILE, "FORCE_MTLS", &mut force_mtls);
    let image_name = std::fs::read_to_string("/version.txt").unwrap().lines().next().unwrap().split("imagename:").nth(1).unwrap().trim().to_string();
    crash_upload_cpc::upload_to_s3(file, 
        dump_paths.get_working_dir(), 
        "", 
        dump_paths.get_dump_name(),
        device_data.get_device_type(),
        VERSION_FILE,
        &image_name,
        device_data.get_is_encryption_enabled(),
        ENABLE_OSCP_STAPLING,
        ENABLE_OSCP,
        device_data.get_is_tls_enabled(),
        device_data.get_build_type(),
        device_data.get_model_num(),
        curl_log_option,
        device_data.get_is_t2_enabled(),
        force_mtls.as_str(),
    )
}

/// Calls the uploadDumpsToS3.sh script with the given arguments if it exists.
///
/// This function is only available when the "shared_api" feature is NOT enabled.
/// It delegates the upload responsibility to a shell script.
///
/// # Arguments
/// * `args` - Arguments to pass to the script, with args[0] being the file to upload
///
/// # Returns
/// * `Ok(exit_status)` if the script ran successfully
/// * `Err` if the script wasn't found or failed with a non-zero exit code
///
/// # Side Effects
/// - Executes an external shell script
/// - The shell script will make network requests and manipulate files
#[cfg(not(feature = "shared_api"))]
pub fn upload_to_s3_script(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    if Path::new(S3_UPLOAD_SCRIPT).exists() {
        let mut cmd_args: Vec<&str> = args.to_vec();
        cmd_args.push("crash-upload");
        let status = std::process::Command::new(S3_UPLOAD_SCRIPT).args(&cmd_args).status()?;
        if status.success() {
            Ok(status)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Script failed with status: {:?}", status),
            ))
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "uploadDumpsToS3.sh not found",
        ))
    }
}

/// Calls getPrivacyControlMode from utils.sh and returns its output as a String.
///
/// This function interfaces with the platform's privacy control system by
/// sourcing the utils.sh script and calling its getPrivacyControlMode function.
///
/// # Returns
/// * `Some(String)` containing the privacy mode ("DO_NOT_SHARE", etc.) if successful
/// * `None` if:
///   - The utils.sh script doesn't exist
///   - The command execution fails
///   - The command exits with a non-zero status
///
/// # Side Effects
/// - Executes a shell command
pub fn get_privacy_control_mode() -> Option<String> {
    let script = "/lib/rdk/utils.sh";
    if Path::new(script).exists() {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!(". {}; getPrivacyControlMode", script))
            .output()
            .ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    } else {
        None
    }
}

/// Processes all dump files in the working directory: sanitizes, compresses, and uploads or saves them.
///
/// This function implements the main dump processing workflow:
/// 1. Finds all dump files in the working directory
/// 2. For each file:
///    - Sanitizes and renames it
///    - Processes telemetry info for minidumps
///    - Creates a tarball with the dump and relevant log files
///    - Cleans up temporary files
/// 3. Hands off tarballs for upload or local storage
///
/// # Arguments
/// * `device_data` - Reference to device metadata (for naming and telemetry)
/// * `dump_paths` - Reference to dump paths and configuration
/// * `crash_ts` - Crash timestamp string for naming files
/// * `no_network` - If true, skips upload and just saves the dump locally
///
/// # Side Effects
/// - Modifies files in the working directory (renames, compresses, deletes)
/// - May create or remove log files and temporary directories
/// - Calls other functions that may upload files or send telemetry
pub fn process_dumps(
    device_data: &DeviceData,
    dump_paths: &DumpPaths,
    crash_ts: &str,
    no_network: bool,
) {
    utils::flush_logger();
    let work_dir = dump_paths.get_working_dir();

    let files = match find_dump_files(work_dir, dump_paths.get_dumps_extn()) {
        Ok(f) => f,
        Err(e) => {
            println!("process_dumps: Error finding dump files: {}", e);
            return;
        }
    };

    for file in files {
        println!("process_dumps: -- Processing file: {}", file.display());
        let orig_file_name = basename(&file);

        if !should_process_dump(dump_paths.get_dump_name(), device_data.get_build_type(), &orig_file_name) {
            println!("process_dumps: Skipping file {} ", orig_file_name);
            continue;
        }
        let sanitized = match sanitize_and_rename(&file) {
            Ok(f) => f,
            Err(e) => {
                println!("process_dumps: Sanitize/rename failed for {:?}: {}", file, e);
                continue;
            }
        };

        if dump_paths.get_dump_name() != "coredump" {
            process_crash_t2_info(&sanitized.to_string_lossy(), device_data.is_t2_enabled);
        }

        if file.is_file() {
            if is_tarball(&sanitized) {
                println!(
                    "process_dumps: Skip archiving {} as it is a tarball already.",
                    basename(&sanitized)
                );
                continue;
            }

            let mod_date = get_last_modified_time_of_file(&sanitized.to_string_lossy())
                .unwrap_or_else(|| crash_ts.to_string());
            let ts_for_naming = if crash_ts.is_empty() { &mod_date } else { crash_ts };

            let mut dump_file_name =
                set_log_file(device_data, ts_for_naming, &sanitized.to_string_lossy());

            if dump_file_name.len() >= 135 {
                if let Some(pos) = dump_file_name.find('_') {
                    dump_file_name = dump_file_name[pos + 1..].to_string();
                }
            }
            let dump_file_name = dump_file_name.replace("<#=#>", "_");

            let dump_dir = Path::new(work_dir);
            let dump_file_path = dump_dir.join(&dump_file_name);
            println!("process_dumps: Dump file path: {}", dump_file_path.display());
            println!("process_dumps: Dump File Name: {}", dump_file_name);


            if sanitized != dump_file_path {
                if let Err(e) = safe_rename(&sanitized, &dump_file_path) {
                    println!(
                        "process_dumps: Failed to rename {} to {}: {}",
                        basename(&sanitized),
                        basename(&dump_file_name),
                        e
                    );
                    continue;
                }
            }

            ensure_core_log_exists();

            let version_file_path = Path::new(work_dir).join("version.txt");
            if !version_file_path.exists() {
                let _ = fs::copy(VERSION_FILE, &version_file_path);
                println!("process_dumps: Version file path: {}", version_file_path.display());
            }

            if let Ok(metadata) = std::fs::metadata(&dump_file_path) {
                println!(
                    "process_dumps: Size of the file: {} bytes",
                    metadata.len()
                );
            }

            if device_data.get_is_t2_enabled() && !dump_paths.get_dump_name().is_empty() {
                t2_count_notify("SYST_ERR_MINIDPZEROSIZE", Some("1"));
            }

            let logfiles: Vec<String> = if dump_paths.dump_name == "coredump" {
                vec![VERSION_FILE.to_string(), CORE_LOG.to_string()]
            } else {
                let crash_url_file = format!("{}/crashed_url.txt", LOG_PATH);
                let crashed_url_file = if Path::new(&crash_url_file).exists() {
                    crash_url_file.clone()
                } else {
                    "".to_string()
                };
                vec![VERSION_FILE.to_string(), CORE_LOG.to_string(), crashed_url_file]
            };

            let logfiles_abs: Vec<String> = logfiles
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if Path::new(s).is_absolute() {
                        s.clone()
                    } else {
                        format!("{}/{}", LOG_PATH, s)
                    }
                })
                .collect();

            let logfiles_refs: Vec<&str> = logfiles_abs.iter().map(|s| s.as_str()).collect();

            println!(
                "process_dumps: Log files (REF) to be added: \n{:#?}\n",
                logfiles_refs
            );

            if dump_paths.dump_name == "minidump" {
                if let Err(e) = add_crashed_log_file(device_data, &logfiles_refs, work_dir) {
                    println!("process_dumps: Failed to add crashed log file: {}", e);
                }
            }

            let tgz_file = if dump_paths.dump_name == "coredump" {
                dump_dir.join(format!("{}.core.tgz", dump_file_name))
            } else {
                dump_dir.join(format!("{}.tgz", dump_file_name))
            };

            let tar_result = compress_files(
                tgz_file.to_str().unwrap(),
                &[dump_file_path.to_str().unwrap()],
                &logfiles_refs,
            );

            if tar_result.is_ok() {
                println!(
                    "process_dumps: Success Compressing the files, {}\n {}\n {}\n {}\n",
                    basename(&tgz_file),
                    basename(&dump_file_path),
                    VERSION_FILE,
                    basename(CORE_LOG)
                );
            } else {
                println!("process_dumps: Compression failed, will retry after copying logs to /tmp");
                let out_files = copy_log_files_to_tmp(&dump_file_name, &logfiles_refs);
                let tmp_dir = format!("/tmp/{}", dump_file_name);
                let tmp_dump_file = Path::new(&tmp_dir).join(&dump_file_name);
                if let Err(e) = fs::copy(&dump_file_path, &tmp_dump_file) {
                    println!("process_dumps: Failed to copy dump file to tmp: {}", e);
                }
                let mut retry_files = vec![tmp_dump_file.to_str().unwrap()];
                retry_files.extend(out_files.iter().map(|s| s.as_str()));
                let retry_tar_result = compress_files(
                    tgz_file.to_str().unwrap(),
                    &retry_files,
                    &[],
                );
                if retry_tar_result.is_ok() {
                    println!(
                        "process_dumps: Success Compressing the files, {} {}",
                        basename(&tgz_file),
                        basename(&tmp_dump_file)
                    );
                } else {
                    println!("process_dumps: Compression Failed .");
                }
            }

            if let Ok(metadata) = std::fs::metadata(&tgz_file) {
                println!(
                    "process_dumps: Size of the compressed file: {} bytes",
                    metadata.len()
                );
            }

            // 21. Remove /tmp/<dump_file_name> temp dir if it exists
            let tmp_dir = format!("/tmp/{}", dump_file_name);
            if Path::new(&tmp_dir).is_dir() {
                rm_rf(&tmp_dir);
                println!(
                    "process_dumps: Temporary Directory Deleted: {}",
                    basename(&tmp_dir)
                );
            }

            // 22. Remove the original dump file after compression
            println!("process_dumps: Skipping original dump file removal for debugging purposes");
            if false {
            rm_rf(dump_file_path.to_str().unwrap());
            }

            // 23. For minidump, remove logs from working dir
            if dump_paths.dump_name != "coredump" {
                println!("process_dumps: ###DEBUG### Skipping log removal in working dir for debugging purposes ");
                if false {
                let _ = remove_logs(work_dir);
                }
            }
        }
    }
    handle_tarballs(device_data, dump_paths, no_network, crash_ts);
}

/// Compresses the given files into a tarball using the `tar` command.
///
/// This function creates a gzipped tarball containing both the primary dump files
/// and any associated log files by executing the system `tar` command.
///
/// # Arguments
/// * `tarball_path` - Output tarball file path
/// * `dump_files` - Primary dump files to include in the tarball
/// * `log_files` - Additional log files to include in the tarball
///
/// # Returns
/// * `Ok(())` if compression succeeded, error otherwise
///
/// # Side Effects
/// - Creates a new tarball file at the specified path
/// - Executes the system `tar` command
#[inline]
pub fn compress_files(
    tarball_path: &str,
    dump_files: &[&str],
    log_files: &[&str],
) -> std::io::Result<()> {
    let mut args = vec!["-zcvf", tarball_path];
    for file in dump_files {
        args.push(file);
    }
    for file in log_files {
        args.push(file);
    }
    let status = Command::new("tar").args(&args).status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "compress_files: tar compression failed",
        ))
    }
}

/// Checks if the given file is a tarball (ends with .tgz).
///
/// A simple utility function that examines the file extension to determine
/// if a file is a compressed tarball archive.
///
/// # Arguments
/// * `file` - Reference to a `Path` to check
///
/// # Returns
/// * `true` if the file has a .tgz extension, `false` otherwise
#[inline]
fn is_tarball(file: &Path) -> bool {
    file.extension().map(|e| e == "tgz").unwrap_or(false)
}

/// Sanitizes the file name and renames the file if needed.
///
/// This function sanitizes the file path by removing unsafe characters, then
/// renames the file on disk if the sanitized name differs from the original.
/// This ensures filenames are compatible with upload and storage systems.
///
/// # Arguments
/// * `file` - Reference to the `Path` of the file to sanitize
///
/// # Returns
/// * `Ok(PathBuf)` containing the sanitized path (which may be the same as the
///   original if no sanitization was needed)
/// * `Err` if the rename operation fails
///
/// # Side Effects
/// - May rename the file on the filesystem if sanitization changes the name
#[inline]
fn sanitize_and_rename(file: &Path) -> io::Result<PathBuf> {
    let orig = file.to_string_lossy();
    let sanitized = sanitize(&orig);
    if sanitized != orig {
        safe_rename(&*orig, &sanitized)?;
        Ok(PathBuf::from(sanitized))
    } else {
        Ok(file.to_path_buf())
    }
}

/// Removes all .log and .txt files from the given directory.
///
/// This function is used to clean up log files after they've been packaged
/// into a tarball. It scans the directory and deletes any file with a .log or
/// .txt extension.
///
/// # Arguments
/// * `working_dir` - Directory path to clean
///
/// # Returns
/// * `Ok(())` on success, or an error if directory operations fail
///
/// # Side Effects
/// - Deletes .log and .txt files from the specified directory
#[inline]
fn remove_logs(working_dir: &str) -> io::Result<()> {
    for entry in fs::read_dir(working_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(".log") || name.ends_with(".txt") {
                println!("remove_logs: Removing {}", path.display());
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// Finds all files in a directory matching the given pattern.
///
/// This function scans a directory and collects all files whose names match
/// the specified pattern (using the `matches_pattern` function).
///
/// # Arguments
/// * `dir` - Directory path to search
/// * `pattern` - Pattern to match in file names (e.g., "*.dmp*", "*.core.tgz")
///
/// # Returns
/// * `Ok(Vec<PathBuf>)` containing paths to all matching files
/// * `Err` if there was an error reading the directory
pub fn find_dump_files(dir: &str, pattern: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let dir_path = std::path::Path::new(dir);
    let mut files = Vec::new();
    if !dir_path.is_dir() {
        return Ok(files);
    }
    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches_pattern(&name, pattern) {
            files.push(entry.path());
        }
    }
    Ok(files)
}

/// Handles all tarballs in the working directory: applies rate limiting, privacy checks,
/// uploads with retries, and performs post-upload cleanup.
///
/// This function is the main coordinator for tarball processing after dumps have been
/// compressed. It finds all tarballs in the working directory and processes each one
/// through `handle_single_tarball()`.
///
/// # Arguments
/// * `device_data` - Reference to device metadata for upload identification
/// * `dump_paths` - Reference to dump paths and configuration
/// * `no_network` - Whether to skip upload and just save dumps locally
/// * `crash_ts` - Crash timestamp string for file naming
///
/// # Side Effects
/// - May upload files to S3
/// - May delete or rename files
/// - May send telemetry notifications
/// - Logs processing status for each tarball
fn handle_tarballs(device_data: &DeviceData, dump_paths: &DumpPaths, no_network: bool, crash_ts: &str) {
    if is_box_rebooting(device_data.is_t2_enabled) {
        return;
    }

    let tarballs = match find_dump_files(dump_paths.get_working_dir(), dump_paths.get_tar_extn()) {
        Ok(t) => t,
        Err(e) => {
            println!("handle_tarballs: Error finding tarballs: {}", e);
            return;
        }
    };
    println!("handle_tarballs: Found tarballs: {:?}", tarballs);

    for tarball in tarballs {
        if let Err(e) = handle_single_tarball(device_data, dump_paths, &tarball, no_network, crash_ts) {
            println!("handle_tarballs: Error handling tarball {:?}: {}", tarball, e);
        }
    }
}

/// Handles a single tarball: checks rate limits, privacy, uploads with retries, and cleans up.
///
/// This function implements the complete processing workflow for a single tarball:
/// 1. Checks recovery time and rate limits
/// 2. Handles no-network mode if enabled
/// 3. Checks privacy settings
/// 4. Sanitizes the filename for S3
/// 5. Uploads the tarball with retries
/// 6. Performs post-upload cleanup
///
/// # Arguments
/// * `device_data` - Reference to device metadata for upload identification
/// * `dump_paths` - Reference to dump paths and configuration
/// * `tarball` - Path to the tarball file to process
/// * `no_network` - Whether to skip upload and just save dumps locally
/// * `crash_ts` - Crash timestamp string for file naming
///
/// # Returns
/// * `Ok(())` on success, or an error if any operation fails
///
/// # Side Effects
/// - May upload files to S3
/// - May delete or rename files
/// - May set recovery time
/// - May remove pending dumps
fn handle_single_tarball(device_data: &DeviceData, dump_paths: &DumpPaths, tarball: &Path, no_network: bool, crash_ts: &str) -> std::io::Result<()> {
    let tarball_str = tarball.to_string_lossy();
    let s3_filename = tarball.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let s3_filename_sanitized = s3_filename.replace("<#=#>", "_");
    let parent = tarball.parent().unwrap_or_else(|| Path::new(dump_paths.get_working_dir()));
    let s3_full_path = parent.join(&s3_filename_sanitized);

    // 1. Rate limiting and recovery time
    if is_recovery_time_reached() {
        rm_rf(DENY_UPLOAD_FILE);
    } else {
        println!("handle_single_tarball: Shifting the recovery time forward.");
        set_recovery_time();
        let _ = remove_pending_dumps(
            dump_paths.get_working_dir(),
            dump_paths.get_dumps_extn(),
        );
        return Ok(());
        // TODO: Should Exit?
    }

    if dump_paths.get_dump_name() == "minidump" && is_upload_limit_reached(dump_paths.get_ts_file())
    {
        println!("handle_single_tarball: Upload rate limit has been reached.");
        mark_as_crash_loop_and_upload(&tarball_str);
        set_recovery_time();
        let _ = remove_pending_dumps(
            dump_paths.get_working_dir(),
            dump_paths.get_dumps_extn(),
        );
        return Ok(());
        // TODO: Should Exit?
    }
    
    // 2. no_network logic: skip upload and just save the dump
    if dump_paths.get_dump_name() == "minidump" && no_network {
        println!("handle_single_tarball: Network is not available, skipping upload and saving dump.");
        save_dump(dump_paths.get_minidumps_path(), s3_filename, Some(crash_ts));
        return Ok(());
    }

    // 3. Privacy mode check
    if device_data.get_device_type() == "mediaclient" && is_privacy_mode_do_not_share() {
        println!("handle_single_tarball: Privacy Mode is DO_NOT_SHARE. Stop Uploading the data to the cloud");
        let _ = remove_pending_dumps(
            dump_paths.get_working_dir(),
            dump_paths.get_dumps_extn(),
        );
        return Ok(());
    }

    // 4. Ensure tarball filename is sanitized for S3
    if s3_filename != s3_filename_sanitized {
        rename_tarball_for_s3(tarball, &s3_filename_sanitized)?;
    }

    // 5. Upload with retries
    let upload_success = upload_tarball_with_retries(s3_full_path.to_str().unwrap(), dump_paths, device_data);

    // 6. Post-upload cleanup
    post_upload_cleanup(upload_success, dump_paths, &s3_full_path, &s3_filename_sanitized);

    Ok(())
}

/// Returns true if privacy mode is DO_NOT_SHARE (from utils.sh).
///
/// This function checks if the device's privacy mode is set to "DO_NOT_SHARE",
/// which indicates that no data should be uploaded to the cloud.
///
/// # Returns
/// * `true` if privacy mode is "DO_NOT_SHARE", `false` otherwise
///
/// # Side Effects
/// - Calls `get_privacy_control_mode()` which executes a shell command
#[inline]
fn is_privacy_mode_do_not_share() -> bool {
    matches!(get_privacy_control_mode().as_deref(), Some("DO_NOT_SHARE"))
}

/// Renames a tarball file to a sanitized name for S3 upload.
///
/// This function replaces special characters in the tarball filename that might
/// cause problems during S3 upload. It performs the actual filesystem rename
/// operation.
///
/// # Arguments
/// * `tarball` - Path to the original tarball
/// * `sanitized_name` - Sanitized file name to use
///
/// # Returns
/// * `Ok(())` on success, or an error if the rename fails
///
/// # Side Effects
/// - Renames a file on the filesystem
fn rename_tarball_for_s3(tarball: &Path, sanitized_name: &str) -> std::io::Result<()> {
    let parent = tarball.parent().unwrap_or_else(|| Path::new(""));
    let orig_path = parent.join(tarball.file_name().unwrap());
    let new_path = parent.join(sanitized_name);
    safe_rename(&orig_path, &new_path)
}

/// Uploads a tarball to S3, retrying up to 3 times.
///
/// This function attempts to upload a tarball to S3, with up to 3 retry attempts
/// if the upload fails. It handles both the Rust and shell script upload implementations
/// based on the feature flags, and logs the upload status.
///
/// # Arguments
/// * `s3_full_path` - Full path to the tarball file to upload
/// * `dump_paths` - Reference to dump paths and configuration
/// * `device_data` - Reference to device metadata for upload identification
///
/// # Returns
/// * `true` if any upload attempt succeeded, `false` if all attempts failed
///
/// # Side Effects
/// - Makes network requests to S3
/// - May create temporary files for upload parameters
/// - May send telemetry notifications
/// - Logs upload status
fn upload_tarball_with_retries(
    s3_full_path: &str,
    dump_paths: &DumpPaths,
    device_data: &DeviceData,
) -> bool {
    let mut upload_status = false;
    for attempt in 1..=3 {
        println!("upload_tarball_with_retries: {}: {} S3 Upload Attempt {}", attempt, dump_paths.get_dump_name(), s3_full_path);
        
        let curl_log_option = "%{remote_ip} %{remote_port}";

        let upload_res: Result<(), String> = {
            #[cfg(feature = "shared_api")]
            {
                match upload_to_s3_lib(&[s3_full_path], dump_paths, device_data, curl_log_option) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(format!("upload_to_s3 failed: {}", e)),
                }
            }
            #[cfg(not(feature = "shared_api"))]
            {
                if let Err(e) = write_uploadtos3params(dump_paths, device_data, "", ENABLE_OSCP_STAPLING, ENABLE_OSCP, curl_log_option) {
                    println!("upload_tarball_with_retries: Failed to write upload parameters: {}", e);
                    return false;
                }
                let res = upload_to_s3_script(&[s3_full_path]);
                if let Err(e) = std::fs::remove_file(S3_UPLOAD_PARAM_FILE) {
                    println!("upload_tarball_with_retries: Failed to remove {}: {}", S3_UPLOAD_PARAM_FILE, e);
                }
                match res {
                    Ok(exit_status) if exit_status.success() => Ok(()),
                    Ok(exit_status) => Err(format!(
                        "Script ran but failed with status: {:?}",
                        exit_status
                    )),
                    Err(e) => Err(format!("upload_to_s3_script failed: {}", e)),
                }
            }
        };

        match upload_res {
            Ok(()) => {
                println!(
                    "upload_tarball_with_retries: {} uploadToS3 SUCCESS",
                    dump_paths.get_dump_name()
                );
                upload_status = true;
                if dump_paths.get_dump_name() == "minidump"
                    && device_data.get_is_t2_enabled()
                {
                    t2_count_notify("SYST_INFO_minidumpUpld", Some("1"));
                }
                break;
            }
            Err(ref e) if e.contains("Script ran but failed with status") => {
                println!(
                    "upload_tarball_with_retries: S3 Amazon Upload of {} failed with script exit status: {}",
                    dump_paths.get_dump_name(),
                    e
                );
            }
            Err(e) => {
                println!("upload_tarball_with_retries: Upload to S3 failed: {}", e);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    upload_status
}

/// Cleans up after upload: removes tarball if successful, logs timestamp, or saves/removes on failure.
///
/// This function handles the post-upload cleanup process, with different behavior based on
/// whether the upload succeeded:
/// - On success: Removes the tarball and logs the upload timestamp
/// - On failure: For minidumps, saves the dump locally; for other types, removes the file
///
/// # Arguments
/// * `upload_success` - Whether the upload succeeded
/// * `dump_paths` - Reference to dump paths and configuration
/// * `tarball` - Path to the tarball file
/// * `s3_filename` - Name of the tarball file
///
/// # Side Effects
/// - May delete files from the filesystem
/// - May log timestamps to the timestamp file
/// - May save dumps to the minidumps directory
fn post_upload_cleanup(upload_success: bool, dump_paths: &DumpPaths, tarball: &Path, s3_filename: &str) { 
    let parent = tarball.parent().unwrap_or_else(|| Path::new(""));
    let s3_path = parent.join(s3_filename);
    println!("post_upload_cleanup: s3_path: {}", s3_path.display());
    println!("post_upload_cleanup: s3_filename: {}", s3_filename);

    println!("post_upload_cleanup: ##DEBUG## Skipping Cleanup intentionally for debugging purposes");
    if false {

    if upload_success {
        println!("post_upload_cleanup: Removing file {}", s3_filename);
        let _ = fs::remove_file(&s3_path);
        log_upload_timestamp(dump_paths.get_ts_file());
    } else {
        println!("post_upload_cleanup: S3 Amazon Upload of {} Failed..!", dump_paths.get_dump_name());
        if dump_paths.get_dump_name() == "minidump" {
            println!("post_upload_cleanup: Check and save the dump {}", s3_filename);
            save_dump(dump_paths.get_minidumps_path(), s3_filename, None);
        } else {
            println!("post_upload_cleanup: Removing file {}", s3_filename);
            let _ = fs::remove_file(&s3_path);
        }
    }
        // TODO: Should exit?
    }
}
