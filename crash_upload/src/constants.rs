//! Crash upload system constants and configuration structures.
//!
//! This module defines constants and configuration structs used throughout the crash upload system,
//! including file paths, RFC names, and device/dump metadata.

pub const LOGMAPPER_FILE: &str = "/etc/breakpad-logmapper.conf";
pub const LOG_FILES: &str = "/tmp/minidump_log_files.txt";

pub const LOG_PATH: &str = "/opt/rdk";
pub const CORE_LOG: &str = "/opt/rdk/core_log.txt";

pub const DEVICE_PROP_FILE: &str = "/opt/device.properties";

pub const T2_SHARED_SCRIPT: &str = "/lib/rdk/t2Shared_api.sh";
pub const MAX_CORE_FILES: usize = 4;

pub const SECUREDUMP_TR181_NAME: &str = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SecDump.Enable";
pub const SECUREDUMP_ENABLE_FILE: &str = "/tmp/.SecureDumpEnable";
pub const SECUREDUMP_DISABLE_FILE: &str = "/tmp/.SecureDumpDisable";
pub const CRASH_UPLOAD_REBOOT_FLAG: &str = "/tmp/set_crash_reboot_flag";
pub const DENY_UPLOAD_FILE: &str = "/tmp/.deny_dump_uploads_till";

pub const UPLOAD_ON_STARTUP: &str = "/opt/.upload_on_startup";
pub const ON_STARTUP_DUMPS_CLEANED_UP_BASE: &str = "/tmp/.on_startup_dumps_cleaned_up";
pub const CRASH_LOOP_FLAG_FILE: &str = ""; // TODO


pub const COREDUMP_MTX_FILE: &str = "/tmp/coredump_mutex_release";

pub const NETWORK_FILE: &str = "/tmp/route_available";
pub const SYSTEM_TIME_FILE: &str = "/tmp/stt_received";
pub const NETWORK_CHECK_ITERATION: usize = 18;
pub const NETWORK_CHECK_TIMEOUT: usize = 10;
pub const SYSTEM_TIME_ITERATION: usize = 10;
pub const SYSTEM_TIME_TIMEOUT: usize = 1;

pub const ENCRYPTION_RFC: &str = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.encryptionEnabled";
pub const CRASH_PORTAL_URL_RFC: &str = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl";

/* UNUSED
pub const INCLUDE_PROP_FILE: &str = "/opt/include.properties";
pub const COREDUMP_PROP_FILE: &str = "/opt/coredump.properties";
pub const HTTP_CODE_FILE: &str = "/tmp/httpcode";
pub const CURL_UPLOAD_TIMEOUT: usize = 45;
pub const S3_FILENAME: &str = "s3filename";
pub const ENABLE_OSCP_STAPLING: &str = "/tmp/.EnableOCSPStapling";
pub const ENABLE_OSCP: &str = "/tmp/.EnableOCSPCA";
pub const POTOMAC_USER: &str = "ccpstbscp";
pub const SHA1_DEFAULT_VALUE: &str = "0000000000000000000000000000000000000000";
pub const TIMESTAMP_DEFAULT_VALUE: &str = "2000-01-01-00-00-00";
pub const MAC_DEFAULT_VALUE: &str = "000000000000";
pub const MODEL_NUM_DEFAULT_VALUE: &str = "UNKNOWN";
*/

/// Holds all relevant paths and extensions for dump processing.
#[derive(Debug)]
pub struct DumpPaths {
    pub dump_name: String,
    pub core_path: String,
    pub minidumps_path: String,
    pub core_back_path: String,
    pub persistent_sec_path: String,
    pub working_dir: String,
    pub dumps_extn: String,
    pub tar_extn: String,
    pub lock_dir_prefix: String,
    pub crash_portal_path: String,
    pub ts_file: String,
}

impl DumpPaths {
    /// Creates a new `DumpPaths` instance with default values.
    pub fn new() -> Self {
        Self {
            dump_name: String::new(),
            core_path: String::new(),
            minidumps_path: String::new(),
            core_back_path: String::new(),
            persistent_sec_path: String::new(),
            working_dir: String::new(),
            dumps_extn: String::new(),
            tar_extn: String::new(),
            lock_dir_prefix: String::new(),
            crash_portal_path: String::new(),
            ts_file: String::new(),
        }
    }
    // Getters
    pub fn get_dump_name(&self) -> &str { &self.dump_name }
    pub fn get_core_path(&self) -> &str { &self.core_path }
    pub fn get_minidumps_path(&self) -> &str { &self.minidumps_path }
    pub fn get_core_back_path(&self) -> &str { &self.core_back_path }
    pub fn get_persistent_sec_path(&self) -> &str { &self.persistent_sec_path }
    pub fn get_working_dir(&self) -> &str { &self.working_dir }
    pub fn get_dumps_extn(&self) -> &str { &self.dumps_extn }
    pub fn get_tar_extn(&self) -> &str { &self.tar_extn }
    pub fn get_lock_dir_prefix(&self) -> &str { &self.lock_dir_prefix }
    pub fn get_crash_portal_path(&self) -> &str { &self.crash_portal_path }
    pub fn get_ts_file(&self) -> &str { &self.ts_file }

    // Setters
    pub fn set_dump_name(&mut self, value: impl Into<String>) { self.dump_name = value.into(); }
    pub fn set_core_path(&mut self, value: impl Into<String>) { self.core_path = value.into(); }
    pub fn set_minidumps_path(&mut self, value: impl Into<String>) { self.minidumps_path = value.into(); }
    pub fn set_core_back_path(&mut self, value: impl Into<String>) { self.core_back_path = value.into(); }
    pub fn set_persistent_sec_path(&mut self, value: impl Into<String>) { self.persistent_sec_path = value.into(); }
    pub fn set_working_dir(&mut self, value: impl Into<String>) { self.working_dir = value.into(); }
    pub fn set_dumps_extn(&mut self, value: impl Into<String>) { self.dumps_extn = value.into(); }
    pub fn set_tar_extn(&mut self, value: impl Into<String>) { self.tar_extn = value.into(); }
    pub fn set_lock_dir_prefix(&mut self, value: impl Into<String>) { self.lock_dir_prefix = value.into(); }
    pub fn set_crash_portal_path(&mut self, value: impl Into<String>) { self.crash_portal_path = value.into(); }
    pub fn set_ts_file(&mut self, value: impl Into<String>) { self.ts_file = value.into(); }
}

/// Holds device-specific metadata and configuration.
#[derive(Debug)]
pub struct DeviceData {
    pub device_type: String,
    pub box_type: String,
    pub model_num: String,
    pub sha1: String,
    pub mac_addr: String,
    pub is_t2_enabled: bool,
    pub is_tls_enabled: String,
    pub is_encryption_enabled: bool,
    pub build_type: String,
    pub portal_url: String,
    //pub device_name: String,
}

impl DeviceData {
    /// Creates a new `DeviceData` instance with default values.
    pub fn new() -> Self {
        Self {
            device_type: String::new(),
            box_type: String::new(),
            model_num: String::new(),
            sha1: String::new(),
            mac_addr: String::new(),
            is_t2_enabled: false,
            is_tls_enabled: String::new(),
            is_encryption_enabled: false,
            build_type: String::new(),
            portal_url: String::new(),
            //device_name: String::new(),
        }
    }
    // Getters
    pub fn get_device_type(&self) -> &str { &self.device_type }
    pub fn get_box_type(&self) -> &str { &self.box_type }
    pub fn get_model_num(&self) -> &str { &self.model_num }
    pub fn get_sha1(&self) -> &str { &self.sha1 }
    pub fn get_mac_addr(&self) -> &str { &self.mac_addr }
    pub fn get_is_t2_enabled(&self) -> bool { self.is_t2_enabled }
    pub fn get_is_tls_enabled(&self) -> &str { &self.is_tls_enabled }
    pub fn get_is_encryption_enabled(&self) -> bool { self.is_encryption_enabled }
    pub fn get_build_type(&self) -> &str { &self.build_type }
    pub fn get_portal_url(&self) -> &str { &self.portal_url }
    //pub fn device_name(&self) -> &str { &self.device_name }

    // Setters
    pub fn set_device_type(&mut self, value: impl Into<String>) { self.device_type = value.into(); }
    pub fn set_box_type(&mut self, value: impl Into<String>) { self.box_type = value.into(); }
    pub fn set_model_num(&mut self, value: impl Into<String>) { self.model_num = value.into(); }
    pub fn set_sha1(&mut self, value: impl Into<String>) { self.sha1 = value.into(); }
    pub fn set_mac_addr(&mut self, value: impl Into<String>) { self.mac_addr = value.into(); }
    pub fn set_t2_enabled(&mut self, value: bool) { self.is_t2_enabled = value; }
    pub fn set_tls(&mut self, value: impl Into<String>) { self.is_tls_enabled = value.into(); }
    pub fn set_encryption_enabled(&mut self, value: bool) { self.is_encryption_enabled = value; }
    pub fn set_build_type(&mut self, value: impl Into<String>) { self.build_type = value.into(); }
    pub fn set_portal_url(&mut self, value: impl Into<String>) { self.portal_url = value.into(); }
    //pub fn set_device_name(&mut self, value: impl Into<String>) { self.device_name = value.into(); }
}

/// Enum representing the type of signal received.
pub enum CrashSignal {
    Term,
    Kill,
}
