// src/constants.rs
pub const LOGMAPPER_FILE: &str = "/etc/breakpad-logmapper.conf";
pub const LOG_FILES: &str = "/tmp/minidump_log_files.txt";
pub const LOG_PATH: &str = "/opt/rdk";
pub const CORE_LOG: &str = "/opt/rdk/core_log.txt";

pub const S3_BUCKET_URL: &str = "s3.amazonaws.com";
pub const HTTP_CODE_FILE: &str = "/tmp/httpcode";
pub const CURL_UPLOAD_TIMEOUT: usize = 45;
pub const FOUR_EIGHTY_SECS: usize = 480;
pub const MAX_CORE_FILES: usize = 4;

pub const TLS: &str = "--tlsv1.2";

pub const enable_oscp_stapling: &str = "/tmp/.EnableOCSPStapling";
pub const enable_oscp: &str = "/tmp/.EnableOCSPCA";

pub const SECUREDUMP_TR181_NAME: &str = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SecDump.Enable";
pub const SECUREDUMP_ENABLE_FILE: &str = "/tmp/.SecureDumpEnable";
pub const SECUREDUMP_DISABLE_FILE: &str = "/tmp/.SecureDumpDisable";
pub const CRASH_UPLOAD_REBOOT_FLAG: &str = "/tmp/set_crash_reboot_flag";
pub const DENY_UPLOAD_FILE: &str = "/tmp/.deny_dump_uploads_till";

pub struct DumpPaths {
    pub core_path: String,
    pub minidumps_path: String,
    pub core_back_path: String,
    pub persistent_sec_path: String,
    pub working_dir: String,
    pub dumps_extn: String,
    pub tar_extn: String,
    pub lock_dir_prefix: String,
    pub crash_portal_path: String,
}

impl DumpPaths {
    pub fn set_core_path(&mut self, path: String) {
        self.core_path = path;
    }
    pub fn set_minidumps_path(&mut self, path: String) {
        self.minidumps_path = path;
    }
    pub fn set_core_back_path(&mut self, path: String) {
        self.core_back_path = path;
    }
    pub fn set_persistent_sec_path(&mut self, path: String) {
        self.persistent_sec_path = path;
    }
    pub fn get_core_path(&self) -> &String {
        &self.core_path
    }
    pub fn get_minidumps_path(&self) -> &String {
        &self.minidumps_path
    }
    pub fn get_core_back_path(&self) -> &String {
        &self.core_back_path
    }
    pub fn get_persistent_sec_path(&self) -> &String {
        &self.persistent_sec_path
    }
    pub fn get_working_dir(&self) -> &String {
        &self.working_dir
    }
    pub fn set_working_dir(&mut self, path: String) {
        self.working_dir = path;
    }
    pub fn get_dumps_extn(&self) -> &String {
        &self.dumps_extn
    }
    pub fn set_dumps_extn(&mut self, extn: String) {
        self.dumps_extn = extn;
    }
    pub fn get_tar_extn(&self) -> &String {
        &self.tar_extn
    }
    pub fn set_tar_extn(&mut self, extn: String) {
        self.tar_extn = extn;
    }
    pub fn get_lock_dir_prefix(&self) -> &String {
        &self.lock_dir_prefix
    }
    pub fn set_lock_dir_prefix(&mut self, prefix: String) {
        self.lock_dir_prefix = prefix;
    }
    pub fn get_crash_portal_path(&self) -> &String {
        &self.crash_portal_path
    }
    pub fn set_crash_portal_path(&mut self, path: String) {
        self.crash_portal_path = path;
    }
    /// Creates a new `DumpPaths` instance with default values.
    pub fn new() -> Self {
        DumpPaths {
            core_path: String::new(),
            minidumps_path: String::new(),
            core_back_path: String::new(),
            persistent_sec_path: String::new(),
            working_dir: String::new(),
            dumps_extn: String::new(),
            tar_extn: String::new(),
            lock_dir_prefix: String::new(),
            crash_portal_path: String::new(),
        }
    }
}
