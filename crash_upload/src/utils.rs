// src/utils.rs
use std::{path::Path};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;

use platform_interface::*;
use utils::*;

// Module-level constants
const SECUREDUMP_TR181_NAME: &str = "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.SecDump.Enable";
const SECUREDUMP_ENABLE_FILE: &str = "/tmp/.SecureDumpEnable";
const SECUREDUMP_DISABLE_FILE: &str = "/tmp/.SecureDumpDisable";
const CRASH_UPLOAD_REBOOT_FLAG: &str = "/tmp/set_crash_reboot_flag";
const DENY_UPLOAD_FILE: &str = "/tmp/.deny_dump_uploads_till";
const SHA1_DEFAULT_VALUE: &str = "0000000000000000000000000000000000000000";
const TIMESTAMP_DEFAULT_VALUE: &str ="2000-01-01-00-00-00";
const MAC_DEFAULT_VALUE: &str ="000000000000";
const MODEL_NUM_DEFAULT_VALUE: &str ="UNKNOWN";

pub struct DumpPaths{
    pub core_path: String,
    pub minidumps_path: String,
    pub core_back_path: String,
    pub persistent_sec_path: String,
}

fn set_secure_dump_flag(is_sec_dump_enabled: &mut bool) {
    if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
        *is_sec_dump_enabled = true;
    } 
    else if Path::new(SECUREDUMP_DISABLE_FILE).exists() 
    {
        *is_sec_dump_enabled = false;
    } 
    else 
    {
        let mut rfc_value = String::new();
        if get_rfc_param(SECUREDUMP_TR181_NAME, &mut rfc_value) {
            *is_sec_dump_enabled = rfc_value.trim().eq_ignore_ascii_case("true");
        }
    }
}

pub fn get_secure_dump_status() -> DumpPaths {
    let mut is_sec_dump_enabled = false;
    set_secure_dump_flag(&mut is_sec_dump_enabled);

    if !is_sec_dump_enabled {
        if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            touch(SECUREDUMP_DISABLE_FILE);
            println!("[SECUREDUMP] Disabled");
        }
        if Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            rm(SECUREDUMP_ENABLE_FILE);
        }
         DumpPaths {
            core_path: "/var/lib/systemd/coredump".to_string(),
            minidumps_path: "/opt/minidumps".to_string(),
            core_back_path: "/opt/corefiles_back".to_string(),
            persistent_sec_path: "/opt".to_string(),
        }
    }
    else {
        if !Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            touch(SECUREDUMP_ENABLE_FILE);
            println!("[SECUREDUMP] Enabled. Dump location changed to /opt/secure.");
        }
        if Path::new(SECUREDUMP_DISABLE_FILE).exists() {
            rm(SECUREDUMP_DISABLE_FILE);
        }

        DumpPaths {
            core_path: "/opt/secure/corefiles".to_string(),
            minidumps_path: "/opt/secure/minidumps".to_string(),
            core_back_path: "/opt/secure/corefiles_back".to_string(),
            persistent_sec_path: "/opt/secure".to_string(),
        }
    }
}

pub fn is_box_rebooting() -> bool {
    if Path::new(CRASH_UPLOAD_REBOOT_FLAG).exists() {
        println!("Skipping Upload, Since Box is Rebooting now...");
        t2_count_notify("SYST_INFO_CoreUpldSkipped", None::<&str>);
        println!("Upload will happen on next reboot");
        return true;
    }
    false
}

pub fn set_recovery_time() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("SystemTime before UNIX_EPOCH").as_secs();
    let dont_upload_for_sec = 600;
    let recovery_time = now + dont_upload_for_sec;
    fs::write(DENY_UPLOAD_FILE, recovery_time.to_string());

}

pub fn is_recovery_time_reached() -> bool {
    if !Path::new(DENY_UPLOAD_FILE).exists() {
        return true;
    }
    let content = match fs::read_to_string(DENY_UPLOAD_FILE){
        Ok(val) => val.trim().to_string(),
        Err(_) => return true,
    };

    let upload_denied_till = match content.parse::<u64>() {
        Ok(val) => val,
        Err(_) => return true
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    now > upload_denied_till
}

