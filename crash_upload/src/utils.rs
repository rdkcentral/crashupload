// src/utils.rs
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use std::process;
use chrono::{DateTime, Local};

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
const LOGMAPPER_FILE: &str = "/etc/breakpad-logmapper.conf";
const LOG_FILES: &str = "/tmp/minidump_log_files.txt";
const LOG_PATH: &str = "/opt/rdk";

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

pub fn get_timestamp_filename(dump_name: &str) -> String {
    format!("/tmp/.{}_upload_timestamps", dump_name)
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
    let _ = fs::write(DENY_UPLOAD_FILE, recovery_time.to_string());
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

fn lock_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut p = path.as_ref().to_path_buf();
    p.set_extension("lock.d");
    p
}

fn is_another_instance_running<P: AsRef<Path>>(path: P) -> bool {
    lock_path(path).is_dir()
}

pub fn create_lock_or_exit<P: AsRef<Path>>(path: P) -> bool {
    let lock = lock_path(&path);
    if is_another_instance_running(&path) {
        println!("Script is already working. {:?}. Skip launching another instance...", lock);
        process::exit(0);
    }

    match fs::create_dir(&lock) {
        Ok(_) => true,
        Err(err) => {
            println!("Error creating {:?}: {}", lock, err);
            false
        }
    }
}

pub fn create_lock_or_wait<P: AsRef<Path>>(path: P) -> bool {
    let lock = lock_path(&path);
    loop {
        if is_another_instance_running(&path) {
            println!("Script is already working. {:?}. Waiting to launch another instance...", lock);
            thread::sleep(time::Duration::from_secs(2));
            continue;
        }

        match fs::create_dir(&lock) {
            Ok(_) => return true,
            Err(err) => {
                println!("Error creating {:?}: {}", lock, err);
                return false;
            }
        }
    }
}

pub fn remove_lock<P: AsRef<Path>>(path: P) {
    let lock = lock_path(&path);
    if lock.is_dir() {
        if let Err(err) = fs::remove_dir(&lock) {
            println!("Error deleting {:?}: {}", lock, err);
        }
    }
}

pub fn sanitize(input: &str) -> String {
    input.chars().filter(|c| match *c {
            'a'..='z' | 'A'..='Z' | '0'..='9' |
            '/' | ' ' | ':' | '+' | '.' | '_' | ',' | '=' | '-' => true,
            _ => false,
        }).collect()
}

pub fn upload_timestamp(ts_file: &String) {
    let mut dev_type = String::new();
    get_property_value_from_file("/etc/device.properties", "BUILD_TYPE", &mut dev_type);
    if dev_type == "prod" {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("SystemTime before UNIX_EPOCH").as_secs();
        
        let _ = fs::write(ts_file, now.to_string());
        truncate_timestamp_file(ts_file);
    }
}

pub fn truncate_timestamp_file(ts_file: &String) {
    if let Err(err) = OpenOptions::new().create(true).append(true).open(ts_file) {
        eprintln!("Failed to create or open {}: {}", ts_file, err);
        return;
    }

    let file = match File::open(ts_file) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("Error opening file {}: {}", ts_file, err);
            return;
        }
    };
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();

    // Take the last 10 lines
    let last_10_lines = lines.iter().rev().take(10).cloned().collect::<Vec<String>>();
    let last_10_lines = last_10_lines.into_iter().rev().collect::<Vec<String>>();

    // Write to temporary file
    let tmp_file_path = format!("{}_tmp", ts_file);
    match File::create(&tmp_file_path) {
        Ok(tmp_file) => {
            let mut writer = BufWriter::new(tmp_file);
            for line in last_10_lines {
                if let Err(err) = writeln!(writer, "{}", line){
                    eprintln!("Failed to write to temp file: {}", err);
                    return;
                }
            }
        }
        Err(err) => {
            eprintln!("Failed to create temp file {}: {}", tmp_file_path, err);
            return;
        }
    }

    // Replace original with temp file
    if let Err(err) = fs::rename(&tmp_file_path, ts_file) {
        eprintln!("Failed to replace original file with temp file: {}", err);
    }
}

pub fn is_upload_limit_reached(ts_file: &String) -> bool {
    let limit_seconds = 600;
        if let Err(err) = OpenOptions::new().create(true).append(true).open(ts_file) {
        eprintln!("Failed to create or open {}: {}", ts_file, err);
        return false;
    }

    let mut file = match File::open(ts_file){
        Ok(f) => f,
        Err(_) => return false
    };
    let mut reader: BufReader<&File> = BufReader::new(&file);

    let line_count = reader.by_ref().lines().count();
    if line_count < 0 { return false; }

    let _ = file.seek(SeekFrom::Start(0));

    let mut reader = BufReader::new(&file);
    let mut first_line = String::new();
    let _ = reader.read_line(&mut first_line);

    let tenth_newest_crash_time: u64 = first_line.split_whitespace().next().expect("No data in first line").parse().expect("Failed to parse timestamp");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("SystemTime before UNIX_EPOCH").as_secs();

    if (now - tenth_newest_crash_time) < limit_seconds {
        println!("Not uploading the dump. Too many dumps.");
        return true;
    }
    false
}

pub fn get_last_modified_time_of_file<P: AsRef<str>>(path: P) -> Option<String>{
    let path_ref = Path::new(path.as_ref());

    if !path_ref.is_file() {
        return None;
    }
    let metadata = fs::metadata(path_ref).ok()?;
    let modified_time: SystemTime = metadata.modified().ok()?;
    // NOTE: this can be done with std::process::Command as well 
    let datetime: DateTime<Local> = modified_time.into();

    Some(datetime.format("%Y-%m-%d-%H-%M-%S").to_string())
}

//pub fn process_crash_t2_info<P: AsRef<str>>(file_path: P) {
// TODO:
//}

fn get_crashed_log_file<P: AsRef<str>>(file_path: P) -> io::Result<()>{
    let file = file_path.as_ref();

    let process_name = file.rsplitn(2, '_').nth(1).unwrap_or(file).trim_start_matches("./");
    println!("Process crashed = {}", process_name);

    let app_name = file.split('_').nth(1).and_then(|s| s.split('-').next()).unwrap_or("");
    
    let breakpad_mapper = BufReader::new(File::open(LOGMAPPER_FILE)?);
    let mut log_files = String::new();
    for line in breakpad_mapper.lines() {
        let line = line?;
        if let Some((key, val)) = line.split_once('='){
            if key.contains(process_name){
                log_files = val.to_string();
                break;
            }
        }
    }
    println!("Crashed process log file(s): {}", log_files);
    if !app_name.is_empty() {
        println!("Appname, Process_Crashed = {} {}", app_name, process_name);
    }
    // Write each log file to LOG_FILES
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILES)?;

    for log_file in log_files.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        writeln!(output, "{}/{}", LOG_PATH, log_file)?;
    }

    Ok(())
}
    