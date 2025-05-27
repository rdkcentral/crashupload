// src/utils.rs
use chrono::{DateTime, Local};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{process, usize};
use std::{thread, time};

use crate::constants::*;
use platform_interface::*;
use utils::*;

fn lock_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut p = path.as_ref().to_path_buf();
    p.set_extension("lock.d");
    p
}

fn is_another_instance_running<P: AsRef<Path>>(path: P) -> bool {
    lock_path(path).is_dir()
}

pub fn set_device_data(device_data: &mut DeviceData) {
    get_property_value_from_file(DEVICE_PROP_FILE, "BOX_TYPE", &mut device_data.box_type);
    get_property_value_from_file(DEVICE_PROP_FILE, "MODEL_NUM", &mut device_data.model_num);
    get_property_value_from_file(DEVICE_PROP_FILE, "DEVICE_TYPE", &mut device_data.device_type);
    get_sha1_value(&mut device_data.sha1);
    let _ = get_device_mac(&mut device_data.mac_addr);
    get_property_value_from_file(DEVICE_PROP_FILE, "BUILD_TYPE", &mut device_data.build_type);
    device_data.t2_enabled = Path::new("/lib/rdk/t2Shared_api.sh").exists();
    device_data.tls = if Path::new("/etc/os-release").exists() {"--tlsv1.2".to_string()} else {"".to_string()};
    device_data.encryption_enabled = if Path::new("/etc/encryption_enabled").exists() {
        set_rfc_param(ENCRYPTION_RFC,"true");
        true
    } else {
        false
    }
}

pub fn should_exit_crash_upload(minidumps_path: &String, core_path: &String) -> bool {
    let minidumps_exists = check_minidumps_exist(&minidumps_path);
    let core_exists = check_core_exist(&core_path);

    !(minidumps_exists || core_exists)
}

fn check_minidumps_exist(minidump_dir: &str) -> bool {
    let path = Path::new(minidump_dir);
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.ends_with(".dmp") || file_name.contains(".dmp") {
                    return true;
                }
            }
        }
    }
    false
}

fn check_core_exist(core_dir: &str) -> bool {
    let path = Path::new(core_dir);
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if file_name.contains("_core") {
                    return true;
                }
            }
        }
    }
    false
}

pub fn set_log_file(device_data: &DeviceData, log_mod_ts: &str, line: &str) {
    let file_name = line.split('/').last().unwrap_or_else(|| line);
    let file_processed = file_name.contains("_mac")
        || file_name.contains("_dat")
        || file_name.contains("_box")
        || file_name.contains("_mod");
    if file_processed {
        println!("{}", file_name);
        println!("Core name is already processed");
    } else {
        println!(
            "{}_mac{}_dat{}_box{}_mod{}_{}",
            device_data.sha1,
            device_data.mac_addr,
            log_mod_ts,
            device_data.box_type,
            device_data.model_num,
            file_name
        );
    }
}

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

pub fn get_secure_dump_status(dump_paths: &mut DumpPaths) {
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
        dump_paths.set_core_path("/var/lib/systemd/coredump".to_string());
        dump_paths.set_minidumps_path("/opt/minidumps".to_string());
        dump_paths.set_core_back_path("/opt/corefiles_back".to_string());
        dump_paths.set_persistent_sec_path("/opt".to_string());
    } else {
        if !Path::new(SECUREDUMP_ENABLE_FILE).exists() {
            touch(SECUREDUMP_ENABLE_FILE);
            println!("[SECUREDUMP] Enabled. Dump location changed to /opt/secure.");
        }
        if Path::new(SECUREDUMP_DISABLE_FILE).exists() {
            rm(SECUREDUMP_DISABLE_FILE);
        }
        dump_paths.set_core_path("/opt/secure/corefiles".to_string());
        dump_paths.set_minidumps_path("/opt/secure/minidumps".to_string());
        dump_paths.set_core_back_path("/opt/secure/corefiles_back".to_string());
        dump_paths.set_persistent_sec_path("/opt/secure".to_string());
    }
}

pub fn create_lock_or_exit<P: AsRef<Path>>(path: P) -> bool {
    let lock = lock_path(&path);
    if is_another_instance_running(&path) {
        println!(
            "Script is already working. {:?}. Skip launching another instance...",
            lock
        );
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
            println!(
                "Script is already working. {:?}. Waiting to launch another instance...",
                lock
            );
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

pub fn is_box_rebooting() -> bool {
    if Path::new(CRASH_UPLOAD_REBOOT_FLAG).exists() {
        println!("Skipping Upload, Since Box is Rebooting now...");
        t2_count_notify("SYST_INFO_CoreUpldSkipped", None::<&str>);
        println!("Upload will happen on next reboot");
        return true;
    }
    false
}

pub fn sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|c| match *c {
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
            | '-' => true,
            _ => false,
        })
        .collect()
}

pub fn is_upload_limit_reached(ts_file: &String) -> bool {
    let limit_seconds = 600;
    if let Err(err) = OpenOptions::new().create(true).append(true).open(ts_file) {
        eprintln!("Failed to create or open {}: {}", ts_file, err);
        return false;
    }

    let mut file = match File::open(ts_file) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut reader: BufReader<&File> = BufReader::new(&file);

    let line_count = reader.by_ref().lines().count();
    if line_count < 10 {
        return false;
    }

    let _ = file.seek(SeekFrom::Start(0));

    let mut reader = BufReader::new(&file);
    let mut first_line = String::new();
    let _ = reader.read_line(&mut first_line);

    let tenth_newest_crash_time: u64 = first_line
        .split_whitespace()
        .next()
        .expect("No data in first line")
        .parse()
        .expect("Failed to parse timestamp");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH")
        .as_secs();

    if (now - tenth_newest_crash_time) < limit_seconds {
        println!("Not uploading the dump. Too many dumps.");
        return true;
    }
    false
}

pub fn set_recovery_time() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH")
        .as_secs();
    let dont_upload_for_sec = 600;
    let recovery_time = now + dont_upload_for_sec;
    let _ = fs::write(DENY_UPLOAD_FILE, recovery_time.to_string());
}

pub fn is_recovery_time_reached() -> bool {
    if !Path::new(DENY_UPLOAD_FILE).exists() {
        return true;
    }
    let content = match fs::read_to_string(DENY_UPLOAD_FILE) {
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

pub fn delete_all_but_most_recent_files<P: AsRef<str>>(
    dir_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir_path.as_ref());
    let mut files: Vec<(PathBuf, SystemTime)> = fs::read_dir(path)?
        .filter_map(|entry| {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => return None,
            };
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => return None,
            };
            let modified = match metadata.modified() {
                Ok(time) => time,
                Err(_) => return None,
            };
            Some((entry.path(), modified))
        })
        .collect();

    files.sort_by(|a, b| b.1.cmp(&a.1));

    // Calculate number of files to delete
    if files.len() > MAX_CORE_FILES {
        let num_files_to_delete = files.len() - MAX_CORE_FILES;

        // Delete the oldest files
        for (file_path, _) in files.iter().rev().take(num_files_to_delete) {
            fs::remove_file(file_path)?;
            println!("Deleted file: {:?}", file_path);
        }
    } else {
        println!("No files need to be deleted. Total files: {}", files.len());
    }
    Ok(())
}

pub fn finalize(dump_paths: &DumpPaths) {
    let _ = cleanup(
        &dump_paths.working_dir,
        &dump_paths.dump_name,
        &dump_paths.dumps_extn,
    );
    let loop_file = Path::new(CRASH_LOOP_FLAG_FILE);
    if loop_file.exists() {
        rm_rf(loop_file);
    }
    remove_lock(&dump_paths.lock_dir_prefix);
    remove_lock(&dump_paths.ts_file);
}

pub fn sig_term_function(dump_paths: &DumpPaths) {
    println!("systemd terminating, Removing the script locks");
    let loop_file = Path::new(CRASH_LOOP_FLAG_FILE);
    if loop_file.exists() {
        rm_rf(loop_file);
    }
    remove_lock(&dump_paths.lock_dir_prefix);
    remove_lock(&dump_paths.ts_file);
}

pub fn sig_kill_function(dump_paths: &DumpPaths) {
    println!("systemd killing, Removing the script locks");
    let loop_file = Path::new(CRASH_LOOP_FLAG_FILE);
    if loop_file.exists() {
        rm_rf(loop_file);
    }
    remove_lock(&dump_paths.lock_dir_prefix);
    remove_lock(&dump_paths.ts_file);
}

pub fn should_process_dump<P: AsRef<str>>(
    dump_name: &String,
    device_type: &String,
    file_name: P,
) -> bool {
    let f_name = file_name.as_ref();
    let status = if dump_name == "minidump"
        || device_type != "prod"
        || f_name.contains("Receiver")
    {
        true
    } else {
        println!("Not Processing dump file {}", f_name);
        false
    };
    status
}

pub fn get_dump_count(path: &String, extn: &String) -> io::Result<usize> {
    let mut count = 0;
    let dir_path = Path::new(path);

    if dir_path.exists() && dir_path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(ext) = file_path.extension() {
                    if ext.to_string_lossy() == extn.to_string() {
                        count += 1;
                    }
                }
            }
        }
    }
    Ok(count)
}

pub fn cleanup(work_dir: &String, dump_name: &String, dump_extn: &String) -> io::Result<()> {
    let work_dir_path = Path::new(work_dir);

    if !work_dir_path.exists()
        || !work_dir_path.is_dir()
        || work_dir_path.read_dir()?.next().is_none()
    {
        println!("Working directory {} is empty", work_dir);
        return Ok(());
    }

    println!("Cleanup {} directory {}", dump_name, work_dir);

    let cut_off_time = SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 2); // 2 days
    for entry in fs::read_dir(work_dir_path)? {
        let entry = entry?;
        let file_path = entry.path();
        if file_path.is_file() {
            if let Some(file_name) = file_path.file_name() {
                let file_name_str = file_name.to_string_lossy();

                // _mac comes befire _dat in the wildcard matching
                if let Some(mac_pos) = file_name_str.find("_mac") {
                    if let Some(dat_pos) = file_name_str.find("_dat") {
                        if mac_pos < dat_pos {
                            let metadata = fs::metadata(&file_path)?;
                            if let Ok(modified_time) = metadata.modified() {
                                if modified_time < cut_off_time {
                                    fs::remove_file(&file_path)?;
                                    println!("Removed file: {}", file_path.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // find and while loop logic
    if !Path::new(UPLOAD_ON_STARTUP).exists() {
        rm_rf(format!("{}/version.txt", work_dir));
        let on_startup_dumps_cleaned_up_str = format!(
            "{}_{}",
            ON_STARTUP_DUMPS_CLEANED_UP_BASE,
            if dump_name == "coredump" { "1" } else { "" }
        );
        let on_startup_dumps_cleaned_up_path = Path::new(&on_startup_dumps_cleaned_up_str);

        if !on_startup_dumps_cleaned_up_path.exists() {
            let path = Path::new(UPLOAD_ON_STARTUP);

            let mut deleted_files = Vec::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let file_path = entry.path();

                if file_path.is_file() {
                    if let Some(file_name) = file_path.file_name() {
                        let file_name_str = file_name.to_string_lossy();

                        if let Some(mac_pos) = file_name_str.find("_mac") {
                            if let Some(dat_pos) = file_name_str.find("_dat") {
                                if mac_pos < dat_pos {
                                    fs::remove_file(&file_path)?;
                                    deleted_files.push(file_path.to_string_lossy().into_owned());
                                }
                            }
                        }
                    }
                }
            }
            println!("Deleting unfinished files: {:?}", deleted_files);

            let mut non_dump_files = Vec::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Some(ext) = file_path.extension() {
                        if ext.to_string_lossy() != dump_extn.as_str() {
                            fs::remove_file(&file_path)?;
                            non_dump_files.push(file_path.to_string_lossy().into_owned());
                        }
                    }
                }
            }
            println!("Deleting non-dump files: {:?}", non_dump_files);
            let _ = delete_all_but_most_recent_files(path.to_str().unwrap_or_default());
            touch(on_startup_dumps_cleaned_up_str.as_str());
        }
    } else {
        if dump_name == "coredump" {
            rm_rf(UPLOAD_ON_STARTUP);
        }
    }
    Ok(())
}

pub fn remove_pending_dumps(path: &String, extn: &String) -> io::Result<()> {
    let dir_path = Path::new(path);

    if dir_path.exists() && dir_path.is_dir() {
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(ext) = file_path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if ext_str == extn.as_str() || ext_str == "tgz" {
                        println!("Removing {} because upload limit has reached or build is blacklisted or TelemetryOptOut is set", file_path.display());
                        rm_rf(path);
                    }
                }
            }
        }
    }
    Ok(())
}

fn process_crash_t2_info(file_path: &String) {
    println!("Processing the crash telemetry info");
    let file = Path::new(file_path);
    let mut file_name_str = file_path.clone();
    let container_delimiter = "<#=#>";
    let backward_delimiter = "-";
    let mut is_tar = false;
    let extension = file.extension().and_then(OsStr::to_str);

    if extension == Some("tgz") {
        println!("The File is already a tarball, this might be a retry or crash during shutdown");
        is_tar = true;

        if let Some(pos) = file_name_str.find("_mod_") {
            file_name_str = file_name_str.split_off(pos + "_mod_".len());
        }
        println!("Original Filename: {}", file.display());
        println!(
            "Removing the meta information New Filename: {}",
            file_name_str
        );
        println!("This could be a retry or crash from previous boot the appname can be truncated");
        t2_count_notify("SYS_INFO_TGZDUMP", Some("1"));
    }
    let mut is_container = false;
    if file_name_str.contains(container_delimiter) {
        is_container = true;

        let parts: Vec<&str> = file_name_str.split(container_delimiter).collect();
        println!("From the file name crashed process is a container");

        if parts.len() >= 2 {
            let container_name = parts[0];
            let container_time = parts[1];

            let (container_status, file): (String, String) = if parts.len() > 2 {
                (parts[1].to_string(), container_name.to_string())
            } else {
                ("unknown".to_string(), container_name.to_string())
            };

            let app_name = container_name.split('_').nth(1).unwrap_or(container_name);
            let process_name = container_name.split('_').next().unwrap_or(container_name);
            t2_val_notify("crashedContainerName_split", container_name);
            t2_val_notify("crashedContainerStatus_split", &container_status);
            t2_val_notify("crashedContainerAppname_split", app_name);
            t2_val_notify("crashedContainerProcessName_split", process_name);
            t2_count_notify("SYS_INFO_CrashedContainer", Some("1"));

            println!("Container crash info Basic: {}, {}", app_name, process_name);
            println!(
                "Container crash info Advanced: {}, {}",
                container_name, container_status
            );
            println!(
                "NEW Appname, Process_Crashed, Status = {}, {}, {}",
                app_name, process_name, container_status
            );
            println!(
                "NEW Processname, App Name, AppState = {}, {}, {}",
                process_name, app_name, container_status
            );
            println!(
                "ContainerName, ContainerStatus = {}, {}",
                container_name, container_status
            );
            println!(
                "NewProcessCrash_split {}, {}",
                container_name, container_status
            );
        }
    }
    let _ = get_crashed_log_file(&file_name_str);
}

/*
// ============================================ In Progress Start ============================================
// TODO: Implement this function
pub fn mark_as_crash_loop_and_upload() {
}

// TODO: Implement this function
pub fn process_dump(dump_paths: &DumpPaths) {

}

pub fn add_crashed_log_file(device_data: &DeviceData) {
    let files = vec!["file1", "file2", "file3"]; // Update

    let mut line_count = 5000;
    if device_data.build_type == "prod" {
        line_count = 500;
    }


}

pub fn copy_log_files_to_tmp(tmp_dir: &String) {
    let tmp_directory = format!("/tmp{}",tmp_dir).as_str();
    let res = 0;
    let limit = 70;
    let mut usage_percent = 0;

    let tmp_path = Path::new("/tmp");

    if tmp_path.is_dir() {
        usage_percent = get_usage_percent(tmp_path);
    }
    else{
        println!("{} is not a directory", tmp_path.display());
    }

    if usage_percent > limit {
        println!("Skipping copying Logs to tmp dir due to limited Memory");
        // TODO
    }
    else {
        println!("Copying logs to tmp dir as Memory available. used size = {}% limit = {}%", usage_percent, limit);
        /* mkdir $TmpDirectory 2> /dev/null
          cp $Logfiles $TmpDirectory 2> /dev/null
        */
        println!("Logs copied to {} Temporary", tmp_directory);

        // Loop

    }

}
// pub fn save_dump(dump_paths: &DumpPaths, new_name: Option<&str>) {
//     if let Some(new_name) = new_name {
//         let original_path = Path::new(&dump_paths.minidumps_path).join(&dump_paths.tar_extn);
//         let new_path = Path::new(&dump_paths.minidumps_path).join(new_name);
//     }

//     let dump_files: Vec<PathBuf> = fs::read_dir(&dump_paths.minidumps_path)?
//         .filter_map(|entry| {
//             let entry = entry.ok()?;
//             let file_type = entry.file_type().ok()?;
//             if file_type.is_file() && entry.path().extension() == Some("tgz".as_ref()) {
//                 Some(entry.path())
//             } else {
//                 None
//             }
//         })
//         .collect();
//     let mut count = dump_files.len();
//     while count > 5 {
//         if let Some(oldest_dump) = dump_files.iter()
//             .min_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH)) {

//             println!("Removing old dump {:?}", oldest_dump);
//             fs::remove_file(oldest_dump)?;

//             count -= 1; // Decrement count
//         }
//     }
//     println!("Total pending Minidumps: {}", count);
// }

*/
// =========================================== In Progress End ============================================

pub fn log_upload_timestamp(ts_file: &String) {
    let mut dev_type = String::new();
    get_property_value_from_file("/etc/device.properties", "BUILD_TYPE", &mut dev_type);
    if dev_type == "prod" {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX_EPOCH")
            .as_secs();

        let _ = fs::write(ts_file, now.to_string());
        let _ = truncate_timestamp_file(ts_file);
    }
}

fn truncate_timestamp_file(ts_file: &String) -> io::Result<()> {
    let ts_path = Path::new(ts_file);

    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(ts_path);
    let file = fs::File::open(ts_path)?;
    let reader = io::BufReader::new(file);

    let lines: Vec<String> = reader
        .lines()
        .map(|line| line.unwrap_or_default())
        .collect();
    let last_10_lines: Vec<String> = lines.iter().rev().take(10).cloned().collect();
    let mut tmp_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(ts_path)?;

    for line in last_10_lines {
        writeln!(tmp_file, "{}", line)?;
    }
    Ok(())
}

pub fn get_last_modified_time_of_file<P: AsRef<str>>(path: P) -> Option<String> {
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

fn get_crashed_log_file<P: AsRef<str>>(file_path: P) -> io::Result<()> {
    let file = file_path.as_ref();

    let process_name = file
        .rsplitn(2, '_')
        .nth(1)
        .unwrap_or(file)
        .trim_start_matches("./");
    println!("Process crashed = {}", process_name);

    let app_name = file
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
    println!("Crashed process log file(s): {}", log_files);
    if !app_name.is_empty() {
        println!("Appname, Process_Crashed = {} {}", app_name, process_name);
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
