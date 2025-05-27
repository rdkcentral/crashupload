use std::process::exit;
// standard library imports
use std::fs::create_dir;
use std::os::unix::thread;
use std::path::Path;
use std::{env, fs, process};

use chrono::Local;
use constants::{DeviceData, COREDUMP_MTX_FILE, CRASH_UPLOAD_REBOOT_FLAG, NETWORK_CHECK_TIMEOUT};
use crashupload_utils::*;
use platform_interface::*;
use utils::sleep;

// crashupload internal module imports
mod constants;
mod crashupload_utils;

fn main() {
    println!("Starting Crash Upload Binary...");
    // EXEC: Command line argument parsing
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <integer> <string> <string>", args[0]);
        process::exit(1);
    }

    // EXEC: Instantiate the DumpPaths & DeviceData structs
    println!("Instantiating DumpPaths and DeviceData structs...");
    let mut device_data = constants::DeviceData::new();
    let mut dump_paths = constants::DumpPaths::new();

    crashupload_utils::set_device_data(&mut device_data);

    //let crash_timestamp = utils::get_crash_timestamp();
    let dump_flag = args[1].parse::<u32>().expect("Dump flag must be a number");
    let upload_flag = &args[2];
    let wait_for_lock = &args[3];

    // EXEC: Set the core and minidump paths based on the upload flag
    if upload_flag == "secure" {
        dump_paths.set_core_path("/opt/secure/corefiles".to_string());
        dump_paths.set_minidumps_path("/opt/secure/minidumps".to_string());
    } else {
        dump_paths.set_core_path("/var/lib/systemd/coredump".to_string());
        dump_paths.set_minidumps_path("/opt/minidumps".to_string());
    }

    if crashupload_utils::should_exit_crash_upload(&dump_paths) {
        println!("Crash upload process is already running. Exiting...");
        std::process::exit(0);
    }

    // EXEC: Secure Dump Status & path Set
    //let _ = crashupload_utils::get_secure_dump_status(&mut dump_paths);

    // core_log.txt file logging can be handled using syslog-ng

    // ==============================
    /* TODO: Implementations for below functions
     * logMessage()
     * tlsLog()
     * checkParameter()
     * deleteAllButTheMostRecentFiles() - In progress
     * cleanup()
     * finalize()
     * sigkill_function()
     * sigterm_function()
     * logUploadTimestamp()
     * truncateTimeStampFile()
     * removePendingDumps()
     * markAsCrashLoopedAndUpload()
     * saveDump()
     * shouldProcessFile()
     * get_crashed_log_file()
     * processCrashTelemtryInfo()
     * add_crashed_log_file()
     * copy_log_files_tmp_dir()
     * processDumps()
     */
    // ==============================

    // let timestamp_filename = crashupload_utils::get_timestamp_filename(dump_name);
    let crash_ts = Local::now().format("%Y-%m-%d-%H-%M-%S").to_string();

    if dump_flag == 1 {
        println!("starting core dump processing...");
        dump_paths.dump_name = "coredump".to_string();
        dump_paths.working_dir = dump_paths.get_core_path().to_string();
        dump_paths.dumps_extn = "*core.prog*.gz*".to_string();
        dump_paths.tar_extn = ".core.tgz".to_string();
        dump_paths.lock_dir_prefix = "/tmp/.uploadCoredumps".to_string();
        dump_paths.crash_portal_path = "/opt/crashportal_uploads/coredumps/".to_string();
    } else {
        println!("starting minidump processing...");
        dump_paths.dump_name = "minidump".to_string();
        dump_paths.working_dir = dump_paths.get_minidumps_path().to_string();
        dump_paths.dumps_extn = "*.dmp*".to_string();
        dump_paths.tar_extn = "*.dmp.tgz".to_string();
        dump_paths.lock_dir_prefix = "/tmp/.uploadMinidumps".to_string();
        dump_paths.crash_portal_path = "/opt/crashportal_uploads/coredumps/".to_string();
        sleep(5);
    };
    dump_paths.ts_file = format!("/tmp/.{}_upload_timestamps", dump_paths.dump_name);

    if wait_for_lock == "wait_for_lock" {
        create_lock_or_wait(dump_paths.get_lock_dir_prefix());
    } else {
        create_lock_or_exit(dump_paths.get_lock_dir_prefix());
    }

    if device_data.device_type == "hybrid" || device_data.device_type == "mediaclient" {
        let uptime_str = fs::read_to_string("/proc/uptime").expect("Unable to read uptime");
        let uptime_val = uptime_str
            .split('.')
            .next()
            .unwrap_or("0")
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        if uptime_val < 480 {
            let sleep_time = 480 - uptime_val;
            println!("Deferring reboot for {} seconds", sleep_time);
            sleep(sleep_time);
            if Path::new(CRASH_UPLOAD_REBOOT_FLAG).exists() {
                println!("Process crashed exiting from the Deferring reboot");
            }
        }
    }

    let w_dir = dump_paths.get_working_dir();
    match fs::read_dir(w_dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => {
            eprintln!("working dir is empty : {}", w_dir);
            std::process::exit(0);
        }
    };

    let mut portal_url = String::new();
    get_rfc_param(
        "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl",
        &mut portal_url,
    );
    let req_type = 17;

    let mut counter = 1;
    let mut no_network = false;
    let route_file = Path::new(constants::NETWORK_FILE);

    while counter <= constants::NETWORK_CHECK_ITERATION {
        println!("Check network status count {}", counter);
        if route_file.exists() {
            println!("Network is available");
            break;
        } else {
            println!(
                "Network is not available, Sleep for {} seconds",
                NETWORK_CHECK_TIMEOUT
            );
            sleep(constants::NETWORK_CHECK_TIMEOUT as u64);
            counter += 1;
        }
    }

    if !route_file.exists() {
        println!("Network is not available. tar dump and save it, as max wait reached");
        no_network = true;
    }

    println!("IP Acquisition completed, Check if system time is received");

    let stt_file = Path::new(constants::SYSTEM_TIME_FILE);
    if !stt_file.exists() {
        while counter <= constants::SYSTEM_TIME_ITERATION {
            if !stt_file.exists() {
                println!("Waiting for STT, iteration {}", counter);
                sleep(constants::SYSTEM_TIME_TIMEOUT as u64);
            } else {
                println!("Received {} flag", constants::SYSTEM_TIME_FILE);
                break;
            }

            if counter == constants::SYSTEM_TIME_ITERATION {
                println!("Continue without {} flag", constants::SYSTEM_TIME_FILE);
            }
            counter += 1;
        }
    } else {
        println!("Received {} flag", constants::SYSTEM_TIME_FILE);
    }

    // trap finalize EXIT

    if !Path::new(COREDUMP_MTX_FILE).exists() && dump_flag == 1 {
        println!("Waiting for Coredump completion");
        sleep(21);
    }

    println!("Mac Address is {}", device_data.mac_addr);

    let mut dump_count = 0;
    dump_count = match get_dump_count(&dump_paths.working_dir, &dump_paths.dumps_extn) {
        Ok(e) => e,
        Err(_) => 0,
    };
    if dump_count == 0 {
        println!("No {} for uploading exist", dump_paths.dump_name);
        exit(0);
    }
    let _ = cleanup(
        &dump_paths.working_dir,
        &dump_paths.dump_name,
        &dump_paths.dumps_extn,
    );
    println!("Portal URL is {}", portal_url);
}
