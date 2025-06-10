use std::process::exit;
// standard library imports
use std::path::Path;
use std::time::Duration;
use std::{env, fs, process, thread};

// external crate imports
use chrono::Local;

// crashupload internal module imports
mod constants;
mod crashupload_utils;

// Utility crates
use crashupload_utils::*;

fn main() {
    println!("Starting Crash Upload Binary...");

    // TODO: Signal handling (trap/finalize on SIGTERM/SIGKILL/EXIT)

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Usage: {} <integer> <string> <string>", args[0]);
        process::exit(1);
    }

    let dump_flag = args[1].parse::<u32>().expect("Dump flag must be a number");
    let upload_flag = &args[2];
    let wait_for_lock = &args[3];

    // Instantiate configuration structs
    println!("Instantiating DumpPaths and DeviceData instances...");
    let mut device_data = constants::DeviceData::new();
    let mut dump_paths = constants::DumpPaths::new();

    // Populate device data from system properties
    crashupload_utils::set_device_data(&mut device_data);

    // Set dump paths based on upload flag
    if upload_flag == "secure" {
        dump_paths.set_core_path("/opt/secure/corefiles");
        dump_paths.set_minidumps_path("/opt/secure/minidumps");
    } else {
        dump_paths.set_core_path("/var/lib/systemd/coredump");
        dump_paths.set_minidumps_path("/opt/minidumps");
    }

    // Exit early if no dumps exist
    if crashupload_utils::should_exit_crash_upload(dump_paths.get_minidumps_path(), dump_paths.get_core_path()) {
        println!("Crash upload process is already running. Exiting...");
        exit(0);
    }

    // Set secure dump status if needed
    crashupload_utils::get_secure_dump_status(&mut dump_paths);

    // Generate crash timestamp
    let crash_ts = Local::now().format("%Y-%m-%d-%H-%M-%S").to_string();
    
    // Configure dump paths and metadata based on dump_flag
    if dump_flag == 1 {
        println!("starting core dump processing...");
        dump_paths.set_dump_name("coredump");
        let core_path = dump_paths.get_core_path().to_string();
        dump_paths.set_working_dir(&core_path);
        dump_paths.set_dumps_extn("*core.prog*.gz*");
        dump_paths.set_tar_extn(".core.tgz");
        dump_paths.set_lock_dir_prefix("/tmp/.uploadCoredumps");
        dump_paths.set_crash_portal_path("/opt/crashportal_uploads/coredumps/");
    } else {
        println!("Starting minidump processing...");
        dump_paths.set_dump_name("minidump");
        let minidumps_path = dump_paths.get_minidumps_path().to_string();
        dump_paths.set_working_dir(&minidumps_path);
        dump_paths.set_dumps_extn("*.dmp*");
        dump_paths.set_tar_extn("*.dmp.tgz");
        dump_paths.set_lock_dir_prefix("/tmp/.uploadMinidumps");
        dump_paths.set_crash_portal_path("/opt/crashportal_uploads/coredumps/");
        thread::sleep(Duration::from_secs(5));
    };
    dump_paths.set_ts_file(format!("/tmp/.{}_upload_timestamps", dump_paths.get_dump_name()));

    // Locking logic
    if wait_for_lock == "wait_for_lock" {
        create_lock_or_wait(dump_paths.get_lock_dir_prefix());
    } else {
        create_lock_or_exit(dump_paths.get_lock_dir_prefix(), device_data.get_is_t2_enabled());
    }

    // Defer upload if device just booted (hybrid/mediaclient)
    let tmp_device_type = device_data.get_device_type();
    if tmp_device_type == "hybrid" || tmp_device_type == "mediaclient" {
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
            thread::sleep(Duration::from_secs(sleep_time));
            if Path::new(constants::CRASH_UPLOAD_REBOOT_FLAG).exists() {
                println!("Process crashed exiting from the Deferring reboot");
                finalize(&dump_paths); // TODO: Should we finalize & exit?
                exit(0);
            }
        }
    }
    
    // Check if working directory is empty
    let w_dir = dump_paths.get_working_dir();
    match fs::read_dir(w_dir) {
        Ok(mut entries) => { 
            if entries.next().is_none() {
                println!("Working dir is empty: {}", w_dir);
                finalize(&dump_paths); // TODO: Should we finalize & exit?
                exit(0);
            }
        }
        Err(_) => {
            println!("working dir is empty : {}", w_dir);
            finalize(&dump_paths); // TODO: Should we finalize & exit?
            exit(0);
        }
    };

    // Network availability check
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
                constants::NETWORK_CHECK_TIMEOUT
            );
            thread::sleep(Duration::from_secs(constants::NETWORK_CHECK_TIMEOUT as u64));
            counter += 1;
        }
    }

    if !route_file.exists() {
        println!("Network is not available. tar dump and save it, as max wait reached");
        no_network = true;
    }

    // System time availability check
    println!("IP Acquisition completed, Check if system time is received");
    let stt_file = Path::new(constants::SYSTEM_TIME_FILE);
    if !stt_file.exists() {
        while counter <= constants::SYSTEM_TIME_ITERATION {
            if !stt_file.exists() {
                println!("Waiting for STT, iteration {}", counter);
                thread::sleep(Duration::from_secs(constants::SYSTEM_TIME_TIMEOUT as u64));
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

    // Wait for coredump completion if needed
    if !Path::new(constants::COREDUMP_MTX_FILE).exists() && dump_flag == 1 {
        println!("Waiting for Coredump completion");
        thread::sleep(Duration::from_secs(21));
    }

    // Early exit if box is rebooting
    if is_box_rebooting(device_data.get_is_t2_enabled()) {
        finalize(&dump_paths); // TODO: Should we finalize & exit?
        exit(0);
    }

    // Print device MAC address
    println!("Mac Address is {}", device_data.get_mac_addr());

    // Count dumps using utility function
    let dump_count = match get_file_count(dump_paths.get_working_dir(), dump_paths.get_dumps_extn(), true) {
        Ok(dump_cnt) => dump_cnt,
        Err(_) => 0,
    };
    if dump_count == 0 {
        println!("No {} for uploading exist", dump_paths.get_dump_name());
        finalize(&dump_paths); // TODO: Should we finalize & exit?
        exit(0);
    }

    // Cleanup old dumps using utility function
    let _ = cleanup(
        dump_paths.get_working_dir(),
        dump_paths.get_dump_name(),
        dump_paths.get_dumps_extn(),
    );

    // Print portal URL and build ID using getters
    println!("Portal URL {}", device_data.get_portal_url());
    println!("buildID is {}", device_data.get_sha1());

    // Final check: working directory must be a directory
    if !Path::new(w_dir).is_dir() {
        exit(1);
    }

    // Main processing loop (up to 3 attempts, as in shell script)
    for _ in 0..3 {
        let files = crashupload_utils::find_dump_files(
            dump_paths.get_working_dir(),
            dump_paths.get_dumps_extn(),
        ).unwrap_or_default();
        if files.is_empty() {
            break;
        }
        process_dumps(&device_data, &dump_paths, &crash_ts, no_network);
    }

    finalize(&dump_paths);
}
