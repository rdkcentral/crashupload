// standard library imports
use std::{env, fs};
use std::fs::create_dir;
use std::os::unix::thread;
use std::path::Path;

use platform_interface::{get_rfc_param, set_rfc_param};
use utils::sleep;

// crashupload internal module imports
mod constants;
mod crashupload_utils;

fn main() {
    println!("Starting Crash Upload Binary...");

    // EXEC: Command line argument parsing
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: <program> <string> <number> <string> <string>");
        eprintln!("Example: <program> \"example_string\" 1 \"example_string\" \"example_string\"");
        std::process::exit(1);
    }

    //let crash_timestamp = utils::get_crash_timestamp();
    let dump_flag = args[2]
        .parse::<u32>()
        .expect("Second argument must be a number");
    let upload_flag = &args[3];
    let wait_for_lock = &args[4];

    // EXEC: Instantiate the DumpPaths struct
    let mut dump_paths = constants::DumpPaths::new();

    // EXEC: Set the core and minidump paths based on the upload flag
    if upload_flag != "secure" {
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
    let dump_name = if dump_flag == 1 {
        "coredump"
    } else {
        "minidump"
    };
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

    if dump_flag == 1 {
        println!("starting core dump processing...");
        dump_paths.set_working_dir(dump_paths.get_core_path().to_string());
        dump_paths.set_dumps_extn("*core.prog*.gz*".to_string());
        dump_paths.set_tar_extn(".core.tgz".to_string());
        dump_paths.set_lock_dir_prefix("/tmp/.uploadCoredumps".to_string());
        dump_paths.set_crash_portal_path("/opt/crashportal_uploads/coredumps/".to_string());
    }
    else
    {
        println!("starting minidump processing...");
        dump_paths.set_working_dir(dump_paths.get_minidumps_path().to_string());
        dump_paths.set_dumps_extn("*.dmp*".to_string());
        dump_paths.set_tar_extn(".dmp.tgz".to_string());
        dump_paths.set_lock_dir_prefix("/tmp/.uploadMinidumps".to_string());
        dump_paths.set_crash_portal_path("/opt/crashportal_uploads/coredumps/".to_string());
        sleep(5);
    };

    let w_dir = dump_paths.get_working_dir();
    match fs::read_dir(w_dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => {
            eprintln!("working dir is empty : {}", w_dir);
            std::process::exit(1);
        }
    };

    let mut portal_url = String::new();
    get_rfc_param("Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl", &mut portal_url);
    let req_type = 17;

    let mut encryption_enabled = false;
    if Path::new("/etc/os-release").exists() { encryption_enabled = set_rfc_param("Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.encryptionEnabled", "true") };


}
