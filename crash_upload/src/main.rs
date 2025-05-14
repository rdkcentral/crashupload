// standard library imports
use std::env;
use std::fs::create_dir;
use std::path::Path;

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

    // Instantiate the DumpPaths struct
    let mut dump_paths = constants::DumpPaths::new();

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
     * deleteAllButTheMostRecentFiles()
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

    // let working_dir = if dump_flag == 1 {
    //     crashupload_utils::get_core_path(upload_flag)
    // }
    // else
    // {
    //     crashupload_utils::get_minidumps_path(upload_flag)
    // };
}
