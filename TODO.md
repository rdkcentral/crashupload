TODO:
- Capture existing uploadDumps.sh and uploadDumpsToS3.sh functionality wise in detail 
- Same process multiple crashes, Multiple process crashes (corner cases)
- Separate Logging log.rs, with WARN, INFO, ERROR, etc log levels
- get_sha1() -> using sha1 crate/ process::Command() if single use
- get_last_modified_time_of_file() -> using chrono crate/ process::Command() if single use
- ~~args parsing in main app~~
    
#### Function Implementations
----
**COMPLETED**
- ~~setLogFile()~~
- ~~create_lock_or_exit()~~
- ~~create_lock_or_wait()~~
- ~~remove_lock()~~
- ~~sanitize()~~
- ~~deleteAllButTheMostRecentFiles()~~
- ~~cleanup()~~
- ~~finalize()~~
- ~~sigkill_function()~~
- ~~sigterm_function()~~
- ~~logUploadTimestamp()~~
- ~~truncateTimeStampFile()~~
- ~~isUploadLimitReached()~~
- ~~setRecoveryTime()~~
- ~~isRecoveryTimeReached()~~
- ~~removePendingDumps()~~
- ~~is_box_rebooting()~~
- ~~shouldProcessFile()~~
- ~~get_crashed_log_file()~~
- ~~processCrashTelemtryInfo()~~
- ~~add_crashed_log_file()~~ - optional args
- ~~copy_log_files_tmp_dir()~~ - optional args
- ~~processDumps()~~ - requires add_crashed_log_file() and copy_log_files_tmp_dir()
- ~~saveDump()~~
- ~~markAsCrashLoopedAndUpload()~~
- checkParameter() - NA
- logMessage() - Not req
- tlsLog() - Not req
- logStdout() - Not req
----
**TODO**
- Signal Handling TRAPs
----