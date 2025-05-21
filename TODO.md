TODO:
- Capture existing uploadDumps.sh and uploadDumpsToS3.sh functionality wise in detail 
- Same process multiple crashes, Multiple process crashes (corner cases)

- Separate Logging log.rs, with WARN, INFO, ERROR, etc log levels
- get_sha1() -> using sha1 crate/ process::Command() if single use
- get_last_modified_time_of_file() -> using chrono crate/ process::Command() if single use
- ~~args parsing in main app~~
- upload dump utils
    - ~~sanitize()~~
    - checkParam()
    - finalize()
    - sigkill_function() and sigterm_function() with trap usage
    - truncateTimeStampFile()
    - isUploadLimitReached()
    - coreUpload() -> find origin
    - saveDumps()
    - processDumps()
    - shouldProcessFile()
    - get_crash_log_file()
    