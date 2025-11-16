# Requirements Document: uploadDumps.sh

## 1. Overview

The `uploadDumps.sh` script is responsible for processing and uploading crash dump files (coredumps and minidumps) from embedded RDK devices to a crash portal server for analysis.

## 2. Functional Requirements

### 2.1 Core Functionality

#### FR-1: Dump File Detection
- **Description**: Detect and identify crash dump files in configured directories
- **Input**: Directory paths (CORE_PATH, MINIDUMPS_PATH)
- **Output**: List of dump files to process
- **Priority**: Critical
- **Details**:
  - Support for coredump files: `*_core*.gz*`
  - Support for minidump files: `*.dmp*`
  - Handle both secure and non-secure dump locations

#### FR-2: File Processing and Archiving
- **Description**: Process dump files and create compressed archives with metadata
- **Input**: Raw dump files
- **Output**: Tarball (.tgz) files with naming convention: `{sha1}_mac{MAC}_dat{DATE}_box{TYPE}_mod{MODEL}_{filename}.tgz`
- **Priority**: Critical
- **Details**:
  - Add version information
  - Include relevant log files
  - Apply filename sanitization
  - Handle container crash information with special delimiter `<#=#>`

#### FR-3: Upload to Server
- **Description**: Upload processed dump files to crash portal server
- **Input**: Tarball files
- **Output**: Upload status (success/failure)
- **Priority**: Critical
- **Details**:
  - Support S3 upload mechanism
  - Implement retry logic (up to 3 attempts)
  - Handle upload timeouts (45 seconds)
  - Support TLS 1.2 encryption

#### FR-4: Crash Rate Limiting
- **Description**: Prevent overwhelming the server with excessive crash uploads
- **Input**: Upload timestamps
- **Output**: Decision to upload or defer
- **Priority**: High
- **Details**:
  - Track last 10 upload timestamps
  - Deny uploads if 10 uploads occurred within 10 minutes
  - Set recovery time of 10 minutes after rate limit is reached
  - Mark excessive crashes as "crashloop" dumps

### 2.2 Configuration Management

#### FR-5: Multi-Platform Support
- **Description**: Support different device types with platform-specific configurations
- **Supported Platforms**:
  - Broadband devices
  - Extender devices
  - Hybrid devices
  - Media client devices
- **Priority**: High

#### FR-6: Configuration Loading
- **Description**: Load configuration from multiple sources
- **Input Files**:
  - `/etc/device.properties`
  - `/etc/include.properties`
  - Platform-specific override files
- **Priority**: High

### 2.3 Resource Management

#### FR-7: Concurrent Execution Control
- **Description**: Prevent multiple simultaneous instances
- **Mechanism**: File-based locking using lock directories
- **Lock Files**:
  - `/tmp/.uploadCoredumps.lock.d` (for coredumps)
  - `/tmp/.uploadMinidumps.lock.d` (for minidumps)
- **Priority**: Critical

#### FR-8: Memory Management
- **Description**: Operate within memory constraints of embedded systems
- **Constraints**:
  - Check `/tmp` directory usage before copying files
  - Abort log copying if `/tmp` usage exceeds 70%
  - Limit number of stored dumps (MAX_CORE_FILES = 4)
- **Priority**: Critical

#### FR-9: Cleanup Operations
- **Description**: Remove old and processed files to conserve storage
- **Actions**:
  - Delete files older than 2 days
  - Remove unfinished files from previous runs on startup
  - Delete non-dump files
  - Keep only the most recent files (up to MAX_CORE_FILES)
- **Priority**: High

### 2.4 Network Operations

#### FR-10: Network Connectivity Check
- **Description**: Verify network availability before upload attempts
- **Mechanism**:
  - Wait for route availability (up to 18 iterations × 10 seconds)
  - Wait for system time synchronization
  - Use platform-specific network interfaces
- **Priority**: High

#### FR-11: OCSP and TLS Support
- **Description**: Support secure communications with certificate validation
- **Features**:
  - OCSP stapling support
  - OCSP CA validation
  - TLS 1.2 enforcement
- **Priority**: High

### 2.5 Logging and Monitoring

#### FR-12: Comprehensive Logging
- **Description**: Log all significant operations and errors
- **Output**: Log file at `$LOG_PATH/core_log.txt`
- **Log Levels**: INFO, WARN, ERROR
- **Priority**: Medium

#### FR-13: Telemetry Integration
- **Description**: Send telemetry events for monitoring
- **Integration**: T2 telemetry system (when enabled)
- **Events**:
  - Process crash notifications
  - Upload success/failure
  - Crashloop detection
  - Zero-size dump detection
- **Priority**: Medium

### 2.6 Privacy and Security

#### FR-14: Telemetry Opt-Out
- **Description**: Respect user privacy preferences
- **Check**: `Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TelemetryOptOut.Enable`
- **Action**: Skip uploads if opt-out is enabled
- **Priority**: High

#### FR-15: Privacy Mode Support
- **Description**: Honor device privacy settings
- **Check**: Privacy control mode
- **Action**: Stop uploads if mode is "DO_NOT_SHARE"
- **Priority**: High

#### FR-16: Secure Dump Handling
- **Description**: Support secure dump locations
- **Flag**: `$UPLOAD_FLAG` = "secure"
- **Paths**:
  - Secure cores: `/opt/secure/corefiles`
  - Secure minidumps: `/opt/secure/minidumps`
- **Priority**: High

### 2.7 Error Handling

#### FR-17: Graceful Degradation
- **Description**: Handle errors without crashing
- **Scenarios**:
  - Missing configuration files (log warning, use defaults)
  - Network unavailable (save dump for later)
  - Upload failure (retry, then save locally)
  - Compression failure (try alternate method with /tmp)
- **Priority**: Critical

#### FR-18: Signal Handling
- **Description**: Handle system signals gracefully
- **Signals**:
  - SIGTERM: Clean up and exit
  - SIGKILL: Remove locks
  - EXIT: Run finalize() function
- **Priority**: Critical

## 3. Inputs

### 3.1 Command Line Arguments
1. **$1**: Reserved (previously CRASHTS, now generated internally)
2. **$2**: DUMP_FLAG (0 = minidump, 1 = coredump)
3. **$3**: UPLOAD_FLAG ("secure" or empty)
4. **$4**: WAIT_FOR_LOCK ("wait_for_lock" or empty)

### 3.2 Environment Variables
- `DEVICE_TYPE`: Device category (broadband, extender, hybrid, mediaclient)
- `BUILD_TYPE`: Build type (prod, dev)
- `BOX_TYPE`: Box type identifier
- `MODEL_NUM`: Device model number
- `RDK_PATH`: Path to RDK scripts
- `LOG_PATH`: Path for log files
- `PORTAL_URL`: Crash portal server URL
- `MULTI_CORE`: Multi-core device flag

### 3.3 Configuration Files
- `/etc/device.properties`: Device-specific configuration
- `/etc/include.properties`: Generic configuration
- `/etc/breakpad-logmapper.conf`: Process-to-log file mapping
- `/lib/rdk/t2Shared_api.sh`: Telemetry API (optional)
- `/lib/rdk/uploadDumpsToS3.sh`: S3 upload functions (optional)
- `/lib/rdk/getSecureDumpStatus.sh`: Secure dump status (optional)
- `/lib/rdk/uploadDumpsUtils.sh`: Utility functions
- Platform-specific override files

### 3.4 Runtime Files
- `/tmp/.macAddress`: Device MAC address
- `/tmp/route_available`: Network ready flag
- `/tmp/stt_received`: System time synchronized flag
- `/tmp/set_crash_reboot_flag`: Reboot in progress flag
- `/tmp/coredump_mutex_release`: Coredump completion flag

### 3.5 Dump Files
- Coredumps: `*_core*.gz*` files in `$CORE_PATH`
- Minidumps: `*.dmp*` files in `$MINIDUMPS_PATH`
- Already processed: `*.tgz` files

## 4. Outputs

### 4.1 Archive Files
- **Format**: `.tgz` (gzip-compressed tar archive)
- **Naming**: `{sha1}_mac{MAC}_dat{DATE}_box{TYPE}_mod{MODEL}_{filename}.tgz`
- **Contents**:
  - Original dump file
  - `version.txt`
  - `core_log.txt`
  - Process-specific log files (for minidumps)
  - `crashed_url.txt` (for video devices, if available)

### 4.2 Log Files
- **Primary**: `$LOG_PATH/core_log.txt`
- **TLS Errors**: `$LOG_PATH/tlsError.log`
- **Temporary**: `/tmp/minidump_log_files.txt`

### 4.3 State Files
- **Lock directories**:
  - `/tmp/.uploadCoredumps.lock.d`
  - `/tmp/.uploadMinidumps.lock.d`
- **Timestamp file**: `/tmp/.{minidump|coredump}_upload_timestamps`
- **Recovery time**: `/tmp/.deny_dump_uploads_till`
- **Cleanup marker**: `/tmp/.on_startup_dumps_cleaned_up_{DUMP_FLAG}`
- **HTTP response**: `/tmp/httpcode`
- **Crash reboot**: `/tmp/crash_reboot` (broadband only)

### 4.4 Upload Results
- **Success**: Dump removed locally, timestamp logged
- **Failure**: Dump saved for retry (minidumps only)
- **Rate Limited**: Crashloop marker created and uploaded

## 5. Dependencies

### 5.1 System Commands
- `busybox sh` or `bash`
- `date`, `stat`, `find`, `ls`, `rm`, `mv`, `cp`, `mkdir`
- `tar`, `gzip`, `nice`
- `grep`, `sed`, `awk`, `cut`, `tr`, `wc`
- `ifconfig`, `cat`, `echo`, `touch`, `chmod`
- `sleep`, `wait`, `exit`, `kill`
- `curl` (with mTLS support)

### 5.2 External Scripts
- `/lib/rdk/t2Shared_api.sh` (optional): Telemetry functions
- `/lib/rdk/uploadDumpsToS3.sh` (optional): S3 upload
- `/lib/rdk/getSecureDumpStatus.sh` (optional): Secure dump check
- `/lib/rdk/uploadDumpsUtils.sh`: Utility functions
- `/lib/rdk/uploadDumpsUtilsDevice.sh` (optional): Device-specific utils
- `/lib/rdk/utils.sh` (optional): General utilities
- `/lib/rdk/commonUtils.sh` (optional): Common utilities
- `/lib/rdk/getpartnerid.sh` (optional): Partner ID retrieval
- `/etc/waninfo.sh` (optional): WAN interface information
- `$RDK_PATH/exec_curl_mtls.sh` (optional): mTLS curl wrapper
- `$RDK_PATH/getDeviceDetails.sh`: Device details retrieval

### 5.3 System Libraries
- Standard C library
- POSIX utilities
- OpenSSL/TLS libraries (for curl)

## 6. Constraints

### 6.1 Timing Constraints
- **Upload timeout**: 45 seconds per attempt
- **Retry delay**: 2 seconds between attempts
- **Network wait**: Up to 180 seconds (18 × 10s)
- **System time wait**: Up to 10 seconds
- **Startup defer**: 480 seconds uptime (video devices only)
- **Coredump wait**: 21 seconds for completion
- **Rate limit window**: 600 seconds (10 minutes)

### 6.2 Resource Constraints
- **Maximum simultaneous instances**: 1 (enforced by locking)
- **Maximum stored dumps**: 4 files
- **Maximum /tmp usage**: 70%
- **Log line retention**: 5000 lines (dev), 500 lines (prod)
- **Filename length**: Maximum 135 characters (ecryptfs limitation)
- **Upload attempts**: 3 retries maximum
- **Tarball size**: Limited by available disk space

### 6.3 Platform Constraints
- Must work on embedded Linux systems with limited resources
- Busybox compatibility required for broadband devices
- Must support multiple device types with different configurations
- Must work with various network interface configurations
- Must handle both Yocto and non-Yocto builds

### 6.4 Security Constraints
- Must use TLS 1.2 for uploads
- Must support OCSP certificate validation
- Must support mTLS authentication
- Must sanitize all user-provided input
- Must respect privacy settings and opt-out flags
- Must handle secure and non-secure dump locations separately

## 7. Edge Cases and Error Handling

### 7.1 Edge Cases

#### EC-1: No Dump Files
- **Scenario**: No dump files found in directory
- **Handling**: Exit gracefully with log message

#### EC-2: Empty MAC Address
- **Scenario**: MAC address cannot be retrieved
- **Handling**: Retry with all interfaces, use default value (000000000000)

#### EC-3: Empty SHA1/Model/Timestamp
- **Scenario**: Required metadata cannot be retrieved
- **Handling**: Use default values to prevent upload failure

#### EC-4: Long Filenames
- **Scenario**: Generated filename exceeds 135 characters
- **Handling**: 
  - Remove SHA1 prefix
  - Truncate process name to 20 characters if still too long

#### EC-5: Container Crashes
- **Scenario**: Dump file contains container crash information with `<#=#>` delimiter
- **Handling**:
  - Parse container name, status, and timestamp
  - Send telemetry events
  - Sanitize delimiter in final filename

#### EC-6: Already Processed Files
- **Scenario**: Dump file already has metadata in filename
- **Handling**: Skip re-processing, use as-is

#### EC-7: Tarball Creation Failure
- **Scenario**: Initial tar command fails
- **Handling**: Copy files to `/tmp` and retry

#### EC-8: Box Rebooting
- **Scenario**: Device reboot detected during processing
- **Handling**: Exit immediately, upload on next boot

#### EC-9: Network Unavailable
- **Scenario**: Network not available after waiting
- **Handling**: Save dump locally for later upload

#### EC-10: Privacy Mode Active
- **Scenario**: Privacy mode set to "DO_NOT_SHARE"
- **Handling**: Remove pending dumps, exit

### 7.2 Error Conditions

#### ERR-1: Missing Configuration Files
- **Error**: Required configuration file not found
- **Handling**: Log warning, continue with available configuration
- **Recovery**: Use default values

#### ERR-2: Lock Creation Failure
- **Error**: Cannot create lock directory
- **Handling**: Log error, attempt to continue
- **Recovery**: May result in concurrent execution

#### ERR-3: Upload Timeout
- **Error**: Upload takes longer than 45 seconds
- **Handling**: Retry up to 3 times with 2-second delay
- **Recovery**: Save dump locally after all retries fail

#### ERR-4: Compression Failure
- **Error**: tar/gzip command fails
- **Handling**: 
  - First: Copy files to /tmp and retry
  - Second: Log error, send telemetry event
- **Recovery**: Continue processing other dumps

#### ERR-5: Zero-Size Dump
- **Error**: Dump file has zero bytes
- **Handling**: Log error, send telemetry event, process anyway
- **Recovery**: Upload will likely fail or be rejected by server

#### ERR-6: Rate Limit Exceeded
- **Error**: More than 10 uploads in 10 minutes
- **Handling**: 
  - Create crashloop marker dump
  - Upload crashloop dump to portal
  - Set 10-minute recovery time
  - Delete pending dumps
- **Recovery**: Resume normal uploads after recovery time

#### ERR-7: Signal Interruption
- **Error**: SIGTERM or SIGKILL received
- **Handling**: Clean up locks, exit immediately
- **Recovery**: Next invocation will resume processing

#### ERR-8: Write Permission Denied
- **Error**: Cannot write to log file or working directory
- **Handling**: Use fallback locations or stdout
- **Recovery**: Continue with reduced logging

## 8. Performance Requirements

### 8.1 CPU Usage
- Use `nice -n 19` for compression to minimize impact
- Avoid compression during reboot if `set_crash_reboot_flag` exists
- Defer processing for 480 seconds on video devices after boot

### 8.2 Memory Usage
- Minimize memory footprint for embedded systems
- Stream file processing where possible
- Check /tmp usage before allocating space
- Clean up temporary files immediately after use

### 8.3 Disk I/O
- Minimize disk writes
- Use efficient compression
- Clean up old files proactively
- Limit number of stored dumps

### 8.4 Network Usage
- Upload timeout of 45 seconds
- Retry with backoff
- Support upload deferral when network unavailable

## 9. Quality Attributes

### 9.1 Reliability
- Must handle all error conditions gracefully
- Must not lose dumps due to errors
- Must prevent concurrent execution conflicts
- Must survive system signals

### 9.2 Maintainability
- Clear separation of concerns
- Well-documented functions
- Consistent naming conventions
- Modular design for platform-specific code

### 9.3 Portability
- Support multiple device types
- Support multiple Linux distributions
- Handle Yocto and non-Yocto builds
- Busybox compatibility

### 9.4 Security
- Sanitize all input
- Use secure communication protocols
- Respect privacy settings
- Handle sensitive data appropriately

### 9.5 Testability
- Each function should be independently testable
- Clear input/output specifications
- Mockable external dependencies
- Logging for debugging

## 10. Migration Considerations for C Implementation

### 10.1 Language-Specific Challenges
- Replace shell command pipelines with C APIs
- Implement pattern matching (currently uses grep/sed/awk)
- Handle dynamic string manipulation
- Implement file globbing (currently uses shell wildcards)

### 10.2 External Command Dependencies
- Minimize calls to external commands
- Use C libraries where possible (e.g., libcurl for uploads)
- Consider embedding critical functionality

### 10.3 Configuration Management
- Implement configuration file parser
- Support multiple configuration sources
- Handle environment variable inheritance

### 10.4 Platform Abstraction
- Create platform-specific abstraction layer
- Use conditional compilation for platform differences
- Maintain single codebase with platform variants

### 10.5 Memory Management
- Implement proper resource cleanup
- Handle memory allocation failures
- Use static allocation where possible for embedded systems
- Implement memory pooling for frequent allocations
