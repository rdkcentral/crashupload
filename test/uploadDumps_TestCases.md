# Functional Test Cases for uploadDumps.sh

## Document Information
- **Script Name**: uploadDumps.sh
- **Repository**: rdkcentral/crashupload
- **Purpose**: Create and upload core dump and minidump files from RDK devices to cloud storage (S3)
- **Version**: Based on commit c17ff99e14e5685d37df83cac3bba3cdb478e13b

---

## Test Suite Overview
This document contains functional test cases covering all features of the uploadDumps.sh script including:
- Configuration loading and validation
- Dump file detection and processing
- Lock mechanism management
- Network connectivity checks
- Telemetry integration
- Compression and archiving
- Upload functionality with retries
- Rate limiting and crash loop detection
- Cleanup operations

---

## 1. Configuration and Initialization Test Cases

### TC-001: Configuration Files Loading - All Files Present (Positive)
**Test Case Name**:  Verify successful loading of all configuration files  
**Pre-condition**:
- Device has all required configuration files present: 
  - `/etc/device.properties`
  - `/etc/include. properties`
  - `/lib/rdk/t2Shared_api.sh`
  - `/lib/rdk/uploadDumpsUtils.sh`
  - `/lib/rdk/uploadDumpsToS3.sh`
  
**Operation**:
1. Execute the script with proper parameters
2. Verify each configuration file is sourced successfully

**Expected Result**:
- All configuration files are loaded without errors
- Required environment variables are set
- IS_T2_ENABLED flag is set to "true"
- No error messages in log file

**Actual Result**:  _[To be filled during testing]_

---

### TC-002: Configuration Files Loading - Missing device.properties (Negative)
**Test Case Name**: Verify handling of missing device.properties file  
**Pre-condition**: 
- `/etc/device.properties` file does not exist
- Other configuration files are present

**Operation**:
1. Execute the script
2. Check log output for error message

**Expected Result**:
- Script logs:  "Missing device configuration file: /etc/device.properties.. !"
- Script continues execution with default values
- No script termination

**Actual Result**: _[To be filled during testing]_

---

### TC-003: Configuration Files Loading - Missing include.properties (Negative)
**Test Case Name**:  Verify handling of missing include.properties file  
**Pre-condition**:
- `/etc/include.properties` file does not exist
- Other configuration files are present

**Operation**:
1. Execute the script
2. Check log output for error message

**Expected Result**: 
- Script logs: "Missing generic configuration file: /etc/include. properties..!"
- Script continues execution with default values
- No script termination

**Actual Result**: _[To be filled during testing]_

---

### TC-004: Device Type Detection - Broadband Device (Positive)
**Test Case Name**: Verify correct path configuration for broadband device  
**Pre-condition**:
- DEVICE_TYPE is set to "broadband"
- Required directories do not exist yet

**Operation**:
1. Set DEVICE_TYPE="broadband" in device.properties
2. Execute the script
3. Verify paths are set correctly

**Expected Result**: 
- CORE_PATH is set to "/minidumps"
- LOG_PATH is set to "/rdklogs/logs"
- LOG_PATH directory is created if it doesn't exist
- COMM_INTERFACE is configured based on MULTI_CORE setting

**Actual Result**: _[To be filled during testing]_

---

### TC-005: Device Type Detection - Extender Device (Positive)
**Test Case Name**: Verify correct path configuration for extender device  
**Pre-condition**:
- DEVICE_TYPE is set to "extender"
- PERSISTENT_PATH/account file exists with partnerId

**Operation**:
1. Set DEVICE_TYPE="extender" in device.properties
2. Execute the script
3. Verify paths and partner ID extraction

**Expected Result**:
- CORE_LOG is set to "/var/log/messages"
- CORE_PATH is set to "/minidumps"
- partnerId is extracted from account file correctly
- ARM_INTERFACE is obtained via getWanInterfaceName

**Actual Result**: _[To be filled during testing]_

---

### TC-006: Upload Flag - Secure Mode (Positive)
**Test Case Name**: Verify secure upload path configuration  
**Pre-condition**:
- Script is executed with UPLOAD_FLAG="secure" (3rd argument)
- Secure directories exist

**Operation**:
1. Execute script with:  `uploadDumps.sh <arg1> <arg2> secure`
2. Verify path settings

**Expected Result**:
- CORE_PATH is set to "/opt/secure/corefiles"
- MINIDUMPS_PATH is set to "/opt/secure/minidumps"
- Script processes dumps from secure locations

**Actual Result**: _[To be filled during testing]_

---

### TC-007: Upload Flag - Normal Mode (Positive)
**Test Case Name**: Verify normal upload path configuration  
**Pre-condition**:
- Script is executed without "secure" flag or with different value
- Standard directories exist

**Operation**: 
1. Execute script with: `uploadDumps.sh <arg1> <arg2> normal`
2. Verify path settings

**Expected Result**: 
- CORE_PATH is set to "/var/lib/systemd/coredump"
- MINIDUMPS_PATH is set to "/opt/minidumps"
- Script processes dumps from standard locations

**Actual Result**: _[To be filled during testing]_

---

### TC-008: Dump Flag Selection - Coredump Mode (Positive)
**Test Case Name**: Verify coredump processing mode initialization  
**Pre-condition**: 
- DUMP_FLAG is set to "1" (2nd argument)
- Coredump files exist in CORE_PATH

**Operation**:
1. Execute script with: `uploadDumps.sh <arg1> 1`
2. Verify mode configuration

**Expected Result**:
- DUMP_NAME is set to "coredump"
- WORKING_DIR is set to CORE_PATH
- DUMPS_EXTN is set to "*core. prog*. gz*"
- TARBALLS is set to "*. core.tgz"
- LOCK_DIR_PREFIX is set to "/tmp/. uploadCoredumps"
- Log message:  "starting coredump processing"

**Actual Result**: _[To be filled during testing]_

---

### TC-009: Dump Flag Selection - Minidump Mode (Positive)
**Test Case Name**: Verify minidump processing mode initialization  
**Pre-condition**:
- DUMP_FLAG is set to "0" or any value other than "1" (2nd argument)
- Minidump files exist in MINIDUMPS_PATH

**Operation**:
1. Execute script with: `uploadDumps.sh <arg1> 0`
2. Verify mode configuration

**Expected Result**:
- DUMP_NAME is set to "minidump"
- WORKING_DIR is set to MINIDUMPS_PATH
- DUMPS_EXTN is set to "*. dmp*"
- TARBALLS is set to "*.dmp.tgz"
- LOCK_DIR_PREFIX is set to "/tmp/.uploadMinidumps"
- Log message: "starting minidump processing"
- Script sleeps for 5 seconds

**Actual Result**:  _[To be filled during testing]_

---

### TC-010: TLS Configuration - Yocto Device (Positive)
**Test Case Name**: Verify TLS 1.2 is forced for Yocto devices  
**Pre-condition**: 
- /etc/os-release file exists
- Device is running Yocto build

**Operation**:
1. Execute script on Yocto device
2. Check TLS variable value

**Expected Result**:
- TLS variable is set to "--tlsv1.2"
- Curl commands will use TLS 1.2 protocol

**Actual Result**: _[To be filled during testing]_

---

## 2. Lock Mechanism Test Cases

### TC-011: Lock Creation - First Instance (Positive)
**Test Case Name**: Verify lock is created successfully for first instance  
**Pre-condition**:
- No existing lock directory exists
- LOCK_DIR_PREFIX is properly set
- WAIT_FOR_LOCK parameter is not "wait_for_lock"

**Operation**:
1. Execute script
2. Check for lock directory creation

**Expected Result**:
- Lock directory "${LOCK_DIR_PREFIX}. lock. d" is created or file created
- Script continues execution
- No error messages logged

**Actual Result**: _[To be filled during testing]_

---

### TC-012: Lock Creation - Second Instance Without Wait (Negative)
**Test Case Name**:  Verify second instance exits when lock exists and wait flag not set  
**Pre-condition**:
- First instance is running with lock directory created
- WAIT_FOR_LOCK parameter is not "wait_for_lock"
- T2 telemetry is enabled

**Operation**:
1. Execute second instance of script
2. Verify it detects existing lock

**Expected Result**:
- Log message: "Script is already working.  ${path}. lock.d.  Skip launch another instance..."
- T2 telemetry notification sent:  "SYST_WARN_NoMinidump"
- Second instance exits with code 0
- Lock directory remains intact

**Actual Result**: _[To be filled during testing]_

---

### TC-013: Lock Creation - Second Instance With Wait (Positive)
**Test Case Name**:  Verify second instance waits when lock exists and wait flag is set  
**Pre-condition**:
- First instance is running with lock directory created
- WAIT_FOR_LOCK parameter is "wait_for_lock"

**Operation**:
1. Execute second instance with:  `uploadDumps.sh <arg1> <arg2> <arg3> wait_for_lock`
2. Monitor log messages
3. Stop first instance
4. Verify second instance continues

**Expected Result**:
- Log message: "Script is already working. ${path}.lock.d.  Waiting to launch another instance..."
- Second instance sleeps for 2 seconds repeatedly
- When first instance completes, second instance acquires lock
- Second instance proceeds with dump processing

**Actual Result**: _[To be filled during testing]_

---

### TC-014: Lock Removal - Normal Exit (Positive)
**Test Case Name**: Verify lock is removed on normal script completion  
**Pre-condition**: 
- Script is running with lock created
- All dumps are processed successfully

**Operation**:
1. Execute script with valid dumps
2. Wait for script completion
3. Check lock directory status

**Expected Result**:
- finalize() function is called
- Lock directory "${LOCK_DIR_PREFIX}.lock.d" is removed
- Timestamp lock is also removed
- Exit is clean without errors

**Actual Result**: _[To be filled during testing]_

---

### TC-015: Lock Removal - SIGTERM Signal (Positive)
**Test Case Name**: Verify lock is removed when script receives SIGTERM  
**Pre-condition**:
- Script is running with lock created
- Script is processing dumps

**Operation**:
1. Execute script
2. Send SIGTERM signal to script process
3. Check lock directory status

**Expected Result**:
- sigterm_function() is triggered
- Log message: "Systemd Terminating, Removing the script locks"
- Lock directory is removed
- Crash loop flag file is removed if exists
- Script terminates gracefully

**Actual Result**: _[To be filled during testing]_

---

### TC-016: Lock Removal - SIGKILL/SIGTERM Signal (Positive)
**Test Case Name**:  Verify lock is removed when script receives SIGKILL  
**Pre-condition**:
- Script is running with lock created
- Script is processing dumps

**Operation**:
1. Execute script
2. Send SIGKILL signal to script process
3. Check lock directory status

**Expected Result**:
- sigkill_function() is triggered
- Log message: "Systemd Killing, Removing the script locks"
- Lock directory is removed
- Crash loop flag file is removed if exists
- Script terminates

**Actual Result**: _[To be filled during testing]_

---

## 3. Dump File Detection Test Cases

### TC-017: Dump File Detection - Broadband Device with Dumps (Positive)
**Test Case Name**: Verify dump files are detected on broadband device  
**Pre-condition**:
- DEVICE_TYPE is "broadband"
- CORE_PATH="/minidumps"
- At least one . dmp file exists in /minidumps

**Operation**:
1. Create test . dmp files in /minidumps
2. Execute script
3. Verify file detection

**Expected Result**: 
- Script detects .dmp files
- Script continues to processing phase
- Log shows files detected

**Actual Result**: _[To be filled during testing]_

---

### TC-018: Dump File Detection - Broadband Device without Dumps (Negative)
**Test Case Name**:  Verify script exits when no dump files on broadband device  
**Pre-condition**:
- DEVICE_TYPE is "broadband"
- CORE_PATH="/minidumps"
- No .dmp files exist in /minidumps

**Operation**:
1. Ensure no . dmp files in /minidumps
2. Execute script
3. Check exit behavior

**Expected Result**:
- Script exits with code 0
- No processing occurs
- Clean exit without errors

**Actual Result**: _[To be filled during testing]_

---

### TC-019: Dump File Detection - Extender Device with Dumps (Positive)
**Test Case Name**:  Verify dump files are detected on extender device  
**Pre-condition**:
- DEVICE_TYPE is "extender"
- CORE_PATH="/minidumps"
- At least one .dmp file exists in /minidumps

**Operation**:
1. Create test .dmp files in /minidumps
2. Execute script
3. Verify file detection

**Expected Result**:
- Script detects .dmp files
- Script continues to processing phase
- Log shows files detected

**Actual Result**: _[To be filled during testing]_

---

### TC-020: Dump File Detection - Video Device with Minidumps (Positive)
**Test Case Name**: Verify minidump files are detected on video device  
**Pre-condition**: 
- DEVICE_TYPE is not "broadband" or "extender"
- At least one .dmp* file exists in MINIDUMPS_PATH

**Operation**:
1. Create test .dmp files in MINIDUMPS_PATH
2. Execute script with DUMP_FLAG="0"
3. Verify file detection

**Expected Result**:
- Script detects .dmp* files
- Script continues to processing phase
- Log shows minidump files detected

**Actual Result**: _[To be filled during testing]_

---

### TC-021: Dump File Detection - Video Device with Coredumps (Positive)
**Test Case Name**: Verify coredump files are detected on video device  
**Pre-condition**: 
- DEVICE_TYPE is not "broadband" or "extender"
- At least one *_core*. * file exists in CORE_PATH

**Operation**:
1. Create test core dump files in CORE_PATH
2. Execute script with DUMP_FLAG="1"
3. Verify file detection

**Expected Result**:
- Script detects *_core*.* files
- Script continues to processing phase
- Log shows coredump files detected

**Actual Result**: _[To be filled during testing]_

---

### TC-022: Dump File Detection - No Dumps Available (Negative)
**Test Case Name**: Verify script exits when no dump files exist  
**Pre-condition**: 
- No .dmp* files in MINIDUMPS_PATH
- No *_core*.* files in CORE_PATH
- Device type is video device

**Operation**:
1. Clean all dump directories
2. Execute script
3. Check exit behavior

**Expected Result**:
- Script exits with code 0 after initial check
- Log message: "working dir is empty $WORKING_DIR" OR exit before this
- No processing occurs

**Actual Result**: _[To be filled during testing]_

---

## 4. MAC Address and Device Information Test Cases

### TC-023: MAC Address Validation - Valid MAC (Positive)
**Test Case Name**: Verify MAC address is correctly retrieved and formatted  
**Pre-condition**: 
- /tmp/. macAddress file exists with valid MAC address
- MAC format:  "AA:BB:CC:DD:EE:FF" or "AABBCCDDEEFF"

**Operation**:
1. Create /tmp/.macAddress with MAC "aa:bb:cc:dd:ee:ff"
2. Execute script
3. Check MAC variable value

**Expected Result**: 
- MAC is read from /tmp/.macAddress
- Colons are removed
- MAC is converted to uppercase:  "AABBCCDDEEFF"
- Log message: "Mac address is AABBCCDDEEFF"

**Actual Result**: _[To be filled during testing]_

---

### TC-024: MAC Address Validation - Empty MAC File (Negative)
**Test Case Name**: Verify handling of empty MAC address  
**Pre-condition**: 
- /tmp/.macAddress file is empty or contains only whitespace
- getMacAddressOnly function is available

**Operation**:
1. Create empty /tmp/.macAddress file
2. Execute script
3. Monitor MAC retrieval attempts

**Expected Result**:
- Log message: "MAC address is empty.  Trying to get it again, including network interfaces currently down."
- getMacAddressOnly() function is called
- If still empty, MAC is set to default "000000000000"
- Log message: "MAC address is still empty.  Setting to default value."
- ifconfig output is logged

**Actual Result**: _[To be filled during testing]_

---

### TC-025: Model Number Retrieval - Broadband Device (Positive)
**Test Case Name**: Verify model number retrieval for broadband device  
**Pre-condition**: 
- DEVICE_TYPE is "broadband"
- MODEL_NUM is set in device.properties

**Operation**: 
1. Set MODEL_NUM in device.properties
2. Execute script
3. Verify modNum variable

**Expected Result**:
- modNum is set from MODEL_NUM variable
- If MODEL_NUM is empty, dmcli command is executed
- modNum is validated via checkParameter
- Log shows buildID and model information

**Actual Result**: _[To be filled during testing]_

---

### TC-026: Model Number Retrieval - Extender Device (Positive)
**Test Case Name**: Verify model number retrieval for extender device  
**Pre-condition**:
- DEVICE_TYPE is "extender"
- getModelNum function is available

**Operation**:
1. Execute script on extender device
2. Verify modNum variable

**Expected Result**:
- modNum is retrieved via getModelNum() function
- modNum is validated via checkParameter
- If empty, set to "UNKNOWN"

**Actual Result**: _[To be filled during testing]_

---

### TC-027: Model Number Retrieval - Video Device (Positive)
**Test Case Name**:  Verify model number retrieval for video device  
**Pre-condition**:
- DEVICE_TYPE is not "broadband" or "extender"
- getDeviceDetails. sh script exists

**Operation**:
1. Execute script on video device
2. Verify modNum variable

**Expected Result**:
- modNum is retrieved via:  `sh $RDK_PATH/getDeviceDetails.sh read model_number`
- modNum is validated via checkParameter
- If empty, set to "UNKNOWN"

**Actual Result**: _[To be filled during testing]_

---

### TC-028: SHA1 Build ID Retrieval (Positive)
**Test Case Name**: Verify SHA1 build ID calculation from version. txt  
**Pre-condition**:
- /version.txt file exists
- getSHA1 function is available

**Operation**: 
1. Execute script
2. Verify sha1 variable value

**Expected Result**:
- sha1 is calculated via:  `getSHA1 /version.txt`
- sha1 is validated via checkParameter
- If empty, set to "0000000000000000000000000000000000000000"
- Log message: "buildID is $sha1"

**Actual Result**: _[To be filled during testing]_

---

### TC-029: Partner ID Retrieval - Standard Device (Positive)
**Test Case Name**: Verify partner ID retrieval for standard devices  
**Pre-condition**: 
- /lib/rdk/getpartnerid.sh exists
- getPartnerId function returns valid partner ID

**Operation**: 
1. Execute script
2. Verify partnerId variable

**Expected Result**:
- getpartnerid.sh is sourced
- partnerId is retrieved via getPartnerId function
- partnerId is used in upload parameters

**Actual Result**: _[To be filled during testing]_

---

### TC-030: Partner ID Retrieval - Extender Device (Positive)
**Test Case Name**: Verify partner ID extraction from account file for extender  
**Pre-condition**:
- DEVICE_TYPE is "extender"
- $PERSISTENT_PATH/account file exists with JSON content
- JSON contains "partnerId" field

**Operation**: 
1. Create account file with:  {"partnerId":"PARTNER123"}
2. Execute script
3. Verify partnerId extraction

**Expected Result**:
- partnerId is extracted using grep and sed
- partnerId value is "PARTNER123"
- partnerId is used in upload operations

**Actual Result**: _[To be filled during testing]_

---

## 5. Network Connectivity Test Cases

### TC-031: Network Check - Video Device Boot Sequence (Positive)
**Test Case Name**: Verify network availability check during boot for video devices  
**Pre-condition**: 
- DEVICE_TYPE is "hybrid" or "mediaclient"
- /tmp/route_available flag file exists
- /tmp/stt_received flag file exists

**Operation**: 
1. Create required flag files before script execution
2. Execute script
3. Monitor network check behavior

**Expected Result**:
- Script checks for /tmp/route_available
- Log message: "Route is Available break the loop"
- Script checks for /tmp/stt_received
- Log message: "Received /tmp/stt_received flag"
- Script continues to dump processing
- No extended waits occur

**Actual Result**:  _[To be filled during testing]_

---

### TC-032: Network Check - Route Not Available (Negative)
**Test Case Name**: Verify handling when network route is not available  
**Pre-condition**:
- DEVICE_TYPE is "hybrid" or "mediaclient"
- /tmp/route_available flag file does NOT exist
- Script waits for 18 iterations (18 * 10 = 180 seconds max)

**Operation**:
1. Remove /tmp/route_available file
2. Execute script
3. Monitor wait iterations

**Expected Result**:
- Script loops checking for route availability
- Log messages: "Check Network status count 1" through "Check Network status count 18"
- Each iteration logs:  "Route is not available sleep for 10"
- After 18 iterations, log: "Route is NOT Available, tar dump and save it as MAX WAIT has been reached"
- NoNetwork flag is set to 1
- Script continues with offline processing

**Actual Result**: _[To be filled during testing]_

---

### TC-033: Network Check - System Time Not Received (Negative)
**Test Case Name**: Verify handling when system time test (STT) is not received  
**Pre-condition**:
- DEVICE_TYPE is "hybrid" or "mediaclient"
- /tmp/route_available exists
- /tmp/stt_received does NOT exist

**Operation**: 
1. Create /tmp/route_available
2. Remove /tmp/stt_received
3. Execute script
4. Monitor STT wait iterations

**Expected Result**:
- After route check passes, STT check begins
- Log message: "IP acquistion completed, Testing the system time is received"
- Script loops up to 10 iterations
- Log messages: "Waiting for STT, iteration 1" through "Waiting for STT, iteration 10"
- After 10 iterations, log: "Continue without /tmp/stt_received flag"
- Script continues processing

**Actual Result**: _[To be filled during testing]_

---

### TC-034: Network Check - Broadband Device (Positive)
**Test Case Name**: Verify network communication status check for broadband device  
**Pre-condition**:
- DEVICE_TYPE is "broadband"
- network_commn_status function is available

**Operation**:
1. Execute script on broadband device
2. Verify network check function call

**Expected Result**:
- network_commn_status function is called
- Function checks network connectivity specific to broadband
- Script waits for network if necessary
- Continues when network is available

**Actual Result**: _[To be filled during testing]_

---

### TC-035: Upload Defer - Video Device Early Boot (Positive)
**Test Case Name**: Verify upload is deferred during early boot phase for video devices  
**Pre-condition**:
- DEVICE_TYPE is "hybrid" or "mediaclient"
- System uptime is less than 480 seconds (8 minutes)
- /proc/uptime shows uptime < 480

**Operation**: 
1. Execute script when uptime is 120 seconds
2. Monitor sleep behavior

**Expected Result**:
- Script reads uptime from /proc/uptime
- Sleep time is calculated: 480 - 120 = 360 seconds
- Log message: "Deferring reboot for 360 seconds"
- Script sleeps for 360 seconds
- After sleep, continues processing

**Actual Result**: _[To be filled during testing]_

---

### TC-036: Upload Defer - Video Device After Boot (Positive)
**Test Case Name**: Verify no upload defer when uptime exceeds threshold  
**Pre-condition**: 
- DEVICE_TYPE is "hybrid" or "mediaclient"
- System uptime is greater than 480 seconds
- /proc/uptime shows uptime > 480

**Operation**:
1. Execute script when uptime is 600 seconds
2.  Verify no defer occurs

**Expected Result**: 
- Script reads uptime from /proc/uptime
- No sleep is performed
- Script immediately continues to processing
- No "Deferring reboot" message

**Actual Result**: _[To be filled during testing]_

---

### TC-037: Upload Defer - Crash During Defer Period (Negative)
**Test Case Name**:  Verify script exits if crash occurs during defer period  
**Pre-condition**:
- DEVICE_TYPE is "hybrid" or "mediaclient"
- System uptime is less than 480 seconds
- /tmp/set_crash_reboot_flag is created during defer sleep

**Operation**:
1. Execute script when uptime is 100 seconds
2. Create /tmp/set_crash_reboot_flag during the sleep period
3. Monitor script behavior

**Expected Result**:
- Script begins deferring with sleep
- /tmp/set_crash_reboot_flag is detected
- Log message: "Process crashed exiting from the Deferring reboot"
- Script breaks from defer loop
- Processing continues or exits based on flag

**Actual Result**:  _[To be filled during testing]_

---

## 6. Privacy Mode Test Cases

### TC-038: Privacy Mode - DO_NOT_SHARE Blocks Upload (Negative)
**Test Case Name**: Verify dumps are not uploaded when privacy mode is DO_NOT_SHARE  
**Pre-condition**:
- DEVICE_TYPE is "mediaclient"
- RBUS parameter `Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode` returns "DO_NOT_SHARE"
- Dump files exist in the working directory

**Operation**: 
1. Configure RBUS to return "DO_NOT_SHARE" for `Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode`
2. Execute with valid dump files present
3. Verify no uploads occur

**Expected Result**: 
- `get_privacy_control_mode()` is called (MEDIACLIENT only) and returns `DO_NOT_SHARE`
- Dumps are scanned and mtime is collected, but `archive_create_smart()` is skipped for each dump in the processing loop via `continue`
- After the archive loop: log message "Privacy mode is DO_NOT_SHARE, skip upload process & cleanup unprocessed dumps"
- `cleanup_batch(do_not_share_cleanup=true)` deletes all dump files matching the extension pattern
- Script exits with code 0 without uploading

**Actual Result**:  _[To be filled during testing]_

---

### TC-039: Privacy Mode - SHARE Allows Upload (Positive)
**Test Case Name**: Verify dumps are uploaded when privacy mode is SHARE  
**Pre-condition**:
- DEVICE_TYPE is "mediaclient"
- RBUS parameter `Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode` returns "SHARE" (or RBUS fails — both default to SHARE)

**Operation**: 
1. Ensure `Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode` returns "SHARE" via RBUS
2. Execute script with valid dumps
3. Verify upload proceeds

**Expected Result**:
- `get_privacy_control_mode()` returns `SHARE`
- Archive creation proceeds normally for each dump
- No privacy block message logged
- Rate limit is checked; dumps are archived and uploaded
- Dumps are successfully uploaded

**Actual Result**: _[To be filled during testing]_

---

### TC-040: Privacy Mode - Non-MEDIACLIENT Device Skips Privacy Check (Positive)
**Test Case Name**: Verify privacy check is not performed on non-mediaclient devices  
**Pre-condition**:
- DEVICE_TYPE is "broadband" or "extender"
- Dump files exist in the working directory

**Operation**: 
1. Execute script on a broadband or extender device with valid dumps
2. Verify upload proceeds without any RBUS privacy mode query

**Expected Result**: 
- `get_privacy_control_mode()` is NOT called (guarded by `config.device_type == DEVICE_TYPE_MEDIACLIENT` in main.c)
- `privacy_mode` remains at the default `SHARE` value set by `config_init_load()`
- All dumps are archived and uploaded normally
- No privacy-related log messages appear

**Actual Result**: _[To be filled during testing]_

---

## 7. Cleanup and Maintenance Test Cases

### TC-041: Cleanup - Old Files Removal (Positive)
**Test Case Name**: Verify files older than 2 days are cleaned up  
**Pre-condition**:
- WORKING_DIR contains dump files with naming pattern *_mac*_dat*
- Some files have modification time > 2 days old
- Some files have modification time < 2 days old

**Operation**:
1. Create test files with different timestamps
2. Execute script
3. Verify cleanup behavior

**Expected Result**:
- cleanup() function is called
- Files older than 2 days matching *_mac*_dat* are deleted
- Log messages: "Removed file:  <filename>" for each deleted file
- Recent files (< 2 days) are retained

**Actual Result**: _[To be filled during testing]_

---

### TC-042: Cleanup - Version File Removal (Positive)
**Test Case Name**: Verify version. txt is removed during cleanup  
**Pre-condition**:
- WORKING_DIR contains version.txt file
- /opt/. upload_on_startup does NOT exist

**Operation**:
1. Create version.txt in WORKING_DIR
2. Execute script
3. Check for version.txt removal

**Expected Result**:
- cleanup() function deletes version.txt from WORKING_DIR
- version.txt is removed successfully

**Actual Result**: _[To be filled during testing]_

---

### TC-043: Cleanup - Startup Cleanup First Run (Positive)
**Test Case Name**: Verify first-run startup cleanup removes unfinished files  
**Pre-condition**:
- ON_STARTUP_DUMPS_CLEANED_UP flag file does NOT exist
- WORKING_DIR contains unfinished files from previous run
- WORKING_DIR contains non-dump files

**Operation**:
1. Create test unfinished files matching *_mac*_dat*
2. Create non-dump files (not matching DUMPS_EXTN)
3. Execute script
4. Verify cleanup actions

**Expected Result**:
- Unfinished files (*_mac*_dat*) are deleted
- Log message: "Deleting unfinished files:  <files>"
- Non-dump files are deleted
- Log message: "Deleting non-dump files :  <files>"
- deleteAllButTheMostRecentFile() is called
- ON_STARTUP_DUMPS_CLEANED_UP flag file is created

**Actual Result**: _[To be filled during testing]_

---

### TC-044: Cleanup - Startup Cleanup Subsequent Runs (Positive)
**Test Case Name**: Verify startup cleanup is skipped on subsequent runs  
**Pre-condition**:
- ON_STARTUP_DUMPS_CLEANED_UP flag file exists
- WORKING_DIR contains various files

**Operation**:
1. Create ON_STARTUP_DUMPS_CLEANED_UP flag
2. Execute script
3. Verify cleanup is minimal

**Expected Result**:
- Full startup cleanup is skipped
- Only old files (> 2 days) are removed
- version.txt is removed
- Unfinished and non-dump file cleanup is NOT performed
- ON_STARTUP_DUMPS_CLEANED_UP flag remains

**Actual Result**: _[To be filled during testing]_

---

### TC-045: Cleanup - Maximum Core Files Limit (Positive)
**Test Case Name**: Verify only 4 most recent dump files are retained  
**Pre-condition**: 
- WORKING_DIR contains more than 4 dump files
- MAX_CORE_FILES is set to 4
- Files have different modification times

**Operation**:
1. Create 10 dump files with varying timestamps
2. Execute script
3. Verify oldest files are deleted

**Expected Result**:
- Number of files is counted
- Oldest 6 files are identified (10 - 4 = 6)
- Oldest files are listed in /tmp/dumps_to_delete. txt
- Log message: "Deleting dump files: <list>"
- Oldest 6 files are deleted
- 4 most recent files remain
- /tmp/dumps_to_delete. txt is cleaned up

**Actual Result**: _[To be filled during testing]_

---

### TC-046: Cleanup - Empty Working Directory (Negative)
**Test Case Name**:  Verify cleanup handles empty working directory gracefully  
**Pre-condition**:
- WORKING_DIR is empty or does not exist

**Operation**:
1. Remove all files from WORKING_DIR or remove directory
2. Execute script
3. Monitor cleanup behavior

**Expected Result**: 
- cleanup() function detects empty directory
- Log message:  "WORKING_DIR is empty!! !"
- Function returns without error
- No cleanup operations performed
- Script continues or exits gracefully

**Actual Result**: _[To be filled during testing]_

---

### TC-047: Cleanup - Upload on Startup Mode (Positive)
**Test Case Name**: Verify special cleanup for upload-on-startup mode  
**Pre-condition**: 
- /opt/. upload_on_startup file exists
- DUMP_FLAG is "1" (coredump mode)

**Operation**:
1. Create /opt/.upload_on_startup flag
2. Execute script with DUMP_FLAG="1"
3. Verify flag removal

**Expected Result**:
- Normal cleanup operations are bypassed
- /opt/.upload_on_startup is removed after coredump processing
- ON_STARTUP_DUMPS_CLEANED_UP flag is NOT created

**Actual Result**: _[To be filled during testing]_

---

## 8. Crash Rate Limiting Test Cases

### TC-048: Upload Limit Check - Under Limit (Positive)
**Test Case Name**: Verify upload proceeds when rate limit is not reached  
**Pre-condition**: 
- Timestamp file has less than 10 entries
- DUMP_NAME is "minidump"

**Operation**:
1. Create timestamp file with 5 entries
2. Execute script with minidump
3. Verify upload proceeds

**Expected Result**:
- isUploadLimitReached() returns false (1)
- No rate limit message logged
- Dump is processed normally
- Upload proceeds to S3

**Actual Result**: _[To be filled during testing]_

---

### TC-049: Upload Limit Check - Limit Reached (Negative)
**Test Case Name**:  Verify upload is blocked when rate limit is reached  
**Pre-condition**:
- Timestamp file has 10 or more entries
- 10th newest entry is less than 600 seconds (10 minutes) old
- DUMP_NAME is "minidump"

**Operation**:
1. Create timestamp file with 10 recent entries
2. Execute script with minidump
3. Monitor rate limiting behavior

**Expected Result**: 
- isUploadLimitReached() returns true (0)
- Log message: "Not uploading the dump.  Too many dumps."
- Log message: "Upload rate limit has been reached."
- Dump is marked as crashlooped
- markAsCrashLoopedAndUpload() is called
- File is renamed to *.crashloop. dmp. tgz
- Recovery time is set (10 minutes)
- Pending dumps are removed

**Actual Result**: _[To be filled during testing]_

---

### TC-050: Upload Limit Check - Coredump Exemption (Positive)
**Test Case Name**: Verify coredumps bypass rate limiting check  
**Pre-condition**: 
- DUMP_NAME is "coredump"
- Rate limit would be triggered for minidumps

**Operation**:
1. Create conditions that would trigger rate limit
2. Execute script with DUMP_FLAG="1" (coredump)
3. Verify rate limit is bypassed

**Expected Result**: 
- isUploadLimitReached() is NOT called for coredumps
- No rate limiting check occurs
- Coredump is processed normally
- Upload proceeds regardless of rate limit state

**Actual Result**: _[To be filled during testing]_

---

### TC-051: Recovery Time Check - Before Recovery (Negative)
**Test Case Name**:  Verify uploads are denied before recovery time is reached  
**Pre-condition**:
- /tmp/. deny_dump_uploads_till file exists
- Current time is less than recovery time value in file

**Operation**:
1. Set recovery time to current time + 300 seconds
2. Execute script immediately
3. Verify upload is denied

**Expected Result**:
- isRecoveryTimeReached() returns false (1)
- Log message: "Shifting the recovery time forward."
- Recovery time is extended by 10 more minutes
- removePendingDumps() is called
- All pending dumps are removed
- Script exits

**Actual Result**: _[To be filled during testing]_

---

### TC-052: Recovery Time Check - After Recovery (Positive)
**Test Case Name**: Verify uploads resume after recovery time is reached  
**Pre-condition**:
- /tmp/.deny_dump_uploads_till file exists
- Current time exceeds recovery time value in file

**Operation**:
1. Set recovery time to current time - 100 seconds (in past)
2. Execute script with valid dump
3. Verify upload proceeds

**Expected Result**:
- isRecoveryTimeReached() returns true (0)
- /tmp/.deny_dump_uploads_till file is removed
- No recovery time extension
- Dump processing proceeds normally
- Upload occurs

**Actual Result**: _[To be filled during testing]_

---

### TC-053: Recovery Time Check - No Recovery File (Positive)
**Test Case Name**:  Verify uploads proceed when recovery file doesn't exist  
**Pre-condition**:
- /tmp/.deny_dump_uploads_till file does NOT exist
- Valid dumps are present

**Operation**:
1. Remove recovery time file
2. Execute script
3. Verify upload proceeds

**Expected Result**:
- isRecoveryTimeReached() returns true (0)
- No recovery time checking occurs
- Dumps are processed normally
- Uploads proceed

**Actual Result**:  _[To be filled during testing]_

---

### TC-054: Recovery Time Check - Invalid File Content (Positive)
**Test Case Name**:  Verify handling of invalid recovery time file content  
**Pre-condition**: 
- /tmp/.deny_dump_uploads_till file exists
- File contains non-numeric data

**Operation**:
1. Create recovery file with content "invalid"
2. Execute script
3. Verify error handling

**Expected Result**: 
- isRecoveryTimeReached() validates file content
- Invalid content is detected
- Function returns true (0) - allows processing
- Uploads proceed despite invalid file

**Actual Result**: _[To be filled during testing]_

---

### TC-055: Timestamp File Management - Truncation (Positive)
**Test Case Name**: Verify timestamp file is truncated to 10 entries  
**Pre-condition**:
- Timestamp file has more than 10 entries
- BUILD_TYPE is "prod"

**Operation**:
1. Create timestamp file with 20 entries
2. Execute script and upload a dump
3. Check timestamp file size

**Expected Result**:
- logUploadTimestamp() is called after successful upload
- truncateTimeStampFile() is called
- Oldest entries are removed
- Only 10 most recent entries remain
- File permissions remain a+rw

**Actual Result**: _[To be filled during testing]_

---

### TC-056: Timestamp File Management - Non-Prod Build (Positive)
**Test Case Name**: Verify timestamps are not logged for non-prod builds  
**Pre-condition**:
- BUILD_TYPE is not "prod" (dev, QA, etc.)
- Dump is uploaded successfully

**Operation**:
1. Set BUILD_TYPE to "dev"
2. Execute script and upload dump
3. Check timestamp file

**Expected Result**:
- logUploadTimestamp() checks BUILD_TYPE
- No timestamp is appended to file
- truncateTimeStampFile() is not called
- Timestamp file remains unchanged or empty

**Actual Result**: _[To be filled during testing]_

---

## 9. Dump File Processing Test Cases

### TC-057: File Sanitization - Special Characters Removed (Positive)
**Test Case Name**: Verify dump files with special characters are sanitized  
**Pre-condition**:
- Dump file exists with special characters in name
- Example: "test$file@name#123. dmp"

**Operation**: 
1. Create dump file with special characters
2. Execute script
3. Verify file is renamed

**Expected Result**:
- File name is sanitized using sed
- Special characters (except allowed:  /a-zA-Z0-9 ._-) are removed
- File is renamed to clean version:  "testfilename123.dmp"
- Processing continues with sanitized name

**Actual Result**: _[To be filled during testing]_

---

### TC-058: File Sanitization - Container Delimiter Preserved (Positive)
**Test Case Name**: Verify container delimiter <#=#> is preserved during sanitization  
**Pre-condition**:
- Dump file contains container delimiter:  "process<#=#>running<#=#>timestamp. dmp"
- File represents containerized application crash

**Operation**:
1. Create dump file with container delimiter
2. Execute script
3. Verify delimiter is preserved

**Expected Result**: 
- Delimiter is temporarily replaced with "PLACEHOLDER" Not Applicable in C code
- Sanitization is performed
- "PLACEHOLDER" is replaced back to "<#=#>"
- Container information is retained
- File is processed correctly

**Actual Result**: _[To be filled during testing]_

---

### TC-059: File Sanitization - Empty Result (Negative)
**Test Case Name**:  Verify dump file is deleted if sanitization results in empty name  
**Pre-condition**: 
- Dump file exists with only special characters:  "@#$%^. dmp"

**Operation**:
1. Create dump file with only special characters
2. Execute script
3. Verify file handling

**Expected Result**:
- After sanitization, f1 is empty
- File is deleted:  rm -f "$f"
- Processing continues to next file
- No crash or error occurs

**Actual Result**:  _[To be filled during testing]_

---

### TC-060:  Tarball Detection - Skip Already Archived (Positive)
**Test Case Name**: Verify already archived tarballs are skipped  
**Pre-condition**:
- File with . tgz extension exists in WORKING_DIR
- File follows naming pattern *_mac*_dat*_box*_mod*. tgz

**Operation**: 
1. Create pre-archived tarball
2. Execute script
3. Verify tarball is skipped

**Expected Result**:
- File extension is checked
- If extension is "tgz", archiving is skipped
- Log message: "Skip archiving $f as it is a tarball already."
- File is not reprocessed
- Continue to next file

**Actual Result**: _[To be filled during testing]_

---

### TC-061: Dump File Naming - Standard Format (Positive)
**Test Case Name**: Verify dump file is renamed with metadata  
**Pre-condition**: 
- Dump file exists:  "process_name. dmp"
- sha1, MAC, timestamp, boxType, modNum are available

**Operation**:
1. Execute script
2. Verify file renaming

**Expected Result**:
- setLogFile() is called with parameters
- File is renamed to: "<sha1>_mac<MAC>_dat<timestamp>_box<boxType>_mod<modNum>_process_name.dmp"
- All metadata is incorporated into filename
- Original file is moved to new name

**Actual Result**: _[To be filled during testing]_

---

### TC-062: Dump File Naming - Long Filename Truncation (Positive)
**Test Case Name**: Verify long filenames are truncated to avoid ecryptfs limits  
**Pre-condition**: 
- Dump file has very long name
- After adding metadata, name exceeds 135 characters
- ecryptfs has 140 character limit

**Operation**: 
1. Create dump with long process name
2. Execute script
3. Verify truncation

**Expected Result**: 
- Filename length is checked
- If >= 135 characters, header is removed
- dumpName is trimmed:  "${dumpName#*_}"
- If still >= 135, process name is truncated to 20 chars
- Log messages show truncation steps
- Final filename is under 140 characters

**Actual Result**: _[To be filled during testing]_

---

### TC-063: Dump File Naming - Already Processed (Positive)
**Test Case Name**: Verify already processed dump files are not renamed  
**Pre-condition**: 
- Dump file already has metadata in name
- Filename matches pattern *_mac*_dat*_box*_mod*

**Operation**:
1. Create file:  "sha1_macAABBCCDDEEFF_dat2025-01-01_boxXG1_modXG1v4_process. dmp"
2. Execute script
3. Verify file is not renamed

**Expected Result**: 
- setLogFile() detects existing metadata pattern
- Log message: "Core name is already processed."
- Original filename is returned unchanged
- File is not renamed again
- Processing continues with original name

**Actual Result**: _[To be filled during testing]_

---

### TC-064: Coredump Naming - mpeos-main Exception (Positive)
**Test Case Name**: Verify mpeos-main coredumps use modDate instead of CRASHTS  
**Pre-condition**: 
- DUMP_FLAG is "1" (coredump mode)
- Dump file name contains "mpeos-main"

**Operation**:
1. Create coredump:  "mpeos-main_12345.core"
2. Execute script
3. Verify naming uses modDate

**Expected Result**: 
- File is checked with:  echo $f | grep -q mpeos-main
- modDate is used instead of CRASHTS for timestamp
- File is renamed using modDate
- Comment notes:  "CRASHTS not reqd as minidump won't be uploaded for mpeos-main"

**Actual Result**: _[To be filled during testing]_

---

### TC-065: Archive Creation - Coredump Mode (Positive)
**Test Case Name**: Verify coredump is compressed into . core.tgz archive  
**Pre-condition**: 
- DUMP_FLAG is "1"
- Valid coredump file exists
- version.txt and CORE_LOG exist

**Operation**:
1. Execute script with coredump
2. Monitor tar creation

**Expected Result**: 
- Files to archive: dumpName, version.txt, CORE_LOG
- If /tmp/set_crash_reboot_flag exists, tar without nice
- Otherwise, tar with:  nice -n 19 tar -zcvf
- Archive name: <dumpName>. core.tgz
- Log message: "Success Compressing the files, <tgzFile> <dumpName> <logfiles>"
- Original dump file is removed after archiving

**Actual Result**: _[To be filled during testing]_

---

### TC-066: Archive Creation - Minidump Mode Video Device (Positive)
**Test Case Name**: Verify minidump archive for hybrid/mediaclient devices  
**Pre-condition**:
- DUMP_FLAG is "0"
- DEVICE_TYPE is "hybrid" or "mediaclient"
- Crashed process log files exist

**Operation**:
1. Execute script with minidump
2. Monitor archive creation

**Expected Result**:
- Files included: dumpName, version.txt, CORE_LOG, crashed_url. txt (if exists)
- add_crashed_log_file() is called to add process logs
- Archive created with: nice -n 19 tar -zcvf
- Archive name: <dumpName>.tgz
- Log message: "Success Compressing the files, <tgzFile> <dumpName> <files>"

**Actual Result**: _[To be filled during testing]_

---

### TC-067: Archive Creation - Minidump Mode Broadband Device (Positive)
**Test Case Name**: Verify minidump archive for broadband/extender devices  
**Pre-condition**:
- DUMP_FLAG is "0"
- DEVICE_TYPE is "broadband" or "extender"
- Log mapper file exists

**Operation**:
1. Execute script with minidump
2. Monitor archive creation

**Expected Result**:
- Files included:  tgzFile, dumpName, version.txt, CORE_LOG
- add_crashed_log_file() is called
- Log files from LOGMAPPER_FILE are added
- Archive created with: nice -n 19 tar -zcvf
- Archive name: <dumpName>.tgz

**Actual Result**: _[To be filled during testing]_

---

### TC-068: Archive Creation - Compression Failure Retry (Positive)
**Test Case Name**: Verify tar retry with /tmp when compression fails  
**Pre-condition**:
- Initial tar command fails (returns non-zero)
- /tmp directory has sufficient space (< 70% usage)

**Operation**:
1. Simulate tar failure (e.g., corrupt file)
2. Execute script
3. Monitor retry behavior

**Expected Result**: 
- Initial tar fails
- T2 telemetry:  "SYST_WARN_CompFail"
- copy_log_files_tmp_dir() is called
- Files are copied to /tmp/<TMP_DIR_NAME>
- Retry tar with files from /tmp
- If successful:  Log "Success Compressing the files, <tgzFile> <OUT_FILES>"
- /tmp/<TMP_DIR_NAME> is cleaned up

**Actual Result**: _[To be filled during testing]_

---

### TC-069: Archive Creation - Compression Failure Final (Negative)
**Test Case Name**:  Verify handling when compression fails completely  
**Pre-condition**: 
- Both tar attempts fail
- File system issues or corruption present

**Operation**:
1. Simulate complete tar failure
2. Execute script
3. Monitor error handling

**Expected Result**: 
- Initial tar fails
- T2 telemetry: "SYST_WARN_CompFail"
- Retry tar also fails
- Log message: "Compression Failed ."
- T2 telemetry: "SYST_ERR_CompFail"
- Script continues to next file
- Failed dump is not uploaded

**Actual Result**: _[To be filled during testing]_

---

### TC-070: Archive Creation - /tmp Space Check (Positive)
**Test Case Name**: Verify /tmp space is checked before copying files  
**Pre-condition**:
- /tmp directory usage is 75% (above 70% limit)
- Tar compression needs retry

**Operation**:
1. Fill /tmp to 75% capacity
2. Trigger tar retry scenario
3. Monitor space check

**Expected Result**:
- copy_log_files_tmp_dir() checks /tmp usage
- Usage is >= 70%
- Log message: "Skipping copying Logs to tmp dir due to limited Memory"
- OUT_FILES is set to original Logfiles
- No files copied to /tmp
- Tar is attempted with original file locations

**Actual Result**: _[To be filled during testing]_

---

### TC-071: Zero Size Dump Detection (Negative)
**Test Case Name**:  Verify zero-size dumps are detected and reported  
**Pre-condition**: 
- Dump file exists but is empty (0 bytes)
- T2 telemetry is enabled

**Operation**:
1. Create zero-size dump file
2. Execute script
3. Monitor telemetry

**Expected Result**: 
- File size is checked with: [ !  -s "$dumpName" ]
- Zero size is detected
- T2 telemetry: "SYST_ERR_MINIDPZEROSIZE"
- Log message shows: "Size of the file:  0"
- File is still processed and uploaded

**Actual Result**: _[To be filled during testing]_

---

## 10. Crash Telemetry and Log File Test Cases

### TC-072: Crash Telemetry - Standard Process Crash (Positive)
**Test Case Name**: Verify telemetry is sent for standard process crash  
**Pre-condition**: 
- DUMP_FLAG is "0" (minidump)
- T2 telemetry is enabled
- Dump file: "crashed_process_12345.dmp"

**Operation**:
1. Execute script with minidump
2. Verify telemetry notifications

**Expected Result**:
- processCrashTelemtryInfo() is called
- get_crashed_log_file() is called
- Process name is extracted
- T2 notifications sent: 
  - t2ValNotify "processCrash_split" <pname>
  - t2ValNotify "SYST_ERR_Process_Crash_accum" <pname>
  - t2CountNotify "SYST_ERR_ProcessCrash"
- Log message: "Process crashed = <pname>"

**Actual Result**: _[To be filled during testing]_

---

### TC-073: Crash Telemetry - Container Crash (Positive)
**Test Case Name**: Verify telemetry for containerized application crash  
**Pre-condition**:
- Dump file contains container delimiter
- File:  "processname_appname<#=#>running<#=#>1234567890.dmp"
- T2 telemetry is enabled

**Operation**:
1. Execute script with container dump
2. Verify container-specific telemetry

**Expected Result**:
- Container is detected:  isContainer=1
- Container name, status, and time are extracted
- Log message: "From the file name crashed process is a container"
- T2 notifications sent:
  - t2ValNotify "crashedContainerName_split" <containerName>
  - t2ValNotify "crashedContainerStatus_split" <containerStatus>
  - t2ValNotify "crashedContainerAppname_split" <Appname>
  - t2ValNotify "crashedContainerProcessName_split" <ProcessName>
  - t2CountNotify "SYS_INFO_CrashedContainer"
  - t2ValNotify "APP_ERROR_Crashed_split" <details>
  - t2ValNotify "APP_ERROR_CrashInfo" <containerName>
  - t2ValNotify "APP_ERROR_CrashInfo_status" <containerStatus>

**Actual Result**: _[To be filled during testing]_

---

### TC-074: Crash Telemetry - Tarball Retry Detection (Positive)
**Test Case Name**: Verify telemetry for pre-existing tarball (retry scenario)  
**Pre-condition**:
- Dump file has . tgz extension
- File: "sha1_mac.. ._dat..._mod..._process.dmp. tgz"
- T2 telemetry is enabled

**Operation**:
1. Execute script with tarball
2. Verify retry detection

**Expected Result**: 
- isTgz flag is set to 1
- Log message: "The File is already a tarball, this might be a retry or crash during shutdown"
- Meta information is removed from filename
- T2 notification:  t2CountNotify "SYS_INFO_TGZDUMP" "1"
- Log message: "This could be a retry or crash from previous boot the appname can be truncated"

**Actual Result**: _[To be filled during testing]_

---

### TC-075: Log File Mapping - Process to Log Files (Positive)
**Test Case Name**: Verify crashed process log files are identified and added  
**Pre-condition**: 
- LOGMAPPER_FILE exists:  /etc/breakpad-logmapper.conf
- Mapping:  "crashed_process=/var/log/process.log,/var/log/app.log"
- Dump file: "crashed_process_12345.dmp"

**Operation**:
1. Execute script
2. Verify log file extraction

**Expected Result**:
- Process name is extracted:  "crashed_process"
- LOGMAPPER_FILE is parsed with awk
- Log files are identified:  "/var/log/process.log,/var/log/app.log"
- Log message: "Crashed process log file(s): <log_files>"
- Files are written to LOG_FILES

**Actual Result**: _[To be filled during testing]_

---

### TC-076: Log File Addition - Production Build (Positive)
**Test Case Name**: Verify 500 lines of logs are added for production builds  
**Pre-condition**:
- BUILD_TYPE is "prod"
- Crashed process log file exists with 1000 lines

**Operation**:
1. Execute script on production build
2. Verify log line limit

**Expected Result**:
- line_count is set to 500 for prod builds
- tail -n 500 is used to extract log lines
- Process log file is created with last 500 lines
- Log message: "Adding File: <process_log> to minidump tarball"
- Log file is added to archive

**Actual Result**: _[To be filled during testing]_

---

### TC-077: Log File Addition - Non-Production Build (Positive)
**Test Case Name**: Verify 5000 lines of logs are added for non-prod builds  
**Pre-condition**:
- BUILD_TYPE is not "prod" (dev, QA, etc.)
- Crashed process log file exists with 6000 lines

**Operation**: 
1. Execute script on non-prod build
2. Verify log line limit

**Expected Result**: 
- line_count is set to 5000 for non-prod builds
- tail -n 5000 is used to extract log lines
- Process log file is created with last 5000 lines
- More detailed logs are included in archive

**Actual Result**:  _[To be filled during testing]_

---

### TC-078: Log File Addition - Missing Log Files (Negative)
**Test Case Name**:  Verify handling when mapped log files don't exist  
**Pre-condition**:
- LOGMAPPER_FILE maps crashed process to non-existent log files
- Log files don't exist on filesystem

**Operation**:
1. Execute script
2. Verify error handling

**Expected Result**: 
- Log files are attempted to be read
- Empty or missing files are skipped
- No error in archive creation
- Archive is created without those log files
- Processing continues normally

**Actual Result**: _[To be filled during testing]_

---

### TC-079: Crashed URL File Addition - Video Device (Positive)
**Test Case Name**: Verify crashed_url.txt is added for video devices  
**Pre-condition**: 
- DEVICE_TYPE is "hybrid" or "mediaclient"
- $LOG_PATH/crashed_url.txt exists

**Operation**:
1. Create crashed_url.txt file
2. Execute script with minidump
3. Verify file inclusion

**Expected Result**:
- crashed_url.txt existence is checked
- If exists, crashedUrlFile variable is set
- File is added to archive files list
- Archive includes crashed_url.txt

**Actual Result**: _[To be filled during testing]_

---

### TC-080: Crashed URL File Addition - File Missing (Positive)
**Test Case Name**:  Verify archive succeeds when crashed_url.txt is missing  
**Pre-condition**:
- DEVICE_TYPE is "hybrid" or "mediaclient"
- $LOG_PATH/crashed_url.txt does NOT exist

**Operation**:
1. Remove crashed_url.txt
2. Execute script
3. Verify archive creation

**Expected Result**: 
- File check: [ -f "$LOG_PATH/crashed_url.txt" ] fails
- crashedUrlFile variable is not set
- Archive is created without crashed_url.txt
- No tar errors occur
- Archive is valid and uploadable

**Actual Result**: _[To be filled during testing]_

---

## 11. Upload Functionality Test Cases

### TC-081: S3 Upload - First Attempt Success (Positive)
**Test Case Name**: Verify successful dump upload to S3 on first attempt  
**Pre-condition**:
- Network connectivity is available
- uploadDumpsToS3.sh script exists
- Valid tarball is ready for upload
- S3 credentials and endpoint configured

**Operation**:
1. Execute script with valid dump
2. Monitor upload process

**Expected Result**:
- Upload parameters are written to /tmp/uploadtos3params
- uploadToS3 function is called with filename
- Upload succeeds with status=0
- /tmp/uploadtos3params is removed
- Log message: "[uploadDumps. sh]:  minidump uploadToS3 SUCESS:  status:  0"
- For minidump with T2: t2CountNotify "SYST_INFO_minidumpUpld"
- Log message: "[uploadDumps.sh]:  Execution Status: 0, S3 Amazon Upload of minidump Success"
- Tarball is deleted after upload
- logUploadTimestamp() is called

**Actual Result**: _[To be filled during testing]_

---

### TC-082: S3 Upload - Retry Logic (Positive)
**Test Case Name**: Verify upload retry on first attempt failure  
**Pre-condition**: 
- Network connectivity is intermittent
- First upload attempt will fail
- Second attempt will succeed

**Operation**:
1.  Simulate network failure for first attempt
2. Execute script
3. Monitor retry behavior

**Expected Result**:
- First upload fails with status != 0
- Log message: "[uploadDumps. sh]:  Execution Status: <status>, S3 Amazon Upload of minidump Failed"
- Log message: "[uploadDumps. sh]: 2:  (Retry), minidump S3 Upload"
- Script sleeps for 2 seconds
- Second upload is attempted
- ARM_INTERFACE is refreshed if waninfo. sh exists
- Second attempt succeeds
- Tarball is deleted

**Actual Result**: _[To be filled during testing]_

---

### TC-083: S3 Upload - All Retries Failed (Negative)
**Test Case Name**: Verify handling when all 3 upload attempts fail  
**Pre-condition**:
- Network is completely unavailable
- All upload attempts will fail

**Operation**:
1. Disable network connectivity
2. Execute script
3. Monitor all retry attempts

**Expected Result**: 
- First attempt fails
- Log message shows retry 1, sleeps 2 seconds
- Second attempt fails (count=2)
- Log message shows retry 2, sleeps 2 seconds
- Third attempt fails (count=3)
- Log message:  "[uploadDumps.sh]:  S3 Amazon Upload of minidump Failed.. !"
- For minidump:  saveDump() is called
- Dump is saved locally for later retry
- For coredump: file is deleted
- Script exits with code 1

**Actual Result**:  _[To be filled during testing]_

---

### TC-084: Verify Fall back path
**Test Case Name**: Verify when c app fail script should trigger
**Pre-condition**:
- Make C app fail.

**Operation**:
TBD

**Expected Result**:
- script should run and success.


---


### TC-085: Verify Only single instance should run
**Test Case Name**: Verify only one instance run at a time between script and c app
**Pre-condition**:
- Trigger multiple instance

**Operation**:
TBD

**Expected Result**:
- Only one instance should run

