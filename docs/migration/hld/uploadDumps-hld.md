# High-Level Design: uploadDumps.sh Migration to C

## 1. Architecture Overview

The uploadDumps C implementation will follow a modular architecture designed for embedded systems with low memory and CPU resources. The design emphasizes platform neutrality, maintainability, and efficient resource usage.

### 1.1 Design Principles

- **Modularity**: Clear separation of concerns with well-defined interfaces
- **Platform Abstraction**: Platform-specific code isolated in separate modules
- **Resource Efficiency**: Minimal memory footprint and CPU usage
- **Error Resilience**: Comprehensive error handling and recovery
- **Maintainability**: Clear code structure with consistent conventions

### 1.2 System Context

```
┌─────────────────────────────────────────────────────────────┐
│                     External Systems                         │
├─────────────────────────────────────────────────────────────┤
│  Crash Portal Server  │  Configuration Files │  System Logs │
└──────────┬────────────┴──────────┬───────────┴──────┬───────┘
           │                       │                   │
           │ HTTPS/TLS             │ Read              │ Write
           │                       │                   │
┌──────────▼───────────────────────▼───────────────────▼───────┐
│                                                               │
│                    uploadDumps Application                    │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   Main      │  │  Platform    │  │    Configuration    │ │
│  │ Controller  │──│  Abstraction │──│      Manager        │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                │                      │            │
│  ┌──────▼────────────────▼──────────────────────▼──────────┐ │
│  │              Core Processing Modules                    │ │
│  ├──────────────┬─────────────┬──────────────┬─────────────┤ │
│  │ Dump File    │   Archive   │   Upload     │  Rate       │ │
│  │ Scanner      │   Creator   │   Manager    │  Limiter    │ │
│  └──────┬───────┴──────┬──────┴──────┬───────┴──────┬──────┘ │
│         │              │              │              │        │
│  ┌──────▼──────────────▼──────────────▼──────────────▼──────┐ │
│  │              Utility and Support Modules                 │ │
│  ├──────────┬──────────┬──────────┬──────────┬─────────────┤ │
│  │ Network  │  File    │  String  │  Lock    │  Logging    │ │
│  │ Utils    │  Utils   │  Utils   │  Manager │  System     │ │
│  └──────────┴──────────┴──────────┴──────────┴─────────────┘ │
│                                                               │
└───────────────────────────────────────────────────────────────┘
           │                       │                   │
           │ inotify               │ Read/Write        │ Read
           │                       │                   │
┌──────────▼───────────────────────▼───────────────────▼───────┐
│        Filesystem (Dump Directories, Temp Files)             │
└──────────────────────────────────────────────────────────────┘
```

## 2. Module/Component Breakdown

### 2.1 Main Controller Module

**Purpose**: Orchestrate the overall dump processing workflow

**Responsibilities**:
- Parse command-line arguments
- Initialize all subsystems
- Coordinate dump processing pipeline
- Handle signals (SIGTERM, SIGKILL)
- Manage cleanup on exit
- Enforce single-instance execution

**Key Interfaces**:
```c
int main(int argc, char *argv[]);
int initialize_system(const config_t *config);
int process_dumps_loop(const config_t *config);
void cleanup_and_exit(int exit_code);
void signal_handler(int signum);
```

**Data Structures**:
```c
typedef struct {
    char *working_dir;
    dump_type_t dump_type;  // COREDUMP or MINIDUMP
    upload_mode_t upload_mode;  // SECURE or NORMAL
    lock_mode_t lock_mode;  // WAIT or EXIT
    device_type_t device_type;
    build_type_t build_type;
    platform_config_t platform;
} config_t;
```

### 2.2 Platform Abstraction Layer

**Purpose**: Isolate platform-specific code and provide unified interface

**Responsibilities**:
- Device type detection (broadband, extender, hybrid, mediaclient)
- Platform-specific path configuration
- Interface name resolution
- Platform-specific feature flags

**Key Interfaces**:
```c
int platform_init(platform_config_t *platform);
const char* platform_get_dump_path(device_type_t type, bool secure);
const char* platform_get_log_path(device_type_t type);
const char* platform_get_interface_name(device_type_t type);
bool platform_supports_feature(platform_feature_t feature);
```

**Data Structures**:
```c
typedef struct {
    device_type_t device_type;
    build_type_t build_type;
    char mac_address[MAC_ADDR_LEN];
    char model_number[MODEL_NUM_LEN];
    char box_type[BOX_TYPE_LEN];
    char sha1_hash[SHA1_LEN];
    char *dump_path;
    char *log_path;
    char *interface_name;
} platform_config_t;
```

### 2.3 Configuration Manager

**Purpose**: Load and manage configuration from multiple sources

**Responsibilities**:
- Parse configuration files
- Load environment variables
- Apply configuration overrides
- Validate configuration
- Provide configuration access

**Key Interfaces**:
```c
int config_load(config_t *config);
int config_load_file(const char *path, config_t *config);
int config_load_environment(config_t *config);
int config_validate(const config_t *config);
const char* config_get_string(const config_t *config, const char *key);
int config_get_int(const config_t *config, const char *key, int default_val);
```

**Configuration Sources**:
1. `/etc/device.properties`
2. `/etc/include.properties`
3. Environment variables
4. Command-line arguments
5. Platform-specific overrides

### 2.4 Dump File Scanner Module

**Purpose**: Discover and enumerate dump files for processing

**Responsibilities**:
- Scan dump directories
- Filter by file patterns (*.dmp*, *_core*.gz*)
- Detect already-processed files
- Return sorted file list
- Handle symbolic links

**Key Interfaces**:
```c
int scanner_init(scanner_t *scanner, const char *directory);
int scanner_find_dumps(scanner_t *scanner, const char *pattern, dump_list_t *list);
int scanner_is_processed(const char *filename);
void scanner_cleanup(scanner_t *scanner);
```

**Data Structures**:
```c
typedef struct {
    char filename[PATH_MAX];
    time_t mtime;
    off_t size;
    dump_type_t type;
} dump_file_t;

typedef struct {
    dump_file_t *files;
    size_t count;
    size_t capacity;
} dump_list_t;
```

### 2.5 Archive Creator Module

**Purpose**: Create compressed archives of dump files with metadata

**Responsibilities**:
- Generate archive filenames with metadata
- Collect log files for inclusion
- Create tar.gz archives
- Handle compression failures
- Implement fallback strategies (copy to /tmp)
- Parse container crash information

**Key Interfaces**:
```c
int archive_create(const dump_file_t *dump, const config_t *config, 
                   char *archive_path, size_t path_len);
int archive_add_metadata(archive_t *archive, const config_t *config);
int archive_add_logs(archive_t *archive, const char *process_name);
int archive_finalize(archive_t *archive);
void archive_cleanup(archive_t *archive);
```

**Data Structures**:
```c
typedef struct {
    char path[PATH_MAX];
    char temp_dir[PATH_MAX];
    FILE *tarfile;
    compression_type_t compression;
    size_t file_count;
    bool use_tmp_fallback;
} archive_t;
```

### 2.6 Upload Manager Module

**Purpose**: Handle upload operations to crash portal server

**Responsibilities**:
- Upload archives via HTTPS/TLS
- Implement retry logic (3 attempts)
- Handle timeouts (45 seconds)
- Support S3 upload
- Verify upload success
- Log upload results
- Handle privacy mode checks

**Key Interfaces**:
```c
int upload_init(upload_config_t *config);
int upload_file(const char *filepath, const upload_config_t *config, 
                upload_result_t *result);
int upload_retry(const char *filepath, const upload_config_t *config, 
                 int max_retries, upload_result_t *result);
bool upload_check_privacy_mode(void);
void upload_cleanup(upload_config_t *config);
```

**Data Structures**:
```c
typedef struct {
    char portal_url[URL_MAX_LEN];
    char partner_id[PARTNER_ID_LEN];
    char crash_portal_path[PATH_MAX];
    int timeout_seconds;
    bool use_tls;
    bool enable_ocsp;
    bool enable_ocsp_stapling;
} upload_config_t;

typedef struct {
    int http_code;
    bool success;
    char error_message[ERROR_MSG_LEN];
    size_t bytes_uploaded;
    int attempts;
} upload_result_t;
```

### 2.7 Rate Limiter Module

**Purpose**: Prevent upload flooding and detect crash loops

**Responsibilities**:
- Track upload timestamps
- Enforce rate limits (10 uploads per 10 minutes)
- Manage recovery time
- Create crashloop markers
- Clean up pending dumps when limited

**Key Interfaces**:
```c
int ratelimit_init(ratelimit_t *limiter, const char *timestamp_file);
bool ratelimit_is_exceeded(ratelimit_t *limiter);
bool ratelimit_is_recovery_time_reached(ratelimit_t *limiter);
int ratelimit_record_upload(ratelimit_t *limiter);
int ratelimit_set_recovery_time(ratelimit_t *limiter, int seconds);
void ratelimit_cleanup(ratelimit_t *limiter);
```

**Data Structures**:
```c
typedef struct {
    char timestamp_file[PATH_MAX];
    char deny_file[PATH_MAX];
    time_t *timestamps;
    size_t timestamp_count;
    time_t recovery_time;
    int limit_count;
    int limit_seconds;
} ratelimit_t;
```

### 2.8 Network Utilities Module

**Purpose**: Network-related helper functions

**Responsibilities**:
- Check network connectivity
- Wait for network availability
- Verify route availability
- Get interface status
- Handle platform-specific network checks

**Key Interfaces**:
```c
bool network_is_available(const char *interface);
int network_wait_for_connection(int max_iterations, int delay_seconds);
bool network_check_route_available(void);
int network_wait_for_system_time(int max_iterations, int delay_seconds);
```

### 2.9 File Utilities Module

**Purpose**: File and directory operations

**Responsibilities**:
- File existence checks
- Directory creation
- File deletion with safety checks
- Temporary file management
- Filename sanitization
- Last modified time retrieval

**Key Interfaces**:
```c
bool file_exists(const char *path);
int file_get_mtime(const char *path, char *timestamp, size_t len);
int file_delete_safely(const char *path);
int file_sanitize_name(const char *input, char *output, size_t len);
int file_create_temp_dir(char *path, size_t len);
void file_cleanup_temp_dir(const char *path);
int file_get_sha1(const char *path, char *hash, size_t len);
```

### 2.10 String Utilities Module

**Purpose**: String manipulation and formatting

**Responsibilities**:
- String sanitization (remove non-alphanumeric)
- MAC address formatting
- Timestamp generation and formatting
- Safe string operations (no buffer overflows)
- Filename generation

**Key Interfaces**:
```c
int string_sanitize(const char *input, char *output, size_t len);
int string_format_mac(const char *mac, char *output, size_t len);
int string_format_timestamp(time_t time, char *output, size_t len);
int string_generate_filename(const char *sha1, const char *mac, 
                            const char *timestamp, const char *box_type,
                            const char *model, const char *original,
                            char *output, size_t len);
```

### 2.11 Lock Manager Module

**Purpose**: Implement file-based locking for single-instance execution

**Responsibilities**:
- Create lock directories
- Check lock existence
- Remove locks
- Wait for lock availability
- Handle stale locks

**Key Interfaces**:
```c
int lock_create(const char *lock_path, lock_mode_t mode);
bool lock_exists(const char *lock_path);
int lock_remove(const char *lock_path);
int lock_wait_for_release(const char *lock_path, int timeout_seconds);
```

**Data Structures**:
```c
typedef enum {
    LOCK_MODE_EXIT,
    LOCK_MODE_WAIT
} lock_mode_t;
```

### 2.12 Logging System Module

**Purpose**: Centralized logging functionality

**Responsibilities**:
- Write to log files
- Format log messages with timestamps
- Support different log levels
- Handle log file rotation
- Platform-specific log formatting
- Telemetry integration

**Key Interfaces**:
```c
int log_init(const char *log_file, device_type_t device_type);
void log_message(log_level_t level, const char *format, ...);
void log_cleanup(void);
int log_telemetry_event(const char *event_name, const char *value);
```

**Data Structures**:
```c
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} log_level_t;
```

## 3. Data Flow

### 3.1 Main Processing Flow

```
Start
  │
  ├─→ Parse Arguments
  │
  ├─→ Initialize Configuration
  │     ├─→ Load config files
  │     ├─→ Load environment
  │     └─→ Validate
  │
  ├─→ Initialize Platform
  │     ├─→ Detect device type
  │     ├─→ Get MAC address
  │     ├─→ Get model/SHA1
  │     └─→ Set paths
  │
  ├─→ Acquire Lock
  │     ├─→ Check lock exists
  │     ├─→ Wait or exit
  │     └─→ Create lock
  │
  ├─→ Check Prerequisites
  │     ├─→ Network available?
  │     ├─→ System time synced?
  │     ├─→ Privacy mode off?
  │     └─→ Opt-out disabled?
  │
  ├─→ Cleanup Old Files
  │     ├─→ Remove files > 2 days
  │     ├─→ Remove unfinished
  │     └─→ Limit to MAX files
  │
  ├─→ Scan for Dumps
  │     ├─→ Find dump files
  │     ├─→ Filter patterns
  │     └─→ Sort by time
  │
  ├─→ Process Each Dump
  │     ├─→ Check rate limit
  │     ├─→ Create archive
  │     ├─→ Upload archive
  │     ├─→ Record timestamp
  │     └─→ Remove processed
  │
  ├─→ Release Lock
  │
  └─→ Exit
```

### 3.2 Dump Processing Flow

```
Dump File
  │
  ├─→ Validate File
  │     ├─→ Check existence
  │     ├─→ Check size
  │     └─→ Check type
  │
  ├─→ Extract Metadata
  │     ├─→ Process name
  │     ├─→ Modification time
  │     ├─→ Container info?
  │     └─→ Crash logs
  │
  ├─→ Generate Archive Name
  │     ├─→ SHA1_macMAC_datDATE_boxTYPE_modMODEL_original
  │     ├─→ Sanitize
  │     └─→ Check length
  │
  ├─→ Create Archive
  │     ├─→ Copy dump file
  │     ├─→ Add version.txt
  │     ├─→ Add core_log.txt
  │     ├─→ Add process logs
  │     └─→ Compress (tar.gz)
  │
  ├─→ Upload Archive
  │     ├─→ Check network
  │     ├─→ Upload via HTTPS
  │     ├─→ Retry on failure
  │     └─→ Verify success
  │
  └─→ Cleanup
        ├─→ Remove archive
        ├─→ Remove temp files
        └─→ Update timestamps
```

### 3.3 Upload Flow

```
Archive File
  │
  ├─→ Pre-Upload Checks
  │     ├─→ Privacy mode?
  │     ├─→ Rate limited?
  │     ├─→ Network available?
  │     └─→ File valid?
  │
  ├─→ Prepare Upload
  │     ├─→ Build URL
  │     ├─→ Set headers
  │     ├─→ Configure TLS
  │     └─→ Set timeout
  │
  ├─→ Upload Attempt
  │     ├─→ Initialize CURL
  │     ├─→ Transfer file
  │     ├─→ Wait for response
  │     └─→ Check HTTP code
  │
  ├─→ Handle Result
  │     ├─→ Success? → Log & return
  │     ├─→ Failure? → Retry
  │     └─→ Max retries? → Save locally
  │
  └─→ Cleanup
        ├─→ Close connection
        └─→ Free resources
```

### 3.4 Rate Limiting Flow

```
Upload Request
  │
  ├─→ Load Timestamps
  │     ├─→ Read timestamp file
  │     └─→ Parse entries
  │
  ├─→ Check Recovery Time
  │     ├─→ Recovery time set?
  │     ├─→ Time elapsed?
  │     └─→ Clear if elapsed
  │
  ├─→ Check Rate Limit
  │     ├─→ Count < 10? → Allow
  │     ├─→ Oldest > 10min ago? → Allow
  │     └─→ Otherwise → Deny
  │
  ├─→ If Denied
  │     ├─→ Create crashloop marker
  │     ├─→ Upload marker
  │     ├─→ Set recovery time
  │     └─→ Remove pending dumps
  │
  ├─→ If Allowed
  │     ├─→ Proceed with upload
  │     ├─→ Record timestamp
  │     └─→ Truncate timestamp file
  │
  └─→ Return Decision
```

## 4. Key Algorithms and Data Structures

### 4.1 Lock Directory Algorithm

```
function create_lock_or_wait(lock_path, mode):
    while true:
        if lock_directory_exists(lock_path):
            if mode == LOCK_MODE_EXIT:
                log("Another instance running")
                exit(0)
            else:
                log("Waiting for lock...")
                sleep(2)
                continue
        
        if create_directory(lock_path) == SUCCESS:
            return SUCCESS
        else:
            log("Error creating lock")
            if mode == LOCK_MODE_EXIT:
                exit(1)
            else:
                sleep(2)
                continue
```

### 4.2 Filename Generation Algorithm

```
function generate_dump_filename(sha1, mac, timestamp, box_type, model, original):
    # Format: sha1_macMAC_datDATE_boxTYPE_modMODEL_original
    
    # Check if already processed
    if original contains "_mac" and "_dat" and "_box" and "_mod":
        return original  # Already has metadata
    
    # Generate base name
    filename = sha1 + "_mac" + mac + "_dat" + timestamp + 
               "_box" + box_type + "_mod" + model + "_" + original
    
    # Handle filename length limit (135 chars for ecryptfs)
    if length(filename) >= 135:
        # Remove SHA1 prefix
        filename = remove_prefix(filename, sha1 + "_")
    
    if length(filename) >= 135:
        # Truncate process name to 20 chars
        filename = truncate_process_name(filename, 20)
    
    # Sanitize
    filename = sanitize(filename)
    
    return filename
```

### 4.3 Rate Limit Check Algorithm

```
function is_upload_limit_reached():
    timestamps = read_timestamp_file()
    
    if count(timestamps) < 10:
        return false  # Not enough uploads yet
    
    oldest_timestamp = timestamps[0]  # First entry
    current_time = now()
    
    if (current_time - oldest_timestamp) < 600:  # 10 minutes
        return true  # Rate limit exceeded
    else:
        return false  # Oldest upload is old enough
```

### 4.4 Archive Creation Algorithm

```
function create_archive(dump_file, config):
    # Generate archive name
    archive_name = generate_dump_filename(...)
    
    # Parse container info if present
    if dump_file contains "<#=#>":
        container_info = parse_container_crash(dump_file)
        send_telemetry(container_info)
    
    # Collect files to archive
    files = []
    files.add(dump_file)
    files.add("version.txt")
    files.add("core_log.txt")
    
    if dump_type == MINIDUMP:
        log_files = get_crashed_log_files(dump_file)
        files.add(log_files)
    
    # Check /tmp usage
    tmp_usage = get_disk_usage("/tmp")
    if tmp_usage > 70%:
        use_tmp_fallback = false
    else:
        use_tmp_fallback = true
        temp_dir = create_temp_directory()
        copy_files_to_temp(files, temp_dir)
        files = temp_dir_files
    
    # Create compressed archive
    try:
        create_tar_gz(archive_name, files)
    catch compression_error:
        if not use_tmp_fallback:
            # Retry with /tmp fallback
            temp_dir = create_temp_directory()
            copy_files_to_temp(files, temp_dir)
            create_tar_gz(archive_name, temp_dir_files)
        else:
            raise error
    
    # Cleanup
    remove_temp_files()
    
    return archive_name
```

### 4.5 Container Crash Parsing Algorithm

```
function parse_container_crash(filename):
    delimiter = "<#=#>"
    backward_delimiter = "-"
    
    if not contains(filename, delimiter):
        return null  # Not a container crash
    
    # Split by delimiter
    parts = split(filename, delimiter)
    
    if count(parts) == 3:
        # Format: processname_appname<#=#>status<#=#>timestamp.dmp
        container_name = parts[0]
        container_status = parts[1]
        container_time = parts[2]
    elif count(parts) == 2:
        # Format: processname_appname<#=#>timestamp.dmp
        container_name = parts[0]
        container_status = "unknown"
        container_time = parts[1]
    
    # Extract app name and process name
    name_parts = split(container_name, "_")
    process_name = name_parts[0]
    app_name = join(name_parts[1:], "_")
    
    # Create normalized filename
    normalized = container_name + backward_delimiter + container_time
    
    return {
        container_name: container_name,
        container_status: container_status,
        app_name: app_name,
        process_name: process_name,
        normalized_filename: normalized
    }
```

## 5. Interfaces and Integration Points

### 5.1 External Library Interfaces

#### 5.1.1 libcurl (Upload)
```c
#include <curl/curl.h>

CURL *curl;
CURLcode res;

curl_global_init(CURL_GLOBAL_DEFAULT);
curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, portal_url);
curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
curl_easy_setopt(curl, CURLOPT_READDATA, file_handle);
curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45);
curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
res = curl_easy_perform(curl);
curl_easy_cleanup(curl);
```

#### 5.1.2 zlib (Compression)
```c
#include <zlib.h>

gzFile gz_file;
gz_file = gzopen(archive_path, "wb");
gzwrite(gz_file, buffer, size);
gzclose(gz_file);
```

#### 5.1.3 OpenSSL (SHA1)
```c
#include <openssl/sha.h>

unsigned char hash[SHA_DIGEST_LENGTH];
SHA1(data, data_len, hash);
```

### 5.2 System Call Interfaces

#### 5.2.1 File Operations
```c
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct stat st;
stat(filepath, &st);
mkdir(dirpath, 0755);
unlink(filepath);
```

#### 5.2.2 Network Operations
```c
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>

struct ifreq ifr;
ioctl(sock, SIOCGIFHWADDR, &ifr);
```

#### 5.2.3 Time Operations
```c
#include <time.h>

time_t now = time(NULL);
struct tm *tm_info = localtime(&now);
strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H-%M-%S", tm_info);
```

### 5.3 Configuration File Format

#### 5.3.1 device.properties
```properties
DEVICE_TYPE=hybrid
BUILD_TYPE=prod
BOX_TYPE=XG1v4
MODEL_NUM=XG1v4
```

#### 5.3.2 include.properties
```properties
RDK_PATH=/lib/rdk
LOG_PATH=/opt/logs
PORTAL_URL=https://crash-portal.example.com/upload
```

### 5.4 Telemetry Integration

#### 5.4.1 T2 Events
```c
// Send count notification
t2_count_notify("SYST_INFO_minidumpUpld");

// Send value notification
t2_val_notify("processCrash_split", process_name);

// Send accumulating value
t2_val_notify("APP_ERROR_Crashed_accum", crash_info);
```

### 5.5 Platform-Specific Integration

#### 5.5.1 Broadband Platform
```c
if (device_type == DEVICE_TYPE_BROADBAND) {
    dump_path = "/minidumps";
    log_path = "/rdklogs/logs";
    // Use dmcli for model number
    get_model_via_dmcli(&config);
}
```

#### 5.5.2 Video Platform
```c
if (device_type == DEVICE_TYPE_HYBRID || 
    device_type == DEVICE_TYPE_MEDIACLIENT) {
    // Defer processing if uptime < 480 seconds
    if (get_uptime() < 480) {
        sleep(480 - get_uptime());
    }
}
```

## 6. Error Handling Strategy

### 6.1 Error Categories

1. **Fatal Errors**: Terminate program
   - Invalid configuration
   - Cannot create lock
   - Out of memory

2. **Recoverable Errors**: Retry or skip
   - Network timeout
   - Upload failure
   - Compression failure

3. **Warnings**: Log and continue
   - Missing optional file
   - Non-critical configuration error

### 6.2 Error Codes

```c
typedef enum {
    ERROR_SUCCESS = 0,
    ERROR_INVALID_ARGS = 1,
    ERROR_CONFIG_LOAD = 2,
    ERROR_LOCK_FAILED = 3,
    ERROR_NETWORK_UNAVAILABLE = 4,
    ERROR_UPLOAD_FAILED = 5,
    ERROR_COMPRESSION_FAILED = 6,
    ERROR_OUT_OF_MEMORY = 7,
    ERROR_FILE_NOT_FOUND = 8,
    ERROR_PERMISSION_DENIED = 9
} error_code_t;
```

### 6.3 Cleanup on Exit

```c
void cleanup_and_exit(int exit_code) {
    // Remove lock
    lock_remove(lock_path);
    
    // Close log file
    log_cleanup();
    
    // Free allocated memory
    config_cleanup(&config);
    
    // Remove temp files
    file_cleanup_temp_dir(temp_dir);
    
    // Set crash reboot flag if broadband
    if (device_type == DEVICE_TYPE_BROADBAND) {
        touch("/tmp/crash_reboot");
    }
    
    exit(exit_code);
}
```

## 7. Performance Considerations

### 7.1 Memory Optimization
- Use static buffers where possible
- Limit dynamic allocations
- Free resources immediately after use
- Use memory pools for frequent allocations
- Target: < 10MB total memory usage

### 7.2 CPU Optimization
- Use low priority for compression (nice 19)
- Avoid unnecessary processing
- Stream large files
- Minimize string operations
- Target: < 5% CPU during normal operation

### 7.3 I/O Optimization
- Minimize file operations
- Use buffered I/O
- Batch operations where possible
- Avoid excessive stat() calls
- Clean up temporary files promptly

### 7.4 Network Optimization
- Set appropriate timeouts
- Reuse connections where possible
- Implement efficient retry logic
- Compress before upload

## 8. Security Considerations

### 8.1 Input Validation
- Validate all command-line arguments
- Sanitize filenames
- Validate file paths (prevent directory traversal)
- Check file sizes before processing

### 8.2 Secure Communication
- Use TLS 1.2 minimum
- Validate certificates (OCSP)
- Use mTLS where available
- Secure credential storage

### 8.3 Privacy
- Check opt-out flags
- Respect privacy mode
- Handle PII appropriately
- Secure dump file handling

### 8.4 File System Security
- Use safe file creation (O_CREAT|O_EXCL)
- Set appropriate permissions
- Validate symbolic links
- Prevent race conditions

## 9. Testing Strategy

### 9.1 Unit Tests
- Test each module independently
- Mock external dependencies
- Test error conditions
- Verify memory management

### 9.2 Integration Tests
- Test module interactions
- Test complete workflow
- Test platform-specific code
- Test configuration loading

### 9.3 System Tests
- Test on target hardware
- Test with real dump files
- Test network conditions
- Test resource constraints

### 9.4 Test Cases
- Normal operation
- Network failures
- Rate limiting
- Crash loops
- Configuration errors
- Missing files
- Permission errors
- Low memory conditions
- Concurrent execution
