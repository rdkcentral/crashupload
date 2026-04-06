# Low-Level Design: uploadDumps.sh Migration to C

## 1. File Structure

```
src/
├── uploadDumps/
│   ├── main.c                      # Main entry point
│   ├── config/
│   │   ├── config_manager.c        # Configuration loading
│   │   └── config_manager.h
│   ├── platform/
│   │   ├── platform.c              # Platform abstraction
│   │   ├── platform.h
│   │   ├── platform_broadband.c    # Broadband-specific code
│   │   ├── platform_video.c        # Video-specific code
│   │   └── platform_extender.c     # Extender-specific code
│   ├── core/
│   │   ├── scanner.c               # Dump file scanner
│   │   ├── scanner.h
│   │   ├── archive.c               # Archive creator
│   │   ├── archive.h
│   │   ├── upload.c                # Upload manager
│   │   ├── upload.h
│   │   ├── ratelimit.c             # Rate limiter
│   │   └── ratelimit.h
│   ├── utils/
│   │   ├── network_utils.c         # Network utilities
│   │   ├── network_utils.h
│   │   ├── file_utils.c            # File utilities
│   │   ├── file_utils.h
│   │   ├── string_utils.c          # String utilities
│   │   ├── string_utils.h
│   │   ├── lock_manager.c          # Lock management
│   │   ├── lock_manager.h
│   │   ├── logger.c                # Logging system
│   │   └── logger.h
│   └── Makefile
├── uploadDumpsUtils/
│   ├── network.c                   # Network functions
│   ├── system.c                    # System info functions
│   ├── file.c                      # File functions
│   ├── reboot.c                    # Reboot function
│   └── uploadDumpsUtils.h          # Public API
└── common/
    ├── types.h                     # Common type definitions
    ├── constants.h                 # Constants
    └── errors.h                    # Error codes
```

## 2. Data Structures

### 2.1 Configuration Structures

```c
// config_manager.h

typedef enum {
    DEVICE_TYPE_BROADBAND,
    DEVICE_TYPE_EXTENDER,
    DEVICE_TYPE_HYBRID,
    DEVICE_TYPE_MEDIACLIENT,
    DEVICE_TYPE_UNKNOWN
} device_type_t;

typedef enum {
    BUILD_TYPE_PROD,
    BUILD_TYPE_DEV,
    BUILD_TYPE_UNKNOWN
} build_type_t;

typedef enum {
    DUMP_TYPE_COREDUMP,
    DUMP_TYPE_MINIDUMP
} dump_type_t;

typedef enum {
    UPLOAD_MODE_NORMAL,
    UPLOAD_MODE_SECURE
} upload_mode_t;

typedef enum {
    LOCK_MODE_EXIT,
    LOCK_MODE_WAIT
} lock_mode_t;

typedef struct {
    device_type_t device_type;
    build_type_t build_type;
    dump_type_t dump_type;
    upload_mode_t upload_mode;
    lock_mode_t lock_mode;
    
    char working_dir[PATH_MAX];
    char log_path[PATH_MAX];
    char core_path[PATH_MAX];
    char minidumps_path[PATH_MAX];
    
    char portal_url[URL_MAX_LEN];
    char partner_id[PARTNER_ID_LEN];
    char rdk_path[PATH_MAX];
    
    bool telemetry_enabled;
    bool multi_core;
    bool enable_ocsp;
    bool enable_ocsp_stapling;
    
    int max_core_files;
    int upload_timeout;
    int max_retries;
} config_t;

typedef struct {
    char mac_address[MAC_ADDR_LEN];
    char model_number[MODEL_NUM_LEN];
    char box_type[BOX_TYPE_LEN];
    char sha1_hash[SHA1_LEN];
    char interface_name[IFNAMSIZ];
} platform_config_t;
```

### 2.2 Dump File Structures

```c
// scanner.h

typedef struct {
    char filename[PATH_MAX];
    char full_path[PATH_MAX];
    time_t mtime;
    off_t size;
    dump_type_t type;
    bool is_processed;
    bool is_container;
} dump_file_t;

typedef struct {
    dump_file_t *files;
    size_t count;
    size_t capacity;
} dump_list_t;

typedef struct {
    char process_name[256];
    char app_name[256];
    char container_name[256];
    char container_status[64];
    time_t crash_time;
    bool is_valid;
} container_info_t;
```

### 2.3 Archive Structures

```c
// archive.h

typedef enum {
    COMPRESSION_NONE,
    COMPRESSION_GZIP
} compression_type_t;

typedef struct {
    char archive_path[PATH_MAX];
    char temp_dir[PATH_MAX];
    char **file_list;
    size_t file_count;
    compression_type_t compression;
    bool use_tmp_fallback;
    bool is_finalized;
} archive_t;
```

### 2.4 Upload Structures

```c
// upload.h

typedef struct {
    char portal_url[URL_MAX_LEN];
    char crash_portal_path[PATH_MAX];
    char partner_id[PARTNER_ID_LEN];
    int timeout_seconds;
    bool use_tls;
    bool enable_ocsp;
    bool enable_ocsp_stapling;
    char curl_log_option[128];
} upload_config_t;

typedef struct {
    int http_code;
    bool success;
    char error_message[ERROR_MSG_LEN];
    char remote_ip[INET_ADDRSTRLEN];
    int remote_port;
    size_t bytes_uploaded;
    int attempts;
    double upload_time;
} upload_result_t;
```

### 2.5 Rate Limiting Structures

```c
// ratelimit.h

typedef struct {
    char timestamp_file[PATH_MAX];
    char deny_file[PATH_MAX];
    time_t *timestamps;
    size_t timestamp_count;
    size_t timestamp_capacity;
    time_t recovery_time;
    int limit_count;        // 10 uploads
    int limit_seconds;      // 600 seconds
} ratelimit_t;
```

## 3. Detailed Function Specifications

### 3.1 Main Controller

```c
// main.c

/**
 * @brief Main entry point
 * 
 * @param argc Argument count
 * @param argv Argument vector
 *        argv[1]: Reserved (not used, previously CRASHTS)
 *        argv[2]: DUMP_FLAG (0=minidump, 1=coredump)
 *        argv[3]: UPLOAD_FLAG ("secure" or empty)
 *        argv[4]: WAIT_FOR_LOCK ("wait_for_lock" or empty)
 * @return Exit code (0=success, non-zero=error)
 */
int main(int argc, char *argv[]);

/**
 * @brief Parse command line arguments
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @param config Configuration structure to populate
 * @return 0 on success, error code on failure
 */
int parse_arguments(int argc, char *argv[], config_t *config);

/**
 * @brief Initialize all subsystems
 * 
 * @param config Configuration structure
 * @param platform Platform configuration
 * @return 0 on success, error code on failure
 */
int initialize_system(const config_t *config, platform_config_t *platform);

/**
 * @brief Main processing loop
 * 
 * @param config Configuration structure
 * @param platform Platform configuration
 * @return 0 on success, error code on failure
 */
int process_dumps_loop(const config_t *config, const platform_config_t *platform);

/**
 * @brief Cleanup and exit
 * 
 * @param exit_code Exit code to return
 */
void cleanup_and_exit(int exit_code) __attribute__((noreturn));

/**
 * @brief Signal handler
 * 
 * @param signum Signal number
 */
void signal_handler(int signum);
```

### 3.2 Configuration Manager

```c
// config_manager.h

/**
 * @brief Load configuration from all sources
 * 
 * @param config Configuration structure to populate
 * @return 0 on success, error code on failure
 */
int config_load(config_t *config);

/**
 * @brief Load configuration from a file
 * 
 * @param path File path
 * @param config Configuration structure to update
 * @return 0 on success, error code on failure
 */
int config_load_file(const char *path, config_t *config);

/**
 * @brief Load configuration from environment variables
 * 
 * @param config Configuration structure to update
 * @return 0 on success, error code on failure
 */
int config_load_environment(config_t *config);

/**
 * @brief Validate configuration
 * 
 * @param config Configuration structure to validate
 * @return 0 if valid, error code otherwise
 */
int config_validate(const config_t *config);

/**
 * @brief Get string value from configuration
 * 
 * @param config Configuration structure
 * @param key Configuration key
 * @param default_val Default value if not found
 * @return Configuration value or default
 */
const char* config_get_string(const config_t *config, const char *key, 
                               const char *default_val);

/**
 * @brief Get integer value from configuration
 * 
 * @param config Configuration structure
 * @param key Configuration key
 * @param default_val Default value if not found
 * @return Configuration value or default
 */
int config_get_int(const config_t *config, const char *key, int default_val);

/**
 * @brief Free configuration resources
 * 
 * @param config Configuration structure to free
 */
void config_cleanup(config_t *config);
```

### 3.3 Platform Abstraction

```c
// platform.h

/**
 * @brief Initialize platform configuration
 * 
 * @param config Global configuration
 * @param platform Platform configuration to populate
 * @return 0 on success, error code on failure
 */
int platform_init(const config_t *config, platform_config_t *platform);

/**
 * @brief Get dump directory path for device type
 * 
 * @param device_type Device type
 * @param secure Secure mode flag
 * @param path Buffer to store path
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int platform_get_dump_path(device_type_t device_type, bool secure, 
                           char *path, size_t len);

/**
 * @brief Get log directory path for device type
 * 
 * @param device_type Device type
 * @param path Buffer to store path
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int platform_get_log_path(device_type_t device_type, char *path, size_t len);

/**
 * @brief Get network interface name for device type
 * 
 * @param device_type Device type
 * @param interface Buffer to store interface name
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int platform_get_interface_name(device_type_t device_type, 
                                char *interface, size_t len);

/**
 * @brief Check if platform supports a feature
 * 
 * @param feature Feature to check
 * @return true if supported, false otherwise
 */
bool platform_supports_feature(platform_feature_t feature);

/**
 * @brief Get device MAC address
 * 
 * @param platform Platform configuration
 * @return 0 on success, error code on failure
 */
int platform_get_mac_address(platform_config_t *platform);

/**
 * @brief Get device model number
 * 
 * @param platform Platform configuration
 * @return 0 on success, error code on failure
 */
int platform_get_model_number(platform_config_t *platform);

/**
 * @brief Get build SHA1 hash
 * 
 * @param platform Platform configuration
 * @return 0 on success, error code on failure
 */
int platform_get_sha1(platform_config_t *platform);
```

### 3.4 Scanner Module

```c
// scanner.h

/**
 * @brief Initialize scanner
 * 
 * @param directory Directory to scan
 * @return Scanner handle or NULL on error
 */
scanner_t* scanner_init(const char *directory);

/**
 * @brief Find dump files matching pattern
 * 
 * @param scanner Scanner handle
 * @param pattern File pattern (e.g., "*.dmp*")
 * @param list List to populate with results
 * @return 0 on success, error code on failure
 */
int scanner_find_dumps(scanner_t *scanner, const char *pattern, 
                       dump_list_t *list);

/**
 * @brief Check if file is already processed
 * 
 * @param filename Filename to check
 * @return true if processed, false otherwise
 */
bool scanner_is_processed(const char *filename);

/**
 * @brief Filter dump list by criteria
 * 
 * @param list Dump list
 * @param filter_func Filter function
 * @return Number of items remaining
 */
int scanner_filter(dump_list_t *list, bool (*filter_func)(const dump_file_t*));

/**
 * @brief Sort dump list by modification time
 * 
 * @param list Dump list to sort
 */
void scanner_sort_by_time(dump_list_t *list);

/**
 * @brief Free scanner resources
 * 
 * @param scanner Scanner handle
 */
void scanner_cleanup(scanner_t *scanner);

/**
 * @brief Free dump list
 * 
 * @param list Dump list to free
 */
void dump_list_free(dump_list_t *list);
```

### 3.5 Archive Creator

```c
// archive.h

/**
 * @brief Create new archive
 * 
 * @param dump Dump file to archive
 * @param config Global configuration
 * @param platform Platform configuration
 * @return Archive handle or NULL on error
 */
archive_t* archive_create(const dump_file_t *dump, 
                          const config_t *config,
                          const platform_config_t *platform);

/**
 * @brief Parse container information from filename
 * 
 * @param filename Dump filename
 * @param info Container info structure to populate
 * @return 0 on success, error code on failure
 */
int archive_parse_container_info(const char *filename, container_info_t *info);

/**
 * @brief Generate archive filename with metadata
 * 
 * @param dump Dump file
 * @param platform Platform configuration
 * @param filename Buffer to store filename
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int archive_generate_filename(const dump_file_t *dump,
                              const platform_config_t *platform,
                              char *filename, size_t len);

/**
 * @brief Add file to archive
 * 
 * @param archive Archive handle
 * @param filepath File to add
 * @return 0 on success, error code on failure
 */
int archive_add_file(archive_t *archive, const char *filepath);

/**
 * @brief Add log files for crashed process
 * 
 * @param archive Archive handle
 * @param process_name Process name
 * @param config Global configuration
 * @return 0 on success, error code on failure
 */
int archive_add_log_files(archive_t *archive, const char *process_name,
                          const config_t *config);

/**
 * @brief Finalize and compress archive
 * 
 * @param archive Archive handle
 * @return 0 on success, error code on failure
 */
int archive_finalize(archive_t *archive);

/**
 * @brief Get archive path
 * 
 * @param archive Archive handle
 * @return Archive file path
 */
const char* archive_get_path(const archive_t *archive);

/**
 * @brief Free archive resources
 * 
 * @param archive Archive handle
 */
void archive_cleanup(archive_t *archive);
```

### 3.6 Upload Manager

```c
// upload.h

/**
 * @brief Initialize upload configuration
 * 
 * @param config Upload configuration
 * @param global_config Global configuration
 * @return 0 on success, error code on failure
 */
int upload_init(upload_config_t *config, const config_t *global_config);

/**
 * @brief Upload file to server
 * 
 * @param filepath File to upload
 * @param config Upload configuration
 * @param result Upload result structure
 * @return 0 on success, error code on failure
 */
int upload_file(const char *filepath, const upload_config_t *config,
                upload_result_t *result);

/**
 * @brief Upload file with retry logic
 * 
 * @param filepath File to upload
 * @param config Upload configuration
 * @param max_retries Maximum retry attempts
 * @param result Upload result structure
 * @return 0 on success, error code on failure
 */
int upload_retry(const char *filepath, const upload_config_t *config,
                 int max_retries, upload_result_t *result);

/**
 * @brief Check if privacy mode is enabled
 * 
 * @return true if enabled, false otherwise
 */
bool upload_check_privacy_mode(void);

/**
 * @brief Free upload configuration
 * 
 * @param config Upload configuration
 */
void upload_cleanup(upload_config_t *config);
```

### 3.7 Rate Limiter

```c
// ratelimit.h

/**
 * @brief Initialize rate limiter
 * 
 * @param timestamp_file Timestamp file path
 * @return Rate limiter handle or NULL on error
 */
ratelimit_t* ratelimit_init(const char *timestamp_file);

/**
 * @brief Check if upload limit is exceeded
 * 
 * @param limiter Rate limiter handle
 * @return true if exceeded, false otherwise
 */
bool ratelimit_is_exceeded(ratelimit_t *limiter);

/**
 * @brief Check if recovery time has been reached
 * 
 * @param limiter Rate limiter handle
 * @return true if reached, false otherwise
 */
bool ratelimit_is_recovery_time_reached(ratelimit_t *limiter);

/**
 * @brief Record upload timestamp
 * 
 * @param limiter Rate limiter handle
 * @return 0 on success, error code on failure
 */
int ratelimit_record_upload(ratelimit_t *limiter);

/**
 * @brief Set recovery time
 * 
 * @param limiter Rate limiter handle
 * @param seconds Seconds from now
 * @return 0 on success, error code on failure
 */
int ratelimit_set_recovery_time(ratelimit_t *limiter, int seconds);

/**
 * @brief Free rate limiter resources
 * 
 * @param limiter Rate limiter handle
 */
void ratelimit_cleanup(ratelimit_t *limiter);
```

### 3.8 Network Utilities

```c
// network_utils.h

/**
 * @brief Check if network is available
 * 
 * @param interface Network interface name
 * @return true if available, false otherwise
 */
bool network_is_available(const char *interface);

/**
 * @brief Wait for network connection
 * 
 * @param max_iterations Maximum wait iterations
 * @param delay_seconds Delay between iterations
 * @return 0 if available, error code on timeout
 */
int network_wait_for_connection(int max_iterations, int delay_seconds);

/**
 * @brief Check if route is available
 * 
 * @return true if available, false otherwise
 */
bool network_check_route_available(void);

/**
 * @brief Wait for system time synchronization
 * 
 * @param max_iterations Maximum wait iterations
 * @param delay_seconds Delay between iterations
 * @return 0 if synced, error code on timeout
 */
int network_wait_for_system_time(int max_iterations, int delay_seconds);

/**
 * @brief Check network communication status (broadband-specific)
 * 
 * @return 0 if OK, error code otherwise
 */
int network_commn_status(void);
```

### 3.9 File Utilities

```c
// file_utils.h

/**
 * @brief Check if file exists
 * 
 * @param path File path
 * @return true if exists, false otherwise
 */
bool file_exists(const char *path);

/**
 * @brief Get file modification time as formatted string
 * 
 * @param path File path
 * @param timestamp Buffer to store timestamp
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_get_mtime_string(const char *path, char *timestamp, size_t len);

/**
 * @brief Get file modification time
 * 
 * @param path File path
 * @return Modification time or 0 on error
 */
time_t file_get_mtime(const char *path);

/**
 * @brief Delete file safely with validation
 * 
 * @param path File path
 * @return 0 on success, error code on failure
 */
int file_delete_safely(const char *path);

/**
 * @brief Sanitize filename (remove invalid characters)
 * 
 * @param input Input filename
 * @param output Output buffer
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_sanitize_name(const char *input, char *output, size_t len);

/**
 * @brief Create temporary directory
 * 
 * @param path Buffer to store path
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_create_temp_dir(char *path, size_t len);

/**
 * @brief Cleanup temporary directory
 * 
 * @param path Directory path
 */
void file_cleanup_temp_dir(const char *path);

/**
 * @brief Calculate SHA1 hash of file
 * 
 * @param path File path
 * @param hash Buffer to store hash
 * @param len Buffer length (must be >= 41)
 * @return 0 on success, error code on failure
 */
int file_get_sha1(const char *path, char *hash, size_t len);

/**
 * @brief Get disk usage percentage
 * 
 * @param path Mount point or directory
 * @return Usage percentage (0-100) or -1 on error
 */
int file_get_disk_usage(const char *path);

/**
 * @brief Copy file
 * 
 * @param src Source file path
 * @param dst Destination file path
 * @return 0 on success, error code on failure
 */
int file_copy(const char *src, const char *dst);

/**
 * @brief Tail file (get last N lines)
 * 
 * @param path File path
 * @param lines Number of lines
 * @param output Buffer to store output
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_tail(const char *path, int lines, char *output, size_t len);
```

### 3.10 String Utilities

```c
// string_utils.h

/**
 * @brief Sanitize string (remove non-alphanumeric characters)
 * 
 * @param input Input string
 * @param output Output buffer
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int string_sanitize(const char *input, char *output, size_t len);

/**
 * @brief Format MAC address
 * 
 * @param mac Input MAC address
 * @param output Output buffer
 * @param len Buffer length
 * @param with_colons Include colons flag
 * @return 0 on success, error code on failure
 */
int string_format_mac(const char *mac, char *output, size_t len, 
                      bool with_colons);

/**
 * @brief Format timestamp
 * 
 * @param time Time value
 * @param output Output buffer
 * @param len Buffer length
 * @param format Format string
 * @return 0 on success, error code on failure
 */
int string_format_timestamp(time_t time, char *output, size_t len,
                            const char *format);

/**
 * @brief Generate dump filename with metadata
 * 
 * @param sha1 SHA1 hash
 * @param mac MAC address
 * @param timestamp Timestamp
 * @param box_type Box type
 * @param model Model number
 * @param original Original filename
 * @param output Output buffer
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int string_generate_filename(const char *sha1, const char *mac,
                             const char *timestamp, const char *box_type,
                             const char *model, const char *original,
                             char *output, size_t len);

/**
 * @brief Replace substring in string
 * 
 * @param str Input/output string
 * @param len String buffer length
 * @param old Old substring
 * @param new New substring
 * @return Number of replacements made
 */
int string_replace(char *str, size_t len, const char *old, const char *new);

/**
 * @brief Check if string contains substring
 * 
 * @param str String to search
 * @param substr Substring to find
 * @return true if found, false otherwise
 */
bool string_contains(const char *str, const char *substr);
```

### 3.11 Lock Manager

```c
// lock_manager.h

/**
 * @brief Create lock
 * 
 * @param lock_path Lock directory path
 * @param mode Lock mode (exit or wait)
 * @return 0 on success, error code on failure
 */
int lock_create(const char *lock_path, lock_mode_t mode);

/**
 * @brief Check if lock exists
 * 
 * @param lock_path Lock directory path
 * @return true if exists, false otherwise
 */
bool lock_exists(const char *lock_path);

/**
 * @brief Remove lock
 * 
 * @param lock_path Lock directory path
 * @return 0 on success, error code on failure
 */
int lock_remove(const char *lock_path);

/**
 * @brief Wait for lock to be released
 * 
 * @param lock_path Lock directory path
 * @param timeout_seconds Maximum wait time
 * @return 0 on success, error code on timeout
 */
int lock_wait_for_release(const char *lock_path, int timeout_seconds);
```

### 3.12 Logging System

```c
// logger.h

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} log_level_t;

/**
 * @brief Initialize logging system
 * 
 * @param log_file Log file path
 * @param device_type Device type (affects format)
 * @return 0 on success, error code on failure
 */
int log_init(const char *log_file, device_type_t device_type);

/**
 * @brief Log message
 * 
 * @param level Log level
 * @param format Format string (printf-style)
 * @param ... Variable arguments
 */
void log_message(log_level_t level, const char *format, ...);

/**
 * @brief Log TLS error
 * 
 * @param format Format string (printf-style)
 * @param ... Variable arguments
 */
void log_tls_error(const char *format, ...);

/**
 * @brief Send telemetry event
 * 
 * @param event_name Event name
 * @param value Event value (optional)
 * @return 0 on success, error code on failure
 */
int log_telemetry_event(const char *event_name, const char *value);

/**
 * @brief Send telemetry count notification
 * 
 * @param event_name Event name
 * @return 0 on success, error code on failure
 */
int log_telemetry_count(const char *event_name);

/**
 * @brief Send telemetry value notification
 * 
 * @param event_name Event name
 * @param value Event value
 * @return 0 on success, error code on failure
 */
int log_telemetry_value(const char *event_name, const char *value);

/**
 * @brief Cleanup logging system
 */
void log_cleanup(void);
```

## 4. Key Algorithms (Pseudocode)

### 4.1 Main Processing Loop

```
function process_dumps_loop(config, platform):
    # Wait for prerequisites
    if not network_wait_for_connection(18, 10):
        log_message("Network unavailable")
        if config.device_type != BROADBAND:
            # Save dumps for later (video devices)
            return ERROR_NETWORK_UNAVAILABLE
    
    if not network_wait_for_system_time(10, 1):
        log_message("System time not synced")
        # Continue anyway
    
    # Privacy check (MEDIACLIENT only)
    if config.device_type == MEDIACLIENT:
        config.privacy_mode = get_privacy_control_mode()
        # RBUS: Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode
        # Returns SHARE (default) or DO_NOT_SHARE
        # Defaults to SHARE if RBUS is unavailable
    
    # Cleanup old files (always runs, regardless of privacy mode)
    cleanup_old_files(config.working_dir)
    
    # Scan for dumps
    scanner = scanner_init(config.working_dir)
    dump_list = []
    
    if config.dump_type == COREDUMP:
        scanner_find_dumps(scanner, "*_core*.gz*", dump_list)
    else:
        scanner_find_dumps(scanner, "*.dmp*", dump_list)
    
    if dump_list.count == 0:
        log_message("No dumps found")
        return SUCCESS
    
    # Archive phase: process each dump (skip archiving if DO_NOT_SHARE)
    for dump in dump_list:
        get_mtime(dump)
        
        if config.privacy_mode == DO_NOT_SHARE:
            continue  # skip archive creation for this dump
        
        # Rename dump file and create archive
        process_single_dump_archive(dump, config, platform)
    
    # If DO_NOT_SHARE: delete dump files and exit without uploading
    if config.privacy_mode == DO_NOT_SHARE:
        cleanup_dump_files(config.working_dir)  # cleanup_batch(do_not_share_cleanup=true)
        return SUCCESS
    
    # Upload phase: rate limit check then upload each archive
    ratelimiter = ratelimit_init(timestamp_file)
    
    for dump in dump_list:
        # Check if box is rebooting
        if file_exists("/tmp/set_crash_reboot_flag"):
            log_message("Box rebooting, exit")
            break
        
        # Check recovery time
        if not ratelimit_is_recovery_time_reached(ratelimiter):
            log_message("Recovery time not reached")
            ratelimit_set_recovery_time(ratelimiter, 600)
            scanner_remove_pending_dumps()
            break
        
        # Check rate limit
        if ratelimit_is_exceeded(ratelimiter):
            log_message("Rate limit exceeded")
            
            # Create crashloop marker
            crashloop_file = create_crashloop_marker(dump)
            
            # Upload crashloop
            upload_config = upload_init(config)
            upload_result = {}
            upload_file(crashloop_file, upload_config, upload_result)
            
            # Set recovery time
            ratelimit_set_recovery_time(ratelimiter, 600)
            scanner_remove_pending_dumps()
            break
        
        # Upload archived dump
        result = upload_single_dump(dump, config, platform)
        
        if result == SUCCESS:
            ratelimit_record_upload(ratelimiter)
    
    # Cleanup
    scanner_cleanup(scanner)
    ratelimit_cleanup(ratelimiter)
    
    return SUCCESS
```

### 4.2 Process Single Dump

```
function process_single_dump(dump, config, platform):
    # Validate dump file
    if not file_exists(dump.full_path):
        return ERROR_FILE_NOT_FOUND
    
    # Check if already processed
    if scanner_is_processed(dump.filename):
        log_message("Already processed")
        return SUCCESS
    
    # Sanitize filename
    sanitized_name = file_sanitize_name(dump.filename)
    
    # Parse container info if present
    if string_contains(dump.filename, "<#=#>"):
        container_info = archive_parse_container_info(dump.filename)
        log_telemetry_value("crashedContainerName_split", container_info.container_name)
        log_telemetry_value("crashedContainerStatus_split", container_info.container_status)
        # ... more telemetry
    
    # Create archive
    archive = archive_create(dump, config, platform)
    if not archive:
        return ERROR_ARCHIVE_CREATE_FAILED
    
    # Add metadata files
    archive_add_file(archive, "version.txt")
    archive_add_file(archive, config.log_path + "/core_log.txt")
    
    # Add process logs for minidumps
    if config.dump_type == MINIDUMP:
        archive_add_log_files(archive, dump.process_name, config)
    
    # Finalize archive (compress)
    result = archive_finalize(archive)
    if result != SUCCESS:
        # Try /tmp fallback
        log_telemetry_count("SYST_WARN_CompFail")
        result = archive_finalize_with_tmp_fallback(archive)
        if result != SUCCESS:
            log_telemetry_count("SYST_ERR_CompFail")
            archive_cleanup(archive)
            return ERROR_COMPRESSION_FAILED
    
    # Get archive path
    archive_path = archive_get_path(archive)
    
    # Upload with retry
    upload_config = upload_init(config)
    upload_result = {}
    result = upload_retry(archive_path, upload_config, 3, upload_result)
    
    if result == SUCCESS:
        log_message("Upload success")
        log_telemetry_count("SYST_INFO_minidumpUpld")
        ratelimit_record_upload()
        file_delete_safely(archive_path)
    else:
        log_message("Upload failed")
        if config.dump_type == MINIDUMP:
            # Save for later
            save_dump_for_later(dump, archive_path)
        else:
            # Remove coredump
            file_delete_safely(archive_path)
    
    # Cleanup
    archive_cleanup(archive)
    upload_cleanup(upload_config)
    
    return result
```

### 4.3 Archive Filename Generation

```
function archive_generate_filename(dump, platform):
    # Get modification time
    mtime_str = file_get_mtime_string(dump.full_path)
    if not mtime_str:
        mtime_str = "2000-01-01-00-00-00"
    
    # Check if already has metadata
    if string_contains(dump.filename, "_mac") and 
       string_contains(dump.filename, "_dat") and
       string_contains(dump.filename, "_box") and
       string_contains(dump.filename, "_mod"):
        return dump.filename  # Already processed
    
    # Generate filename
    filename = platform.sha1 + "_mac" + platform.mac_address + 
               "_dat" + mtime_str + "_box" + platform.box_type + 
               "_mod" + platform.model_number + "_" + dump.filename
    
    # Check length limit (ecryptfs limitation)
    if len(filename) >= 135:
        # Remove SHA1 prefix
        filename = filename.replace(platform.sha1 + "_", "")
    
    if len(filename) >= 135:
        # Truncate process name
        process_name = extract_process_name(filename)
        truncated = process_name[0:20]
        filename = filename.replace(process_name, truncated)
    
    # Sanitize
    filename = file_sanitize_name(filename)
    
    # Replace container delimiter
    filename = string_replace(filename, "<#=#>", "_")
    
    # Add extension
    if config.dump_type == COREDUMP:
        filename += ".core.tgz"
    else:
        filename += ".tgz"
    
    return filename
```

### 4.4 Upload with Retry

```
function upload_retry(filepath, config, max_retries, result):
    attempts = 0
    
    while attempts < max_retries:
        attempts += 1
        
        # Initialize CURL
        curl = curl_easy_init()
        if not curl:
            return ERROR_CURL_INIT_FAILED
        
        # Set options
        curl_easy_setopt(curl, CURLOPT_URL, config.portal_url)
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1)
        curl_easy_setopt(curl, CURLOPT_READDATA, file_handle)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.timeout_seconds)
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2)
        
        if config.enable_ocsp:
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1)
        
        # Perform upload
        res = curl_easy_perform(curl)
        
        if res == CURLE_OK:
            # Get HTTP code
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_code)
            
            if result.http_code >= 200 and result.http_code < 300:
                # Success
                curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, result.remote_ip)
                curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &result.remote_port)
                result.success = true
                result.attempts = attempts
                curl_easy_cleanup(curl)
                return SUCCESS
        
        # Failed - log and retry
        log_message("Upload attempt %d failed: %s", attempts, curl_easy_strerror(res))
        curl_easy_cleanup(curl)
        
        if attempts < max_retries:
            sleep(2)  # Wait before retry
    
    # All retries failed
    result.success = false
    result.attempts = attempts
    return ERROR_UPLOAD_FAILED
```

## 5. Memory Management

### 5.1 Static Buffers

Use static buffers for strings and small structures to minimize allocations:

```c
// Example: platform_init()
int platform_get_mac_address(platform_config_t *platform) {
    static char mac_buffer[MAC_ADDR_LEN];
    // Use mac_buffer for processing
    strncpy(platform->mac_address, mac_buffer, MAC_ADDR_LEN);
    return 0;
}
```

### 5.2 Dynamic Allocations

Use dynamic allocation only when necessary:

```c
// Example: dump list
dump_list_t* dump_list_create(size_t initial_capacity) {
    dump_list_t *list = malloc(sizeof(dump_list_t));
    if (!list) return NULL;
    
    list->files = calloc(initial_capacity, sizeof(dump_file_t));
    if (!list->files) {
        free(list);
        return NULL;
    }
    
    list->count = 0;
    list->capacity = initial_capacity;
    return list;
}

void dump_list_free(dump_list_t *list) {
    if (list) {
        free(list->files);
        free(list);
    }
}
```

### 5.3 Resource Cleanup

Always use cleanup functions and RAII-style patterns:

```c
int process_dump(const dump_file_t *dump) {
    archive_t *archive = NULL;
    upload_config_t upload_cfg = {0};
    int result = ERROR;
    
    archive = archive_create(dump, &config, &platform);
    if (!archive) {
        result = ERROR_ARCHIVE_CREATE_FAILED;
        goto cleanup;
    }
    
    result = archive_finalize(archive);
    if (result != SUCCESS) {
        goto cleanup;
    }
    
    result = upload_init(&upload_cfg, &config);
    if (result != SUCCESS) {
        goto cleanup;
    }
    
    // ... more processing
    
cleanup:
    if (archive) archive_cleanup(archive);
    upload_cleanup(&upload_cfg);
    return result;
}
```

## 6. Error Handling

### 6.1 Error Codes

```c
// errors.h

typedef enum {
    SUCCESS = 0,
    ERROR_INVALID_ARGS = 1,
    ERROR_CONFIG_LOAD = 2,
    ERROR_LOCK_FAILED = 3,
    ERROR_NETWORK_UNAVAILABLE = 4,
    ERROR_UPLOAD_FAILED = 5,
    ERROR_COMPRESSION_FAILED = 6,
    ERROR_OUT_OF_MEMORY = 7,
    ERROR_FILE_NOT_FOUND = 8,
    ERROR_PERMISSION_DENIED = 9,
    ERROR_CURL_INIT_FAILED = 10,
    ERROR_ARCHIVE_CREATE_FAILED = 11,
    // ... more error codes
} error_code_t;
```

### 6.2 Error Propagation

```c
int function_that_can_fail() {
    int result;
    
    result = subfunc1();
    if (result != SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "subfunc1 failed: %d", result);
        return result;
    }
    
    result = subfunc2();
    if (result != SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "subfunc2 failed: %d", result);
        return result;
    }
    
    return SUCCESS;
}
```

## 7. Testing Strategy

### 7.1 Unit Tests

```c
// test_string_utils.c

void test_generate_filename() {
    char output[PATH_MAX];
    int result;
    
    result = string_generate_filename(
        "abc123", "AABBCCDDEE", "2024-01-01-12-00-00",
        "XG1", "XG1v4", "process.dmp",
        output, sizeof(output)
    );
    
    assert(result == SUCCESS);
    assert(strcmp(output, "abc123_macAABBCCDDEE_dat2024-01-01-12-00-00_boxXG1_modXG1v4_process.dmp") == 0);
}

void test_filename_length_limit() {
    char output[PATH_MAX];
    char long_process[256];
    
    // Create very long process name
    memset(long_process, 'A', 200);
    long_process[200] = '\0';
    strcat(long_process, ".dmp");
    
    int result = string_generate_filename(
        "1234567890123456789012345678901234567890",  // 40 char SHA1
        "AABBCCDDEE", "2024-01-01-12-00-00",
        "XG1", "XG1v4", long_process,
        output, sizeof(output)
    );
    
    assert(result == SUCCESS);
    assert(strlen(output) < 135);  // Must be under limit
}
```

### 7.2 Integration Tests

```c
// test_integration.c

void test_full_dump_processing() {
    // Setup
    create_test_dump_file("test.dmp");
    config_t config = load_test_config();
    platform_config_t platform = {0};
    platform_init(&config, &platform);
    
    // Execute
    int result = process_dumps_loop(&config, &platform);
    
    // Verify
    assert(result == SUCCESS);
    assert(!file_exists("test.dmp"));  // Original removed
    // Check upload was called (mock verification)
    
    // Cleanup
    cleanup_test_environment();
}
```

## 8. Build System

### 8.1 Makefile

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -D_GNU_SOURCE
LDFLAGS = -lcurl -lssl -lcrypto -lz

# Source files
SRCS = main.c \
       config/config_manager.c \
       platform/platform.c \
       platform/platform_broadband.c \
       platform/platform_video.c \
       core/scanner.c \
       core/archive.c \
       core/upload.c \
       core/ratelimit.c \
       utils/network_utils.c \
       utils/file_utils.c \
       utils/string_utils.c \
       utils/lock_manager.c \
       utils/logger.c

OBJS = $(SRCS:.c=.o)

TARGET = uploadDumps

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install:
	install -m 0755 $(TARGET) /lib/rdk/

.PHONY: all clean install
```
