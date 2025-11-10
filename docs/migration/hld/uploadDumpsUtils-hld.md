# High-Level Design: uploadDumpsUtils.sh Migration to C

## 1. Architecture Overview

The uploadDumpsUtils C implementation will provide a library of utility functions for the main uploadDumps application. This module focuses on system information retrieval, network operations, and common helper functions optimized for embedded platforms.

### 1.1 Design Principles

- **Reusability**: Provide generic, reusable functions
- **Efficiency**: Minimize system calls and external command execution
- **Portability**: Abstract platform-specific operations
- **Safety**: Implement bounds checking and error handling
- **Simplicity**: Single-purpose functions with clear interfaces

### 1.2 System Context

```
┌────────────────────────────────────────────────────┐
│         uploadDumps Main Application               │
└─────────────────┬──────────────────────────────────┘
                  │
                  │ Calls utility functions
                  │
┌─────────────────▼──────────────────────────────────┐
│         uploadDumpsUtils Library                   │
├────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌────────────┐  ┌────────────┐ │
│  │   Network    │  │   System   │  │   File     │ │
│  │   Utils      │  │   Info     │  │   Utils    │ │
│  └──────┬───────┘  └──────┬─────┘  └──────┬─────┘ │
│         │                 │                │       │
│  ┌──────▼─────────────────▼────────────────▼─────┐ │
│  │         Platform Abstraction Layer            │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────┬──────────────────────────────────┘
                  │
                  │ System calls
                  │
┌─────────────────▼──────────────────────────────────┐
│            Operating System                        │
├────────────────────────────────────────────────────┤
│  Network │ Filesystem │ Process  │ Time │ Crypto  │
└────────────────────────────────────────────────────┘
```

## 2. Module/Component Breakdown

### 2.1 Network Utilities Module

**Purpose**: Provide network interface operations and information retrieval

**Responsibilities**:
- Get network interface names
- Retrieve MAC addresses
- Retrieve IP addresses
- Handle platform-specific interface naming

**Key Interfaces**:
```c
int network_get_wan_interface_name(char *interface, size_t len);
int network_get_mac_address(const char *interface, char *mac, size_t len, bool with_colons);
int network_get_ip_address(const char *interface, char *ip, size_t len);
int network_get_erouter_mac(char *mac, size_t len);
int network_get_cm_mac(char *mac, size_t len);
```

**Data Structures**:
```c
typedef struct {
    char name[IFNAMSIZ];
    unsigned char hwaddr[6];
    struct in_addr ipaddr;
    bool is_up;
} network_interface_t;
```

**Implementation Strategy**:
- Use `getifaddrs()` for modern systems
- Fall back to `ioctl()` for older systems
- Cache interface information where appropriate
- Handle both Ethernet and wireless interfaces

### 2.2 System Information Module

**Purpose**: Retrieve system and device information

**Responsibilities**:
- Get system uptime
- Get device model
- Check process status
- Retrieve timestamps

**Key Interfaces**:
```c
int system_get_uptime(uint64_t *uptime_seconds);
int system_get_model(char *model, size_t len);
int system_check_process(const char *process_name, bool *is_running);
int system_get_timestamp(char *timestamp, size_t len, const char *format);
```

**Data Structures**:
```c
typedef struct {
    uint64_t uptime_seconds;
    uint64_t idle_seconds;
} system_uptime_t;

typedef struct {
    char model_name[MODEL_NAME_LEN];
    char image_name[IMAGE_NAME_LEN];
    char version[VERSION_LEN];
} device_info_t;
```

**Implementation Strategy**:
- Read `/proc/uptime` directly instead of parsing command output
- Parse `/proc/<pid>/stat` for process information
- Use `sysinfo()` for uptime on modern systems
- Cache model information (read once)

### 2.3 File Utilities Module

**Purpose**: File operations and metadata retrieval

**Responsibilities**:
- Get file modification time
- Calculate file checksums
- Format timestamps
- Safe file operations

**Key Interfaces**:
```c
int file_get_mtime_string(const char *filepath, char *timestamp, size_t len);
int file_get_sha1(const char *filepath, char *hash, size_t len);
int file_read_line(const char *filepath, char *buffer, size_t len);
time_t file_get_mtime(const char *filepath);
```

**Implementation Strategy**:
- Use `stat()` system call for file metadata
- Use OpenSSL for SHA1 calculation
- Implement efficient file reading
- Handle large files with streaming

### 2.4 Reboot Control Module

**Purpose**: System reboot operations with logging

**Responsibilities**:
- Initiate system reboot
- Log reboot reason
- Get caller information

**Key Interfaces**:
```c
int reboot_system(const char *process_name, const char *reason);
int reboot_get_caller_info(char *process_name, size_t len);
```

**Implementation Strategy**:
- Use `reboot()` system call
- Parse `/proc/self/cmdline` for caller info
- Integrate with logging system
- Call external reboot script for compatibility

## 3. Data Flow

### 3.1 Network MAC Address Retrieval Flow

```
Request MAC Address
  │
  ├─→ Check Cache
  │     ├─→ Cached? → Return cached value
  │     └─→ Not cached → Continue
  │
  ├─→ Get Interface Name
  │     ├─→ Check /etc/waninfo.sh
  │     ├─→ Use getWanInterfaceName()
  │     └─→ Fall back to default
  │
  ├─→ Query Interface
  │     ├─→ Method 1: getifaddrs()
  │     │     ├─→ Iterate interfaces
  │     │     ├─→ Find matching name
  │     │     ├─→ Extract hwaddr
  │     │     └─→ Return if found
  │     │
  │     └─→ Method 2: ioctl() fallback
  │           ├─→ Open socket
  │           ├─→ SIOCGIFHWADDR
  │           ├─→ Extract address
  │           └─→ Close socket
  │
  ├─→ Format MAC Address
  │     ├─→ Remove colons if requested
  │     ├─→ Convert to uppercase
  │     └─→ Copy to output buffer
  │
  ├─→ Cache Result
  │     └─→ Store for future calls
  │
  └─→ Return Success
```

### 3.2 File Modification Time Flow

```
Request File mtime
  │
  ├─→ Validate Input
  │     ├─→ Check filepath not NULL
  │     └─→ Check output buffer valid
  │
  ├─→ Get File Status
  │     ├─→ Call stat()
  │     ├─→ Check return value
  │     └─→ Handle errors
  │
  ├─→ Extract Timestamp
  │     ├─→ Get st_mtime
  │     └─→ Convert to time_t
  │
  ├─→ Format Timestamp
  │     ├─→ Convert to struct tm
  │     ├─→ Format: "YYYY-MM-DD-HH-MM-SS"
  │     └─→ Copy to output buffer
  │
  └─→ Return Success
```

### 3.3 Process Check Flow

```
Check Process Running
  │
  ├─→ Open /proc Directory
  │     ├─→ opendir("/proc")
  │     └─→ Check success
  │
  ├─→ Iterate Process Directories
  │     ├─→ Read directory entries
  │     ├─→ Filter numeric names (PIDs)
  │     └─→ For each PID:
  │
  ├─→ Check Process Name
  │     ├─→ Read /proc/<PID>/cmdline
  │     ├─→ Compare with target name
  │     ├─→ Match found? → Return true
  │     └─→ Continue if no match
  │
  ├─→ Close Directory
  │
  └─→ Return Result
        ├─→ Found → true
        └─→ Not found → false
```

### 3.4 System Uptime Retrieval Flow

```
Get System Uptime
  │
  ├─→ Method 1: sysinfo() (preferred)
  │     ├─→ Call sysinfo()
  │     ├─→ Extract uptime field
  │     └─→ Return if successful
  │
  ├─→ Method 2: /proc/uptime (fallback)
  │     ├─→ Open /proc/uptime
  │     ├─→ Read first field
  │     ├─→ Parse as double
  │     ├─→ Convert to uint64_t
  │     └─→ Return uptime
  │
  └─→ Format and Return
        ├─→ Uptime in seconds
        └─→ Return success
```

## 4. Key Algorithms and Data Structures

### 4.1 MAC Address Formatting Algorithm

```
function format_mac_address(raw_mac, output, with_colons):
    bytes = raw_mac[6]  # 6 bytes
    
    if with_colons:
        # Format: AA:BB:CC:DD:EE:FF
        snprintf(output, len, "%02X:%02X:%02X:%02X:%02X:%02X",
                 bytes[0], bytes[1], bytes[2], 
                 bytes[3], bytes[4], bytes[5])
    else:
        # Format: AABBCCDDEEFF
        snprintf(output, len, "%02X%02X%02X%02X%02X%02X",
                 bytes[0], bytes[1], bytes[2], 
                 bytes[3], bytes[4], bytes[5])
    
    # Convert to uppercase (if needed)
    for i in range(strlen(output)):
        output[i] = toupper(output[i])
    
    return SUCCESS
```

### 4.2 Timestamp Formatting Algorithm

```
function format_timestamp(time_value, format_string):
    # Convert time_t to struct tm
    tm_info = localtime(&time_value)
    
    if format_string == "file_mtime":
        # Format: YYYY-MM-DD-HH-MM-SS
        format = "%Y-%m-%d-%H-%M-%S"
    elif format_string == "standard":
        # Format: YYYY-MM-DD HH:MM:SS
        format = "%Y-%m-%d %H:%M:%S"
    
    # Format using strftime
    char buffer[TIMESTAMP_LEN]
    strftime(buffer, sizeof(buffer), format, tm_info)
    
    return buffer
```

### 4.3 Interface Information Caching

```c
typedef struct {
    char wan_interface[IFNAMSIZ];
    unsigned char wan_mac[6];
    char wan_ip[INET_ADDRSTRLEN];
    time_t cached_at;
    bool is_valid;
} interface_cache_t;

static interface_cache_t g_interface_cache = {0};

int network_get_mac_address(const char *interface, char *mac, size_t len, bool with_colons) {
    time_t now = time(NULL);
    
    // Check cache validity (cache for 60 seconds)
    if (g_interface_cache.is_valid && 
        strcmp(g_interface_cache.wan_interface, interface) == 0 &&
        (now - g_interface_cache.cached_at) < 60) {
        // Use cached value
        return format_mac_address(g_interface_cache.wan_mac, mac, len, with_colons);
    }
    
    // Fetch fresh data
    unsigned char hwaddr[6];
    if (get_interface_hwaddr(interface, hwaddr) != 0) {
        return ERROR_NETWORK_INTERFACE_NOT_FOUND;
    }
    
    // Update cache
    memcpy(g_interface_cache.wan_mac, hwaddr, 6);
    strncpy(g_interface_cache.wan_interface, interface, IFNAMSIZ);
    g_interface_cache.cached_at = now;
    g_interface_cache.is_valid = true;
    
    // Format and return
    return format_mac_address(hwaddr, mac, len, with_colons);
}
```

### 4.4 SHA1 Calculation Algorithm

```c
int file_get_sha1(const char *filepath, char *hash, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    char hash_string[SHA_DIGEST_LENGTH * 2 + 1];
    
    // Open file
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return ERROR_FILE_NOT_FOUND;
    }
    
    // Initialize SHA1 context
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    
    // Read and hash file in chunks
    unsigned char buffer[8192];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA1_Update(&sha_ctx, buffer, bytes_read);
    }
    
    // Finalize hash
    SHA1_Final(digest, &sha_ctx);
    
    // Close file
    fclose(file);
    
    // Convert to hex string
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&hash_string[i * 2], "%02x", digest[i]);
    }
    hash_string[SHA_DIGEST_LENGTH * 2] = '\0';
    
    // Copy to output
    if (len < sizeof(hash_string)) {
        return ERROR_BUFFER_TOO_SMALL;
    }
    strncpy(hash, hash_string, len);
    
    return SUCCESS;
}
```

### 4.5 Process Existence Check Algorithm

```c
bool system_check_process(const char *process_name) {
    DIR *proc_dir;
    struct dirent *entry;
    char cmdline_path[PATH_MAX];
    char cmdline[1024];
    bool found = false;
    
    // Open /proc directory
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        return false;
    }
    
    // Iterate through /proc entries
    while ((entry = readdir(proc_dir)) != NULL) {
        // Skip non-numeric entries (only PIDs)
        if (!isdigit(entry->d_name[0])) {
            continue;
        }
        
        // Build path to cmdline
        snprintf(cmdline_path, sizeof(cmdline_path), 
                 "/proc/%s/cmdline", entry->d_name);
        
        // Read cmdline
        FILE *f = fopen(cmdline_path, "r");
        if (!f) {
            continue;
        }
        
        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        
        if (bytes_read > 0) {
            cmdline[bytes_read] = '\0';
            
            // Check if process name matches
            if (strstr(cmdline, process_name) != NULL) {
                found = true;
                break;
            }
        }
    }
    
    closedir(proc_dir);
    return found;
}
```

## 5. Interfaces and Integration Points

### 5.1 External Library Interfaces

#### 5.1.1 OpenSSL (SHA1)
```c
#include <openssl/sha.h>

SHA_CTX sha_ctx;
unsigned char digest[SHA_DIGEST_LENGTH];

SHA1_Init(&sha_ctx);
SHA1_Update(&sha_ctx, data, data_len);
SHA1_Final(digest, &sha_ctx);
```

#### 5.1.2 Network Libraries
```c
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

// Method 1: getifaddrs (modern)
struct ifaddrs *ifaddr, *ifa;
getifaddrs(&ifaddr);
for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    // Process interface
}
freeifaddrs(ifaddr);

// Method 2: ioctl (fallback)
struct ifreq ifr;
int sock = socket(AF_INET, SOCK_DGRAM, 0);
strncpy(ifr.ifr_name, interface, IFNAMSIZ);
ioctl(sock, SIOCGIFHWADDR, &ifr);
close(sock);
```

### 5.2 System Call Interfaces

#### 5.2.1 File Statistics
```c
#include <sys/stat.h>

struct stat file_stat;
if (stat(filepath, &file_stat) == 0) {
    time_t mtime = file_stat.st_mtime;
    off_t size = file_stat.st_size;
}
```

#### 5.2.2 System Information
```c
#include <sys/sysinfo.h>

struct sysinfo si;
if (sysinfo(&si) == 0) {
    long uptime = si.uptime;
    unsigned long totalram = si.totalram;
}
```

#### 5.2.3 Time Functions
```c
#include <time.h>

time_t now = time(NULL);
struct tm *tm_info = localtime(&now);
char timestamp[64];
strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
```

### 5.3 Configuration Integration

#### 5.3.1 WAN Interface Configuration
```c
// Check for waninfo.sh
int network_get_wan_interface_name(char *interface, size_t len) {
    // Try to source /etc/waninfo.sh
    if (access("/etc/waninfo.sh", R_OK) == 0) {
        // Call getWanInterfaceName function from script
        FILE *fp = popen(". /etc/waninfo.sh && getWanInterfaceName", "r");
        if (fp) {
            if (fgets(interface, len, fp) != NULL) {
                // Remove newline
                interface[strcspn(interface, "\n")] = '\0';
                pclose(fp);
                return SUCCESS;
            }
            pclose(fp);
        }
    }
    
    // Use default
    strncpy(interface, "erouter0", len);
    return SUCCESS;
}
```

### 5.4 Public API Header

```c
// uploadDumpsUtils.h

#ifndef UPLOADDUMPS_UTILS_H
#define UPLOADDUMPS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Constants
#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define TIMESTAMP_LEN 32
#define SHA1_LEN 41
#define MODEL_NAME_LEN 64

// Network utilities
int network_get_wan_interface_name(char *interface, size_t len);
int network_get_mac_address(const char *interface, char *mac, size_t len, bool with_colons);
int network_get_ip_address(const char *interface, char *ip, size_t len);

// System information
int system_get_uptime(uint64_t *uptime_seconds);
int system_get_model(char *model, size_t len);
bool system_check_process(const char *process_name);
int system_get_timestamp(char *timestamp, size_t len, const char *format);

// File utilities
int file_get_mtime_string(const char *filepath, char *timestamp, size_t len);
int file_get_sha1(const char *filepath, char *hash, size_t len);
time_t file_get_mtime(const char *filepath);

// Reboot control
int reboot_system(const char *process_name, const char *reason);

#endif // UPLOADDUMPS_UTILS_H
```

## 6. Error Handling Strategy

### 6.1 Error Codes

```c
typedef enum {
    UTILS_SUCCESS = 0,
    UTILS_ERROR_INVALID_PARAM = -1,
    UTILS_ERROR_NETWORK_INTERFACE = -2,
    UTILS_ERROR_FILE_NOT_FOUND = -3,
    UTILS_ERROR_PERMISSION_DENIED = -4,
    UTILS_ERROR_BUFFER_TOO_SMALL = -5,
    UTILS_ERROR_SYSTEM_CALL = -6,
    UTILS_ERROR_PARSE_ERROR = -7
} utils_error_t;
```

### 6.2 Error Handling Pattern

```c
int function_name(parameters) {
    // Validate inputs
    if (invalid_input) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Perform operation
    int result = system_call();
    if (result < 0) {
        // Log error
        log_error("System call failed: %s", strerror(errno));
        return UTILS_ERROR_SYSTEM_CALL;
    }
    
    // Return success
    return UTILS_SUCCESS;
}
```

## 7. Performance Considerations

### 7.1 Caching Strategy

- **Interface Information**: Cache for 60 seconds
- **Model Information**: Cache indefinitely (read once)
- **Uptime**: No caching (always fresh)
- **Process Status**: No caching (always fresh)

### 7.2 Optimization Techniques

1. **Minimize System Calls**:
   - Batch operations where possible
   - Cache results of expensive operations
   - Use efficient APIs (getifaddrs vs multiple ioctls)

2. **Efficient String Operations**:
   - Use fixed-size buffers
   - Avoid unnecessary copies
   - Use strncpy/snprintf for safety

3. **File I/O**:
   - Use buffered I/O
   - Read large files in chunks
   - Close files promptly

4. **Memory Management**:
   - Prefer stack allocation
   - Free resources in reverse order
   - Use memory pools for frequent allocations

### 7.3 Performance Targets

- MAC address retrieval: < 1ms (cached), < 10ms (fresh)
- File mtime: < 1ms
- SHA1 calculation: < 100ms per MB
- Process check: < 50ms
- Uptime retrieval: < 1ms

## 8. Platform Compatibility

### 8.1 Busybox Compatibility

The C implementation eliminates dependency on busybox utilities:
- No need for `ifconfig` (use system calls)
- No need for `stat` command (use stat() call)
- No need for `ps` command (read /proc directly)
- No need for `date` command (use time functions)

### 8.2 Platform-Specific Code

```c
#ifdef PLATFORM_BROADBAND
    // Broadband-specific code
    default_interface = "wan0";
#elif defined(PLATFORM_VIDEO)
    // Video-specific code
    default_interface = "erouter0";
#else
    // Generic default
    default_interface = "eth0";
#endif
```

### 8.3 Cross-Platform Support

- Use POSIX-compliant APIs where possible
- Provide fallback implementations
- Handle different filesystem layouts
- Support both systemd and SysV init systems

## 9. Testing Strategy

### 9.1 Unit Tests

```c
// Test MAC address formatting
void test_format_mac_address() {
    unsigned char mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    char output[MAC_ADDR_LEN];
    
    // Test with colons
    format_mac_address(mac, output, sizeof(output), true);
    assert(strcmp(output, "AA:BB:CC:DD:EE:FF") == 0);
    
    // Test without colons
    format_mac_address(mac, output, sizeof(output), false);
    assert(strcmp(output, "AABBCCDDEEFF") == 0);
}

// Test timestamp formatting
void test_format_timestamp() {
    time_t test_time = 1609459200; // 2021-01-01 00:00:00 UTC
    char output[TIMESTAMP_LEN];
    
    format_timestamp(test_time, output, sizeof(output), "file_mtime");
    assert(strcmp(output, "2021-01-01-00-00-00") == 0);
}
```

### 9.2 Integration Tests

- Test with real network interfaces
- Test with actual /proc filesystem
- Test file operations on real files
- Test error conditions

### 9.3 Mock Interfaces

```c
// Mock interface for testing
typedef struct {
    int (*get_interface_hwaddr)(const char *interface, unsigned char *hwaddr);
    int (*read_proc_uptime)(uint64_t *uptime);
    int (*stat_file)(const char *path, struct stat *st);
} system_ops_t;

extern system_ops_t *g_system_ops;  // Can be mocked for testing
```

## 10. Migration Notes

### 10.1 Breaking Changes from Shell Version

1. **Return Types**: Functions return int error codes instead of strings
2. **MAC Format**: Caller must specify with_colons parameter explicitly
3. **Error Handling**: No silent failures; all errors are reported
4. **Caching**: Some values are cached (behavior change)

### 10.2 Backward Compatibility

To maintain compatibility during transition:

```c
// Wrapper for shell scripts (temporary)
int main_legacy_wrapper(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <function> [args...]\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "getMacAddress") == 0) {
        char mac[MAC_ADDR_LEN];
        network_get_mac_address("wan0", mac, sizeof(mac), true);
        printf("%s\n", mac);
    }
    // ... other function wrappers
    
    return 0;
}
```

### 10.3 Performance Improvements

Compared to shell script version:
- **50-90% faster** for most operations (no process spawning)
- **Lower memory usage** (no shell interpreter overhead)
- **More predictable** (no external command variations)
- **Better error handling** (structured error codes)
