# Low-Level Design: uploadDumpsUtils.sh Migration to C

## 1. File Structure

```
src/uploadDumpsUtils/
├── network.c                   # Network utility functions
├── system.c                    # System information functions
├── file.c                      # File utility functions
├── reboot.c                    # Reboot control function
├── uploadDumpsUtils.h          # Public API header
├── internal.h                  # Internal definitions
└── Makefile
```

## 2. Data Structures

### 2.1 Common Types

```c
// internal.h

#define MAC_ADDR_LEN 18
#define IP_ADDR_LEN 16
#define TIMESTAMP_LEN 32
#define SHA1_LEN 41
#define MODEL_NAME_LEN 64
#define INTERFACE_NAME_LEN 16

// Cache structure for interface information
typedef struct {
    char wan_interface[IFNAMSIZ];
    unsigned char wan_mac[6];
    char wan_ip[INET_ADDRSTRLEN];
    time_t cached_at;
    bool is_valid;
} interface_cache_t;

// Cache structure for model information
typedef struct {
    char model_name[MODEL_NAME_LEN];
    bool is_valid;
} model_cache_t;
```

### 2.2 Error Codes

```c
// uploadDumpsUtils.h

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

## 3. Detailed Function Specifications

### 3.1 Network Functions

```c
// network.c

/**
 * @brief Get WAN interface name
 * 
 * Checks /etc/waninfo.sh if available, otherwise uses default "erouter0"
 * 
 * @param interface Buffer to store interface name
 * @param len Buffer length
 * @return 0 on success, error code on failure
 * 
 * Implementation:
 * 1. Check if /etc/waninfo.sh exists
 * 2. If yes, source it and call getWanInterfaceName()
 * 3. If no or function fails, use default "erouter0"
 * 4. Copy result to output buffer
 */
int network_get_wan_interface_name(char *interface, size_t len) {
    if (!interface || len < IFNAMSIZ) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Try to get from waninfo.sh
    if (access("/etc/waninfo.sh", R_OK) == 0) {
        FILE *fp = popen(". /etc/waninfo.sh && getWanInterfaceName 2>/dev/null", "r");
        if (fp) {
            char result[IFNAMSIZ];
            if (fgets(result, sizeof(result), fp) != NULL) {
                result[strcspn(result, "\n")] = '\0';
                if (strlen(result) > 0) {
                    strncpy(interface, result, len - 1);
                    interface[len - 1] = '\0';
                    pclose(fp);
                    return UTILS_SUCCESS;
                }
            }
            pclose(fp);
        }
    }
    
    // Use default
    strncpy(interface, "erouter0", len - 1);
    interface[len - 1] = '\0';
    return UTILS_SUCCESS;
}

/**
 * @brief Get MAC address from interface
 * 
 * Uses getifaddrs() if available, falls back to ioctl()
 * Results are cached for 60 seconds
 * 
 * @param interface Interface name
 * @param mac Buffer to store MAC address
 * @param len Buffer length
 * @param with_colons Include colons in output
 * @return 0 on success, error code on failure
 */
int network_get_mac_address(const char *interface, char *mac, size_t len, 
                            bool with_colons) {
    static interface_cache_t cache = {0};
    time_t now = time(NULL);
    unsigned char hwaddr[6];
    
    // Validate parameters
    if (!interface || !mac || len < MAC_ADDR_LEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Check cache (valid for 60 seconds)
    if (cache.is_valid && 
        strcmp(cache.wan_interface, interface) == 0 &&
        (now - cache.cached_at) < 60) {
        return format_mac_address(cache.wan_mac, mac, len, with_colons);
    }
    
    // Method 1: Try getifaddrs (modern)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            
            if (strcmp(ifa->ifa_name, interface) == 0 &&
                ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(hwaddr, s->sll_addr, 6);
                freeifaddrs(ifaddr);
                
                // Update cache
                memcpy(cache.wan_mac, hwaddr, 6);
                strncpy(cache.wan_interface, interface, IFNAMSIZ);
                cache.cached_at = now;
                cache.is_valid = true;
                
                return format_mac_address(hwaddr, mac, len, with_colons);
            }
        }
        freeifaddrs(ifaddr);
    }
    
    // Method 2: Try ioctl (fallback)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return UTILS_ERROR_NETWORK_INTERFACE;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, 6);
        close(sock);
        
        // Update cache
        memcpy(cache.wan_mac, hwaddr, 6);
        strncpy(cache.wan_interface, interface, IFNAMSIZ);
        cache.cached_at = now;
        cache.is_valid = true;
        
        return format_mac_address(hwaddr, mac, len, with_colons);
    }
    
    close(sock);
    return UTILS_ERROR_NETWORK_INTERFACE;
}

/**
 * @brief Format MAC address
 * 
 * @param hwaddr Hardware address (6 bytes)
 * @param output Output buffer
 * @param len Buffer length
 * @param with_colons Include colons flag
 * @return 0 on success, error code on failure
 */
static int format_mac_address(const unsigned char *hwaddr, char *output, 
                              size_t len, bool with_colons) {
    if (with_colons) {
        snprintf(output, len, "%02X:%02X:%02X:%02X:%02X:%02X",
                 hwaddr[0], hwaddr[1], hwaddr[2],
                 hwaddr[3], hwaddr[4], hwaddr[5]);
    } else {
        snprintf(output, len, "%02X%02X%02X%02X%02X%02X",
                 hwaddr[0], hwaddr[1], hwaddr[2],
                 hwaddr[3], hwaddr[4], hwaddr[5]);
    }
    return UTILS_SUCCESS;
}

/**
 * @brief Get IP address from interface
 * 
 * @param interface Interface name
 * @param ip Buffer to store IP address
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int network_get_ip_address(const char *interface, char *ip, size_t len) {
    if (!interface || !ip || len < INET_ADDRSTRLEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Method 1: Try getifaddrs
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            
            if (strcmp(ifa->ifa_name, interface) == 0 &&
                ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip, len);
                freeifaddrs(ifaddr);
                return UTILS_SUCCESS;
            }
        }
        freeifaddrs(ifaddr);
    }
    
    // Method 2: Try ioctl
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return UTILS_ERROR_NETWORK_INTERFACE;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, len);
        close(sock);
        return UTILS_SUCCESS;
    }
    
    close(sock);
    return UTILS_ERROR_NETWORK_INTERFACE;
}
```

### 3.2 System Information Functions

```c
// system.c

/**
 * @brief Get system uptime in seconds
 * 
 * Uses sysinfo() if available, falls back to /proc/uptime
 * 
 * @param uptime_seconds Pointer to store uptime
 * @return 0 on success, error code on failure
 */
int system_get_uptime(uint64_t *uptime_seconds) {
    if (!uptime_seconds) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Method 1: Try sysinfo (preferred)
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        *uptime_seconds = si.uptime;
        return UTILS_SUCCESS;
    }
    
    // Method 2: Read /proc/uptime (fallback)
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) {
        return UTILS_ERROR_FILE_NOT_FOUND;
    }
    
    double uptime_double;
    if (fscanf(fp, "%lf", &uptime_double) == 1) {
        *uptime_seconds = (uint64_t)uptime_double;
        fclose(fp);
        return UTILS_SUCCESS;
    }
    
    fclose(fp);
    return UTILS_ERROR_PARSE_ERROR;
}

/**
 * @brief Get device model from version file
 * 
 * Reads /fss/gw/version.txt and extracts model from imagename line
 * Result is cached indefinitely
 * 
 * @param model Buffer to store model name
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int system_get_model(char *model, size_t len) {
    static model_cache_t cache = {0};
    
    if (!model || len < MODEL_NAME_LEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    // Check cache
    if (cache.is_valid) {
        strncpy(model, cache.model_name, len - 1);
        model[len - 1] = '\0';
        return UTILS_SUCCESS;
    }
    
    // Read version file
    FILE *fp = fopen("/fss/gw/version.txt", "r");
    if (!fp) {
        return UTILS_ERROR_FILE_NOT_FOUND;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // Look for imagename: line
        if (strncmp(line, "imagename:", 10) == 0) {
            // Extract value after colon
            char *value = line + 10;
            while (*value == ' ' || *value == '\t') value++;
            
            // Get first underscore-separated field
            char *underscore = strchr(value, '_');
            size_t model_len;
            if (underscore) {
                model_len = underscore - value;
            } else {
                model_len = strcspn(value, "\n\r");
            }
            
            if (model_len > 0 && model_len < MODEL_NAME_LEN) {
                strncpy(cache.model_name, value, model_len);
                cache.model_name[model_len] = '\0';
                cache.is_valid = true;
                
                strncpy(model, cache.model_name, len - 1);
                model[len - 1] = '\0';
                
                fclose(fp);
                return UTILS_SUCCESS;
            }
        }
    }
    
    fclose(fp);
    return UTILS_ERROR_PARSE_ERROR;
}

/**
 * @brief Check if process is running
 * 
 * Scans /proc directory for process matching name
 * 
 * @param process_name Process name to search for
 * @param is_running Pointer to store result
 * @return 0 on success, error code on failure
 */
int system_check_process(const char *process_name, bool *is_running) {
    if (!process_name || !is_running) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    *is_running = false;
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return UTILS_ERROR_PERMISSION_DENIED;
    }
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Skip non-numeric entries (only PIDs)
        if (!isdigit(entry->d_name[0])) {
            continue;
        }
        
        // Build path to cmdline
        char cmdline_path[PATH_MAX];
        snprintf(cmdline_path, sizeof(cmdline_path), 
                 "/proc/%s/cmdline", entry->d_name);
        
        // Read cmdline
        FILE *fp = fopen(cmdline_path, "r");
        if (!fp) {
            continue;
        }
        
        char cmdline[1024];
        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        fclose(fp);
        
        if (bytes_read > 0) {
            cmdline[bytes_read] = '\0';
            
            // Check if process name matches
            if (strstr(cmdline, process_name) != NULL) {
                *is_running = true;
                closedir(proc_dir);
                return UTILS_SUCCESS;
            }
        }
    }
    
    closedir(proc_dir);
    return UTILS_SUCCESS;
}

/**
 * @brief Get current timestamp
 * 
 * @param timestamp Buffer to store timestamp
 * @param len Buffer length
 * @param format Format string (NULL for default)
 * @return 0 on success, error code on failure
 */
int system_get_timestamp(char *timestamp, size_t len, const char *format) {
    if (!timestamp || len < TIMESTAMP_LEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    const char *fmt = format ? format : "%Y-%m-%d %H:%M:%S";
    
    if (strftime(timestamp, len, fmt, tm_info) == 0) {
        return UTILS_ERROR_BUFFER_TOO_SMALL;
    }
    
    return UTILS_SUCCESS;
}
```

### 3.3 File Utility Functions

```c
// file.c

/**
 * @brief Get file modification time as formatted string
 * 
 * @param filepath File path
 * @param timestamp Buffer to store timestamp
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_get_mtime_string(const char *filepath, char *timestamp, size_t len) {
    if (!filepath || !timestamp || len < TIMESTAMP_LEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return UTILS_ERROR_FILE_NOT_FOUND;
    }
    
    struct tm *tm_info = localtime(&st.st_mtime);
    
    // Format: YYYY-MM-DD-HH-MM-SS
    if (strftime(timestamp, len, "%Y-%m-%d-%H-%M-%S", tm_info) == 0) {
        return UTILS_ERROR_BUFFER_TOO_SMALL;
    }
    
    return UTILS_SUCCESS;
}

/**
 * @brief Get file modification time
 * 
 * @param filepath File path
 * @return Modification time or 0 on error
 */
time_t file_get_mtime(const char *filepath) {
    if (!filepath) {
        return 0;
    }
    
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return 0;
    }
    
    return st.st_mtime;
}

/**
 * @brief Calculate SHA1 hash of file
 * 
 * Reads file in 8KB chunks for efficiency
 * 
 * @param filepath File path
 * @param hash Buffer to store hash (must be >= 41 bytes)
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_get_sha1(const char *filepath, char *hash, size_t len) {
    if (!filepath || !hash || len < SHA1_LEN) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return UTILS_ERROR_FILE_NOT_FOUND;
    }
    
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    
    unsigned char buffer[8192];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        SHA1_Update(&sha_ctx, buffer, bytes_read);
    }
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, &sha_ctx);
    
    fclose(fp);
    
    // Convert to hex string
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", digest[i]);
    }
    hash[SHA_DIGEST_LENGTH * 2] = '\0';
    
    return UTILS_SUCCESS;
}

/**
 * @brief Read single line from file
 * 
 * @param filepath File path
 * @param buffer Buffer to store line
 * @param len Buffer length
 * @return 0 on success, error code on failure
 */
int file_read_line(const char *filepath, char *buffer, size_t len) {
    if (!filepath || !buffer || len == 0) {
        return UTILS_ERROR_INVALID_PARAM;
    }
    
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        return UTILS_ERROR_FILE_NOT_FOUND;
    }
    
    if (fgets(buffer, len, fp) == NULL) {
        fclose(fp);
        return UTILS_ERROR_PARSE_ERROR;
    }
    
    // Remove newline
    buffer[strcspn(buffer, "\n\r")] = '\0';
    
    fclose(fp);
    return UTILS_SUCCESS;
}
```

### 3.4 Reboot Function

```c
// reboot.c

/**
 * @brief Reboot system with logging
 * 
 * Calls /rebootNow.sh script with process name and reason
 * If process_name is NULL, attempts to get parent process
 * 
 * @param process_name Process name (NULL for auto-detect)
 * @param reason Reboot reason (NULL for default)
 * @return Does not return on success, error code on failure
 */
int reboot_system(const char *process_name, const char *reason) {
    char cmd[512];
    char proc_name[256] = "";
    char reboot_reason[256] = "";
    
    // Get process name if not provided
    if (!process_name) {
        pid_t ppid = getppid();
        char cmdline_path[PATH_MAX];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", ppid);
        
        FILE *fp = fopen(cmdline_path, "r");
        if (fp) {
            if (fgets(proc_name, sizeof(proc_name), fp) != NULL) {
                proc_name[strcspn(proc_name, "\0")] = '\0';
            }
            fclose(fp);
        }
        
        if (strlen(proc_name) == 0) {
            strncpy(proc_name, "unknown", sizeof(proc_name));
        }
        
        process_name = proc_name;
    }
    
    // Get reason if not provided
    if (!reason) {
        strncpy(reboot_reason, "Rebooting by calling rebootFunc of utils.sh script...",
                sizeof(reboot_reason));
        reason = reboot_reason;
    }
    
    // Build command
    snprintf(cmd, sizeof(cmd), "/rebootNow.sh -s '%s' -o '%s'",
             process_name, reason);
    
    // Execute reboot script
    int result = system(cmd);
    
    // If we get here, reboot failed
    return (result == 0) ? UTILS_SUCCESS : UTILS_ERROR_SYSTEM_CALL;
}
```

## 4. Public API Header

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

// Error codes
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

// Network utilities
int network_get_wan_interface_name(char *interface, size_t len);
int network_get_mac_address(const char *interface, char *mac, size_t len, 
                            bool with_colons);
int network_get_ip_address(const char *interface, char *ip, size_t len);

// System information
int system_get_uptime(uint64_t *uptime_seconds);
int system_get_model(char *model, size_t len);
int system_check_process(const char *process_name, bool *is_running);
int system_get_timestamp(char *timestamp, size_t len, const char *format);

// File utilities
int file_get_mtime_string(const char *filepath, char *timestamp, size_t len);
int file_get_sha1(const char *filepath, char *hash, size_t len);
int file_read_line(const char *filepath, char *buffer, size_t len);
time_t file_get_mtime(const char *filepath);

// Reboot control
int reboot_system(const char *process_name, const char *reason);

#endif // UPLOADDUMPS_UTILS_H
```

## 5. Implementation Notes

### 5.1 Caching Strategy

```c
// network.c - MAC address caching

static interface_cache_t g_interface_cache = {0};

int network_get_mac_address(const char *interface, char *mac, size_t len,
                            bool with_colons) {
    time_t now = time(NULL);
    
    // Cache valid for 60 seconds
    if (g_interface_cache.is_valid &&
        strcmp(g_interface_cache.wan_interface, interface) == 0 &&
        (now - g_interface_cache.cached_at) < 60) {
        return format_mac_address(g_interface_cache.wan_mac, mac, len, with_colons);
    }
    
    // ... fetch fresh data ...
    
    // Update cache
    memcpy(g_interface_cache.wan_mac, hwaddr, 6);
    strncpy(g_interface_cache.wan_interface, interface, IFNAMSIZ);
    g_interface_cache.cached_at = now;
    g_interface_cache.is_valid = true;
    
    return format_mac_address(hwaddr, mac, len, with_colons);
}
```

### 5.2 Fallback Pattern

```c
// system.c - Uptime with fallback

int system_get_uptime(uint64_t *uptime_seconds) {
    // Try method 1 (preferred)
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        *uptime_seconds = si.uptime;
        return UTILS_SUCCESS;
    }
    
    // Try method 2 (fallback)
    FILE *fp = fopen("/proc/uptime", "r");
    if (fp) {
        double uptime;
        if (fscanf(fp, "%lf", &uptime) == 1) {
            *uptime_seconds = (uint64_t)uptime;
            fclose(fp);
            return UTILS_SUCCESS;
        }
        fclose(fp);
    }
    
    // All methods failed
    return UTILS_ERROR_SYSTEM_CALL;
}
```

### 5.3 Streaming Pattern

```c
// file.c - SHA1 with streaming

int file_get_sha1(const char *filepath, char *hash, size_t len) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return UTILS_ERROR_FILE_NOT_FOUND;
    
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    
    // Process file in chunks
    unsigned char buffer[8192];
    size_t bytes;
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        SHA1_Update(&ctx, buffer, bytes);
    }
    
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, &ctx);
    fclose(fp);
    
    // Convert to hex string
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", digest[i]);
    }
    
    return UTILS_SUCCESS;
}
```

## 6. Testing

### 6.1 Unit Tests

```c
// test_network.c

void test_get_mac_address() {
    char mac[MAC_ADDR_LEN];
    int result;
    
    // Test with colons
    result = network_get_mac_address("erouter0", mac, sizeof(mac), true);
    assert(result == UTILS_SUCCESS || result == UTILS_ERROR_NETWORK_INTERFACE);
    
    if (result == UTILS_SUCCESS) {
        assert(strlen(mac) == 17);  // AA:BB:CC:DD:EE:FF
        assert(mac[2] == ':');
        assert(mac[5] == ':');
    }
    
    // Test without colons
    result = network_get_mac_address("erouter0", mac, sizeof(mac), false);
    if (result == UTILS_SUCCESS) {
        assert(strlen(mac) == 12);  // AABBCCDDEEFF
        assert(strchr(mac, ':') == NULL);
    }
}

void test_get_mac_address_cache() {
    char mac1[MAC_ADDR_LEN];
    char mac2[MAC_ADDR_LEN];
    
    // First call
    int result1 = network_get_mac_address("erouter0", mac1, sizeof(mac1), false);
    
    // Second call (should use cache)
    int result2 = network_get_mac_address("erouter0", mac2, sizeof(mac2), false);
    
    if (result1 == UTILS_SUCCESS && result2 == UTILS_SUCCESS) {
        assert(strcmp(mac1, mac2) == 0);  // Should be identical
    }
}

void test_format_timestamp() {
    char timestamp[TIMESTAMP_LEN];
    time_t test_time = 1704067200;  // 2024-01-01 00:00:00 UTC
    
    struct tm *tm_info = localtime(&test_time);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H-%M-%S", tm_info);
    
    // Verify format
    assert(strlen(timestamp) == 19);  // YYYY-MM-DD-HH-MM-SS
    assert(timestamp[4] == '-');
    assert(timestamp[7] == '-');
}

void test_process_check() {
    bool is_running;
    
    // Test with init (should always be running on Linux)
    int result = system_check_process("init", &is_running);
    assert(result == UTILS_SUCCESS);
    // Note: Can't assert is_running == true because systemd might be PID 1
    
    // Test with non-existent process
    result = system_check_process("this-process-does-not-exist-123456", &is_running);
    assert(result == UTILS_SUCCESS);
    assert(is_running == false);
}
```

### 6.2 Integration Tests

```c
// test_integration.c

void test_full_network_workflow() {
    char interface[IFNAMSIZ];
    char mac[MAC_ADDR_LEN];
    char ip[IP_ADDR_LEN];
    
    // Get interface name
    int result = network_get_wan_interface_name(interface, sizeof(interface));
    assert(result == UTILS_SUCCESS);
    assert(strlen(interface) > 0);
    
    // Get MAC address
    result = network_get_mac_address(interface, mac, sizeof(mac), false);
    if (result == UTILS_SUCCESS) {
        assert(strlen(mac) == 12);
        
        // Verify all characters are hex digits
        for (size_t i = 0; i < strlen(mac); i++) {
            assert(isxdigit(mac[i]));
        }
    }
    
    // Get IP address
    result = network_get_ip_address(interface, ip, sizeof(ip));
    if (result == UTILS_SUCCESS) {
        // Verify it looks like an IP address
        assert(strchr(ip, '.') != NULL);
    }
}

void test_file_operations() {
    // Create test file
    const char *test_file = "/tmp/test_utils.txt";
    FILE *fp = fopen(test_file, "w");
    assert(fp != NULL);
    fprintf(fp, "test content\n");
    fclose(fp);
    
    // Test mtime
    char timestamp[TIMESTAMP_LEN];
    int result = file_get_mtime_string(test_file, timestamp, sizeof(timestamp));
    assert(result == UTILS_SUCCESS);
    assert(strlen(timestamp) == 19);
    
    // Test SHA1
    char hash[SHA1_LEN];
    result = file_get_sha1(test_file, hash, sizeof(hash));
    assert(result == UTILS_SUCCESS);
    assert(strlen(hash) == 40);
    
    // Verify hash is hex
    for (size_t i = 0; i < strlen(hash); i++) {
        assert(isxdigit(hash[i]));
    }
    
    // Cleanup
    unlink(test_file);
}
```

## 7. Build System

```makefile
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -fPIC
LDFLAGS = -lssl -lcrypto -shared

# Source files
SRCS = network.c system.c file.c reboot.c

OBJS = $(SRCS:.c=.o)

# Library target
TARGET = libuploadDumpsUtils.so

# Static library (optional)
STATIC_TARGET = libuploadDumpsUtils.a

all: $(TARGET) $(STATIC_TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(STATIC_TARGET): $(OBJS)
	ar rcs $@ $^

%.o: %.c uploadDumpsUtils.h internal.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(STATIC_TARGET)

install:
	install -m 0755 $(TARGET) /usr/lib/
	install -m 0644 uploadDumpsUtils.h /usr/include/

# Test target
test: all
	$(CC) $(CFLAGS) -o test_utils test_network.c test_integration.c -L. -luploadDumpsUtils -lssl -lcrypto
	./test_utils

.PHONY: all clean install test
```

## 8. Usage Example

```c
// example.c - Using the uploadDumpsUtils library

#include "uploadDumpsUtils.h"
#include <stdio.h>

int main() {
    char mac[MAC_ADDR_LEN];
    char ip[IP_ADDR_LEN];
    char model[MODEL_NAME_LEN];
    uint64_t uptime;
    
    // Get MAC address
    if (network_get_mac_address("erouter0", mac, sizeof(mac), false) == UTILS_SUCCESS) {
        printf("MAC: %s\n", mac);
    }
    
    // Get IP address
    if (network_get_ip_address("erouter0", ip, sizeof(ip)) == UTILS_SUCCESS) {
        printf("IP: %s\n", ip);
    }
    
    // Get model
    if (system_get_model(model, sizeof(model)) == UTILS_SUCCESS) {
        printf("Model: %s\n", model);
    }
    
    // Get uptime
    if (system_get_uptime(&uptime) == UTILS_SUCCESS) {
        printf("Uptime: %lu seconds\n", uptime);
    }
    
    // Check if process is running
    bool is_running;
    if (system_check_process("systemd", &is_running) == UTILS_SUCCESS) {
        printf("systemd is %s\n", is_running ? "running" : "not running");
    }
    
    // Get file SHA1
    char hash[SHA1_LEN];
    if (file_get_sha1("/version.txt", hash, sizeof(hash)) == UTILS_SUCCESS) {
        printf("SHA1: %s\n", hash);
    }
    
    return 0;
}
```

## 9. Performance Optimizations

### 9.1 Reduce System Calls

```c
// Before (shell version): Multiple process spawns
// - ifconfig erouter0 | grep HWaddr | cut -d " " -f7 | sed 's/://g'
// 4 process spawns for a single MAC address!

// After (C version): Single system call
int network_get_mac_address(...) {
    struct ifreq ifr;
    ioctl(sock, SIOCGIFHWADDR, &ifr);  // Just one system call
    // Process in memory
    return format_mac_address(...);
}
```

### 9.2 Caching Expensive Operations

```c
// Cache MAC address for 60 seconds
// Cache model indefinitely (doesn't change)
// No caching for process check (dynamic)
// No caching for uptime (always changing)
```

### 9.3 Efficient String Operations

```c
// Avoid repeated string allocations
static char mac_buffer[MAC_ADDR_LEN];  // Reuse buffer

// Use stack buffers when possible
char temp[256];  // Instead of malloc
```

## 10. Migration Path

### 10.1 Backward Compatibility Wrapper

For gradual migration, provide shell wrapper:

```bash
#!/bin/sh
# uploadDumpsUtils_wrapper.sh
# Temporary wrapper to call C library from shell scripts

case "$1" in
    getMacAddressOnly)
        /usr/bin/utils_cli get_mac
        ;;
    getIPAddress)
        /usr/bin/utils_cli get_ip "$2"
        ;;
    getModel)
        /usr/bin/utils_cli get_model
        ;;
    Uptime)
        /usr/bin/utils_cli get_uptime
        ;;
    *)
        echo "Unknown function: $1"
        exit 1
        ;;
esac
```

### 10.2 Command-Line Tool

```c
// utils_cli.c - CLI wrapper for library

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "get_mac") == 0) {
        char mac[MAC_ADDR_LEN];
        if (network_get_mac_address("erouter0", mac, sizeof(mac), false) == UTILS_SUCCESS) {
            printf("%s\n", mac);
            return 0;
        }
    } else if (strcmp(argv[1], "get_ip") == 0) {
        char *interface = argc > 2 ? argv[2] : "erouter0";
        char ip[IP_ADDR_LEN];
        if (network_get_ip_address(interface, ip, sizeof(ip)) == UTILS_SUCCESS) {
            printf("%s\n", ip);
            return 0;
        }
    } else if (strcmp(argv[1], "get_model") == 0) {
        char model[MODEL_NAME_LEN];
        if (system_get_model(model, sizeof(model)) == UTILS_SUCCESS) {
            printf("%s\n", model);
            return 0;
        }
    } else if (strcmp(argv[1], "get_uptime") == 0) {
        uint64_t uptime;
        if (system_get_uptime(&uptime) == UTILS_SUCCESS) {
            printf("%lu\n", uptime);
            return 0;
        }
    }
    
    fprintf(stderr, "Command failed or unknown: %s\n", argv[1]);
    return 1;
}
```
