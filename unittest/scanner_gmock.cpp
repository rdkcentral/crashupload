/**
 * @file scanner_gmock.cpp
 * @brief Mock implementations for external functions used in scanner.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in scanner.c
 * - External utility functions from other modules
 * - Required for testing scanner functionality
 * 
 * Functions mocked:
 * - is_regular_file() - File utility to check if path is regular file
 * - join_path() - File utility to join directory and filename paths
 * - t2ValNotify() - Telemetry notification with value
 * - t2CountNotify() - Telemetry counter notification
 * 
 * NOT mocked (POSIX/glibc/system calls):
 * - opendir, readdir, closedir, stat, unlink, rename
 * - fopen, fclose, fprintf, fgets, fputc
 * - malloc, free, calloc, strdup
 * - memcpy, memset, strcpy, strncpy, strlen, strcmp, strstr, etc.
 */

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// Mock state control structure
struct ScannerMockState {
    // is_regular_file
    int is_regular_file_return_value;
    bool is_regular_file_custom_behavior;
    
    // join_path
    int join_path_return_value;
    bool join_path_custom_behavior;
    
    // t2 telemetry
    bool t2_enabled;
    int t2_val_notify_call_count;
    int t2_count_notify_call_count;
    char last_t2_key[256];
    char last_t2_val[256];
};

static ScannerMockState g_scanner_mock_state = {
    1,      // is_regular_file returns 1 (true) by default
    false,  // no custom behavior
    0,      // join_path returns 0 (success) by default
    false,  // no custom behavior
    false,  // t2 disabled by default
    0,      // t2 call counts
    0,
    "",     // last t2 key/val
    ""
};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for is_regular_file mock
 * @param return_value Return value for the mock (1 for regular file, 0 otherwise)
 */
void set_mock_is_regular_file_behavior(int return_value) {
    g_scanner_mock_state.is_regular_file_return_value = return_value;
    g_scanner_mock_state.is_regular_file_custom_behavior = true;
}

/**
 * Set behavior for join_path mock
 * @param return_value Return value for the mock (0 for success, -1 for error)
 */
void set_mock_join_path_behavior(int return_value) {
    g_scanner_mock_state.join_path_return_value = return_value;
    g_scanner_mock_state.join_path_custom_behavior = true;
}

/**
 * Enable or disable T2 telemetry mocking
 * @param enabled true to enable telemetry, false to disable
 */
void set_mock_t2_enabled(bool enabled) {
    g_scanner_mock_state.t2_enabled = enabled;
}

/**
 * Reset all scanner mocks to default state
 */
void reset_scanner_mocks() {
    g_scanner_mock_state.is_regular_file_return_value = 1;
    g_scanner_mock_state.is_regular_file_custom_behavior = false;
    g_scanner_mock_state.join_path_return_value = 0;
    g_scanner_mock_state.join_path_custom_behavior = false;
    g_scanner_mock_state.t2_enabled = false;
    g_scanner_mock_state.t2_val_notify_call_count = 0;
    g_scanner_mock_state.t2_count_notify_call_count = 0;
    g_scanner_mock_state.last_t2_key[0] = '\0';
    g_scanner_mock_state.last_t2_val[0] = '\0';
}

/**
 * Get T2 notification call counts (for verification in tests)
 */
int get_t2_val_notify_call_count() {
    return g_scanner_mock_state.t2_val_notify_call_count;
}

int get_t2_count_notify_call_count() {
    return g_scanner_mock_state.t2_count_notify_call_count;
}

// ============================================================================
// Mock Function Implementations
// ============================================================================

/**
 * Mock implementation of is_regular_file()
 * Checks if a path points to a regular file
 * 
 * @param path File path to check
 * @return 1 if regular file, 0 otherwise
 * 
 * Default behavior: Uses real stat() to check file type
 * Custom behavior: Returns configured return value
 */
int is_regular_file(const char *path) {
    if (!path) {
        return 0;
    }
    
    if (g_scanner_mock_state.is_regular_file_custom_behavior) {
        // Return configured value
        return g_scanner_mock_state.is_regular_file_return_value;
    }
    
    // Default: Use real stat() to check
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    
    return S_ISREG(st.st_mode) ? 1 : 0;
}

/**
 * Mock implementation of join_path()
 * Safely joins directory and filename into destination buffer
 * 
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param dir Directory path
 * @param name Filename
 * @return 0 on success, -1 on error (overflow)
 * 
 * Default behavior: Safely concatenates dir + "/" + name
 * Custom behavior: Returns configured return value
 */
int join_path(char *dest, size_t dest_size, const char *dir, const char *name) {
    if (!dest || dest_size == 0 || !dir || !name) {
        return -1;
    }
    
    if (g_scanner_mock_state.join_path_custom_behavior) {
        // Return configured value (but still try to create valid path)
        if (g_scanner_mock_state.join_path_return_value == 0) {
            // Success case - create path
            size_t dir_len = strlen(dir);
            size_t name_len = strlen(name);
            
            // Check if path will fit
            if (dir_len + 1 + name_len + 1 > dest_size) {
                return -1;
            }
            
            // Copy directory
            strncpy(dest, dir, dest_size - 1);
            dest[dest_size - 1] = '\0';
            
            // Add separator if needed
            if (dir_len > 0 && dir[dir_len - 1] != '/') {
                strncat(dest, "/", dest_size - strlen(dest) - 1);
            }
            
            // Add filename
            strncat(dest, name, dest_size - strlen(dest) - 1);
        }
        return g_scanner_mock_state.join_path_return_value;
    }
    
    // Default behavior: Safely join paths
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    
    // Check if result will fit in buffer
    size_t needed = dir_len + 1 + name_len + 1; // dir + "/" + name + null
    if (needed > dest_size) {
        return -1;
    }
    
    // Copy directory
    strncpy(dest, dir, dest_size - 1);
    dest[dest_size - 1] = '\0';
    
    // Add separator if directory doesn't end with one
    if (dir_len > 0 && dir[dir_len - 1] != '/') {
        strncat(dest, "/", dest_size - strlen(dest) - 1);
    }
    
    // Add filename
    strncat(dest, name, dest_size - strlen(dest) - 1);
    
    return 0;
}
#if 0
/**
 * Mock implementation of t2ValNotify()
 * Telemetry notification with key-value pair
 * 
 * @param key Telemetry key
 * @param val Telemetry value
 * 
 * This is a stub that tracks calls for testing purposes
 */
void t2ValNotify(const char *key, const char *val) {
    if (!key) {
        return;
    }
    
    g_scanner_mock_state.t2_val_notify_call_count++;
    
    // Store last key/val for verification
    strncpy(g_scanner_mock_state.last_t2_key, key, 
            sizeof(g_scanner_mock_state.last_t2_key) - 1);
    g_scanner_mock_state.last_t2_key[sizeof(g_scanner_mock_state.last_t2_key) - 1] = '\0';
    
    if (val) {
        strncpy(g_scanner_mock_state.last_t2_val, val, 
                sizeof(g_scanner_mock_state.last_t2_val) - 1);
        g_scanner_mock_state.last_t2_val[sizeof(g_scanner_mock_state.last_t2_val) - 1] = '\0';
    } else {
        g_scanner_mock_state.last_t2_val[0] = '\0';
    }
    
    // Optional: Print for debugging
    if (g_scanner_mock_state.t2_enabled) {
        printf("[T2_VAL] %s = %s\n", key, val ? val : "(null)");
    }
}

/**
 * Mock implementation of t2CountNotify()
 * Telemetry counter notification
 * 
 * @param key Telemetry key
 * @param val_or_null Optional value (can be NULL for simple counter)
 * 
 * This is a stub that tracks calls for testing purposes
 */
void t2CountNotify(const char *key, const char *val_or_null) {
    if (!key) {
        return;
    }
    
    g_scanner_mock_state.t2_count_notify_call_count++;
    
    // Store last key/val for verification
    strncpy(g_scanner_mock_state.last_t2_key, key, 
            sizeof(g_scanner_mock_state.last_t2_key) - 1);
    g_scanner_mock_state.last_t2_key[sizeof(g_scanner_mock_state.last_t2_key) - 1] = '\0';
    
    if (val_or_null) {
        strncpy(g_scanner_mock_state.last_t2_val, val_or_null, 
                sizeof(g_scanner_mock_state.last_t2_val) - 1);
        g_scanner_mock_state.last_t2_val[sizeof(g_scanner_mock_state.last_t2_val) - 1] = '\0';
    } else {
        g_scanner_mock_state.last_t2_val[0] = '\0';
    }
    
    // Optional: Print for debugging
    if (g_scanner_mock_state.t2_enabled) {
        printf("[T2_COUNT] %s %s\n", key, val_or_null ? val_or_null : "");
    }
}
#endif
// ============================================================================
// Additional Mock Utilities (Optional)
// ============================================================================

/**
 * Get last telemetry key sent (for test verification)
 */
const char* get_last_t2_key() {
    return g_scanner_mock_state.last_t2_key;
}

/**
 * Get last telemetry value sent (for test verification)
 */
const char* get_last_t2_val() {
    return g_scanner_mock_state.last_t2_val;
}

/**
 * Clear telemetry counters
 */
void clear_t2_counters() {
    g_scanner_mock_state.t2_val_notify_call_count = 0;
    g_scanner_mock_state.t2_count_notify_call_count = 0;
    g_scanner_mock_state.last_t2_key[0] = '\0';
    g_scanner_mock_state.last_t2_val[0] = '\0';
}

} // extern "C"

// ============================================================================
// Mock Implementation Notes
// ============================================================================

/*
 * FUNCTIONS NOT MOCKED (POSIX/glibc/Linux system calls):
 * 
 * File I/O:
 * - fopen, fclose, fprintf, fgets, fputc, fputs
 * - open, close, read, write
 * 
 * Directory Operations:
 * - opendir, readdir, closedir
 * - mkdir, rmdir
 * 
 * File System:
 * - stat, lstat, fstat
 * - unlink, rename, symlink
 * - access, chmod, chown
 * 
 * Memory Management:
 * - malloc, calloc, realloc, free
 * - strdup, strndup
 * 
 * String Operations:
 * - strlen, strcmp, strncmp, strcpy, strncpy
 * - strcat, strncat, strchr, strrchr, strstr
 * - memcpy, memset, memmove, memcmp, memchr
 * - strcspn, strspn
 * 
 * Standard I/O:
 * - printf, fprintf, sprintf, snprintf
 * 
 * Environment:
 * - getenv, setenv, unsetenv
 * 
 * Time:
 * - time, gmtime, localtime, strftime
 * 
 * Process:
 * - sleep, usleep
 * 
 * Character Classification:
 * - isspace, isalpha, isdigit, isalnum
 * 
 * Error Handling:
 * - errno
 * 
 * These are all standard library functions that should work as-is
 * during testing. The test environment provides real implementations.
 */

// ============================================================================
// Mock Behavior Configuration Guide
// ============================================================================

/*
 * HOW TO USE MOCKS IN TESTS:
 * 
 * 1. Reset mocks before each test:
 *    reset_scanner_mocks();
 * 
 * 2. Configure is_regular_file behavior:
 *    // Make is_regular_file return false (not a regular file)
 *    set_mock_is_regular_file_behavior(0);
 *    
 *    // Make is_regular_file return true (is a regular file)
 *    set_mock_is_regular_file_behavior(1);
 * 
 * 3. Configure join_path behavior:
 *    // Make join_path fail (buffer overflow scenario)
 *    set_mock_join_path_behavior(-1);
 *    
 *    // Make join_path succeed
 *    set_mock_join_path_behavior(0);
 * 
 * 4. Enable telemetry tracking:
 *    set_mock_t2_enabled(true);
 *    
 *    // After test, check telemetry calls:
 *    int val_count = get_t2_val_notify_call_count();
 *    int count_count = get_t2_count_notify_call_count();
 *    const char* last_key = get_last_t2_key();
 * 
 * 5. Clear telemetry counters between tests:
 *    clear_t2_counters();
 * 
 * EXAMPLE TEST:
 * 
 * TEST_F(ScannerTest, ProcessFile_NotRegularFile) {
 *     // Configure mock to return false
 *     set_mock_is_regular_file_behavior(0);
 *     
 *     char fullpath[] = "/tmp/not_a_file";
 *     char dump_type[] = "0";
 *     config_t config;
 *     
 *     int result = process_file_entry(fullpath, dump_type, &config);
 *     
 *     // Should return early since it's not a regular file
 *     EXPECT_EQ(result, 0);
 * }
 */
