/**
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * @file mainapp_gmock.cpp
 * @brief Mock implementations for external functions used in main.c and system_init.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in main.c and system_init.c
 * - External utility functions from other modules
 * - Required for testing main application functionality
 * 
 * Functions mocked:
 * - config_init_load() - Configuration initialization and loading
 * - get_privacy_control_mode() - Get privacy control mode
 * - platform_initialize() - Platform initialization
 * - filePresentCheck() - File presence check
 * - lock_acquire() - Lock acquisition
 * - lock_release() - Lock release
 * - prerequisites_wait() - Prerequisites waiting
 * - privacy_uploads_blocked() - Privacy check
 * - cleanup_batch() - Batch cleanup
 * - scanner_find_dumps() - Dump scanning
 * - process_file_entry() - File entry processing
 * - file_get_mtime_formatted() - Get formatted modification time
 * - get_crash_timestamp_utc() - Get crash timestamp
 * - check_process_dmp_file() - Check if process dump file
 * - extract_pname() - Extract process name
 * - trim_process_name_in_path() - Trim process name in path
 * - archive_create_smart() - Smart archive creation
 * - is_box_rebooting() - Check if box is rebooting
 * - ratelimit_check_unified() - Rate limit check
 * - remove_pending_dumps() - Remove pending dumps
 * - upload_process() - Upload process
 * - logger_error() - Error logging
 * - logger_info() - Info logging
 * - logger_warn() - Warning logging
 * 
 * NOT mocked (POSIX/glibc/system calls):
 * - printf, fprintf, snprintf, sprintf
 * - malloc, free, calloc, strdup, realloc
 * - memcpy, memset, strcpy, strncpy, strlen, strcmp, strstr, strchr, strrchr
 * - fopen, fclose, fread, fwrite, unlink, open, close, chmod
 * - sleep, getpid, exit, atoi
 * - sigaction, signal handling
 */

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"
#include "../c_sourcecode/common/constants.h"
}

// Mock state control structure
struct MainAppMockState {
    // config_init_load
    int config_init_load_return_value;
    bool config_init_load_custom_behavior;
    
    // get_privacy_control_mode
    privacy_control_t get_privacy_control_mode_return_value;
    bool get_privacy_control_mode_custom_behavior;
    
    // platform_initialize
    int platform_initialize_return_value;
    bool platform_initialize_custom_behavior;
    
    // filePresentCheck
    int file_present_check_return_value;
    bool file_present_check_custom_behavior;
    
    // lock_acquire
    int lock_acquire_return_value;
    bool lock_acquire_custom_behavior;
    
    // prerequisites_wait
    int prerequisites_wait_return_value;
    bool prerequisites_wait_custom_behavior;
    
    // privacy_uploads_blocked
    bool privacy_uploads_blocked_return_value;
    bool privacy_uploads_blocked_custom_behavior;
    
    // cleanup_batch
    int cleanup_batch_return_value;
    int cleanup_batch_call_count;
    
    // scanner_find_dumps
    int scanner_find_dumps_return_value;
    int scanner_find_dumps_output_count;
    bool scanner_find_dumps_custom_behavior;
    
    // process_file_entry
    int process_file_entry_return_value;
    bool process_file_entry_custom_behavior;
    
    // file_get_mtime_formatted
    int file_get_mtime_formatted_return_value;
    char file_get_mtime_formatted_output[64];
    bool file_get_mtime_formatted_custom_behavior;
    
    // get_crash_timestamp_utc
    int get_crash_timestamp_utc_return_value;
    char get_crash_timestamp_utc_output[64];
    
    // check_process_dmp_file
    bool check_process_dmp_file_return_value;
    bool check_process_dmp_file_custom_behavior;
    
    // extract_pname
    char* extract_pname_return_value;
    bool extract_pname_custom_behavior;
    
    // trim_process_name_in_path
    int trim_process_name_in_path_return_value;
    char trim_process_name_in_path_output[1024];
    bool trim_process_name_in_path_custom_behavior;
    
    // archive_create_smart
    int archive_create_smart_return_value;
    bool archive_create_smart_custom_behavior;
    
    // is_box_rebooting
    bool is_box_rebooting_return_value;
    bool is_box_rebooting_custom_behavior;
    
    // ratelimit_check_unified
    int ratelimit_check_unified_return_value;
    bool ratelimit_check_unified_custom_behavior;
    
    // upload_process
    int upload_process_return_value;
    bool upload_process_custom_behavior;
    
    // Logger call counts
    int logger_init_call_count;
    int logger_exit_call_count;
    int crashupload_log_call_count;
    int logger_error_call_count;
    int logger_info_call_count;
    int logger_warn_call_count;
};

static MainAppMockState g_mainapp_mock_state = {
    0,          // config_init_load returns success
    false,      // no custom behavior
    
    SHARE,      // get_privacy_control_mode returns SHARE
    false,      // no custom behavior
    
    0,          // platform_initialize returns success
    false,      // no custom behavior
    -1,         // filePresentCheck returns file not present by default
    false,      // no custom behavior
    10,         // lock_acquire returns valid fd
    false,      // no custom behavior
    0,          // prerequisites_wait returns success
    false,      // no custom behavior
    false,      // privacy_uploads_blocked returns false
    false,      // no custom behavior
    0,          // cleanup_batch returns success
    0,          // cleanup_batch call count
    1,          // scanner_find_dumps returns 1 dump found
    1,          // output count
    false,      // no custom behavior
    0,          // process_file_entry returns success
    false,      // no custom behavior
    0,          // file_get_mtime_formatted returns success
    "2026-01-07-10-30-45", // default timestamp
    false,      // no custom behavior
    0,          // get_crash_timestamp_utc returns success
    "20260107_103045",     // default UTC timestamp
    false,      // check_process_dmp_file returns false
    false,      // no custom behavior
    nullptr,    // extract_pname returns nullptr by default
    false,      // no custom behavior
    0,          // trim_process_name_in_path returns success
    "",         // empty output
    false,      // no custom behavior
    0,          // archive_create_smart returns success
    false,      // no custom behavior
    false,      // is_box_rebooting returns false
    false,      // no custom behavior
    0,          // ratelimit_check_unified returns allow
    false,      // no custom behavior
    0,          // upload_process returns success
    false,      // no custom behavior
    0,          // logger_init call count
    0,          // logger_exit call count
    0,          // crashupload_log call count
    0,          // logger_error call count
    0,          // logger_info call count
    0           // logger_warn call count
};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for config_init_load mock
 */
void set_mock_config_init_load_behavior(int return_value) {
    g_mainapp_mock_state.config_init_load_return_value = return_value;
    g_mainapp_mock_state.config_init_load_custom_behavior = true;
}

/**
 * Set behavior for get_privacy_control_mode mock
 */
void set_mock_get_privacy_control_mode_behavior(privacy_control_t return_value) {
    g_mainapp_mock_state.get_privacy_control_mode_return_value = return_value;
    g_mainapp_mock_state.get_privacy_control_mode_custom_behavior = true;
}

/**
 * Set behavior for platform_initialize mock
 */
void set_mock_platform_initialize_behavior(int return_value) {
    g_mainapp_mock_state.platform_initialize_return_value = return_value;
    g_mainapp_mock_state.platform_initialize_custom_behavior = true;
}

/**
 * Set behavior for filePresentCheck mock
 */
void set_mock_file_present_check_behavior(int return_value) {
    g_mainapp_mock_state.file_present_check_return_value = return_value;
    g_mainapp_mock_state.file_present_check_custom_behavior = true;
}

/**
 * Set behavior for lock_acquire mock
 */
void set_mock_lock_acquire_behavior(int return_value) {
    g_mainapp_mock_state.lock_acquire_return_value = return_value;
    g_mainapp_mock_state.lock_acquire_custom_behavior = true;
}

/**
 * Set behavior for prerequisites_wait mock
 */
void set_mock_prerequisites_wait_behavior(int return_value) {
    g_mainapp_mock_state.prerequisites_wait_return_value = return_value;
    g_mainapp_mock_state.prerequisites_wait_custom_behavior = true;
}

/**
 * Set behavior for privacy_uploads_blocked mock
 */
void set_mock_privacy_uploads_blocked_behavior(bool return_value) {
    g_mainapp_mock_state.privacy_uploads_blocked_return_value = return_value;
    g_mainapp_mock_state.privacy_uploads_blocked_custom_behavior = true;
}

/**
 * Set behavior for scanner_find_dumps mock
 */
void set_mock_scanner_find_dumps_behavior(int return_value, int output_count) {
    g_mainapp_mock_state.scanner_find_dumps_return_value = return_value;
    g_mainapp_mock_state.scanner_find_dumps_output_count = output_count;
    g_mainapp_mock_state.scanner_find_dumps_custom_behavior = true;
}

/**
 * Set behavior for process_file_entry mock
 */
void set_mock_process_file_entry_behavior(int return_value) {
    g_mainapp_mock_state.process_file_entry_return_value = return_value;
    g_mainapp_mock_state.process_file_entry_custom_behavior = true;
}

/**
 * Set behavior for file_get_mtime_formatted mock
 */
void set_mock_file_get_mtime_formatted_behavior(int return_value, const char* output) {
    g_mainapp_mock_state.file_get_mtime_formatted_return_value = return_value;
    if (output) {
        strncpy(g_mainapp_mock_state.file_get_mtime_formatted_output, output, 
                sizeof(g_mainapp_mock_state.file_get_mtime_formatted_output) - 1);
    }
    g_mainapp_mock_state.file_get_mtime_formatted_custom_behavior = true;
}

/**
 * Set behavior for get_crash_timestamp_utc mock
 */
void set_mock_get_crash_timestamp_utc_behavior(int return_value, const char* output) {
    g_mainapp_mock_state.get_crash_timestamp_utc_return_value = return_value;
    if (output) {
        strncpy(g_mainapp_mock_state.get_crash_timestamp_utc_output, output, 
                sizeof(g_mainapp_mock_state.get_crash_timestamp_utc_output) - 1);
    }
}

/**
 * Set behavior for check_process_dmp_file mock
 */
void set_mock_check_process_dmp_file_behavior(bool return_value) {
    g_mainapp_mock_state.check_process_dmp_file_return_value = return_value;
    g_mainapp_mock_state.check_process_dmp_file_custom_behavior = true;
}

/**
 * Set behavior for extract_pname mock
 */
void set_mock_extract_pname_behavior(const char* return_value) {
    if (g_mainapp_mock_state.extract_pname_return_value) {
        free(g_mainapp_mock_state.extract_pname_return_value);
        g_mainapp_mock_state.extract_pname_return_value = nullptr;
    }
    if (return_value) {
        g_mainapp_mock_state.extract_pname_return_value = strdup(return_value);
    }
    g_mainapp_mock_state.extract_pname_custom_behavior = true;
}

/**
 * Set behavior for trim_process_name_in_path mock
 */
void set_mock_trim_process_name_in_path_behavior(int return_value, const char* output) {
    g_mainapp_mock_state.trim_process_name_in_path_return_value = return_value;
    if (output) {
        strncpy(g_mainapp_mock_state.trim_process_name_in_path_output, output, 
                sizeof(g_mainapp_mock_state.trim_process_name_in_path_output) - 1);
    }
    g_mainapp_mock_state.trim_process_name_in_path_custom_behavior = true;
}

/**
 * Set behavior for archive_create_smart mock
 */
void set_mock_archive_create_smart_behavior(int return_value) {
    g_mainapp_mock_state.archive_create_smart_return_value = return_value;
    g_mainapp_mock_state.archive_create_smart_custom_behavior = true;
}

/**
 * Set behavior for is_box_rebooting mock
 */
void set_mock_is_box_rebooting_behavior(bool return_value) {
    g_mainapp_mock_state.is_box_rebooting_return_value = return_value;
    g_mainapp_mock_state.is_box_rebooting_custom_behavior = true;
}

/**
 * Set behavior for ratelimit_check_unified mock
 */
void set_mock_ratelimit_check_unified_behavior(int return_value) {
    g_mainapp_mock_state.ratelimit_check_unified_return_value = return_value;
    g_mainapp_mock_state.ratelimit_check_unified_custom_behavior = true;
}

/**
 * Set behavior for upload_process mock
 */
void set_mock_upload_process_behavior(int return_value) {
    g_mainapp_mock_state.upload_process_return_value = return_value;
    g_mainapp_mock_state.upload_process_custom_behavior = true;
}

/**
 * Get logger call counts
 */
int get_logger_error_call_count() {
    return g_mainapp_mock_state.logger_error_call_count;
}

int get_logger_info_call_count() {
    return g_mainapp_mock_state.logger_info_call_count;
}

int get_logger_warn_call_count() {
    return g_mainapp_mock_state.logger_warn_call_count;
}

int get_cleanup_batch_call_count() {
    return g_mainapp_mock_state.cleanup_batch_call_count;
}

/**
 * Reset all main app mocks to default state
 */
void reset_mainapp_mocks() {
    g_mainapp_mock_state.config_init_load_return_value = 0;
    g_mainapp_mock_state.config_init_load_custom_behavior = false;
    
    g_mainapp_mock_state.get_privacy_control_mode_return_value = SHARE;
    g_mainapp_mock_state.get_privacy_control_mode_custom_behavior = false;
    
    g_mainapp_mock_state.platform_initialize_return_value = 0;
    g_mainapp_mock_state.platform_initialize_custom_behavior = false;
    
    g_mainapp_mock_state.file_present_check_return_value = -1;
    g_mainapp_mock_state.file_present_check_custom_behavior = false;
    
    g_mainapp_mock_state.lock_acquire_return_value = 10;
    g_mainapp_mock_state.lock_acquire_custom_behavior = false;
    
    g_mainapp_mock_state.prerequisites_wait_return_value = 0;
    g_mainapp_mock_state.prerequisites_wait_custom_behavior = false;
    
    g_mainapp_mock_state.privacy_uploads_blocked_return_value = false;
    g_mainapp_mock_state.privacy_uploads_blocked_custom_behavior = false;
    
    g_mainapp_mock_state.cleanup_batch_return_value = 0;
    g_mainapp_mock_state.cleanup_batch_call_count = 0;
    
    g_mainapp_mock_state.scanner_find_dumps_return_value = 1;
    g_mainapp_mock_state.scanner_find_dumps_output_count = 1;
    g_mainapp_mock_state.scanner_find_dumps_custom_behavior = false;
    
    g_mainapp_mock_state.process_file_entry_return_value = 0;
    g_mainapp_mock_state.process_file_entry_custom_behavior = false;
    
    g_mainapp_mock_state.file_get_mtime_formatted_return_value = 0;
    strcpy(g_mainapp_mock_state.file_get_mtime_formatted_output, "2026-01-07-10-30-45");
    g_mainapp_mock_state.file_get_mtime_formatted_custom_behavior = false;
    
    g_mainapp_mock_state.get_crash_timestamp_utc_return_value = 0;
    strcpy(g_mainapp_mock_state.get_crash_timestamp_utc_output, "20260107_103045");
    
    g_mainapp_mock_state.check_process_dmp_file_return_value = false;
    g_mainapp_mock_state.check_process_dmp_file_custom_behavior = false;
    
    if (g_mainapp_mock_state.extract_pname_return_value) {
        free(g_mainapp_mock_state.extract_pname_return_value);
        g_mainapp_mock_state.extract_pname_return_value = nullptr;
    }
    g_mainapp_mock_state.extract_pname_custom_behavior = false;
    
    g_mainapp_mock_state.trim_process_name_in_path_return_value = 0;
    memset(g_mainapp_mock_state.trim_process_name_in_path_output, 0, 
           sizeof(g_mainapp_mock_state.trim_process_name_in_path_output));
    g_mainapp_mock_state.trim_process_name_in_path_custom_behavior = false;
    
    g_mainapp_mock_state.archive_create_smart_return_value = 0;
    g_mainapp_mock_state.archive_create_smart_custom_behavior = false;
    
    g_mainapp_mock_state.is_box_rebooting_return_value = false;
    g_mainapp_mock_state.is_box_rebooting_custom_behavior = false;
    
    g_mainapp_mock_state.ratelimit_check_unified_return_value = 0;
    g_mainapp_mock_state.ratelimit_check_unified_custom_behavior = false;
    
    g_mainapp_mock_state.upload_process_return_value = 0;
    g_mainapp_mock_state.upload_process_custom_behavior = false;
    
    g_mainapp_mock_state.logger_init_call_count = 0;
    g_mainapp_mock_state.logger_exit_call_count = 0;
    g_mainapp_mock_state.crashupload_log_call_count = 0;
    g_mainapp_mock_state.logger_error_call_count = 0;
    g_mainapp_mock_state.logger_info_call_count = 0;
    g_mainapp_mock_state.logger_warn_call_count = 0;
}

// ============================================================================
// Mock Implementations
// ============================================================================

/**
 * Mock: Configuration initialization and loading
 */
int config_init_load(config_t *config, int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    if (!config) {
        return -1;
    }
    
    
    // Default behavior: initialize config with test values
    memset(config, 0, sizeof(config_t));
    config->device_type = DEVICE_TYPE_MEDIACLIENT;
    config->dump_type = DUMP_TYPE_MINIDUMP;
    strncpy(config->working_dir_path, "/tmp/test_dumps", sizeof(config->working_dir_path) - 1);
    strncpy(config->core_log_file, "/tmp/test_core.log", sizeof(config->core_log_file) - 1);
    strncpy(config->box_type, "TEST_BOX", sizeof(config->box_type) - 1);
    if (g_mainapp_mock_state.config_init_load_custom_behavior) {
        return g_mainapp_mock_state.config_init_load_return_value;
    }
    
    return 0;
}

/**
 * Mock: Get privacy control mode
 */
privacy_control_t get_privacy_control_mode(void) {
    // Default behavior: return SHARE
    if (g_mainapp_mock_state.get_privacy_control_mode_custom_behavior) {
        return g_mainapp_mock_state.get_privacy_control_mode_return_value;
    }
    
    return SHARE;
}

/**
 * Mock: Platform initialization
 */
int platform_initialize(const config_t *config, platform_config_t *platform) {
    if (!config || !platform) {
        return -1;
    }
    
    
    // Default behavior: initialize platform with test values
    memset(platform, 0, sizeof(platform_config_t));
    strncpy(platform->model, "TEST_MODEL", sizeof(platform->model) - 1);
    strncpy(platform->mac_address, "00:11:22:33:44:55", sizeof(platform->mac_address));
    strncpy(platform->platform_sha1, "abc123def456", sizeof(platform->platform_sha1) - 1);
    if (g_mainapp_mock_state.platform_initialize_custom_behavior) {
        return g_mainapp_mock_state.platform_initialize_return_value;
    }
    
    return 0;
}

/**
 * Mock: File presence check
 */
int filePresentCheck(const char *filepath) {
    if (!filepath) {
        return -1;
    }
    
    if (g_mainapp_mock_state.file_present_check_custom_behavior) {
        return g_mainapp_mock_state.file_present_check_return_value;
    }
    
    // Default: file not present
    return -1;
}

/**
 * Mock: Lock acquisition
 */
int lock_acquire(const char *lock_file, int timeout_sec) {
    if (!lock_file || timeout_sec < 0) {
        return -1;
    }
    
    if (g_mainapp_mock_state.lock_acquire_custom_behavior) {
        return g_mainapp_mock_state.lock_acquire_return_value;
    }
    
    // Default: return valid fd
    return 10;
}

/**
 * Mock: Lock release
 */
void lock_release(int fd, const char *file) {
    (void)fd;
    (void)file;
    // No-op for mock
}

/**
 * Mock: Prerequisites wait
 */
int prerequisites_wait(config_t *config, int timeout_sec) {
    if (!config || timeout_sec < 0) {
        return -1;
    }
    
    if (g_mainapp_mock_state.prerequisites_wait_custom_behavior) {
        return g_mainapp_mock_state.prerequisites_wait_return_value;
    }
    
    // Default: prerequisites met
    return 0;
}

/**
 * Mock: Privacy uploads blocked check
 */
bool privacy_uploads_blocked(const config_t *config) {
    if (!config) {
        return true;
    }
    
    if (g_mainapp_mock_state.privacy_uploads_blocked_custom_behavior) {
        return g_mainapp_mock_state.privacy_uploads_blocked_return_value;
    }
    
    // Default: not blocked
    return false;
}

/**
 * Mock: Cleanup batch
 */
int cleanup_batch(const char *working_dir, const char *pattern, 
                  const char *cleanup_base, const char *dump_type, 
                  size_t max_files, bool do_not_share_cleanup) {
    (void)working_dir;
    (void)pattern;
    (void)cleanup_base;
    (void)dump_type;
    (void)max_files;
    (void)do_not_share_cleanup;
    
    g_mainapp_mock_state.cleanup_batch_call_count++;
    return g_mainapp_mock_state.cleanup_batch_return_value;
}

/**
 * Mock: Remove pending dumps
 */
void remove_pending_dumps(const char *working_dir, const char *pattern) {
    (void)working_dir;
    (void)pattern;
    // No-op for mock
}

/**
 * Mock: Scanner find dumps
 */
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count) {
    if (!path || !dumps || !count) {
        return -1;
    }
    
    if (g_mainapp_mock_state.scanner_find_dumps_custom_behavior) {
        if (g_mainapp_mock_state.scanner_find_dumps_return_value > 0) {
            *dumps = (dump_file_t*)malloc(g_mainapp_mock_state.scanner_find_dumps_output_count * sizeof(dump_file_t));
            if (*dumps) {
                memset(*dumps, 0, g_mainapp_mock_state.scanner_find_dumps_output_count * sizeof(dump_file_t));
                for (int i = 0; i < g_mainapp_mock_state.scanner_find_dumps_output_count; i++) {
                    snprintf((*dumps)[i].path, sizeof((*dumps)[i].path), "/tmp/test_dump_%d.dmp", i);
                }
                *count = g_mainapp_mock_state.scanner_find_dumps_output_count;
            }
        } else {
            *count = 0;
        }
        return g_mainapp_mock_state.scanner_find_dumps_return_value;
    }
    
    // Default: return 1 dump
    *dumps = (dump_file_t*)malloc(sizeof(dump_file_t));
    if (*dumps) {
        memset(*dumps, 0, sizeof(dump_file_t));
        strncpy((*dumps)[0].path, "/tmp/test_dump.dmp", sizeof((*dumps)[0].path) - 1);
        *count = 1;
        return 1;
    }
    
    return -1;
}

/**
 * Mock: Process file entry
 */
int process_file_entry(char *fullpath, char *dump_type, const config_t *config) {
    if (!fullpath || !dump_type || !config) {
        return -1;
    }
    
    if (g_mainapp_mock_state.process_file_entry_custom_behavior) {
        return g_mainapp_mock_state.process_file_entry_return_value;
    }
    
    return 0;
}

/**
 * Mock: Get formatted modification time
 */
int file_get_mtime_formatted(const char *path, char *mtime, size_t len) {
    if (!path || !mtime || len == 0) {
        return -1;
    }
    
    if (g_mainapp_mock_state.file_get_mtime_formatted_custom_behavior) {
        if (g_mainapp_mock_state.file_get_mtime_formatted_return_value == 0) {
            strncpy(mtime, g_mainapp_mock_state.file_get_mtime_formatted_output, len - 1);
            mtime[len - 1] = '\0';
        }
        return g_mainapp_mock_state.file_get_mtime_formatted_return_value;
    }
    
    // Default: return test timestamp
    strncpy(mtime, "2026-01-07-10-30-45", len - 1);
    mtime[len - 1] = '\0';
    return 0;
}

/**
 * Mock: Get crash timestamp UTC
 */
int get_crash_timestamp_utc(char *out, size_t outsz) {
    if (!out || outsz == 0) {
        return -1;
    }
    
    strncpy(out, g_mainapp_mock_state.get_crash_timestamp_utc_output, outsz - 1);
    out[outsz - 1] = '\0';
    return g_mainapp_mock_state.get_crash_timestamp_utc_return_value;
}

/**
 * Mock: Check process dump file
 */
bool check_process_dmp_file(const char *file) {
    if (!file) {
        return false;
    }
    
    if (g_mainapp_mock_state.check_process_dmp_file_custom_behavior) {
        return g_mainapp_mock_state.check_process_dmp_file_return_value;
    }
    
    return false;
}

/**
 * Mock: Extract process name
 */
char *extract_pname(const char *filepath) {
    if (!filepath) {
        return nullptr;
    }
    
    if (g_mainapp_mock_state.extract_pname_custom_behavior) {
        if (g_mainapp_mock_state.extract_pname_return_value) {
            return strdup(g_mainapp_mock_state.extract_pname_return_value);
        }
        return nullptr;
    }
    
    return nullptr;
}

/**
 * Mock: Trim process name in path
 */
int trim_process_name_in_path(const char *full_path, const char *process_name, 
                              int max_pname_trim, char *out, size_t out_len) {
    if (!full_path || !process_name || !out || out_len == 0) {
        return -1;
    }
    
    (void)max_pname_trim;
    
    if (g_mainapp_mock_state.trim_process_name_in_path_custom_behavior) {
        if (g_mainapp_mock_state.trim_process_name_in_path_return_value == 0) {
            strncpy(out, g_mainapp_mock_state.trim_process_name_in_path_output, out_len - 1);
            out[out_len - 1] = '\0';
        }
        return g_mainapp_mock_state.trim_process_name_in_path_return_value;
    }
    
    // Default: copy full path
    strncpy(out, full_path, out_len - 1);
    out[out_len - 1] = '\0';
    return 0;
}

/**
 * Mock: Archive create smart
 */
int archive_create_smart(const dump_file_t *dump, const config_t *config,
                         const platform_config_t *platform,
                         archive_info_t *archive, char *new_dump_name) {
    if (!dump || !config || !platform || !archive || !new_dump_name) {
        return -1;
    }
    
    if (g_mainapp_mock_state.archive_create_smart_custom_behavior) {
        if (g_mainapp_mock_state.archive_create_smart_return_value == 0) {
            snprintf(archive->archive_name, sizeof(archive->archive_name), 
                     "/tmp/test_archive.tar.gz");
        }
        return g_mainapp_mock_state.archive_create_smart_return_value;
    }
    
    // Default: create test archive name
    snprintf(archive->archive_name, sizeof(archive->archive_name), 
             "/tmp/test_archive.tar.gz");
    return 0;
}

/**
 * Mock: Check if box is rebooting
 */
bool is_box_rebooting(bool t2_enabled) {
    (void)t2_enabled;
    
    if (g_mainapp_mock_state.is_box_rebooting_custom_behavior) {
        return g_mainapp_mock_state.is_box_rebooting_return_value;
    }
    
    return false;
}

/**
 * Mock: Rate limit check unified
 */
int ratelimit_check_unified(dump_type_t dump) {
    (void)dump;
    
    if (g_mainapp_mock_state.ratelimit_check_unified_custom_behavior) {
        return g_mainapp_mock_state.ratelimit_check_unified_return_value;
    }
    
    // Default: allow upload
    return 0;
}

/**
 * Mock: Upload process
 */
int upload_process(archive_info_t *archive, const config_t *config, 
                   const platform_config_t *platform) {
    if (!archive || !config || !platform) {
        return -1;
    }
    
    if (g_mainapp_mock_state.upload_process_custom_behavior) {
        return g_mainapp_mock_state.upload_process_return_value;
    }
    
    // Default: success
    return 0;
}

/**
 * Mock: Logger init
 */
int logger_init(void) {
    g_mainapp_mock_state.logger_init_call_count++;
    // Default: success
    return 0;
}

/**
 * Mock: Logger exit
 */
void logger_exit(void) {
    g_mainapp_mock_state.logger_exit_call_count++;
}

/**
 * Mock: Crashupload log (fallback logging)
 */
void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)msg;
    g_mainapp_mock_state.crashupload_log_call_count++;
}

/**
 * Mock: Logger error
 */
void logger_error(const char *fmt, ...) {
    (void)fmt;
    g_mainapp_mock_state.logger_error_call_count++;
}

/**
 * Mock: Logger info
 */
void logger_info(const char *fmt, ...) {
    (void)fmt;
    g_mainapp_mock_state.logger_info_call_count++;
}

/**
 * Mock: Logger warn
 */
void logger_warn(const char *fmt, ...) {
    (void)fmt;
    g_mainapp_mock_state.logger_warn_call_count++;
}

} // extern "C"
