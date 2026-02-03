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
 * @file archive_gmock.cpp
 * @brief Mock implementations for external functions used by archive.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in archive.c
 * - User-defined functions (NOT standard C library, POSIX, or libarchive functions)
 * - Required for testing archive functionality
 * 
 * Functions mocked:
 * - is_regular_file() - from file_utils.c
 * - file_get_mtime_formatted() - from file_utils.c
 * - extract_tail() - from file_utils.c
 * - file_get_size() - from file_utils.c
 * - filePresentCheck() - from RDK library
 * 
 * NOT mocked (POSIX/glibc/system/libarchive):
 * - All archive_* functions (libarchive)
 * - stat, statvfs, open, read, close, rename, unlink (POSIX)
 * - setpriority, strchr, strstr, strrchr, snprintf, etc. (glibc)
 */

#include <cstring>
#include <cstdio>
#include <cstdint>

// Mock state control structure
struct ArchiveMockState {
    // is_regular_file mock state
    int is_regular_file_return_value;
    int is_regular_file_call_count;
    
    // file_get_mtime_formatted mock state
    int file_get_mtime_formatted_return_value;
    char file_get_mtime_formatted_output[64];
    int file_get_mtime_formatted_call_count;
    
    // extract_tail mock state
    int extract_tail_return_value;
    int extract_tail_call_count;
    
    // file_get_size mock state
    int file_get_size_return_value;
    uint64_t file_get_size_output;
    int file_get_size_call_count;
    
    // filePresentCheck mock state
    int filePresentCheck_return_value;
    int filePresentCheck_call_count;
};

static ArchiveMockState g_archive_mock_state = {
    1,      // is_regular_file returns 1 (true) by default
    0,      // call count
    0,      // file_get_mtime_formatted returns 0 (success) by default
    "2025-01-05-12-30-45",  // default timestamp
    0,      // call count
    0,      // extract_tail returns 0 (success) by default
    0,      // call count
    0,      // file_get_size returns 0 (success) by default
    1024,   // default file size
    0,      // call count
    1,      // filePresentCheck returns 1 (not present) by default
    0       // call count
};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for is_regular_file mock
 * @param return_value Return value for the mock (1 = regular file, 0 = not)
 */
void set_mock_is_regular_file_behavior(int return_value) {
    g_archive_mock_state.is_regular_file_return_value = return_value;
}

/**
 * Get call count for is_regular_file
 */
int get_mock_is_regular_file_call_count() {
    return g_archive_mock_state.is_regular_file_call_count;
}

/**
 * Set behavior for file_get_mtime_formatted mock
 * @param return_value Return value for the mock (0 = success, -1 = error)
 * @param output_value Value to copy to output buffer (can be NULL)
 */
void set_mock_file_get_mtime_formatted_behavior(int return_value, const char* output_value) {
    g_archive_mock_state.file_get_mtime_formatted_return_value = return_value;
    if (output_value) {
        strncpy(g_archive_mock_state.file_get_mtime_formatted_output, output_value, 
                sizeof(g_archive_mock_state.file_get_mtime_formatted_output) - 1);
        g_archive_mock_state.file_get_mtime_formatted_output[
            sizeof(g_archive_mock_state.file_get_mtime_formatted_output) - 1] = '\0';
    } else {
        g_archive_mock_state.file_get_mtime_formatted_output[0] = '\0';
    }
}

/**
 * Get call count for file_get_mtime_formatted
 */
int get_mock_file_get_mtime_formatted_call_count() {
    return g_archive_mock_state.file_get_mtime_formatted_call_count;
}

/**
 * Set behavior for extract_tail mock
 * @param return_value Return value for the mock (0 = success, -1 = error)
 */
void set_mock_extract_tail_behavior(int return_value) {
    g_archive_mock_state.extract_tail_return_value = return_value;
}

/**
 * Get call count for extract_tail
 */
int get_mock_extract_tail_call_count() {
    return g_archive_mock_state.extract_tail_call_count;
}

/**
 * Set behavior for file_get_size mock
 * @param return_value Return value for the mock (0 = success, -1 = error)
 * @param size_value File size to return
 */
void set_mock_file_get_size_behavior(int return_value, uint64_t size_value) {
    g_archive_mock_state.file_get_size_return_value = return_value;
    g_archive_mock_state.file_get_size_output = size_value;
}

/**
 * Get call count for file_get_size
 */
int get_mock_file_get_size_call_count() {
    return g_archive_mock_state.file_get_size_call_count;
}

/**
 * Set behavior for filePresentCheck mock
 * @param return_value Return value for the mock (0 = file exists, non-zero = doesn't exist)
 */
void set_mock_filePresentCheck_behavior(int return_value) {
    g_archive_mock_state.filePresentCheck_return_value = return_value;
}

/**
 * Get call count for filePresentCheck
 */
int get_mock_filePresentCheck_call_count() {
    return g_archive_mock_state.filePresentCheck_call_count;
}

/**
 * Reset all mock states to defaults
 */
void reset_archive_mocks() {
    g_archive_mock_state.is_regular_file_return_value = 1;
    g_archive_mock_state.is_regular_file_call_count = 0;
    
    g_archive_mock_state.file_get_mtime_formatted_return_value = 0;
    strcpy(g_archive_mock_state.file_get_mtime_formatted_output, "2025-01-05-12-30-45");
    g_archive_mock_state.file_get_mtime_formatted_call_count = 0;
    
    g_archive_mock_state.extract_tail_return_value = 0;
    g_archive_mock_state.extract_tail_call_count = 0;
    
    g_archive_mock_state.file_get_size_return_value = 0;
    g_archive_mock_state.file_get_size_output = 1024;
    g_archive_mock_state.file_get_size_call_count = 0;
    
    g_archive_mock_state.filePresentCheck_return_value = 1;
    g_archive_mock_state.filePresentCheck_call_count = 0;
}

// ============================================================================
// Mock Function Implementations
// ============================================================================

/**
 * Mock implementation of is_regular_file from file_utils.c
 * 
 * Checks if the given path is a regular file.
 * 
 * @param path File path to check
 * @return 1 if regular file, 0 otherwise
 */
int is_regular_file(const char *path) {
    g_archive_mock_state.is_regular_file_call_count++;
    
    if (!path) {
        return 0;
    }
    
    return g_archive_mock_state.is_regular_file_return_value;
}

/**
 * Mock implementation of file_get_mtime_formatted from file_utils.c
 * 
 * Gets the file modification time formatted as YYYY-MM-DD-HH-MM-SS.
 * 
 * @param path File path
 * @param mtime Buffer to store formatted time
 * @param len Buffer length (minimum 20 bytes)
 * @return 0 on success, -1 on error
 */
int file_get_mtime_formatted(const char *path, char *mtime, size_t len) {
    g_archive_mock_state.file_get_mtime_formatted_call_count++;
    
    if (!path || !mtime || len < 20) {
        return -1;
    }
    
    if (g_archive_mock_state.file_get_mtime_formatted_return_value == 0) {
        // Success case - copy mocked output
        strncpy(mtime, g_archive_mock_state.file_get_mtime_formatted_output, len - 1);
        mtime[len - 1] = '\0';
    }
    
    return g_archive_mock_state.file_get_mtime_formatted_return_value;
}

/**
 * Mock implementation of extract_tail from file_utils.c
 * 
 * Extracts the last N lines from source file to destination file.
 * 
 * @param src Source file path
 * @param dst Destination file path
 * @param max_lines Maximum number of lines to extract
 * @return 0 on success, -1 on error
 */
int extract_tail(const char *src, const char *dst, int max_lines) {
    g_archive_mock_state.extract_tail_call_count++;
    
    if (!src || !dst || max_lines <= 0) {
        return -1;
    }
    
    return g_archive_mock_state.extract_tail_return_value;
}

/**
 * Mock implementation of file_get_size from file_utils.c
 * 
 * Gets the file size in bytes.
 * 
 * @param path File path
 * @param size Pointer to store file size
 * @return 0 on success, -1 on error
 */
int file_get_size(const char *path, uint64_t *size) {
    g_archive_mock_state.file_get_size_call_count++;
    
    if (!path || !size) {
        return -1;
    }
    
    if (g_archive_mock_state.file_get_size_return_value == 0) {
        *size = g_archive_mock_state.file_get_size_output;
    }
    
    return g_archive_mock_state.file_get_size_return_value;
}

/**
 * Mock implementation of filePresentCheck from RDK library
 * 
 * Checks if a file exists.
 * 
 * @param filename File path to check
 * @return 0 if file exists, non-zero if doesn't exist
 */
int filePresentCheck(const char *filename) {
    g_archive_mock_state.filePresentCheck_call_count++;
    
    if (!filename) {
        return 1;  // File doesn't exist
    }
    
    return g_archive_mock_state.filePresentCheck_return_value;
}

/**
 * Mock implementation of crashupload_log
 * 
 * This is the logging function used by crashupload components.
 * For unit tests, we provide a minimal mock that discards log messages.
 * 
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param msg Format string and variadic arguments
 */
void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...) {
    // Mock implementation - do nothing
    (void)level;
    (void)file;
    (void)line;
    (void)msg;
}

} // extern "C"
