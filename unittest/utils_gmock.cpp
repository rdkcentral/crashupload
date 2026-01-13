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
 * @file utils_gmock.cpp
 * @brief Mock implementations for external functions used by cleanup_batch.c and file_utils.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in cleanup_batch.c or file_utils.c
 * - User-defined functions (NOT standard C library, POSIX, or libcrypto functions)
 * - Required for testing utility functions
 * 
 * Functions mocked:
 * - stripinvalidchar() - from common_device_api.h
 * - TLSLOG() - macro/function from rdkv_cdl_log_wrapper.h
 * 
 * NOT mocked (POSIX/glibc/system/libcrypto):
 * - All OpenSSL/crypto functions (EVP_*, BIO_*, SHA1_*, etc.)
 * - All POSIX APIs (stat, opendir, readdir, closedir, unlink, fopen, fclose, etc.)
 * - All glibc functions (strlen, strcmp, strdup, snprintf, etc.)
 * - All system calls (clock_gettime, gmtime_r, etc.)
 */

#include <cstring>
#include <cstdio>
#include <cstdarg>

// Mock state control structure
struct UtilsMockState {
    // stripinvalidchar mock state
    int stripinvalidchar_call_count;
    size_t stripinvalidchar_return_value;
    
    // TLSLOG mock state
    int tlslog_call_count;
};

static UtilsMockState g_utils_mock_state = {
    0,      // stripinvalidchar call count
    0,      // default return value (no chars stripped)
    0       // tlslog call count
};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for stripinvalidchar mock
 * @param return_value Number of characters stripped (typically 0 for success)
 */
void set_mock_stripinvalidchar_behavior(size_t return_value) {
    g_utils_mock_state.stripinvalidchar_return_value = return_value;
}

/**
 * Get call count for stripinvalidchar
 */
int get_mock_stripinvalidchar_call_count() {
    return g_utils_mock_state.stripinvalidchar_call_count;
}

/**
 * Get call count for TLSLOG
 */
int get_mock_tlslog_call_count() {
    return g_utils_mock_state.tlslog_call_count;
}

/**
 * Reset all mock states to defaults
 */
void reset_utils_mocks() {
    g_utils_mock_state.stripinvalidchar_call_count = 0;
    g_utils_mock_state.stripinvalidchar_return_value = 0;
    g_utils_mock_state.tlslog_call_count = 0;
}

// ============================================================================
// Mock Function Implementations
// ============================================================================

/**
 * Mock implementation of stripinvalidchar from common_device_api.h
 * 
 * Strips invalid characters from a string (typically newlines and control chars).
 * In the real implementation, this modifies the string in-place.
 * 
 * @param str String to process
 * @param len Length of string
 * @return Number of characters in the processed string
 */
size_t stripinvalidchar(char *str, size_t len) {
    g_utils_mock_state.stripinvalidchar_call_count++;
    
    if (!str || len == 0) {
        return 0;
    }
    
    // Simple mock: strip trailing newlines and whitespace
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r' || 
                       str[len - 1] == ' ' || str[len - 1] == '\t')) {
        str[len - 1] = '\0';
        len--;
    }
    
    return len;
}

/**
 * Mock implementation of TLSLOG macro/function from rdkv_cdl_log_wrapper.h
 * 
 * This is typically a logging macro for TLS-related errors.
 * We provide a simple function implementation for testing.
 * 
 * @param level Log level (e.g., TLS_LOG_ERR)
 * @param format Format string
 * @param ... Variable arguments
 */
void TLSLOG(int level, const char *format, ...) {
    g_utils_mock_state.tlslog_call_count++;
    
    // In test environment, we can optionally log or just track the call
    // For now, we just count the calls
    (void)level;
    (void)format;
}

// Define TLS_LOG_ERR constant if not already defined
#ifndef TLS_LOG_ERR
#define TLS_LOG_ERR 3
#endif

} // extern "C"
