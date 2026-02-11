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
 * @file config_manager_mock.cpp
 * @brief Mock implementations for external user-defined functions
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in config_manager.c
 * - User-defined functions (NOT standard C library functions)
 * - Required for testing config_manager functionality
 * 
 * Functions mocked:
 * - getIncludePropertyData() - RDK utility function
 * - getDevicePropertyData() - RDK utility function
 * - filePresentCheck() - RDK utility function
 */

#include <cstring>
#include <cstdio>

#define UTILS_SUCCESS 1
#define UTILS_FAIL -1

// Mock state control structure
struct MockState {
    // getIncludePropertyData mock state
    int include_prop_return_value;
    char include_prop_output[256];
    
    // getDevicePropertyData mock state
    int device_prop_return_value;
    char device_prop_output[256];
    
    // filePresentCheck mock state
    int file_present_return_value;
};

static MockState g_mock_state = {0, "", 0, "", 0};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for getIncludePropertyData mock
 * @param return_value Return value for the mock
 * @param output_value Value to copy to output buffer (can be NULL)
 */
void set_mock_getIncludePropertyData_behavior(int return_value, const char* output_value) {
    g_mock_state.include_prop_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.include_prop_output, output_value, sizeof(g_mock_state.include_prop_output) - 1);
        g_mock_state.include_prop_output[sizeof(g_mock_state.include_prop_output) - 1] = '\0';
    } else {
        g_mock_state.include_prop_output[0] = '\0';
    }
}

/**
 * Set behavior for getDevicePropertyData mock
 * @param return_value Return value for the mock
 * @param output_value Value to copy to output buffer (can be NULL)
 */
void set_mock_getDevicePropertyData_behavior(int return_value, const char* output_value) {
    g_mock_state.device_prop_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.device_prop_output, output_value, sizeof(g_mock_state.device_prop_output) - 1);
        g_mock_state.device_prop_output[sizeof(g_mock_state.device_prop_output) - 1] = '\0';
    } else {
        g_mock_state.device_prop_output[0] = '\0';
    }
}

/**
 * Set behavior for filePresentCheck mock
 * @param return_value Return value for the mock (0 = file exists, non-zero = doesn't exist)
 */
void set_mock_filePresentCheck_behavior(int return_value) {
    g_mock_state.file_present_return_value = return_value;
}

/**
 * Reset all mock states to defaults
 */
void reset_all_mocks() {
    g_mock_state.include_prop_return_value = 0;
    g_mock_state.include_prop_output[0] = '\0';
    g_mock_state.device_prop_return_value = 0;
    g_mock_state.device_prop_output[0] = '\0';
    g_mock_state.file_present_return_value = 0;
}

// ============================================================================
// Mock Function Implementations
// ============================================================================

/**
 * Mock implementation of getIncludePropertyData
 * 
 * This is an RDK utility function that reads properties from include.properties file.
 * The real implementation is provided by RDK libraries.
 * 
 * @param param Property key to look up
 * @param value Buffer to store the property value
 * @param len Buffer length
 * @return 0 (UTILS_SUCCESS) on success, -1 on failure
 */
int getIncludePropertyData(const char* param, char* value, int len) {
    if (!param || !value || len <= 0) {
        return -1;
    }
    
    // Return mocked behavior
    if (g_mock_state.include_prop_return_value == UTILS_SUCCESS) {
        // Success case - copy mocked output
        if (g_mock_state.include_prop_output[0] != '\0') {
            strncpy(value, g_mock_state.include_prop_output, len - 1);
            value[len - 1] = '\0';
        }
    }
    
    return g_mock_state.include_prop_return_value;
}

/**
 * Mock implementation of getDevicePropertyData
 * 
 * This is an RDK utility function that reads device properties from device.properties file.
 * The real implementation is provided by RDK libraries.
 * 
 * @param param Property key to look up
 * @param value Buffer to store the property value
 * @param len Buffer length
 * @return 0 (UTILS_SUCCESS) on success, -1 on failure
 */
int getDevicePropertyData(const char* param, char* value, int len) {
    if (!param || !value || len <= 0) {
        return -1;
    }
    //printf("getDevicePropertyData =%s=\n", g_mock_state.device_prop_output); 
    // Return mocked behavior
    if (g_mock_state.device_prop_return_value == UTILS_SUCCESS) {
        // Success case - copy mocked output
        if (g_mock_state.device_prop_output[0] != '\0') {
            strncpy(value, g_mock_state.device_prop_output, len - 1);
            value[len - 1] = '\0';
            //printf("getDevicePropertyData =>%s<=\n", value); 
        }
    }
    
    return g_mock_state.device_prop_return_value;
}

/**
 * Mock implementation of filePresentCheck
 * 
 * This is an RDK utility function that checks if a file exists.
 * The real implementation is provided by RDK libraries.
 * 
 * @param filename Path to the file to check
 * @return 0 if file exists, non-zero if file doesn't exist or error
 */
int filePresentCheck(const char* filename) {
    if (!filename) {
        return -1;
    }
    
    // Return mocked behavior
    return g_mock_state.file_present_return_value;
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
