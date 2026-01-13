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
 * @file platform_gmock.cpp
 * @brief Mock implementations for external RDK functions used in platform.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in platform.c
 * - RDK utility functions (NOT standard C library functions)
 * - Required for testing platform functionality
 * 
 * Functions mocked:
 * - stripinvalidchar() - RDK utility function to strip invalid chars
 * - getDevicePropertyData() - RDK utility function to get device properties
 * - GetHwMacAddress() - RDK utility function to get hardware MAC address
 * - GetModelNum() - RDK utility function to get model number
 * - file_get_sha1() - File utility function to get SHA1 hash
 */

#include <cstring>
#include <cstdio>

#define UTILS_SUCCESS 1
#define UTILS_FAIL -1

// Mock state control structure
struct MockState {
    // stripinvalidchar
    int stripinvalidchar_return_value;
    
    // getDevicePropertyData
    int getDevicePropertyData_return_value;
    char getDevicePropertyData_output[256];
    
    // GetHwMacAddress
    int GetHwMacAddress_return_value;
    char GetHwMacAddress_output[256];
    
    // GetModelNum
    int GetModelNum_return_value;
    char GetModelNum_output[256];
    
    // file_get_sha1
    int file_get_sha1_return_value;
    char file_get_sha1_output[256];
};

static MockState g_mock_state = {0, 0, "", 0, "", 0, "", 0, ""};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for stripinvalidchar mock
 * @param return_value Return value for the mock (number of valid chars)
 */
void set_mock_stripinvalidchar_behavior(int return_value) {
    g_mock_state.stripinvalidchar_return_value = return_value;
}

/**
 * Set behavior for getDevicePropertyData mock
 * @param return_value Return value for the mock
 * @param output_value Value to copy to output buffer (can be NULL)
 */
void set_mock_getDevicePropertyData_behavior(int return_value, const char* output_value) {
    g_mock_state.getDevicePropertyData_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.getDevicePropertyData_output, output_value, 
                sizeof(g_mock_state.getDevicePropertyData_output) - 1);
        g_mock_state.getDevicePropertyData_output[sizeof(g_mock_state.getDevicePropertyData_output) - 1] = '\0';
    } else {
        g_mock_state.getDevicePropertyData_output[0] = '\0';
    }
}

/**
 * Set behavior for GetHwMacAddress mock
 * @param return_value Return value for the mock (number of chars in MAC)
 * @param output_value MAC address to copy to output buffer (can be NULL)
 */
void set_mock_GetHwMacAddress_behavior(int return_value, const char* output_value) {
    g_mock_state.GetHwMacAddress_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.GetHwMacAddress_output, output_value, 
                sizeof(g_mock_state.GetHwMacAddress_output) - 1);
        g_mock_state.GetHwMacAddress_output[sizeof(g_mock_state.GetHwMacAddress_output) - 1] = '\0';
    } else {
        g_mock_state.GetHwMacAddress_output[0] = '\0';
    }
}

/**
 * Set behavior for GetModelNum mock
 * @param return_value Return value for the mock (number of chars in model)
 * @param output_value Model number to copy to output buffer (can be NULL)
 */
void set_mock_GetModelNum_behavior(int return_value, const char* output_value) {
    g_mock_state.GetModelNum_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.GetModelNum_output, output_value, 
                sizeof(g_mock_state.GetModelNum_output) - 1);
        g_mock_state.GetModelNum_output[sizeof(g_mock_state.GetModelNum_output) - 1] = '\0';
    } else {
        g_mock_state.GetModelNum_output[0] = '\0';
    }
}

/**
 * Set behavior for file_get_sha1 mock
 * @param return_value Return value for the mock (0 success, -1 failure)
 * @param output_value SHA1 hash to copy to output buffer (can be NULL)
 */
void set_mock_file_get_sha1_behavior(int return_value, const char* output_value) {
    g_mock_state.file_get_sha1_return_value = return_value;
    if (output_value) {
        strncpy(g_mock_state.file_get_sha1_output, output_value, 
                sizeof(g_mock_state.file_get_sha1_output) - 1);
        g_mock_state.file_get_sha1_output[sizeof(g_mock_state.file_get_sha1_output) - 1] = '\0';
    } else {
        g_mock_state.file_get_sha1_output[0] = '\0';
    }
}

/**
 * Reset all mock states to default values
 */
void reset_all_platform_mocks() {
    memset(&g_mock_state, 0, sizeof(g_mock_state));
}

// ============================================================================
// Mock Implementations
// ============================================================================

/**
 * Mock implementation of stripinvalidchar
 * 
 * This is an RDK utility function that strips invalid characters from a string.
 * The real implementation is provided by RDK libraries.
 * 
 * @param str String to process (modified in place)
 * @param len Length of the string
 * @return Number of valid characters remaining
 */
size_t stripinvalidchar(char* str, size_t len) {
    if (!str || len == 0) {
        return 0;
    }
    
    // If return value is set, use it; otherwise do simple processing
    if (g_mock_state.stripinvalidchar_return_value > 0) {
        return (size_t)g_mock_state.stripinvalidchar_return_value;
    }
    
    // Default behavior: count valid chars (simulating MAC address validation)
    size_t count = 0;
    for (size_t i = 0; i < len && str[i] != '\0'; i++) {
        char c = str[i];
        if ((c >= '0' && c <= '9') || 
            (c >= 'A' && c <= 'F') || 
            (c >= 'a' && c <= 'f') || 
            c == ':') {
            count++;
        }
    }
    return count;
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
 * @return UTILS_SUCCESS on success, UTILS_FAIL on failure
 */
int getDevicePropertyData(const char* param, char* value, int len) {
    if (!param || !value || len <= 0) {
        return UTILS_FAIL;
    }
    
    // Return mocked behavior
    if (g_mock_state.getDevicePropertyData_return_value == UTILS_SUCCESS) {
        // Success case - copy mocked output
        if (g_mock_state.getDevicePropertyData_output[0] != '\0') {
            strncpy(value, g_mock_state.getDevicePropertyData_output, len - 1);
            value[len - 1] = '\0';
        }
    }
    
    return g_mock_state.getDevicePropertyData_return_value;
}

/**
 * Mock implementation of GetHwMacAddress
 * 
 * This is an RDK utility function that gets hardware MAC address from network interface.
 * The real implementation is provided by RDK libraries.
 * 
 * @param interface Network interface name
 * @param mac Buffer to store MAC address
 * @param len Buffer length
 * @return Number of characters in MAC address (>0 on success, 0 on failure)
 */
size_t GetHwMacAddress(const char* interface, char* mac, size_t len) {
    if (!interface || !mac || len == 0) {
        return 0;
    }
    
    // Return mocked behavior
    if (g_mock_state.GetHwMacAddress_return_value > 0) {
        // Success case - copy mocked MAC address
        if (g_mock_state.GetHwMacAddress_output[0] != '\0') {
            strncpy(mac, g_mock_state.GetHwMacAddress_output, len - 1);
            mac[len - 1] = '\0';
        }
    } else {
        mac[0] = '\0';
    }
    
    return (size_t)g_mock_state.GetHwMacAddress_return_value;
}

/**
 * Mock implementation of GetModelNum
 * 
 * This is an RDK utility function that gets device model number.
 * The real implementation is provided by RDK libraries.
 * 
 * @param model Buffer to store model number
 * @param len Buffer length
 * @return Number of characters in model number (>0 on success, 0 on failure)
 */
size_t GetModelNum(char* model, size_t len) {
    if (!model || len == 0) {
        return 0;
    }
    
    // Return mocked behavior
    if (g_mock_state.GetModelNum_return_value > 0) {
        // Success case - copy mocked model number
        if (g_mock_state.GetModelNum_output[0] != '\0') {
            strncpy(model, g_mock_state.GetModelNum_output, len - 1);
            model[len - 1] = '\0';
        }
    } else {
        model[0] = '\0';
    }
    
    return (size_t)g_mock_state.GetModelNum_return_value;
}

/**
 * Mock implementation of file_get_sha1
 * 
 * This is a file utility function that gets SHA1 hash of a file.
 * The real implementation is in file_utils.c.
 * 
 * @param path File path
 * @param hash Buffer to store SHA1 hash
 * @param len Buffer length
 * @return 0 on success, -1 on failure
 */
int file_get_sha1(const char* path, char* hash, size_t len) {
    if (!path || !hash || len == 0) {
        return -1;
    }
    
    // Return mocked behavior
    if (g_mock_state.file_get_sha1_return_value == 0) {
        // Success case - copy mocked SHA1 hash
        if (g_mock_state.file_get_sha1_output[0] != '\0') {
            strncpy(hash, g_mock_state.file_get_sha1_output, len - 1);
            hash[len - 1] = '\0';
        }
    }
    
    return g_mock_state.file_get_sha1_return_value;
}

} // extern "C"
