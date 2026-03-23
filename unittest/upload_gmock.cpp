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
 * @file upload_gmock.cpp
 * @brief Mock implementations for external functions used in upload.c
 * 
 * This file provides mock implementations for functions that are:
 * - Declared but not defined in upload.c
 * - External utility functions from other modules
 * - Required for testing upload functionality
 * 
 * Functions mocked:
 * - read_RFCProperty() - RFC property reading
 * - getDevicePropertyData() - Device property reading
 * - urlEncodeString() - URL encoding utility
 * - performMetadataPostWithCertRotationEx() - Metadata POST with certificate rotation
 * - __uploadutil_get_status() - Upload utility status
 * - extractS3PresignedUrl() - S3 presigned URL extraction
 * - performS3PutUpload() - S3 PUT upload
 * - tls_log() - TLS logging
 * - compute_s3_md5_base64() - MD5 computation for S3
 * - GetCrashFirmwareVersion() - Get firmware version
 * - GetPartnerId() - Get partner ID
 * - filePresentCheck() - Check file presence
 * - set_time() - Set timestamp
 * 
 * NOT mocked (POSIX/glibc/system calls):
 * - printf, fprintf, snprintf, sprintf
 * - malloc, free, calloc, strdup
 * - memcpy, memset, strcpy, strncpy, strlen, strcmp, strstr
 * - fopen, fclose, fread, fwrite, unlink
 * - sleep, getpid
 */

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "types.h"

// External type definitions for mocking
typedef struct {
    char cert_path[256];
    char key_path[256];
    int status;
} MtlsAuth_t;
}

// Mock state control structure
struct UploadMockState {
    // RFC property reading
    int read_rfc_property_return_value;
    char read_rfc_property_output[512];
    bool read_rfc_property_custom_behavior;
    
    // Device property reading
    int get_device_property_return_value;
    char get_device_property_output[512];
    bool get_device_property_custom_behavior;
    
    // URL encoding
    char* url_encode_output;
    bool url_encode_custom_behavior;
    bool url_encode_return_null;
    
    // Metadata POST
    int metadata_post_return_value;
    long metadata_post_http_code;
    bool metadata_post_custom_behavior;
    
    // Upload status
    long upload_status_http_code;
    int upload_status_curl_ret;
    
    // S3 URL extraction
    int extract_s3_url_return_value;
    char extract_s3_url_output[1024];
    bool extract_s3_url_custom_behavior;
    
    // S3 PUT upload
    int s3_put_upload_return_value;
    bool s3_put_upload_custom_behavior;
    
    // TLS log
    bool tls_log_return_value;
    int tls_log_call_count;
    
    // MD5 computation
    int compute_md5_return_value;
    char compute_md5_output[128];
    bool compute_md5_custom_behavior;
    
    // Firmware version
    size_t firmware_version_return_value;
    char firmware_version_output[128];
    bool firmware_version_custom_behavior;
    
    // Partner ID
    int partner_id_return_value;
    char partner_id_output[16];
    bool partner_id_custom_behavior;
    
    // File present check
    int file_present_return_value;
    bool file_present_custom_behavior;
    
    // Set time
    int set_time_return_value;
    bool set_time_custom_behavior;
};

static UploadMockState g_upload_mock_state = {
    1,          // read_rfc_property returns success by default
    "",         // empty output
    false,      // no custom behavior
    0,          // get_device_property returns success by default
    "",         // empty output
    false,      // no custom behavior
    nullptr,    // url_encode_output
    false,      // no custom behavior
    false,      // don't return null
    0,          // metadata_post returns success
    200,        // HTTP 200 OK
    false,      // no custom behavior
    200,        // HTTP 200 OK
    0,          // curl success
    0,          // extract_s3_url returns success
    "",         // empty output
    false,      // no custom behavior
    0,          // s3_put_upload returns success
    false,      // no custom behavior
    true,       // tls_log returns true
    0,          // tls_log call count
    0,          // compute_md5 returns success
    "",         // empty output
    false,      // no custom behavior
    0,          // firmware_version returns 0
    "",         // empty output
    false,      // no custom behavior
    1,          // partner_id returns success
    "",         // empty output
    false,      // no custom behavior
    0,          // file_present returns success
    false,      // no custom behavior
    0,          // set_time returns success
    false       // no custom behavior
};

// ============================================================================
// Mock Control Functions (Called from tests)
// ============================================================================

extern "C" {

/**
 * Set behavior for read_RFCProperty mock
 */
void set_mock_read_rfc_property_behavior(int return_value, const char* output) {
    g_upload_mock_state.read_rfc_property_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.read_rfc_property_output, output, 
                sizeof(g_upload_mock_state.read_rfc_property_output) - 1);
    }
    g_upload_mock_state.read_rfc_property_custom_behavior = true;
}

/**
 * Set behavior for getDevicePropertyData mock
 */
void set_mock_get_device_property_behavior(int return_value, const char* output) {
    g_upload_mock_state.get_device_property_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.get_device_property_output, output, 
                sizeof(g_upload_mock_state.get_device_property_output) - 1);
    }
    g_upload_mock_state.get_device_property_custom_behavior = true;
}

/**
 * Set behavior for urlEncodeString mock
 */
void set_mock_url_encode_behavior(const char* output, bool return_null) {
    if (g_upload_mock_state.url_encode_output) {
        free(g_upload_mock_state.url_encode_output);
        g_upload_mock_state.url_encode_output = nullptr;
    }
    
    if (output && !return_null) {
        g_upload_mock_state.url_encode_output = strdup(output);
    }
    g_upload_mock_state.url_encode_return_null = return_null;
    g_upload_mock_state.url_encode_custom_behavior = true;
}

/**
 * Set behavior for performMetadataPostWithCertRotationEx mock
 */
void set_mock_metadata_post_behavior(int return_value, long http_code) {
    g_upload_mock_state.metadata_post_return_value = return_value;
    g_upload_mock_state.metadata_post_http_code = http_code;
    g_upload_mock_state.metadata_post_custom_behavior = true;
}

/**
 * Set behavior for upload status
 */
void set_mock_upload_status(long http_code, int curl_ret) {
    g_upload_mock_state.upload_status_http_code = http_code;
    g_upload_mock_state.upload_status_curl_ret = curl_ret;
}

/**
 * Set behavior for extractS3PresignedUrl mock
 */
void set_mock_extract_s3_url_behavior(int return_value, const char* output) {
    g_upload_mock_state.extract_s3_url_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.extract_s3_url_output, output, 
                sizeof(g_upload_mock_state.extract_s3_url_output) - 1);
    }
    g_upload_mock_state.extract_s3_url_custom_behavior = true;
}

/**
 * Set behavior for performS3PutUpload mock
 */
void set_mock_s3_put_upload_behavior(int return_value) {
    g_upload_mock_state.s3_put_upload_return_value = return_value;
    g_upload_mock_state.s3_put_upload_custom_behavior = true;
}

/**
 * Set behavior for compute_s3_md5_base64 mock
 */
void set_mock_compute_md5_behavior(int return_value, const char* output) {
    g_upload_mock_state.compute_md5_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.compute_md5_output, output, 
                sizeof(g_upload_mock_state.compute_md5_output) - 1);
    }
    g_upload_mock_state.compute_md5_custom_behavior = true;
}

/**
 * Set behavior for GetCrashFirmwareVersion mock
 */
void set_mock_firmware_version_behavior(size_t return_value, const char* output) {
    g_upload_mock_state.firmware_version_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.firmware_version_output, output, 
                sizeof(g_upload_mock_state.firmware_version_output) - 1);
    }
    g_upload_mock_state.firmware_version_custom_behavior = true;
}

/**
 * Set behavior for GetPartnerId mock
 */
void set_mock_partner_id_behavior(int return_value, const char* output) {
    g_upload_mock_state.partner_id_return_value = return_value;
    if (output) {
        strncpy(g_upload_mock_state.partner_id_output, output, 
                sizeof(g_upload_mock_state.partner_id_output) - 1);
    }
    g_upload_mock_state.partner_id_custom_behavior = true;
}

/**
 * Set behavior for filePresentCheck mock
 */
void set_mock_file_present_behavior(int return_value) {
    g_upload_mock_state.file_present_return_value = return_value;
    g_upload_mock_state.file_present_custom_behavior = true;
}

/**
 * Set behavior for set_time mock
 */
void set_mock_set_time_behavior(int return_value) {
    g_upload_mock_state.set_time_return_value = return_value;
    g_upload_mock_state.set_time_custom_behavior = true;
}

/**
 * Get TLS log call count
 */
int get_tls_log_call_count() {
    return g_upload_mock_state.tls_log_call_count;
}

/**
 * Reset all upload mocks to default state
 */
void reset_upload_mocks() {
    g_upload_mock_state.read_rfc_property_return_value = 1;
    memset(g_upload_mock_state.read_rfc_property_output, 0, 
           sizeof(g_upload_mock_state.read_rfc_property_output));
    g_upload_mock_state.read_rfc_property_custom_behavior = false;
    
    g_upload_mock_state.get_device_property_return_value = 0;
    memset(g_upload_mock_state.get_device_property_output, 0, 
           sizeof(g_upload_mock_state.get_device_property_output));
    g_upload_mock_state.get_device_property_custom_behavior = false;
    
    if (g_upload_mock_state.url_encode_output) {
        free(g_upload_mock_state.url_encode_output);
        g_upload_mock_state.url_encode_output = nullptr;
    }
    g_upload_mock_state.url_encode_custom_behavior = false;
    g_upload_mock_state.url_encode_return_null = false;
    
    g_upload_mock_state.metadata_post_return_value = 0;
    g_upload_mock_state.metadata_post_http_code = 200;
    g_upload_mock_state.metadata_post_custom_behavior = false;
    
    g_upload_mock_state.upload_status_http_code = 200;
    g_upload_mock_state.upload_status_curl_ret = 0;
    
    g_upload_mock_state.extract_s3_url_return_value = 0;
    memset(g_upload_mock_state.extract_s3_url_output, 0, 
           sizeof(g_upload_mock_state.extract_s3_url_output));
    g_upload_mock_state.extract_s3_url_custom_behavior = false;
    
    g_upload_mock_state.s3_put_upload_return_value = 0;
    g_upload_mock_state.s3_put_upload_custom_behavior = false;
    
    g_upload_mock_state.tls_log_return_value = true;
    g_upload_mock_state.tls_log_call_count = 0;
    
    g_upload_mock_state.compute_md5_return_value = 0;
    memset(g_upload_mock_state.compute_md5_output, 0, 
           sizeof(g_upload_mock_state.compute_md5_output));
    g_upload_mock_state.compute_md5_custom_behavior = false;
    
    g_upload_mock_state.firmware_version_return_value = 0;
    memset(g_upload_mock_state.firmware_version_output, 0, 
           sizeof(g_upload_mock_state.firmware_version_output));
    g_upload_mock_state.firmware_version_custom_behavior = false;
    
    g_upload_mock_state.partner_id_return_value = 1;
    memset(g_upload_mock_state.partner_id_output, 0, 
           sizeof(g_upload_mock_state.partner_id_output));
    g_upload_mock_state.partner_id_custom_behavior = false;
    
    g_upload_mock_state.file_present_return_value = 0;
    g_upload_mock_state.file_present_custom_behavior = false;
    
    g_upload_mock_state.set_time_return_value = 0;
    g_upload_mock_state.set_time_custom_behavior = false;
}

// ============================================================================
// Mock Implementations
// ============================================================================

/**
 * Mock: Read RFC property
 */
int read_RFCProperty(const char* type, const char* key, char *data, size_t datasize) {
    if (!key || !data || !type || datasize == 0) {
        return -1;
    }
    
    if (g_upload_mock_state.read_rfc_property_custom_behavior) {
        if (g_upload_mock_state.read_rfc_property_output[0] != '\0') {
            strncpy(data, g_upload_mock_state.read_rfc_property_output, datasize - 1);
            data[datasize - 1] = '\0';
        } else {
            data[0] = '\0';
        }
        return g_upload_mock_state.read_rfc_property_return_value;
    }
    
    // Default behavior: return failure with empty string
    data[0] = '\0';
    return -1;
}

/**
 * Mock: Get device property data
 */
int getDevicePropertyData(const char* key, char *data, unsigned int  datasize) {
    if (!key || !data || datasize == 0) {
        return -1;
    }
    
    if (g_upload_mock_state.get_device_property_custom_behavior) {
        if (g_upload_mock_state.get_device_property_output[0] != '\0') {
            strncpy(data, g_upload_mock_state.get_device_property_output, datasize - 1);
            data[datasize - 1] = '\0';
        } else {
            data[0] = '\0';
        }
        return g_upload_mock_state.get_device_property_return_value;
    }
    
    // Default behavior: return success with test URL
    strncpy(data, "https://test.example.com/upload", datasize - 1);
    data[datasize - 1] = '\0';
    return 0;
}

/**
 * Mock: URL encode string
 */
char* urlEncodeString(const char* str) {
    if (!str) {
        return nullptr;
    }
    
    if (g_upload_mock_state.url_encode_custom_behavior) {
        if (g_upload_mock_state.url_encode_return_null) {
            return nullptr;
        }
        if (g_upload_mock_state.url_encode_output) {
            return strdup(g_upload_mock_state.url_encode_output);
        }
    }
    
    // Default behavior: return copy of input string
    return strdup(str);
}

/**
 * Mock: Perform metadata POST with certificate rotation
 */
int performMetadataPostWithCertRotationEx(const char* url, const char* filepath, 
                                          const char* postdata, MtlsAuth_t* sec_out, 
                                          long* http_code) {
    if (!url || !filepath || !postdata || !http_code) {
        return -1;
    }
    if (sec_out) {
        printf("MTLS is enabled\n");
    } 
    if (g_upload_mock_state.metadata_post_custom_behavior) {
        *http_code = g_upload_mock_state.metadata_post_http_code;
        return g_upload_mock_state.metadata_post_return_value;
    }
    
    // Default behavior: return success with HTTP 200
    *http_code = 200;
    return 0;
}

/**
 * Mock: Get upload status
 */
void __uploadutil_get_status(long* http_code, int* curl_ret) {
    if (http_code) {
        *http_code = g_upload_mock_state.upload_status_http_code;
    }
    if (curl_ret) {
        *curl_ret = g_upload_mock_state.upload_status_curl_ret;
    }
}

/**
 * Mock: Extract S3 presigned URL
 */
int extractS3PresignedUrl(const char* url_file, char* out_url, size_t size) {
    if (!url_file || !out_url || size == 0) {
        return -1;
    }
    
    if (g_upload_mock_state.extract_s3_url_custom_behavior) {
        if (g_upload_mock_state.extract_s3_url_output[0] != '\0') {
            strncpy(out_url, g_upload_mock_state.extract_s3_url_output, size - 1);
            out_url[size - 1] = '\0';
        } else {
            out_url[0] = '\0';
        }
        return g_upload_mock_state.extract_s3_url_return_value;
    }
    
    // Default behavior: return test S3 URL
    strncpy(out_url, "https://s3.amazonaws.com/test-bucket/upload", size - 1);
    out_url[size - 1] = '\0';
    return 0;
}

/**
 * Mock: Perform S3 PUT upload
 */
int performS3PutUpload(const char* url, const char* filepath, MtlsAuth_t* sec_out) {
    if (!url || !filepath) {
        return -1;
    }
    
    if (sec_out) {
        printf("MTLS is enabled\n");
    } 
    if (g_upload_mock_state.s3_put_upload_custom_behavior) {
        return g_upload_mock_state.s3_put_upload_return_value;
    }
    
    // Default behavior: return success
    return 0;
}

/**
 * Mock: TLS log
 */
bool tls_log(int curl_code, const char* device_type, const char* fqdn) {
    g_upload_mock_state.tls_log_call_count++;
    if (!device_type || !fqdn || curl_code) {
        return g_upload_mock_state.tls_log_return_value;
    }
    return g_upload_mock_state.tls_log_return_value;
}

/**
 * Mock: Compute S3 MD5 base64
 */
int compute_s3_md5_base64(const char* filepath, char* out_b64_md5, size_t out_len) {
    if (!filepath || !out_b64_md5 || out_len == 0) {
        return -1;
    }
    
    if (g_upload_mock_state.compute_md5_custom_behavior) {
        if (g_upload_mock_state.compute_md5_output[0] != '\0') {
            strncpy(out_b64_md5, g_upload_mock_state.compute_md5_output, out_len - 1);
            out_b64_md5[out_len - 1] = '\0';
        } else {
            out_b64_md5[0] = '\0';
        }
        return g_upload_mock_state.compute_md5_return_value;
    }
    
    // Default behavior: return test MD5
    strncpy(out_b64_md5, "abc123def456", out_len - 1);
    out_b64_md5[out_len - 1] = '\0';
    return 0;
}

/**
 * Mock: Get crash firmware version
 */
size_t GetCrashFirmwareVersion(const char* versionFile, char* pFWVersion, size_t szBufSize) {
    if (!versionFile || !pFWVersion || szBufSize == 0) {
        return 0;
    }
    
    if (g_upload_mock_state.firmware_version_custom_behavior) {
        if (g_upload_mock_state.firmware_version_output[0] != '\0') {
            strncpy(pFWVersion, g_upload_mock_state.firmware_version_output, szBufSize - 1);
            pFWVersion[szBufSize - 1] = '\0';
            return g_upload_mock_state.firmware_version_return_value;
        }
    }
    
    // Default behavior: return test version
    strncpy(pFWVersion, "TEST_VERSION_1.0.0", szBufSize - 1);
    pFWVersion[szBufSize - 1] = '\0';
    return strlen(pFWVersion);
}

/**
 * Mock: Get partner ID
 */
size_t GetPartnerId(char* pPartnerId, size_t szBufSize) {
    if (!pPartnerId || szBufSize == 0) {
        return 0;
    }
    
    if (g_upload_mock_state.partner_id_custom_behavior) {
        if (g_upload_mock_state.partner_id_output[0] != '\0') {
            strncpy(pPartnerId, g_upload_mock_state.partner_id_output, szBufSize - 1);
            pPartnerId[szBufSize - 1] = '\0';
            return g_upload_mock_state.partner_id_return_value;
        }
        return g_upload_mock_state.partner_id_return_value;
    }
    
    // Default behavior: return "comcast"
    strncpy(pPartnerId, "comcast", szBufSize - 1);
    pPartnerId[szBufSize - 1] = '\0';
    return 1;
}

/**
 * Mock: File present check
 */
int filePresentCheck(const char* filepath) {
    if (!filepath) {
        return -1;
    }
    
    if (g_upload_mock_state.file_present_custom_behavior) {
        return g_upload_mock_state.file_present_return_value;
    }
    
    // Default behavior: return file not present
    return -1;
}

/**
 * Mock: Set time
 */
int set_time(const char* deny_file, int type) {
    if (!deny_file || type < 0) {
        return -1;
    }
    
    if (g_upload_mock_state.set_time_custom_behavior) {
        return g_upload_mock_state.set_time_return_value;
    }
    
    // Default behavior: return success
    return 0;
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
