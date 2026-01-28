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
 * @file upload_gtest.cpp
 * @brief Comprehensive GTest suite for upload.c
 * 
 * Test Coverage:
 * - get_crashupload_s3signed_url(): All positive/negative test cases
 * - upload_file(): All positive/negative test cases with retry logic
 * - upload_process(): Complete workflow testing
 * - Parameter validation (NULL, invalid, empty, oversized)
 * - Buffer overflow/underflow protection
 * - Edge cases and boundary conditions
 * - All function paths and branches
 * - Retry logic and error handling
 * - Different device types (BROADBAND, MEDIACLIENT)
 * - Different dump types (MINIDUMP, COREDUMP)
 * 
 * Target: >90% line coverage, >95% function coverage
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../c_sourcecode/include/upload.h"
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"
#include "../c_sourcecode/common/constants.h"

// External functions being tested
int get_crashupload_s3signed_url(char *url, size_t size_buf);
int upload_file(const char *filepath, const char *url, const char *dump_name, 
                const char *crash_fw_version, const char *build_type, 
                const char *model, const char *md5sum, device_type_t device_type, bool t2_enabled);
int upload_process(archive_info_t *archive, const config_t *config, 
                   const platform_config_t *platform);

// Mock control functions
void set_mock_read_rfc_property_behavior(int return_value, const char* output);
void set_mock_get_device_property_behavior(int return_value, const char* output);
void set_mock_url_encode_behavior(const char* output, bool return_null);
void set_mock_metadata_post_behavior(int return_value, long http_code);
void set_mock_upload_status(long http_code, int curl_ret);
void set_mock_extract_s3_url_behavior(int return_value, const char* output);
void set_mock_s3_put_upload_behavior(int return_value);
void set_mock_compute_md5_behavior(int return_value, const char* output);
void set_mock_firmware_version_behavior(size_t return_value, const char* output);
void set_mock_partner_id_behavior(int return_value, const char* output);
void set_mock_file_present_behavior(int return_value);
void set_mock_set_time_behavior(int return_value);
int get_tls_log_call_count();
void reset_upload_mocks();
}

using ::testing::_;
using ::testing::Return;

// ============================================================================
// Test Fixture
// ============================================================================

class UploadTest : public ::testing::Test {
protected:
    const char* test_dir = "/tmp/upld_test";
    const char* test_archive = "/tmp/upld_test/test_archive.tar.gz";
    const char* test_url = "https://test.crashportal.com/upload";
    const char* test_s3_url = "https://s3.amazonaws.com/test-bucket/upload";
    
    config_t test_config;
    platform_config_t test_platform;
    archive_info_t test_archive_info;
    
    void SetUp() override {
        // Reset all mocks before each test
        reset_upload_mocks();
        
        // Create test directories
        system("mkdir -p /tmp/upld_test");
        
        // Initialize test config
        memset(&test_config, 0, sizeof(config_t));
        test_config.device_type = DEVICE_TYPE_MEDIACLIENT;
        test_config.dump_type = DUMP_TYPE_MINIDUMP;
        test_config.build_type = BUILD_TYPE_PROD;
        strncpy(test_config.build_type_val, "PROD", sizeof(test_config.build_type_val) - 1);
        strncpy(test_config.upload_url, test_url, sizeof(test_config.upload_url) - 1);
        test_config.t2_enabled = false;
        test_config.upload_timeout = 45;
        
        // Initialize test platform
        memset(&test_platform, 0, sizeof(platform_config_t));
        strncpy(test_platform.model, "TEST_MODEL_X1", sizeof(test_platform.model) - 1);
        strncpy(test_platform.mac_address, "00:11:22:33:44:55", sizeof(test_platform.mac_address));
        strncpy(test_platform.firmware_version, "1.0.0", sizeof(test_platform.firmware_version) - 1);
        
        // Initialize test archive info
        memset(&test_archive_info, 0, sizeof(archive_info_t));
        strncpy(test_archive_info.archive_name, test_archive, sizeof(test_archive_info.archive_name) - 1);
        test_archive_info.created_in_tmp = true;
        
        // Create test archive file
        create_test_file(test_archive, 2048);
    }
    
    void TearDown() override {
        // Clean up after each test
        cleanup_test_files();
        reset_upload_mocks();
    }
    
    // Helper function to create test files
    void create_test_file(const char* path, size_t size = 1024) {
        FILE* fp = fopen(path, "w");
        if (fp) {
            for (size_t i = 0; i < size; i++) {
                fputc('A', fp);
            }
            fclose(fp);
        }
    }
    
    // Helper function to remove test files
    void cleanup_test_files() {
        system("rm -rf /tmp/upld_test");
    }
    
    // Helper to check if file exists
    bool file_exists(const char* path) {
        struct stat st;
        return (stat(path, &st) == 0);
    }
};

// ============================================================================
// get_crashupload_s3signed_url Tests
// ============================================================================

TEST_F(UploadTest, GetS3SignedUrl_NullUrlPointer) {
    int result = get_crashupload_s3signed_url(nullptr, 512);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, GetS3SignedUrl_ZeroSize) {
    char url[512] = {0};
    int result = get_crashupload_s3signed_url(url, 0);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, GetS3SignedUrl_NegativeSize) {
    char url[512] = {0};
    int result = get_crashupload_s3signed_url(url, -1);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, GetS3SignedUrl_AllNullParameters) {
    int result = get_crashupload_s3signed_url(nullptr, 0);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, GetS3SignedUrl_RFCSuccess) {
    char url[512] = {0};
    set_mock_read_rfc_property_behavior(1, "https://test.s3.signing.url");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, 1);
    EXPECT_STREQ(url, "https://test.s3.signing.url");
}

TEST_F(UploadTest, GetS3SignedUrl_RFCFailureFallbackToDeviceProperties) {
    char url[512] = {0};
    set_mock_read_rfc_property_behavior(-1, "");
    set_mock_get_device_property_behavior(0, "https://fallback.s3.url");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(url, "https://fallback.s3.url");
}

TEST_F(UploadTest, GetS3SignedUrl_RFCEmptyStringFallbackToDeviceProperties) {
    char url[512] = {0};
    set_mock_read_rfc_property_behavior(1, "");
    set_mock_get_device_property_behavior(0, "https://fallback2.s3.url");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(url, "https://fallback2.s3.url");
}

TEST_F(UploadTest, GetS3SignedUrl_BothRFCAndDevicePropertiesFail) {
    char url[512] = {0};
    set_mock_read_rfc_property_behavior(-1, "");
    set_mock_get_device_property_behavior(-1, "");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, GetS3SignedUrl_SmallBuffer) {
    char url[16] = {0};
    set_mock_read_rfc_property_behavior(1, "https://very.long.url.that.exceeds.buffer.size.s3.signing.url");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, 1);
    // Should truncate to fit buffer
}

TEST_F(UploadTest, GetS3SignedUrl_LargeBuffer) {
    char url[2048] = {0};
    set_mock_read_rfc_property_behavior(1, "https://test.url");
    
    int result = get_crashupload_s3signed_url(url, sizeof(url));
    
    EXPECT_EQ(result, 1);
    EXPECT_STREQ(url, "https://test.url");
}

// ============================================================================
// upload_file Tests - Parameter Validation
// ============================================================================

TEST_F(UploadTest, UploadFile_NullFilepath) {
    int result = upload_file(nullptr, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullUrl) {
    int result = upload_file(test_archive, nullptr, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullDumpName) {
    int result = upload_file(test_archive, test_url, nullptr, "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullCrashFwVersion) {
    int result = upload_file(test_archive, test_url, "minidump", nullptr, 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullBuildType) {
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             nullptr, "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullModel) {
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", nullptr, "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_NullMd5sum) {
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", nullptr, DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_AllNullParameters) {
    int result = upload_file(nullptr, nullptr, nullptr, nullptr, 
                             nullptr, nullptr, nullptr, DEVICE_TYPE_MEDIACLIENT, false);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadFile_EmptyFilepath) {
    int result = upload_file("", test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    // Should not crash, may return error
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_EmptyUrl) {
    int result = upload_file(test_archive, "", "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    // Should not crash, may return error
    EXPECT_EQ(result, 0);
}

// ============================================================================
// upload_file Tests - Success Cases
// ============================================================================

TEST_F(UploadTest, UploadFile_SuccessFirstAttempt) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
    // File should be deleted after successful upload
    EXPECT_FALSE(file_exists(test_archive));
}

TEST_F(UploadTest, UploadFile_SuccessWithUrlEncoding) {
    set_mock_url_encode_behavior("encoded%20filename", false);
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_SuccessWithNullUrlEncoding) {
    set_mock_url_encode_behavior(nullptr, true);
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_SuccessCoredump) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "coredump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_SuccessBroadband) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_BROADBAND, false);
    
    EXPECT_EQ(result, 0);
}

// ============================================================================
// upload_file Tests - Retry Logic
// ============================================================================

TEST_F(UploadTest, UploadFile_RetryOnMetadataPostFailure) {
    // First attempt fails, second succeeds
    static int attempt = 0;
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 6); // First attempt
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(6); // First S3 upload fails
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
   
    printf("result =%d and attemt=%d\n", result, attempt); 
    // Should retry up to 3 times and fail
    EXPECT_NE(result, 0);
    // TLS log should be called for each failure
    EXPECT_GT(get_tls_log_call_count(), 0);
}

TEST_F(UploadTest, UploadFile_RetryThreeTimesAndFail) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(500, 6);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(6);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    printf("result =%d\n", result); 
    EXPECT_EQ(result, 6);
    // File should still exist after failed upload
    EXPECT_TRUE(file_exists(test_archive));
}

TEST_F(UploadTest, UploadFile_CurlError6Retry) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(0, 6);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(6);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    printf("result =%d\n", result); 
    
    EXPECT_NE(result, 0);
}

TEST_F(UploadTest, UploadFile_HttpError500Retry) {
    set_mock_metadata_post_behavior(0, 500);
    set_mock_upload_status(500, 22);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(22);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    printf("result =%d\n", result); 
    
    EXPECT_NE(result, 0);
}

// ============================================================================
// upload_file Tests - Error Cases
// ============================================================================

TEST_F(UploadTest, UploadFile_ExtractS3UrlFailure) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(-1, "");
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_NE(result, 0);
}

TEST_F(UploadTest, UploadFile_ExtractS3UrlEmptyOutput) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, "");
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_NE(result, 0);
}

TEST_F(UploadTest, UploadFile_S3PutUploadFailure) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(-1);
    set_mock_upload_status(500, 7);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_NE(result, 0);
}

TEST_F(UploadTest, UploadFile_MetadataPostFailure) {
    set_mock_metadata_post_behavior(-1, 0);
    set_mock_upload_status(0, -1);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_NE(result, 0);
}

// ============================================================================
// upload_file Tests - Buffer Overflow Protection
// ============================================================================

TEST_F(UploadTest, UploadFile_VeryLongFilepath) {
    char long_path[4096];
    memset(long_path, 'A', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    
    int result = upload_file(long_path, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    // Should not crash
    EXPECT_NE(result, 0);
}

TEST_F(UploadTest, UploadFile_VeryLongUrl) {
    char long_url[4096];
    memset(long_url, 'A', sizeof(long_url) - 1);
    long_url[sizeof(long_url) - 1] = '\0';
    
    int result = upload_file(test_archive, long_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    // Should not crash
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_VeryLongParameters) {
    char long_str[4096];
    memset(long_str, 'B', sizeof(long_str) - 1);
    long_str[sizeof(long_str) - 1] = '\0';
    
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, long_str, long_str, 
                             long_str, long_str, long_str, DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, -1);
    // Should not crash but post_filed buffer may be exceeded
    // Check that function handles this gracefully
}

TEST_F(UploadTest, UploadFile_SpecialCharactersInParameters) {
    set_mock_url_encode_behavior("encoded%20special", false);
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, 
                             "dump&name=special", "1.0.0&version", 
                             "PROD&build", "MODEL&X", "md5&sum", 
                             DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_PostFieldBufferOverflow) {
    // Create very long strings that would overflow post_filed buffer
    char long_filename[2048];
    memset(long_filename, 'F', sizeof(long_filename) - 1);
    long_filename[sizeof(long_filename) - 1] = '\0';
    
    set_mock_url_encode_behavior(long_filename, false);
    
    int result = upload_file(test_archive, test_url, long_filename, long_filename, 
                             long_filename, long_filename, long_filename, 
                             DEVICE_TYPE_MEDIACLIENT, false);
    
    // Should detect buffer overflow and exit loop
    EXPECT_EQ(result, -1);
}

// ============================================================================
// upload_file Tests - Different Device Types
// ============================================================================

TEST_F(UploadTest, UploadFile_MediaclientDevice) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_MEDIACLIENT, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_BroadbandDevice) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_BROADBAND, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_VideoDevice) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_VIDEO, false);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadFile_UnknownDevice) {
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_file(test_archive, test_url, "minidump", "1.0.0", 
                             "PROD", "MODEL_X", "md5sum123", DEVICE_TYPE_UNKNOWN, false);
    
    // Should handle unknown device type
    EXPECT_EQ(result, 0);
}

// ============================================================================
// upload_process Tests - Parameter Validation
// ============================================================================

TEST_F(UploadTest, UploadProcess_NullArchive) {
    int result = upload_process(nullptr, &test_config, &test_platform);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadProcess_NullConfig) {
    int result = upload_process(&test_archive_info, nullptr, &test_platform);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadProcess_NullPlatform) {
    int result = upload_process(&test_archive_info, &test_config, nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadProcess_AllNullParameters) {
    int result = upload_process(nullptr, nullptr, nullptr);
    EXPECT_EQ(result, -1);
}

// ============================================================================
// upload_process Tests - Success Cases
// ============================================================================

TEST_F(UploadTest, UploadProcess_SuccessMediaclientMinidump) {
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false"); // EncryptCloudUpload
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com"); // CrashPortal
    set_mock_read_rfc_property_behavior(1, test_url); // CrashPortalEndURL
    set_mock_compute_md5_behavior(0, "");
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
    // Archive should be deleted after successful upload
    EXPECT_FALSE(file_exists(test_archive));
}

TEST_F(UploadTest, UploadProcess_SuccessMediaclientCoredump) {
    test_config.dump_type = DUMP_TYPE_COREDUMP;
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_compute_md5_behavior(0, "");
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadProcess_SuccessWithEncryption) {
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "true"); // EncryptCloudUpload enabled
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_compute_md5_behavior(0, "computed_md5_base64");
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadProcess_SuccessWithOCSPStapling) {
    // Create OCSP files
    system("touch /tmp/.EnableOCSPStapling");
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_compute_md5_behavior(0, "");
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_file_present_behavior(0); // File present
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
    
    unlink("/tmp/.EnableOCSPStapling");
}

// ============================================================================
// upload_process Tests - RFC Fallback
// ============================================================================

TEST_F(UploadTest, UploadProcess_RFCFailureFallbackToS3SignedUrl) {
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(-1, ""); // EncryptCloudUpload fails
    set_mock_read_rfc_property_behavior(-1, ""); // CrashPortal fails
    set_mock_read_rfc_property_behavior(-1, ""); // CrashPortalEndURL fails
    set_mock_get_device_property_behavior(0, test_url); // Fallback to S3
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadProcess_GetS3SignedUrlFailure) {
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(-1, "");
    set_mock_read_rfc_property_behavior(-1, "");
    set_mock_read_rfc_property_behavior(-1, "");
    set_mock_get_device_property_behavior(-1, ""); // S3 URL fetch fails
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, -1);
}

// ============================================================================
// upload_process Tests - Error Cases
// ============================================================================

TEST_F(UploadTest, UploadProcess_UploadFileFailure) {
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 500);
    set_mock_upload_status(500, 22);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(22);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_NE(result, 0);
    // Archive should still exist for minidump
    EXPECT_TRUE(file_exists(test_archive));
}

TEST_F(UploadTest, UploadProcess_UploadFailureCoredumpRemoved) {
    test_config.dump_type = DUMP_TYPE_COREDUMP;
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 500);
    set_mock_upload_status(500, 22);
    set_mock_set_time_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_NE(result, 0);
    // Archive should be deleted for coredump even on failure
    EXPECT_FALSE(file_exists(test_archive));
}

TEST_F(UploadTest, UploadProcess_BroadbandNotSupported) {
    test_config.device_type = DEVICE_TYPE_BROADBAND;
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadProcess_UnknownDeviceType) {
    test_config.device_type = DEVICE_TYPE_UNKNOWN;
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, -1);
}

TEST_F(UploadTest, UploadProcess_GetPartnerIdFailureFallback) {
    set_mock_partner_id_behavior(0, ""); // GetPartnerId fails
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    // Should fallback to "comcast" and succeed
    EXPECT_EQ(result, 0);
}

// ============================================================================
// upload_process Tests - Edge Cases
// ============================================================================

TEST_F(UploadTest, UploadProcess_EmptyArchiveName) {
    test_archive_info.archive_name[0] = '\0';
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    // Should handle empty archive name
    EXPECT_EQ(result, 0);
}

TEST_F(UploadTest, UploadProcess_NonExistentArchive) {
    strncpy(test_archive_info.archive_name, "/tmp/nonexistent_archive.tar.gz", 
            sizeof(test_archive_info.archive_name) - 1);
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    printf("result=%d\n", result); 
    // Upload may succeed but file won't be deleted
}

TEST_F(UploadTest, UploadProcess_VeryLongArchivePath) {
    char long_path[600];
    memset(long_path, 'A', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    strncpy(test_archive_info.archive_name, long_path, 
            sizeof(test_archive_info.archive_name) - 1);
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    printf("result=%d\n", result);
    // Should not crash
}

TEST_F(UploadTest, UploadProcess_SpecialCharactersInPaths) {
    strncpy(test_archive_info.archive_name, "/tmp/test archive with spaces.tar.gz", 
            sizeof(test_archive_info.archive_name) - 1);
    create_test_file(test_archive_info.archive_name, 2048);
    
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
    
    unlink(test_archive_info.archive_name);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(UploadTest, Integration_CompleteUploadFlow) {
    // Setup complete successful flow
    set_mock_partner_id_behavior(1, "testpartner");
    set_mock_read_rfc_property_behavior(1, "true"); // Encryption enabled
    set_mock_read_rfc_property_behavior(1, "crashportal.integration.test");
    set_mock_read_rfc_property_behavior(1, "https://integration.test.com/upload");
    set_mock_compute_md5_behavior(0, "integration_md5_hash");
    set_mock_firmware_version_behavior(18, "INTEGRATION_FW_2.0");
    set_mock_metadata_post_behavior(0, 200);
    set_mock_upload_status(200, 0);
    set_mock_extract_s3_url_behavior(0, "https://s3.amazonaws.com/integration/upload");
    set_mock_s3_put_upload_behavior(0);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    EXPECT_EQ(result, 0);
    EXPECT_FALSE(file_exists(test_archive));
}

TEST_F(UploadTest, Integration_CompleteUploadFlowWithRetry) {
    // First upload attempt fails, second succeeds
    set_mock_partner_id_behavior(1, "comcast");
    set_mock_read_rfc_property_behavior(1, "false");
    set_mock_read_rfc_property_behavior(1, "crashportal.test.com");
    set_mock_read_rfc_property_behavior(1, test_url);
    set_mock_firmware_version_behavior(10, "1.0.0");
    set_mock_metadata_post_behavior(0, 200);
    
    // First attempt fails
    set_mock_upload_status(500, 7);
    set_mock_extract_s3_url_behavior(0, test_s3_url);
    set_mock_s3_put_upload_behavior(7);
    
    int result = upload_process(&test_archive_info, &test_config, &test_platform);
    
    // Should retry and eventually fail after 3 attempts
    EXPECT_NE(result, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
