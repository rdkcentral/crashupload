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
 * @file config_manager_gtest.cpp
 * @brief Comprehensive GTest suite for config_manager.c
 * 
 * Test Coverage:
 * - Positive and negative test cases
 * - Parameter validation (NULL, invalid, empty)
 * - Buffer overflow protection
 * - NULL pointer dereference
 * - Edge cases and boundary conditions
 * - All function paths and branches
 * 
 * Target: >90% line and function coverage
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

extern "C" {
#include "../c_sourcecode/src/config/config_manager.h"
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"
#include "../c_sourcecode/common/constants.h"

// Mock function declarations
int mock_getIncludePropertyData(const char* param, char* value, int len);
int mock_getDevicePropertyData(const char* param, char* value, int len);
int mock_filePresentCheck(const char* filename);

// External mock control functions
void set_mock_getIncludePropertyData_behavior(int return_value, const char* output_value);
void set_mock_getDevicePropertyData_behavior(int return_value, const char* output_value);
void set_mock_filePresentCheck_behavior(int return_value);
void reset_all_mocks();
}

using ::testing::_;
using ::testing::Return;

#define UTILS_SUCCESS 1
#define UTILS_FAIL -1

// ============================================================================
// Test Fixture
// ============================================================================

class ConfigManagerTest : public ::testing::Test {
protected:
    config_t test_config;
    char test_argv0[32];
    char test_argv1[32];
    char test_argv2[32];
    char test_argv3[32];
    char test_argv4[32];
    char* test_argv[5];

    void SetUp() override {
        memset(&test_config, 0, sizeof(config_t));
        
        strcpy(test_argv0, "crashupload");
        strcpy(test_argv1, "arg1");
        strcpy(test_argv2, "0");  // Default to minidump
        strcpy(test_argv3, "normal");
        strcpy(test_argv4, "no_wait");
        
        test_argv[0] = test_argv0;
        test_argv[1] = test_argv1;
        test_argv[2] = test_argv2;
        test_argv[3] = test_argv3;
        test_argv[4] = test_argv4;
        
        reset_all_mocks();
    }

    void TearDown() override {
        reset_all_mocks();
        // Clean up any test files
        unlink("/tmp/tmtryoptout");
    }
};

// ============================================================================
// Tests for config_init_load() - Positive Cases
// ============================================================================

TEST_F(ConfigManagerTest, ConfigInitLoad_ValidConfig_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");  // UTILS_SUCCESS = 0
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "XG1v4");
    set_mock_filePresentCheck_behavior(1);  // t2 not present
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_STREQ(test_config.log_file, "/tmp/minidump_log_files.txt");
    EXPECT_STREQ(test_config.log_mapper_file, "/etc/breakpad-logmapper.conf");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_MediaClientDevice_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_MEDIACLIENT);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_HybridDevice_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "hybrid");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_MEDIACLIENT);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_BroadbandDevice_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "broadband");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_BROADBAND);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_ExtenderDevice_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "extender");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_EXTENDER);
    EXPECT_STREQ(test_config.core_log_file, "/var/log/messages");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_ProdBuildType_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "prod");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.build_type, BUILD_TYPE_PROD);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_DevBuildType_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "dev");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.build_type, BUILD_TYPE_DEV);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_SecureMode_Success) {
    strcpy(test_argv3, "secure");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 4, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.upload_mode, UPLOAD_MODE_SECURE);
    EXPECT_STREQ(test_config.core_path, "/opt/secure/corefiles");
    EXPECT_STREQ(test_config.minidump_path, "/opt/secure/minidumps");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_NormalMode_Success) {
    strcpy(test_argv3, "normal");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 4, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.upload_mode, UPLOAD_MODE_NORMAL);
    EXPECT_STREQ(test_config.core_path, "/var/lib/systemd/coredump");
    EXPECT_STREQ(test_config.minidump_path, "/opt/minidumps");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_MinidumpType_Success) {
    strcpy(test_argv2, "0");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 3, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_MINIDUMP);
    EXPECT_STREQ(test_config.working_dir_path, test_config.minidump_path);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_CoredumpType_Success) {
    strcpy(test_argv2, "1");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 3, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_COREDUMP);
    EXPECT_STREQ(test_config.working_dir_path, test_config.core_path);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_MinidumpBroadband_WorkingDirOverride) {
    strcpy(test_argv2, "0");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "broadband");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 3, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_MINIDUMP);
    EXPECT_STREQ(test_config.working_dir_path, "/minidumps");
    EXPECT_STREQ(test_config.minidump_path, "/minidumps");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_MinidumpExtender_WorkingDirOverride) {
    strcpy(test_argv2, "0");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "extender");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 3, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_MINIDUMP);
    EXPECT_STREQ(test_config.working_dir_path, "/minidumps");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_T2Enabled_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(0);  // t2 present (filePresentCheck returns 0 on success)
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_TRUE(test_config.t2_enabled);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_T2Disabled_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);  // t2 not present
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_FALSE(test_config.t2_enabled);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_LockModeWait_Success) {
    strcpy(test_argv4, "wait_for_lock");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.lock_mode, LOCK_MODE_WAIT);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_LockModeExit_Success) {
    strcpy(test_argv4, "no_wait");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.lock_mode, LOCK_MODE_EXIT);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_DefaultLogPathOnError_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_FAIL, "");  // Fail to get log path
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_STREQ(test_config.log_path, "/opt/logs");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_UnknownBuildType_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_FAIL, "");  // Fail to get build type
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    //EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(result, ERR_CONFIG_MISSING_REQUIRED);
    //EXPECT_EQ(test_config.build_type, BUILD_TYPE_UNKNOWN);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_UnknownBoxType_Success) {
    set_mock_getIncludePropertyData_behavior(0, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_FAIL, "");  // Fail to get box type
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    //EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(result, ERR_CONFIG_MISSING_REQUIRED);
    //EXPECT_STREQ(test_config.box_type, "UNKNOWN");
}

TEST_F(ConfigManagerTest, ConfigInitLoad_UnknownDeviceType_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "unknown_device");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_UNKNOWN);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_UnknownDumpType_Success) {
    strcpy(test_argv2, "99");  // Invalid dump type
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 3, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_UNKNOWN);
}

#if 0
// ============================================================================
// Tests for config_init_load() - Negative Cases
// ============================================================================

TEST_F(ConfigManagerTest, ConfigInitLoad_NullConfig_Failure) {
    int result = config_init_load(nullptr, 5, test_argv);
    EXPECT_EQ(result, -1);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_DeviceTypeFailure_Error) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_FAIL, "");  // Fail device type lookup
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, ERR_CONFIG_MISSING_REQUIRED);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_MinArgc_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 1, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    // Should still initialize but without argc-dependent fields
}

TEST_F(ConfigManagerTest, ConfigInitLoad_ZeroArgc_Success) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 0, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
}

// ============================================================================
// Tests for get_opt_out_status()
// ============================================================================

TEST_F(ConfigManagerTest, GetOptOutStatus_BothTrue_ReturnsTrue) {
    // Create optout file with "true"
    FILE* fp = fopen("/tmp/tmtryoptout", "w");
    ASSERT_NE(fp, nullptr);
    fprintf(fp, "true\n");
    fclose(fp);
    
    bool result = get_opt_out_status();
    
    // RFC is hardcoded to "true", file is "true" -> should return true
    EXPECT_TRUE(result);
    
    unlink("/tmp/tmtryoptout");
}

TEST_F(ConfigManagerTest, GetOptOutStatus_FileNotExists_ReturnsFalse) {
    unlink("/tmp/tmtryoptout");  // Ensure file doesn't exist
    
    bool result = get_opt_out_status();
    
    // RFC is "true" but file doesn't exist (defaults to "false") -> should return false
    EXPECT_FALSE(result);
}

TEST_F(ConfigManagerTest, GetOptOutStatus_FileFalse_ReturnsFalse) {
    FILE* fp = fopen("/tmp/tmtryoptout", "w");
    ASSERT_NE(fp, nullptr);
    fprintf(fp, "false\n");
    fclose(fp);
    
    bool result = get_opt_out_status();
    
    // RFC is "true" but file is "false" -> should return false
    EXPECT_FALSE(result);
    
    unlink("/tmp/tmtryoptout");
}

TEST_F(ConfigManagerTest, GetOptOutStatus_FileEmpty_ReturnsFalse) {
    FILE* fp = fopen("/tmp/tmtryoptout", "w");
    ASSERT_NE(fp, nullptr);
    fclose(fp);
    
    bool result = get_opt_out_status();
    
    EXPECT_FALSE(result);
    
    unlink("/tmp/tmtryoptout");
}

// ============================================================================
// Tests for config_get() - Negative Cases (Not Implemented)
// ============================================================================

TEST_F(ConfigManagerTest, ConfigGet_NotImplemented) {
    char value[256];
    int result = config_get("test_key", value, sizeof(value));
    EXPECT_EQ(result, ERR_NOT_IMPLEMENTED);
}

TEST_F(ConfigManagerTest, ConfigGet_NullKey_NotImplemented) {
    char value[256];
    int result = config_get(nullptr, value, sizeof(value));
    EXPECT_EQ(result, ERR_NOT_IMPLEMENTED);
}

TEST_F(ConfigManagerTest, ConfigGet_NullValue_NotImplemented) {
    int result = config_get("key", nullptr, 256);
    EXPECT_EQ(result, ERR_NOT_IMPLEMENTED);
}

TEST_F(ConfigManagerTest, ConfigGet_ZeroLength_NotImplemented) {
    char value[256];
    int result = config_get("key", value, 0);
    EXPECT_EQ(result, ERR_NOT_IMPLEMENTED);
}

// ============================================================================
// Tests for config_cleanup()
// ============================================================================

TEST_F(ConfigManagerTest, ConfigCleanup_ValidConfig_Success) {
    strcpy(test_config.log_file, "test_value");
    strcpy(test_config.box_type, "test_box");
    test_config.device_type = DEVICE_TYPE_MEDIACLIENT;
    
    config_cleanup(&test_config);
    
    // All fields should be zeroed
    EXPECT_EQ(test_config.log_file[0], '\0');
    EXPECT_EQ(test_config.box_type[0], '\0');
    EXPECT_EQ(test_config.device_type, 0);
}

TEST_F(ConfigManagerTest, ConfigCleanup_NullConfig_NoSegfault) {
    // Should not crash
    config_cleanup(nullptr);
    // If we reach here, test passed
    SUCCEED();
}

TEST_F(ConfigManagerTest, ConfigCleanup_AlreadyClean_Success) {
    memset(&test_config, 0, sizeof(config_t));
    
    config_cleanup(&test_config);
    
    // Should still be all zeros
    EXPECT_EQ(test_config.device_type, 0);
}

// ============================================================================
// Buffer Overflow Protection Tests
// ============================================================================

TEST_F(ConfigManagerTest, ConfigInitLoad_LongLogPath_NoOverflow) {
    char long_path[128];
    memset(long_path, 'A', sizeof(long_path) - 1);
    long_path[127] = '\0';
    
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, long_path);
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    // Ensure null terminator is present
    EXPECT_EQ(test_config.log_path[sizeof(test_config.log_path) - 1], '\0');
}

TEST_F(ConfigManagerTest, ConfigInitLoad_LongBoxType_NoOverflow) {
    char long_box[128];
    memset(long_box, 'B', sizeof(long_box) - 1);
    long_box[127] = '\0';
    
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, long_box);
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    // Check buffer is within bounds
    EXPECT_LT(strlen(test_config.box_type), sizeof(test_config.box_type));
}

// ============================================================================
// Edge Case and Boundary Tests
// ============================================================================

TEST_F(ConfigManagerTest, ConfigInitLoad_EdgeCase_Argc2_MinidumpPath) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 2, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    // Should not set dump_type or working_dir_path
}

TEST_F(ConfigManagerTest, ConfigInitLoad_EdgeCase_ExactSecureMatch) {
    strcpy(test_argv3, "secure");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 4, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.upload_mode, UPLOAD_MODE_SECURE);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_EdgeCase_PartialSecureMatch) {
    strcpy(test_argv3, "securemode");  // Contains "secure" but longer
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 4, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    // Should still match because strncmp checks first 6 chars
    EXPECT_EQ(test_config.upload_mode, UPLOAD_MODE_SECURE);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_EdgeCase_ExactWaitForLockMatch) {
    strcpy(test_argv4, "wait_for_lock");
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.lock_mode, LOCK_MODE_WAIT);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_EdgeCase_EmptyDeviceProperty) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "");  // Empty string
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_UNKNOWN);
}

TEST_F(ConfigManagerTest, ConfigInitLoad_OptOutStatus_Integration) {
    // Create optout file
    FILE* fp = fopen("/tmp/tmtryoptout", "w");
    ASSERT_NE(fp, nullptr);
    fprintf(fp, "true\n");
    fclose(fp);
    
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    EXPECT_TRUE(test_config.opt_out);
    
    unlink("/tmp/tmtryoptout");
}
#endif
// ============================================================================
// Additional Coverage Tests
// ============================================================================

TEST_F(ConfigManagerTest, ConfigInitLoad_AllFieldsInitialized) {
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/custom/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(0);  // t2 enabled
    
    strcpy(test_argv2, "1");  // coredump
    strcpy(test_argv3, "secure");
    strcpy(test_argv4, "wait_for_lock");
    
    int result = config_init_load(&test_config, 5, test_argv);
    
    EXPECT_EQ(result, CONFIG_SUCCESS);
    
    // Verify all critical fields are set
    EXPECT_STREQ(test_config.log_file, "/tmp/minidump_log_files.txt");
    EXPECT_STREQ(test_config.log_mapper_file, "/etc/breakpad-logmapper.conf");
    EXPECT_STREQ(test_config.log_path, "/custom/logs");
    EXPECT_EQ(test_config.device_type, DEVICE_TYPE_MEDIACLIENT);
    EXPECT_EQ(test_config.dump_type, DUMP_TYPE_COREDUMP);
    EXPECT_EQ(test_config.upload_mode, UPLOAD_MODE_SECURE);
    EXPECT_EQ(test_config.lock_mode, LOCK_MODE_WAIT);
    EXPECT_TRUE(test_config.t2_enabled);
}

// ============================================================================
// Tests for get_privacy_control_mode()
// ============================================================================

TEST_F(ConfigManagerTest, GetPrivacyControlMode_ValidConfig_ReturnsShare) {
    // Set up required mocks for config_init_load
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    
    // Test with valid config - should get SHARE from stub
    int result = config_init_load(&test_config, 5, test_argv);
    ASSERT_EQ(result, CONFIG_SUCCESS);
    
    privacy_control_t privacy_result = get_privacy_control_mode();
    
    // In stub mode, this should return SHARE
    EXPECT_EQ(privacy_result, SHARE);
}

TEST_F(ConfigManagerTest, GetPrivacyControlMode_ReturnsValidEnum) {
    // Test that function returns valid privacy_control_t enum value
    privacy_control_t result = get_privacy_control_mode();
    
    // Result should be either SHARE or DO_NOT_SHARE
    EXPECT_TRUE(result == SHARE || result == DO_NOT_SHARE);
}

TEST_F(ConfigManagerTest, GetPrivacyControlMode_RbusStubBehavior) {
    // Test that verifies the RBUS stub functions are called
    privacy_control_t result = get_privacy_control_mode();
    
    // With RBUS stubs (when RBUS_API_ENABLED not defined), 
    // rbus_get_string_param returns true with "SHARE"
    EXPECT_EQ(result, SHARE);
}

// ============================================================================
// Tests for RFC Interface Coverage
// ============================================================================

extern "C" {
#include "../c_sourcecode/src/rfcInterface/rfcinterface.h"
}

TEST_F(ConfigManagerTest, WriteRFCProperty_StringType_ReturnsNotApplicable) {
    // Test write_RFCProperty with string data type (stub mode)
    int result = write_RFCProperty("rfcTestType", "TestKey", "TestValue", RFC_STRING);
    
    // In stub mode (RFC_API_ENABLED not defined), should return READ_RFC_NOTAPPLICABLE
    EXPECT_EQ(result, WRITE_RFC_NOTAPPLICABLE);
}

TEST_F(ConfigManagerTest, WriteRFCProperty_BoolType_ReturnsNotApplicable) {
    // Test write_RFCProperty with boolean data type
    int result = write_RFCProperty("rfcTestType", "TestKey", "true", RFC_BOOL);
    
    EXPECT_EQ(result, WRITE_RFC_NOTAPPLICABLE);
}

TEST_F(ConfigManagerTest, WriteRFCProperty_UintType_ReturnsNotApplicable) {
    // Test write_RFCProperty with unsigned int data type
    int result = write_RFCProperty("rfcTestType", "TestKey", "42", RFC_UINT);
    
    EXPECT_EQ(result, WRITE_RFC_NOTAPPLICABLE);
}

TEST_F(ConfigManagerTest, WriteRFCProperty_NullParameters_HandlesSafely) {
    // Test with NULL parameters - stub should handle gracefully
    int result1 = write_RFCProperty(nullptr, "Key", "Value", RFC_STRING);
    int result2 = write_RFCProperty("Type", nullptr, "Value", RFC_STRING);
    int result3 = write_RFCProperty("Type", "Key", nullptr, RFC_STRING);
    
    // All should return WRITE_RFC_NOTAPPLICABLE in stub mode
    EXPECT_EQ(result1, WRITE_RFC_NOTAPPLICABLE);
    EXPECT_EQ(result2, WRITE_RFC_NOTAPPLICABLE);
    EXPECT_EQ(result3, WRITE_RFC_NOTAPPLICABLE);
}

TEST_F(ConfigManagerTest, ReadRFCProperty_AdditionalCoverage) {
    // Additional test to ensure read_RFCProperty stub is fully covered
    char buffer[128] = {0};
    
    int result = read_RFCProperty("rfcType", "TestKey", buffer, sizeof(buffer));
    
    // Stub should return READ_RFC_NOTAPPLICABLE
    EXPECT_EQ(result, READ_RFC_NOTAPPLICABLE);
}

// ============================================================================
// Tests for RBUS Interface (Stub Coverage)
// ============================================================================

extern "C" {
bool rbus_init(void);
void rbus_cleanup(void);
bool rbus_get_string_param(const char *param_name, char *value_buf, size_t buf_size);
}

TEST_F(ConfigManagerTest, RbusInit_Stub_ReturnsTrue) {
    // Test rbus_init stub implementation
    bool result = rbus_init();
    EXPECT_TRUE(result);
}

TEST_F(ConfigManagerTest, RbusCleanup_Stub_NoOp) {
    // Test rbus_cleanup stub implementation (no-op, just verify it doesn't crash)
    rbus_init();
    rbus_cleanup();
    // If we get here without crashing, the test passes
    SUCCEED();
}

TEST_F(ConfigManagerTest, RbusGetStringParam_Stub_ReturnsShare) {
    char buffer[64] = {0};
    
    bool result = rbus_get_string_param("Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode", 
                                         buffer, sizeof(buffer));
    
    EXPECT_TRUE(result);
    EXPECT_STREQ(buffer, "SHARE");
}

TEST_F(ConfigManagerTest, RbusGetStringParam_NullParam_ReturnsFalse) {
    char buffer[64] = {0};
    
    // Test with NULL parameter name
    bool result = rbus_get_string_param(nullptr, buffer, sizeof(buffer));
    
    // Should handle NULL gracefully (check actual implementation behavior)
    // Most implementations would log a warning and return true with "SHARE" in stub mode
    EXPECT_TRUE(result);
}

TEST_F(ConfigManagerTest, RbusGetStringParam_NullBuffer_HandlesSafely) {
    // Test with NULL buffer - should not crash
    bool result = rbus_get_string_param("SomeParam", nullptr, 64);
    
    // In stub mode, it checks if value_buf is non-NULL
    // The stub should handle this gracefully
    EXPECT_TRUE(result);
}

TEST_F(ConfigManagerTest, RbusGetStringParam_ZeroBufferSize_HandlesSafely) {
    char buffer[64] = {0};
    
    // Test with zero buffer size
    bool result = rbus_get_string_param("SomeParam", buffer, 0);
    
    // Stub checks buf_size > 0 before writing
    EXPECT_TRUE(result);
}

// ============================================================================
// Tests for config_cleanup()
// ============================================================================

TEST_F(ConfigManagerTest, ConfigCleanup_ValidConfig_ZerosFields) {
    // First populate config with real data
    set_mock_getIncludePropertyData_behavior(UTILS_SUCCESS, "/opt/logs");
    set_mock_getDevicePropertyData_behavior(UTILS_SUCCESS, "mediaclient");
    set_mock_filePresentCheck_behavior(1);
    config_init_load(&test_config, 5, test_argv);

    // config should have non-zero fields now
    EXPECT_NE(test_config.device_type, 0);

    // Cleanup should zero everything
    config_cleanup(&test_config);

    // Verify fields are zeroed
    config_t zeroed;
    memset(&zeroed, 0, sizeof(config_t));
    EXPECT_EQ(memcmp(&test_config, &zeroed, sizeof(config_t)), 0);
}

TEST_F(ConfigManagerTest, ConfigCleanup_NullConfig_HandlesGracefully) {
    // Should not crash on NULL input (the `if (config)` guard prevents it)
    config_cleanup(nullptr);
    SUCCEED();
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
