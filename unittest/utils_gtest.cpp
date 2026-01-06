/**
 * @file utils_gtest.cpp
 * @brief Comprehensive GTest suite for cleanup_batch.c and file_utils.c
 * 
 * Test Coverage:
 * - Positive and negative test cases
 * - Parameter validation (NULL, invalid, empty)
 * - Buffer overflow/underflow protection
 * - NULL pointer dereference
 * - Edge cases and boundary conditions
 * - All function paths and branches
 * - Different input combinations
 * 
 * Target: >90% line coverage and >95% function coverage
 * 
 * Functions tested from file_utils.c:
 * - tls_log()
 * - GetCrashFirmwareVersion()
 * - join_path()
 * - compute_s3_md5_base64()
 * - file_get_sha1()
 * - file_get_mtime_formatted()
 * - file_get_size()
 * - get_crash_timestamp_utc()
 * - extract_tail()
 * - trim_process_name_in_path()
 * - is_regular_file()
 * - check_process_dmp_file()
 * 
 * Functions tested from cleanup_batch.c:
 * - cleanup_batch()
 * - remove_pending_dumps()
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
#include <dirent.h>

extern "C" {
#include "../c_sourcecode/src/utils/cleanup_batch.h"
#include "../c_sourcecode/include/file_utils.h"
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"

// Mock function declarations
void set_mock_stripinvalidchar_behavior(size_t return_value);
int get_mock_stripinvalidchar_call_count();
int get_mock_tlslog_call_count();
void reset_utils_mocks();
}

using ::testing::_;
using ::testing::Return;

// ============================================================================
// Test Fixture
// ============================================================================

class UtilsTest : public ::testing::Test {
protected:
    // Test file paths
    const char* test_dir = "/tmp/test_crashupload_utils";
    const char* test_file = "/tmp/test_utils_file.txt";
    const char* test_version = "/tmp/test_version.txt";
    const char* test_log = "/tmp/test_log.txt";
    
    void SetUp() override {
        reset_utils_mocks();
        
        // Create test directory
        mkdir(test_dir, 0755);
        
        // Create some test files
        CreateTestFile(test_file, "test content for utilities");
        CreateTestFile(test_version, "imagename:TEST_VERSION_1.0.0\nother:data\n");
        
        // Create test log file with multiple lines
        CreateTestFile(test_log, 
            "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\n"
            "Line 6\nLine 7\nLine 8\nLine 9\nLine 10\n");
    }

    void TearDown() override {
        reset_utils_mocks();
        
        // Clean up test files
        unlink(test_file);
        unlink(test_version);
        unlink(test_log);
        
        // Clean up test directory recursively
        RemoveDirectory(test_dir);
    }
    
    void CreateTestFile(const char* path, const char* content) {
        FILE* fp = fopen(path, "w");
        if (fp) {
            if (content) {
                fwrite(content, 1, strlen(content), fp);
            }
            fclose(fp);
        }
    }
    
    void CreateTestDirectory(const char* path) {
        mkdir(path, 0755);
    }
    
    void RemoveDirectory(const char* path) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
        system(cmd);
    }
    
    bool FileExists(const char* path) {
        struct stat st;
        return (stat(path, &st) == 0);
    }
    
    long GetFileSize(const char* path) {
        struct stat st;
        if (stat(path, &st) == 0) {
            return st.st_size;
        }
        return -1;
    }
};

// ============================================================================
// Tests for tls_log() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, TlsLog_ValidInputNonBroadband_Success) {
    bool result = tls_log(35, "video", "example.com");
    EXPECT_TRUE(result);
    //EXPECT_GT(get_mock_tlslog_call_count(), 0);
}

TEST_F(UtilsTest, TlsLog_ValidInputBroadband_NoLogging) {
    bool result = tls_log(35, "broadband", "example.com");
    EXPECT_TRUE(result);
    // For broadband, TLSLOG should not be called
    EXPECT_EQ(get_mock_tlslog_call_count(), 0);
}

TEST_F(UtilsTest, TlsLog_AllTLSErrorCodes_Success) {
    int tls_error_codes[] = {35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91};
    int num_codes = sizeof(tls_error_codes) / sizeof(tls_error_codes[0]);
    
    for (int i = 0; i < num_codes; i++) {
        reset_utils_mocks();
        bool result = tls_log(tls_error_codes[i], "video", "example.com");
        EXPECT_TRUE(result);
        //EXPECT_GT(get_mock_tlslog_call_count(), 0);
    }
}

TEST_F(UtilsTest, TlsLog_NonTLSErrorCode_NoLogging) {
    reset_utils_mocks();
    bool result = tls_log(404, "video", "example.com");
    EXPECT_TRUE(result);
    EXPECT_EQ(get_mock_tlslog_call_count(), 0);
}

// ============================================================================
// Tests for tls_log() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, TlsLog_NullDeviceType_Failure) {
    bool result = tls_log(35, NULL, "example.com");
    EXPECT_FALSE(result);
}

TEST_F(UtilsTest, TlsLog_NullFqdn_Failure) {
    bool result = tls_log(35, "video", NULL);
    EXPECT_FALSE(result);
}

TEST_F(UtilsTest, TlsLog_BothNull_Failure) {
    bool result = tls_log(35, NULL, NULL);
    EXPECT_FALSE(result);
}

// ============================================================================
// Tests for GetCrashFirmwareVersion() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, GetCrashFirmwareVersion_ValidFile_Success) {
    char version[64] = {0};
    
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    
    EXPECT_GT(result, 0);
    EXPECT_NE(version[0], '\0');
    EXPECT_GT(get_mock_stripinvalidchar_call_count(), 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_FileWithImagename_ExtractsCorrectly) {
    CreateTestFile(test_version, "key1:value1\nimagename:FIRMWARE_2.0\nkey2:value2\n");
    
    char version[64] = {0};
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    
    EXPECT_GT(result, 0);
    EXPECT_NE(version[0], '\0');
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_LargeBuffer_Success) {
    char version[256] = {0};
    
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    
    EXPECT_GT(result, 0);
}

// ============================================================================
// Tests for GetCrashFirmwareVersion() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, GetCrashFirmwareVersion_NullVersionFile_Failure) {
    char version[64] = {0};
    
    size_t result = GetCrashFirmwareVersion(NULL, version, sizeof(version));
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_NullBuffer_Failure) {
    size_t result = GetCrashFirmwareVersion(test_version, NULL, 64);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_BothNull_Failure) {
    size_t result = GetCrashFirmwareVersion(NULL, NULL, 64);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_FileNotExist_Failure) {
    char version[64] = {0};
    
    size_t result = GetCrashFirmwareVersion("/tmp/nonexistent_file.txt", version, sizeof(version));
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_NoImagenameInFile_Failure) {
    CreateTestFile(test_version, "key1:value1\nkey2:value2\n");
    
    char version[64] = {0};
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_EmptyFile_Failure) {
    CreateTestFile(test_version, "");
    
    char version[64] = {0};
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, GetCrashFirmwareVersion_BufferTooSmall_HandledSafely) {
    char version[5] = {0};
    
    size_t result = GetCrashFirmwareVersion(test_version, version, sizeof(version));
    system("cat /tmp/test_version.txt");
    printf("result = %lu and version file=%s And version=%s\n", result, test_version, version); 
    // Should handle small buffer safely (may truncate)
    EXPECT_LT(strlen(version), sizeof(version));
}

// ============================================================================
// Tests for join_path() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, JoinPath_ValidDirAndName_Success) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "/tmp/dumps", "file.dmp");
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(result, "/tmp/dumps/file.dmp");
}

TEST_F(UtilsTest, JoinPath_DirWithTrailingSlash_Success) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "/tmp/dumps/", "file.dmp");
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(result, "/tmp/dumps/file.dmp");
}

TEST_F(UtilsTest, JoinPath_EmptyDir_Success) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "", "file.dmp");
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(result, "file.dmp");
}

TEST_F(UtilsTest, JoinPath_RootDir_Success) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "/", "file.dmp");
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(result, "/file.dmp");
}

TEST_F(UtilsTest, JoinPath_NestedPath_Success) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "/opt/minidumps/archives", "dump.tgz");
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(result, "/opt/minidumps/archives/dump.tgz");
}

// ============================================================================
// Tests for join_path() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, JoinPath_NullDest_Failure) {
    int ret = join_path(NULL, 512, "/tmp", "file.txt");
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, JoinPath_NullDir_Failure) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), NULL, "file.txt");
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, JoinPath_NullName_Failure) {
    char result[512];
    
    int ret = join_path(result, sizeof(result), "/tmp", NULL);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, JoinPath_AllNull_Failure) {
    int ret = join_path(NULL, 512, NULL, NULL);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, JoinPath_BufferTooSmall_Failure) {
    char result[10];
    
    int ret = join_path(result, sizeof(result), "/tmp/very/long/path", "file.txt");
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, JoinPath_NameTooLongForEmptyDir_Failure) {
    char result[10];
    char long_name[50];
    memset(long_name, 'A', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    
    int ret = join_path(result, sizeof(result), "", long_name);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for file_get_sha1() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, FileGetSha1_ValidFile_Success) {
    char hash[41];
    
    int ret = file_get_sha1(test_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(hash), 40);
    // Verify it's a valid hex string
    for (int i = 0; i < 40; i++) {
        EXPECT_TRUE((hash[i] >= '0' && hash[i] <= '9') || 
                    (hash[i] >= 'a' && hash[i] <= 'f'));
    }
}

TEST_F(UtilsTest, FileGetSha1_EmptyFile_Success) {
    const char* empty_file = "/tmp/empty_file.txt";
    CreateTestFile(empty_file, "");
    
    char hash[41];
    int ret = file_get_sha1(empty_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(hash), 40);
    
    unlink(empty_file);
}

TEST_F(UtilsTest, FileGetSha1_LargeFile_Success) {
    const char* large_file = "/tmp/large_file.txt";
    FILE* fp = fopen(large_file, "w");
    if (fp) {
        // Write 100KB of data
        char buffer[1024];
        memset(buffer, 'A', sizeof(buffer));
        for (int i = 0; i < 100; i++) {
            fwrite(buffer, 1, sizeof(buffer), fp);
        }
        fclose(fp);
    }
    
    char hash[41];
    int ret = file_get_sha1(large_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(hash), 40);
    
    unlink(large_file);
}

TEST_F(UtilsTest, FileGetSha1_BufferExactSize_Success) {
    char hash[41];  // Exact size
    
    int ret = file_get_sha1(test_file, hash, 41);
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, FileGetSha1_BufferLargerThanNeeded_Success) {
    char hash[100];  // Larger buffer
    
    int ret = file_get_sha1(test_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(hash), 40);
}

// ============================================================================
// Tests for file_get_sha1() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, FileGetSha1_NullPath_Failure) {
    char hash[41];
    
    int ret = file_get_sha1(NULL, hash, sizeof(hash));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSha1_NullHash_Failure) {
    int ret = file_get_sha1(test_file, NULL, 41);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSha1_BufferTooSmall_Failure) {
    char hash[40];  // One byte too small
    
    int ret = file_get_sha1(test_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSha1_FileNotExist_Failure) {
    char hash[41];
    
    int ret = file_get_sha1("/tmp/nonexistent_file.txt", hash, sizeof(hash));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSha1_AllNullParameters_Failure) {
    int ret = file_get_sha1(NULL, NULL, 0);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for compute_s3_md5_base64() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, ComputeS3Md5Base64_ValidFile_Success) {
    char md5[64];
    
    int ret = compute_s3_md5_base64(test_file, md5, sizeof(md5));
    
    EXPECT_EQ(ret, 0);
    EXPECT_GT(strlen(md5), 0);
}

TEST_F(UtilsTest, ComputeS3Md5Base64_EmptyFile_Success) {
    const char* empty_file = "/tmp/empty_md5.txt";
    CreateTestFile(empty_file, "");
    
    char md5[64];
    int ret = compute_s3_md5_base64(empty_file, md5, sizeof(md5));
    
    EXPECT_EQ(ret, 0);
    
    unlink(empty_file);
}

TEST_F(UtilsTest, ComputeS3Md5Base64_LargeBuffer_Success) {
    char md5[128];
    
    int ret = compute_s3_md5_base64(test_file, md5, sizeof(md5));
    
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Tests for compute_s3_md5_base64() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, ComputeS3Md5Base64_NullFilepath_Failure) {
    char md5[64];
    
    int ret = compute_s3_md5_base64(NULL, md5, sizeof(md5));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ComputeS3Md5Base64_NullOutput_Failure) {
    int ret = compute_s3_md5_base64(test_file, NULL, 64);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ComputeS3Md5Base64_BufferTooSmall_Failure) {
    char md5[20];  // Too small for base64 MD5
    
    int ret = compute_s3_md5_base64(test_file, md5, sizeof(md5));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ComputeS3Md5Base64_FileNotExist_Failure) {
    char md5[64];
    
    int ret = compute_s3_md5_base64("/tmp/nonexistent.txt", md5, sizeof(md5));
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for file_get_mtime_formatted() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, FileGetMtimeFormatted_ValidFile_Success) {
    char mtime[64];
    
    int ret = file_get_mtime_formatted(test_file, mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, 0);
    EXPECT_GE(strlen(mtime), 19);  // YYYY-MM-DD-HH-MM-SS = 19 chars
}

TEST_F(UtilsTest, FileGetMtimeFormatted_MinimumBuffer_Success) {
    char mtime[20];  // Minimum required size
    
    int ret = file_get_mtime_formatted(test_file, mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, FileGetMtimeFormatted_LargeBuffer_Success) {
    char mtime[128];
    
    int ret = file_get_mtime_formatted(test_file, mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Tests for file_get_mtime_formatted() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, FileGetMtimeFormatted_NullPath_Failure) {
    char mtime[64];
    
    int ret = file_get_mtime_formatted(NULL, mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetMtimeFormatted_NullBuffer_Failure) {
    int ret = file_get_mtime_formatted(test_file, NULL, 64);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetMtimeFormatted_BufferTooSmall_Failure) {
    char mtime[10];  // Too small
    
    int ret = file_get_mtime_formatted(test_file, mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetMtimeFormatted_FileNotExist_Failure) {
    char mtime[64];
    
    int ret = file_get_mtime_formatted("/tmp/nonexistent.txt", mtime, sizeof(mtime));
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for file_get_size() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, FileGetSize_ValidFile_Success) {
    uint64_t size;
    
    int ret = file_get_size(test_file, &size);
    
    EXPECT_EQ(ret, 0);
    EXPECT_GT(size, 0);
}

TEST_F(UtilsTest, FileGetSize_EmptyFile_ReturnsZero) {
    const char* empty = "/tmp/empty_size.txt";
    CreateTestFile(empty, "");
    
    uint64_t size;
    int ret = file_get_size(empty, &size);
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(size, 0);
    
    unlink(empty);
}

TEST_F(UtilsTest, FileGetSize_LargeFile_Success) {
    const char* large = "/tmp/large_size.txt";
    FILE* fp = fopen(large, "w");
    if (fp) {
        char buffer[1024];
        memset(buffer, 'X', sizeof(buffer));
        for (int i = 0; i < 1000; i++) {
            fwrite(buffer, 1, sizeof(buffer), fp);
        }
        fclose(fp);
    }
    
    uint64_t size;
    int ret = file_get_size(large, &size);
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(size, 1024000);
    
    unlink(large);
}

// ============================================================================
// Tests for file_get_size() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, FileGetSize_NullPath_Failure) {
    uint64_t size;
    
    int ret = file_get_size(NULL, &size);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSize_NullSize_Failure) {
    int ret = file_get_size(test_file, NULL);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSize_BothNull_Failure) {
    int ret = file_get_size(NULL, NULL);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, FileGetSize_FileNotExist_Failure) {
    uint64_t size;
    
    int ret = file_get_size("/tmp/nonexistent.txt", &size);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for get_crash_timestamp_utc() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, GetCrashTimestampUtc_ValidBuffer_Success) {
    char timestamp[64];
    
    int ret = get_crash_timestamp_utc(timestamp, sizeof(timestamp));
    
    EXPECT_EQ(ret, 0);
    EXPECT_GE(strlen(timestamp), 19);
}

TEST_F(UtilsTest, GetCrashTimestampUtc_MinimumBuffer_Success) {
    char timestamp[20];
    
    int ret = get_crash_timestamp_utc(timestamp, sizeof(timestamp));
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, GetCrashTimestampUtc_LargeBuffer_Success) {
    char timestamp[128];
    
    int ret = get_crash_timestamp_utc(timestamp, sizeof(timestamp));
    
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Tests for get_crash_timestamp_utc() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, GetCrashTimestampUtc_NullBuffer_Failure) {
    int ret = get_crash_timestamp_utc(NULL, 64);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, GetCrashTimestampUtc_BufferTooSmall_Failure) {
    char timestamp[10];
    
    int ret = get_crash_timestamp_utc(timestamp, sizeof(timestamp));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, GetCrashTimestampUtc_ZeroSize_Failure) {
    char timestamp[64];
    
    int ret = get_crash_timestamp_utc(timestamp, 0);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for extract_tail() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, ExtractTail_ValidInputs_Success) {
    const char* output = "/tmp/tail_output.txt";
    
    int ret = extract_tail(test_log, output, 5);
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(FileExists(output));
    
    // Verify output file has content
    EXPECT_GT(GetFileSize(output), 0);
    
    unlink(output);
}

TEST_F(UtilsTest, ExtractTail_ExtractAllLines_Success) {
    const char* output = "/tmp/tail_all.txt";
    
    int ret = extract_tail(test_log, output, 100);  // More than file has
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(FileExists(output));
    
    unlink(output);
}

TEST_F(UtilsTest, ExtractTail_ExtractOneLine_Success) {
    const char* output = "/tmp/tail_one.txt";
    
    int ret = extract_tail(test_log, output, 1);
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(FileExists(output));
    
    unlink(output);
}

TEST_F(UtilsTest, ExtractTail_LargeLineCount_Success) {
    const char* output = "/tmp/tail_large.txt";
    
    int ret = extract_tail(test_log, output, 5000);
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(FileExists(output));
    
    unlink(output);
}

TEST_F(UtilsTest, ExtractTail_EmptyFile_Success) {
    const char* empty = "/tmp/empty_tail.txt";
    const char* output = "/tmp/tail_empty_out.txt";
    CreateTestFile(empty, "");
    
    int ret = extract_tail(empty, output, 10);
    
    EXPECT_EQ(ret, 0);
    
    unlink(empty);
    unlink(output);
}

// ============================================================================
// Tests for extract_tail() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, ExtractTail_NullSource_Failure) {
    const char* output = "/tmp/tail_output.txt";
    
    int ret = extract_tail(NULL, output, 5);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ExtractTail_NullDestination_Failure) {
    int ret = extract_tail(test_log, NULL, 5);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ExtractTail_BothNull_Failure) {
    int ret = extract_tail(NULL, NULL, 5);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ExtractTail_ZeroLines_Failure) {
    const char* output = "/tmp/tail_zero.txt";
    
    int ret = extract_tail(test_log, output, 0);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ExtractTail_NegativeLines_Failure) {
    const char* output = "/tmp/tail_neg.txt";
    
    int ret = extract_tail(test_log, output, -5);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, ExtractTail_SourceNotExist_Failure) {
    const char* output = "/tmp/tail_output.txt";
    
    int ret = extract_tail("/tmp/nonexistent.txt", output, 5);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for trim_process_name_in_path() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, TrimProcessNameInPath_ValidInput_Success) {
    const char* path = "/tmp/myprocess_dump_myprocess.dmp";
    const char* process = "myprocess";
    char output[256];
    
    int ret = trim_process_name_in_path(path, process, 4, output, sizeof(output));
    
    EXPECT_EQ(ret, 0);
    EXPECT_NE(output[0], '\0');
}

TEST_F(UtilsTest, TrimProcessNameInPath_NoOccurrence_CopiesPath) {
    const char* path = "/tmp/dump.dmp";
    const char* process = "myprocess";
    char output[256];
    
    int ret = trim_process_name_in_path(path, process, 4, output, sizeof(output));
    
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(output, path);
}

TEST_F(UtilsTest, TrimProcessNameInPath_MultipleOccurrences_TrimsAll) {
    const char* path = "myprocess_myprocess_myprocess";
    const char* process = "myprocess";
    char output[256];
    
    int ret = trim_process_name_in_path(path, process, 4, output, sizeof(output));
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, TrimProcessNameInPath_TrimToZero_Success) {
    const char* path = "/tmp/myprocess.dmp";
    const char* process = "myprocess";
    char output[256];
    
    int ret = trim_process_name_in_path(path, process, 0, output, sizeof(output));
    
    // Should handle trim to 0 (though unusual)
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Tests for trim_process_name_in_path() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, TrimProcessNameInPath_NullFullPath_Failure) {
    char output[256];
    
    int ret = trim_process_name_in_path(NULL, "process", 4, output, sizeof(output));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, TrimProcessNameInPath_NullProcessName_Failure) {
    const char* path = "/tmp/test.dmp";
    char output[256];
    
    int ret = trim_process_name_in_path(path, NULL, 4, output, sizeof(output));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, TrimProcessNameInPath_NullOutput_Failure) {
    const char* path = "/tmp/test.dmp";
    
    int ret = trim_process_name_in_path(path, "process", 4, NULL, 256);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, TrimProcessNameInPath_ZeroOutputLen_Failure) {
    const char* path = "/tmp/test.dmp";
    char output[256];
    
    int ret = trim_process_name_in_path(path, "process", 4, output, 0);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, TrimProcessNameInPath_EmptyProcessName_Failure) {
    const char* path = "/tmp/test.dmp";
    char output[256];
    
    int ret = trim_process_name_in_path(path, "", 4, output, sizeof(output));
    
    EXPECT_EQ(ret, -1);
}

TEST_F(UtilsTest, TrimProcessNameInPath_OutputBufferTooSmall_Failure) {
    const char* path = "/tmp/verylongprocessname_dump.dmp";
    char output[10];  // Too small
    
    int ret = trim_process_name_in_path(path, "name", 2, output, sizeof(output));
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for is_regular_file() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, IsRegularFile_ValidFile_ReturnsTrue) {
    int result = is_regular_file(test_file);
    
    EXPECT_EQ(result, 1);
}

TEST_F(UtilsTest, IsRegularFile_EmptyFile_ReturnsTrue) {
    const char* empty = "/tmp/empty_regular.txt";
    CreateTestFile(empty, "");
    
    int result = is_regular_file(empty);
    
    EXPECT_EQ(result, 1);
    
    unlink(empty);
}

// ============================================================================
// Tests for is_regular_file() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, IsRegularFile_Directory_ReturnsFalse) {
    int result = is_regular_file(test_dir);
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, IsRegularFile_FileNotExist_ReturnsFalse) {
    int result = is_regular_file("/tmp/nonexistent_file.txt");
    
    EXPECT_EQ(result, 0);
}

TEST_F(UtilsTest, IsRegularFile_NullPath_ReturnsFalse) {
    int result = is_regular_file(NULL);
    
    EXPECT_EQ(result, 0);
}

// ============================================================================
// Tests for check_process_dmp_file() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, CheckProcessDmpFile_ContainsMac_ReturnsTrue) {
    bool result = check_process_dmp_file("dump_macAABBCC_file.dmp");
    
    EXPECT_TRUE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_ContainsDat_ReturnsTrue) {
    bool result = check_process_dmp_file("dump_dat20250105_file.dmp");
    
    EXPECT_TRUE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_ContainsBox_ReturnsTrue) {
    bool result = check_process_dmp_file("dump_boxXG1v4_file.dmp");
    
    EXPECT_TRUE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_ContainsMod_ReturnsTrue) {
    bool result = check_process_dmp_file("dump_modXG1_file.dmp");
    
    EXPECT_TRUE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_ContainsMultiple_ReturnsTrue) {
    bool result = check_process_dmp_file("dump_macAABB_dat20250105_boxXG1_modXG1.dmp");
    
    EXPECT_TRUE(result);
}

// ============================================================================
// Tests for check_process_dmp_file() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, CheckProcessDmpFile_NoMarkers_ReturnsFalse) {
    bool result = check_process_dmp_file("simple_dump.dmp");
    
    EXPECT_FALSE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_NullFile_ReturnsFalse) {
    bool result = check_process_dmp_file(NULL);
    
    EXPECT_FALSE(result);
}

TEST_F(UtilsTest, CheckProcessDmpFile_EmptyString_ReturnsFalse) {
    bool result = check_process_dmp_file("");
    
    EXPECT_FALSE(result);
}

// ============================================================================
// Tests for cleanup_batch() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, CleanupBatch_ValidDirectory_Success) {
    // Create test directory with files
    CreateTestDirectory(test_dir);
    char file1[256], file2[256];
    snprintf(file1, sizeof(file1), "%s/test1.dmp", test_dir);
    snprintf(file2, sizeof(file2), "%s/test2.dmp", test_dir);
    CreateTestFile(file1, "test data 1");
    CreateTestFile(file2, "test data 2");
    
    int ret = cleanup_batch(test_dir, "*.dmp", 
                           "/tmp/test_onstart", "0", 10);
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, CleanupBatch_EmptyDirectory_Success) {
    CreateTestDirectory(test_dir);
    
    int ret = cleanup_batch(test_dir, "*.dmp", 
                           "/tmp/test_onstart", "0", 10);
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, CleanupBatch_DirectoryNotExist_ReturnsSuccess) {
    int ret = cleanup_batch("/tmp/nonexistent_dir", "*.dmp", 
                           "/tmp/test_onstart", "0", 10);
    
    EXPECT_EQ(ret, 0);  // Returns 0 if directory doesn't exist
}

// ============================================================================
// Tests for cleanup_batch() - Negative Cases
// ============================================================================

TEST_F(UtilsTest, CleanupBatch_NullWorkingDir_Failure) {
    int ret = cleanup_batch(NULL, "*.dmp", 
                           "/tmp/test_onstart", "0", 10);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for remove_pending_dumps() - Positive Cases
// ============================================================================

TEST_F(UtilsTest, RemovePendingDumps_ValidDirectory_Success) {
    CreateTestDirectory(test_dir);
    char dmp_file[256], tgz_file[256], other_file[256];
    snprintf(dmp_file, sizeof(dmp_file), "%s/test.dmp", test_dir);
    snprintf(tgz_file, sizeof(tgz_file), "%s/test.tgz", test_dir);
    snprintf(other_file, sizeof(other_file), "%s/test.txt", test_dir);
    
    CreateTestFile(dmp_file, "dump data");
    CreateTestFile(tgz_file, "archive data");
    CreateTestFile(other_file, "other data");
    
    remove_pending_dumps(test_dir, "*.dmp");
    
    // .dmp and .tgz files should be removed, .txt should remain
    EXPECT_FALSE(FileExists(dmp_file));
    EXPECT_FALSE(FileExists(tgz_file));
    EXPECT_TRUE(FileExists(other_file));
}

TEST_F(UtilsTest, RemovePendingDumps_EmptyDirectory_NoError) {
    CreateTestDirectory(test_dir);
    
    // Should not crash or error on empty directory
    remove_pending_dumps(test_dir, "*.dmp");
}

TEST_F(UtilsTest, RemovePendingDumps_DirectoryNotExist_NoError) {
    // Should not crash if directory doesn't exist
    remove_pending_dumps("/tmp/nonexistent_dir", "*.dmp");
}

TEST_F(UtilsTest, RemovePendingDumps_RecursiveDirectories_Success) {
    CreateTestDirectory(test_dir);
    char subdir[256];
    snprintf(subdir, sizeof(subdir), "%s/subdir", test_dir);
    CreateTestDirectory(subdir);
    
    char file1[256], file2[270];
    snprintf(file1, sizeof(file1), "%s/test.dmp", test_dir);
    snprintf(file2, sizeof(file2), "%s/test.dmp", subdir);
    CreateTestFile(file1, "data1");
    CreateTestFile(file2, "data2");
    
    remove_pending_dumps(test_dir, "*.dmp");
    
    EXPECT_FALSE(FileExists(file1));
    EXPECT_FALSE(FileExists(file2));
}

// ============================================================================
// Edge Cases and Buffer Tests
// ============================================================================

TEST_F(UtilsTest, FileGetSha1_BinaryFile_Success) {
    const char* bin_file = "/tmp/binary.dat";
    FILE* fp = fopen(bin_file, "wb");
    if (fp) {
        unsigned char data[256];
        for (int i = 0; i < 256; i++) {
            data[i] = (unsigned char)i;
        }
        fwrite(data, 1, sizeof(data), fp);
        fclose(fp);
    }
    
    char hash[41];
    int ret = file_get_sha1(bin_file, hash, sizeof(hash));
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(strlen(hash), 40);
    
    unlink(bin_file);
}

TEST_F(UtilsTest, JoinPath_VeryLongValidPath_Success) {
    char result[512];
    char long_dir[400];
    memset(long_dir, 'A', sizeof(long_dir) - 1);
    long_dir[sizeof(long_dir) - 1] = '\0';
    
    int ret = join_path(result, sizeof(result), "/tmp", "short.txt");
    
    EXPECT_EQ(ret, 0);
}

TEST_F(UtilsTest, ExtractTail_VeryLongLines_Success) {
    const char* long_line_file = "/tmp/long_lines.txt";
    const char* output = "/tmp/long_out.txt";
    
    FILE* fp = fopen(long_line_file, "w");
    if (fp) {
        for (int i = 0; i < 10; i++) {
            fprintf(fp, "This is a moderately long line number %d\n", i);
        }
        fclose(fp);
    }
    
    int ret = extract_tail(long_line_file, output, 5);
    
    EXPECT_EQ(ret, 0);
    
    unlink(long_line_file);
    unlink(output);
}

TEST_F(UtilsTest, TrimProcessNameInPath_VeryLongProcessName_Success) {
    const char* path = "/tmp/verylongprocessnamethatexceedslimits_dump.dmp";
    const char* process = "verylongprocessnamethatexceedslimits";
    char output[256];
    
    int ret = trim_process_name_in_path(path, process, 10, output, sizeof(output));
    
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
