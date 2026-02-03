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
 * @file ratelimit_gtest.cpp
 * @brief Comprehensive GTest suite for rate limiting functions
 * 
 * Tests all rate limiting logic including:
 * - set_time()
 * - is_upload_limit_reached()
 * - is_recovery_time_reached()
 * - ratelimit_check_unified()
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

extern "C" {
#include "../c_sourcecode/include/ratelimit.h"
#include "../c_sourcecode/common/types.h"
}

// ============================================================================
// Test Fixture
// ============================================================================

class RateLimitTest : public ::testing::Test {
protected:
    const char* test_deny_file = "/tmp/test_deny_file.txt";
    const char* test_timestamp_file = "/tmp/test_timestamps.txt";
    
    void SetUp() override {
        // Clean up any existing test files
        unlink(test_deny_file);
        unlink(test_timestamp_file);
        unlink("/tmp/.deny_dump_uploads_till");
        unlink("/tmp/.minidump_upload_timestamps");
    }

    void TearDown() override {
        // Clean up test files
        unlink(test_deny_file);
        unlink(test_timestamp_file);
        unlink("/tmp/.deny_dump_uploads_till");
        unlink("/tmp/.minidump_upload_timestamps");
    }
    
    void CreateTimestampFile(const char* path, int num_lines) {
        FILE* fp = fopen(path, "w");
        if (fp) {
            time_t now = time(NULL);
            // NOTE: Current implementation checks the LAST line, not first
            // So we write oldest first, newest last
            for (int i = num_lines - 1; i >= 0; i--) {
                fprintf(fp, "%ld\n", now - (i * 10));
            }
            fclose(fp);
        }
    }
    
    void CreateDenyFile(const char* path, long timestamp) {
        FILE* fp = fopen(path, "w");
        if (fp) {
            fprintf(fp, "%ld", timestamp);
            fclose(fp);
        }
    }
};

// ============================================================================
// Tests for set_time() - Positive Cases
// ============================================================================

TEST_F(RateLimitTest, SetTime_CurrentTime_Success) {
    int ret = set_time(test_deny_file, CURRENT_TIME);
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(access(test_deny_file, F_OK) == 0);
}

TEST_F(RateLimitTest, SetTime_RecoveryTime_Success) {
    int ret = set_time(test_deny_file, RECOVERY_TIME);
    
    EXPECT_EQ(ret, 0);
    
    // Verify file contains future timestamp
    FILE* fp = fopen(test_deny_file, "r");
    ASSERT_NE(fp, nullptr);
    
    long stored_time;
    fscanf(fp, "%ld", &stored_time);
    fclose(fp);
    
    time_t now = time(NULL);
    EXPECT_GT(stored_time, now);
}

TEST_F(RateLimitTest, SetTime_OverwriteExisting_Success) {
    // Create initial file
    CreateDenyFile(test_deny_file, 1234567890);
    
    // Overwrite
    int ret = set_time(test_deny_file, CURRENT_TIME);
    
    EXPECT_EQ(ret, 0);
}

// ============================================================================
// Tests for set_time() - Negative Cases
// ============================================================================

TEST_F(RateLimitTest, SetTime_NullPath_Failure) {
    int ret = set_time(NULL, CURRENT_TIME);
    
    EXPECT_EQ(ret, -1);
}

TEST_F(RateLimitTest, SetTime_InvalidDirectory_Failure) {
    int ret = set_time("/nonexistent/dir/file.txt", CURRENT_TIME);
    
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// Tests for is_upload_limit_reached() - Positive Cases
// ============================================================================

TEST_F(RateLimitTest, IsUploadLimitReached_FileNotExist_AllowUpload) {
    int ret = is_upload_limit_reached("/tmp/nonexistent_timestamps.txt");
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_EmptyFile_AllowUpload) {
    FILE* fp = fopen(test_timestamp_file, "w");
    fclose(fp);
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_LessThan10Lines_AllowUpload) {
    CreateTimestampFile(test_timestamp_file, 5);
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_Exactly10Lines_AllowUpload) {
    CreateTimestampFile(test_timestamp_file, 10);
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_11LinesOldTimestamp_AllowUpload) {
    // Create 11 lines with OLD timestamps (outside recovery window)
    // NOTE: Implementation checks LAST line timestamp
    FILE* fp = fopen(test_timestamp_file, "w");
    if (fp) {
        time_t old_time = time(NULL) - 700; // 11+ minutes ago
        for (int i = 0; i < 11; i++) {
            fprintf(fp, "%ld\n", old_time - (i * 10));
        }
        fclose(fp);
    }
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_11LinesRecentTimestamp_BlockUpload) {
    // Create 11 lines with RECENT timestamps (within recovery window)
    // NOTE: Current implementation checks the LAST line for timestamp
    CreateTimestampFile(test_timestamp_file, 11);
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    // Rate limit should be triggered (>10 lines and last timestamp is recent)
    EXPECT_EQ(ret, STOP_UPLOAD);
}

TEST_F(RateLimitTest, IsUploadLimitReached_InvalidContent_AllowUpload) {
    FILE* fp = fopen(test_timestamp_file, "w");
    if (fp) {
        fprintf(fp, "not_a_number\n");
        fclose(fp);
    }
    
    int ret = is_upload_limit_reached(test_timestamp_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Tests for is_upload_limit_reached() - Negative Cases
// ============================================================================

TEST_F(RateLimitTest, IsUploadLimitReached_NullFile_AllowUpload) {
    int ret = is_upload_limit_reached(NULL);
    
    // NULL file should allow upload (fail-safe)
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Tests for is_recovery_time_reached() - Positive Cases
// ============================================================================

TEST_F(RateLimitTest, IsRecoveryTimeReached_FileNotExist_AllowUpload) {
    int ret = is_recovery_time_reached("/tmp/nonexistent_deny.txt");
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsRecoveryTimeReached_ExpiredTime_AllowUpload) {
    // Create deny file with past timestamp
    time_t past_time = time(NULL) - 100;
    CreateDenyFile(test_deny_file, past_time);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsRecoveryTimeReached_FutureTime_BlockUpload) {
    // Create deny file with future timestamp
    time_t future_time = time(NULL) + 1000;
    CreateDenyFile(test_deny_file, future_time);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, STOP_UPLOAD);
}

TEST_F(RateLimitTest, IsRecoveryTimeReached_InvalidContent_AllowUpload) {
    FILE* fp = fopen(test_deny_file, "w");
    if (fp) {
        fprintf(fp, "invalid_timestamp");
        fclose(fp);
    }
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, IsRecoveryTimeReached_EmptyFile_AllowUpload) {
    FILE* fp = fopen(test_deny_file, "w");
    fclose(fp);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Tests for is_recovery_time_reached() - Negative Cases
// ============================================================================

TEST_F(RateLimitTest, IsRecoveryTimeReached_NullFile_AllowUpload) {
    int ret = is_recovery_time_reached(NULL);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Tests for ratelimit_check_unified() - Positive Cases
// ============================================================================

TEST_F(RateLimitTest, RatelimitCheckUnified_NoFiles_AllowUpload) {
    int ret = ratelimit_check_unified(DUMP_TYPE_MINIDUMP);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, RatelimitCheckUnified_RecoveryNotReached_BlockUpload) {
    // Set recovery time in future
    time_t future = time(NULL) + 600;
    CreateDenyFile("/tmp/.deny_dump_uploads_till", future);
    
    int ret = ratelimit_check_unified(DUMP_TYPE_MINIDUMP);
    
    EXPECT_EQ(ret, RATELIMIT_BLOCK);
}

TEST_F(RateLimitTest, RatelimitCheckUnified_UploadLimitReached_BlockUpload) {
    // Create 11 recent timestamps
    CreateTimestampFile("/tmp/.minidump_upload_timestamps", 11);
    
    int ret = ratelimit_check_unified(DUMP_TYPE_MINIDUMP);
    
    // Should block due to rate limit
    EXPECT_EQ(ret, RATELIMIT_BLOCK);
}

TEST_F(RateLimitTest, RatelimitCheckUnified_CoredumpType_AllowUpload) {
    // Coredump should always allow (no rate limiting)
    int ret = ratelimit_check_unified(DUMP_TYPE_COREDUMP);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, RatelimitCheckUnified_BothChecksPassed_AllowUpload) {
    // Recovery time passed and upload limit not reached
    CreateTimestampFile("/tmp/.minidump_upload_timestamps", 5);
    
    int ret = ratelimit_check_unified(DUMP_TYPE_MINIDUMP);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(RateLimitTest, Integration_FullRateLimitCycle) {
    // 1. Initially should allow upload
    EXPECT_EQ(ratelimit_check_unified(DUMP_TYPE_MINIDUMP), ALLOW_UPLOAD);
    
    // 2. Simulate 11 uploads by writing timestamps
    // NOTE: Implementation checks LAST line, so write oldest first, newest last
    FILE* fp = fopen("/tmp/.minidump_upload_timestamps", "w");
    ASSERT_NE(fp, nullptr);
    time_t now = time(NULL);
    for (int i = 10; i >= 0; i--) {
        fprintf(fp, "%ld\n", now - (i * 10));
    }
    fclose(fp);
    
    // 3. Should now block
    EXPECT_EQ(ratelimit_check_unified(DUMP_TYPE_MINIDUMP), RATELIMIT_BLOCK);
    
    // 4. Recovery file should be created
    EXPECT_TRUE(access("/tmp/.deny_dump_uploads_till", F_OK) == 0);
}

TEST_F(RateLimitTest, Integration_RecoveryTimeExpiration) {
    // Set recovery time to just expired
    time_t just_expired = time(NULL) - 1;
    CreateDenyFile("/tmp/.deny_dump_uploads_till", just_expired);
    
    // Should allow upload after expiry
    EXPECT_EQ(ratelimit_check_unified(DUMP_TYPE_MINIDUMP), ALLOW_UPLOAD);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(RateLimitTest, EdgeCase_ExactlyAtRecoveryBoundary) {
    time_t boundary = time(NULL);
    CreateDenyFile("/tmp/.deny_dump_uploads_till", boundary);
    
    int ret = is_recovery_time_reached("/tmp/.deny_dump_uploads_till");
    
    // At boundary (now == deny_until), should STOP (now > deny_until is false)
    EXPECT_EQ(ret, STOP_UPLOAD);
}

TEST_F(RateLimitTest, EdgeCase_ZeroTimestamp) {
    CreateDenyFile(test_deny_file, 0);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

TEST_F(RateLimitTest, EdgeCase_VeryLargeTimestamp) {
    CreateDenyFile(test_deny_file, 9999999999L);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, STOP_UPLOAD);
}

TEST_F(RateLimitTest, EdgeCase_NegativeTimestamp) {
    CreateDenyFile(test_deny_file, -100);
    
    int ret = is_recovery_time_reached(test_deny_file);
    
    EXPECT_EQ(ret, ALLOW_UPLOAD);
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
