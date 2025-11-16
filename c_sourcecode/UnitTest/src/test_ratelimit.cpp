/* FULL IMPLEMENTATION - GTest unit tests for rate limiter module */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

extern "C" {
    #include "../../../src/ratelimit/ratelimit.c"  // Include implementation for testing
}

class RateLimitTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset rate limiter before each test
        ratelimit_reset();
        unlink(RATE_LIMIT_FILE);
    }
    
    void TearDown() override {
        // Cleanup rate limit file
        unlink(RATE_LIMIT_FILE);
        state_loaded = 0;
        memset(&state, 0, sizeof(state));
    }
};

TEST_F(RateLimitTest, InitialCheckPasses) {
    int result = ratelimit_check();
    EXPECT_EQ(result, 0);
    EXPECT_EQ(ratelimit_get_count(), 0);
}

TEST_F(RateLimitTest, RecordUploads) {
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(ratelimit_record_upload(), 0);
    }
    
    EXPECT_EQ(ratelimit_get_count(), 5);
}

TEST_F(RateLimitTest, RateLimitEnforced) {
    // Record MAX_UPLOADS uploads
    for (int i = 0; i < MAX_UPLOADS; i++) {
        ratelimit_record_upload();
    }
    
    // Next check should fail (rate limited)
    EXPECT_EQ(ratelimit_check(), -1);
    EXPECT_EQ(ratelimit_get_count(), MAX_UPLOADS);
}

TEST_F(RateLimitTest, RateLimitNotEnforced) {
    // Record less than MAX_UPLOADS
    for (int i = 0; i < MAX_UPLOADS - 1; i++) {
        ratelimit_record_upload();
    }
    
    // Next check should pass
    EXPECT_EQ(ratelimit_check(), 0);
    EXPECT_EQ(ratelimit_get_count(), MAX_UPLOADS - 1);
}

TEST_F(RateLimitTest, CrashloopDetection) {
    // Simulate rapid uploads (crashloop scenario)
    for (int i = 0; i < CRASHLOOP_THRESHOLD; i++) {
        ratelimit_check();
        ratelimit_record_upload();
    }
    
    // Should enter recovery mode
    EXPECT_EQ(ratelimit_is_recovery_mode(), 1);
    
    // Further checks should fail
    EXPECT_EQ(ratelimit_check(), -1);
}

TEST_F(RateLimitTest, RecoveryModeBlocks) {
    // Force recovery mode
    state.recovery_mode = 1;
    state.count = 1;
    state.timestamps[0] = time(NULL);
    state_loaded = 1;
    
    // Check should fail while in recovery
    EXPECT_EQ(ratelimit_check(), -1);
}

TEST_F(RateLimitTest, ExitRecoveryMode) {
    // Enter recovery mode
    state.recovery_mode = 1;
    state.count = 1;
    state.timestamps[0] = time(NULL) - TIME_WINDOW_SECONDS - 1;  // Old timestamp
    state_loaded = 1;
    
    // Check should succeed and exit recovery
    EXPECT_EQ(ratelimit_check(), 0);
    EXPECT_EQ(ratelimit_is_recovery_mode(), 0);
}

TEST_F(RateLimitTest, ResetClearsState) {
    // Record some uploads
    for (int i = 0; i < 5; i++) {
        ratelimit_record_upload();
    }
    
    EXPECT_EQ(ratelimit_get_count(), 5);
    
    // Reset
    ratelimit_reset();
    
    EXPECT_EQ(ratelimit_get_count(), 0);
    EXPECT_EQ(ratelimit_is_recovery_mode(), 0);
}

TEST_F(RateLimitTest, StatePersistence) {
    // Record uploads
    for (int i = 0; i < 3; i++) {
        ratelimit_record_upload();
    }
    
    // Clear in-memory state
    state_loaded = 0;
    memset(&state, 0, sizeof(state));
    
    // Load from file
    EXPECT_EQ(ratelimit_get_count(), 3);  // Should load from file
}

TEST_F(RateLimitTest, OldTimestampsCleaned) {
    // Add old timestamps (outside time window)
    state.count = 3;
    state.timestamps[0] = time(NULL) - TIME_WINDOW_SECONDS - 100;
    state.timestamps[1] = time(NULL) - TIME_WINDOW_SECONDS - 50;
    state.timestamps[2] = time(NULL);  // Current
    state_loaded = 1;
    
    // Get count should clean old timestamps
    EXPECT_EQ(ratelimit_get_count(), 1);  // Only current timestamp remains
}

TEST_F(RateLimitTest, MaxUploadsRecording) {
    // Try to record more than MAX_UPLOADS
    for (int i = 0; i < MAX_UPLOADS + 5; i++) {
        ratelimit_record_upload();
    }
    
    // Should cap at MAX_UPLOADS
    EXPECT_EQ(ratelimit_get_count(), MAX_UPLOADS);
}

TEST_F(RateLimitTest, CrashloopCounterReset) {
    // Simulate uploads spaced out
    state.crashloop_count = 2;
    state.last_crashloop_check = time(NULL) - CRASHLOOP_WINDOW_SECONDS - 10;
    state_loaded = 1;
    
    // Next check should reset counter
    ratelimit_check();
    
    EXPECT_EQ(state.crashloop_count, 1);  // Reset to 1
}

TEST_F(RateLimitTest, MultipleChecksBeforeRecord) {
    // Multiple checks should not increase crashloop counter excessively
    for (int i = 0; i < 3; i++) {
        ratelimit_check();
    }
    
    EXPECT_EQ(ratelimit_is_recovery_mode(), 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
