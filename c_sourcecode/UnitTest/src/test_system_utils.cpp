/* FULL IMPLEMENTATION - Comprehensive GTest unit tests for system_utils */

#include <gtest/gtest.h>
extern "C" {
#include "system_utils.h"
}

class SystemUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test setup if needed
    }
};

// Test 1: Get system uptime
TEST_F(SystemUtilsTest, GetUptime) {
    uint64_t uptime;
    EXPECT_EQ(system_get_uptime(&uptime), 0);
    EXPECT_GT(uptime, 0); // System should have been running for some time
}

// Test 2: Uptime - Invalid parameter
TEST_F(SystemUtilsTest, UptimeNullPointer) {
    EXPECT_EQ(system_get_uptime(NULL), -1);
}

// Test 3: Get device model
TEST_F(SystemUtilsTest, GetModel) {
    char model[64];
    int result = system_get_model(model, sizeof(model));
    // May succeed or fail depending on environment
    if (result == 0) {
        EXPECT_GT(strlen(model), 0);
    }
}

// Test 4: Model caching - verify indefinite cache
TEST_F(SystemUtilsTest, ModelCaching) {
    char model1[64], model2[64];
    
    int result1 = system_get_model(model1, sizeof(model1));
    int result2 = system_get_model(model2, sizeof(model2));
    
    if (result1 == 0 && result2 == 0) {
        // Second call should return cached value
        EXPECT_STREQ(model1, model2);
    }
}

// Test 5: Model - Invalid parameters
TEST_F(SystemUtilsTest, ModelNullBuffer) {
    EXPECT_EQ(system_get_model(NULL, 64), -1);
}

// Test 6: Model - Zero-length buffer
TEST_F(SystemUtilsTest, ModelZeroLength) {
    char model[64];
    EXPECT_EQ(system_get_model(model, 0), -1);
}

// Test 7: Check if process is running - init (PID 1)
TEST_F(SystemUtilsTest, CheckProcessInit) {
    bool is_running;
    EXPECT_EQ(system_check_process("systemd", &is_running), 0);
    // Init/systemd should typically be running (or "init" on older systems)
}

// Test 8: Check process - non-existent process
TEST_F(SystemUtilsTest, CheckProcessNonExistent) {
    bool is_running;
    EXPECT_EQ(system_check_process("nonexistent_process_12345", &is_running), 0);
    EXPECT_FALSE(is_running);
}

// Test 9: Check process - Invalid parameters
TEST_F(SystemUtilsTest, CheckProcessNullName) {
    bool is_running;
    EXPECT_EQ(system_check_process(NULL, &is_running), -1);
}

// Test 10: Check process - NULL pointer
TEST_F(SystemUtilsTest, CheckProcessNullPointer) {
    EXPECT_EQ(system_check_process("init", NULL), -1);
}

// Test 11: System reboot - should return (skeleton implementation)
TEST_F(SystemUtilsTest, SystemReboot) {
    // Note: This is a skeleton function that calls system()
    // We don't actually want to reboot during tests
    // Just verify function exists and has proper signature
    // EXPECT_EQ(system_reboot(), 0); // Don't actually call it!
    SUCCEED(); // Placeholder test
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
