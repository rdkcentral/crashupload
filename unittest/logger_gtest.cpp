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
 * @file logger_gtest.cpp
 * @brief Minimal GTest suite for logger functions
 * 
 * Tests logger initialization and cleanup
 */

#include <gtest/gtest.h>

extern "C" {
int logger_init(void);
void logger_exit(void);
void logger_error(const char *fmt, ...);
void logger_warn(const char *fmt, ...);
void logger_info(const char *fmt, ...);
}

// ============================================================================
// Test Fixture
// ============================================================================

class LoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup for each test
    }

    void TearDown() override {
        // Cleanup after each test
    }
};

// ============================================================================
// Tests for logger_init()
// ============================================================================

TEST_F(LoggerTest, LoggerInit_Success) {
    int result = logger_init();
    EXPECT_EQ(result, 0);
}

TEST_F(LoggerTest, LoggerInit_MultipleCallsSucceed) {
    int result1 = logger_init();
    int result2 = logger_init();
    
    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
}

// ============================================================================
// Tests for logger_exit()
// ============================================================================

TEST_F(LoggerTest, LoggerExit_AfterInit_Success) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_exit();
    });
}

TEST_F(LoggerTest, LoggerExit_WithoutInit_NoError) {
    EXPECT_NO_THROW({
        logger_exit();
    });
}

TEST_F(LoggerTest, LoggerExit_MultipleCalls_NoError) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_exit();
        logger_exit();
    });
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(LoggerTest, Integration_InitAndExit) {
    EXPECT_EQ(logger_init(), 0);
    
    EXPECT_NO_THROW({
        logger_exit();
    });
}

TEST_F(LoggerTest, Integration_FullCycle_AllLogLevels) {
    EXPECT_EQ(logger_init(), 0);
    
    // Test all log levels don't crash
    EXPECT_NO_THROW({
        logger_error("Test error message");
        logger_warn("Test warning message");
        logger_info("Test info message");
    });
    
    EXPECT_NO_THROW({
        logger_exit();
    });
}

// ============================================================================
// Tests for logger_error()
// ============================================================================

TEST_F(LoggerTest, LoggerError_SimpleMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_error("Simple error message");
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerError_FormattedMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_error("Error code: %d, message: %s", 42, "test");
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerError_WithoutInit_NoSegfault) {
    // Should not crash even without init
    EXPECT_NO_THROW({
        logger_error("Error without init");
    });
}

// ============================================================================
// Tests for logger_warn()
// ============================================================================

TEST_F(LoggerTest, LoggerWarn_SimpleMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_warn("Simple warning message");
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerWarn_FormattedMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_warn("Warning: %s at line %d", "file.c", 123);
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerWarn_WithoutInit_NoSegfault) {
    // Should not crash even without init
    EXPECT_NO_THROW({
        logger_warn("Warning without init");
    });
}

// ============================================================================
// Tests for logger_info()
// ============================================================================

TEST_F(LoggerTest, LoggerInfo_SimpleMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_info("Simple info message");
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerInfo_FormattedMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_info("Info: processed %d files in %d seconds", 100, 5);
    });
    
    logger_exit();
}

TEST_F(LoggerTest, LoggerInfo_WithoutInit_NoSegfault) {
    // Should not crash even without init
    EXPECT_NO_THROW({
        logger_info("Info without init");
    });
}

TEST_F(LoggerTest, LoggerInfo_LongMessage) {
    logger_init();
    
    EXPECT_NO_THROW({
        logger_info("This is a very long message that tests the buffer handling: %s %s %s %s %s",
                   "word1", "word2", "word3", "word4", "word5");
    });
    
    logger_exit();
}

TEST_F(LoggerTest, Integration_MultipleSessions) {
    // First session
    logger_init();
    logger_exit();
    
    // Second session
    logger_init();
    logger_exit();
    
    SUCCEED();
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
