/* FULL IMPLEMENTATION - Comprehensive GTest unit tests for file_utils */

#include <gtest/gtest.h>
#include <fstream>
extern "C" {
#include "file_utils.h"
}

class FileUtilsTest : public ::testing::Test {
protected:
    std::string test_file = "/tmp/test_file_utils.txt";
    
    void SetUp() override {
        // Create a test file
        std::ofstream ofs(test_file);
        ofs << "Test content for file_utils\n";
        ofs.close();
    }
    
    void TearDown() override {
        // Clean up test file
        std::remove(test_file.c_str());
    }
};

// Test 1: Calculate SHA1 of file
TEST_F(FileUtilsTest, CalculateSHA1) {
    char hash[41];
    EXPECT_EQ(file_get_sha1(test_file.c_str(), hash, sizeof(hash)), 0);
    EXPECT_EQ(strlen(hash), 40); // SHA1 is 40 hex chars
}

// Test 2: SHA1 - Consistent hash for same content
TEST_F(FileUtilsTest, SHA1Consistency) {
    char hash1[41], hash2[41];
    EXPECT_EQ(file_get_sha1(test_file.c_str(), hash1, sizeof(hash1)), 0);
    EXPECT_EQ(file_get_sha1(test_file.c_str(), hash2, sizeof(hash2)), 0);
    EXPECT_STREQ(hash1, hash2);
}

// Test 3: SHA1 - Invalid parameters
TEST_F(FileUtilsTest, SHA1NullPath) {
    char hash[41];
    EXPECT_EQ(file_get_sha1(NULL, hash, sizeof(hash)), -1);
}

// Test 4: SHA1 - NULL buffer
TEST_F(FileUtilsTest, SHA1NullBuffer) {
    EXPECT_EQ(file_get_sha1(test_file.c_str(), NULL, 41), -1);
}

// Test 5: SHA1 - Insufficient buffer
TEST_F(FileUtilsTest, SHA1InsufficientBuffer) {
    char hash[20];
    EXPECT_EQ(file_get_sha1(test_file.c_str(), hash, sizeof(hash)), -1);
}

// Test 6: SHA1 - Non-existent file
TEST_F(FileUtilsTest, SHA1NonExistentFile) {
    char hash[41];
    EXPECT_EQ(file_get_sha1("/nonexistent/file.txt", hash, sizeof(hash)), -1);
}

// Test 7: Get file modification time
TEST_F(FileUtilsTest, GetMtime) {
    char mtime[20];
    EXPECT_EQ(file_get_mtime_formatted(test_file.c_str(), mtime, sizeof(mtime)), 0);
    EXPECT_GT(strlen(mtime), 0);
    // Format: YYYY-MM-DD-HH-MM-SS (19 chars)
    EXPECT_EQ(strlen(mtime), 19);
}

// Test 8: Mtime - Invalid parameters
TEST_F(FileUtilsTest, MtimeNullPath) {
    char mtime[20];
    EXPECT_EQ(file_get_mtime_formatted(NULL, mtime, sizeof(mtime)), -1);
}

// Test 9: File exists - existing file
TEST_F(FileUtilsTest, FileExists) {
    EXPECT_TRUE(file_exists(test_file.c_str()));
}

// Test 10: File exists - non-existent file
TEST_F(FileUtilsTest, FileNotExists) {
    EXPECT_FALSE(file_exists("/nonexistent/file.txt"));
}

// Test 11: File exists - NULL path
TEST_F(FileUtilsTest, FileExistsNullPath) {
    EXPECT_FALSE(file_exists(NULL));
}

// Test 12: Get file size
TEST_F(FileUtilsTest, GetFileSize) {
    uint64_t size;
    EXPECT_EQ(file_get_size(test_file.c_str(), &size), 0);
    EXPECT_GT(size, 0);
}

// Test 13: Get file size - Invalid parameters
TEST_F(FileUtilsTest, GetFileSizeNullPath) {
    uint64_t size;
    EXPECT_EQ(file_get_size(NULL, &size), -1);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
