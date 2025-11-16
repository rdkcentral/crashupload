/* FULL IMPLEMENTATION - GTest unit tests for archive module */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
    #include "../../../src/archive/archive.c"  // Include implementation for testing
}

class ArchiveTest : public ::testing::Test {
protected:
    char test_dir[256];
    char test_file[512];
    char archive_path[512];
    
    void SetUp() override {
        snprintf(test_dir, sizeof(test_dir), "/tmp/archive_test_%d", getpid());
        mkdir(test_dir, 0755);
        
        snprintf(test_file, sizeof(test_file), "%s/test_input.txt", test_dir);
        snprintf(archive_path, sizeof(archive_path), "%s/test.tgz", test_dir);
        
        // Create test input file
        FILE *fp = fopen(test_file, "wb");
        if (fp) {
            fprintf(fp, "Test content for archiving\n");
            fclose(fp);
        }
    }
    
    void TearDown() override {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
        system(cmd);
    }
};

TEST_F(ArchiveTest, CreateArchiveBasic) {
    int result = archive_create(test_file, archive_path);
    
    EXPECT_EQ(result, 0);
    
    // Verify archive was created
    struct stat st;
    EXPECT_EQ(stat(archive_path, &st), 0);
    EXPECT_GT(st.st_size, 0);
}

TEST_F(ArchiveTest, InvalidParameters) {
    EXPECT_EQ(archive_create(NULL, archive_path), -1);
    EXPECT_EQ(archive_create(test_file, NULL), -1);
    EXPECT_EQ(archive_create(NULL, NULL), -1);
}

TEST_F(ArchiveTest, NonExistentInput) {
    int result = archive_create("/nonexistent/file.txt", archive_path);
    EXPECT_EQ(result, -1);
}

TEST_F(ArchiveTest, GenerateFilenameBasic) {
    char output[512];
    
    int result = archive_generate_filename(
        "/tmp/crash.dmp",
        "AA:BB:CC:DD:EE:FF",
        "XG1v4",
        "abc123def456",
        output,
        sizeof(output)
    );
    
    EXPECT_EQ(result, 0);
    EXPECT_TRUE(strstr(output, "AABBCCDDEEFF") != NULL);  // MAC without colons
    EXPECT_TRUE(strstr(output, "XG1v4") != NULL);         // Model
    EXPECT_TRUE(strstr(output, "abc123def456") != NULL);  // SHA1
    EXPECT_TRUE(strstr(output, "crash.dmp") != NULL);     // Basename
    EXPECT_TRUE(strstr(output, ".tgz") != NULL);          // Extension
}

TEST_F(ArchiveTest, GenerateFilenameWithTimestamp) {
    char output[512];
    
    archive_generate_filename(
        "/var/dumps/test.core",
        "11:22:33:44:55:66",
        "ModelX",
        "sha1hash",
        output,
        sizeof(output)
    );
    
    // Should contain timestamp in format datYYYY-MM-DD-HH-MM-SS
    EXPECT_TRUE(strstr(output, "dat") != NULL);
    EXPECT_TRUE(strstr(output, "mac112233445566") != NULL);
}

TEST_F(ArchiveTest, GenerateFilenameLongInput) {
    char output[512];
    char long_path[256];
    
    // Create a very long filename
    snprintf(long_path, sizeof(long_path), 
             "/tmp/very_long_filename_that_exceeds_ecryptfs_limit_of_135_characters_"
             "and_should_be_truncated_appropriately_to_avoid_filesystem_errors.dmp");
    
    int result = archive_generate_filename(
        long_path,
        "AA:BB:CC:DD:EE:FF",
        "VeryLongModelNameThatExceedsLimits",
        "0123456789abcdef0123456789abcdef01234567",
        output,
        sizeof(output)
    );
    
    EXPECT_EQ(result, 0);
    // Should be truncated to 135 chars for ecryptfs compatibility
    EXPECT_LE(strlen(output), 135);
    // Should still end with .tgz
    EXPECT_TRUE(strstr(output + strlen(output) - 4, ".tgz") != NULL);
}

TEST_F(ArchiveTest, GenerateFilenameNullParameters) {
    char output[512];
    
    EXPECT_EQ(archive_generate_filename(NULL, "mac", "model", "sha", output, 512), -1);
    EXPECT_EQ(archive_generate_filename("path", NULL, "model", "sha", output, 512), -1);
    EXPECT_EQ(archive_generate_filename("path", "mac", NULL, "sha", output, 512), -1);
    EXPECT_EQ(archive_generate_filename("path", "mac", "model", "sha", NULL, 512), -1);
}

TEST_F(ArchiveTest, GenerateFilenameRemovesColons) {
    char output[512];
    
    archive_generate_filename(
        "/tmp/test.dmp",
        "11:22:33:44:55:66",
        "Model",
        "sha",
        output,
        sizeof(output)
    );
    
    // MAC address should not have colons in output
    EXPECT_TRUE(strstr(output, "mac112233445566") != NULL);
    EXPECT_TRUE(strstr(output, "11:22:33") == NULL);
}

TEST_F(ArchiveTest, GenerateFilenameWithBasenameOnly) {
    char output[512];
    
    archive_generate_filename(
        "simple.dmp",  // No path
        "AA:BB:CC:DD:EE:FF",
        "Model",
        "sha1",
        output,
        sizeof(output)
    );
    
    EXPECT_TRUE(strstr(output, "simple.dmp") != NULL);
}

TEST_F(ArchiveTest, GenerateFilenameNullOptionals) {
    char output[512];
    
    // SHA1 can be NULL
    int result = archive_generate_filename(
        "/tmp/test.dmp",
        "AA:BB:CC:DD:EE:FF",
        "Model",
        NULL,  // NULL SHA1
        output,
        sizeof(output)
    );
    
    EXPECT_EQ(result, 0);
    EXPECT_TRUE(strstr(output, "unknown") != NULL);  // Should use "unknown"
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
