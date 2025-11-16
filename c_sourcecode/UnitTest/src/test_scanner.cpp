/* FULL IMPLEMENTATION - GTest unit tests for scanner module */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
    #include "../../../src/scanner/scanner.c"  // Include implementation for testing
}

class ScannerTest : public ::testing::Test {
protected:
    char test_dir[256];
    
    void SetUp() override {
        // Create temporary test directory
        snprintf(test_dir, sizeof(test_dir), "/tmp/scanner_test_%d", getpid());
        mkdir(test_dir, 0755);
    }
    
    void TearDown() override {
        // Cleanup test files and directory
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
        system(cmd);
        scanner_cleanup();
    }
    
    void create_test_file(const char *filename, size_t size = 100) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", test_dir, filename);
        FILE *fp = fopen(path, "wb");
        if (fp) {
            for (size_t i = 0; i < size; i++) {
                fputc('A', fp);
            }
            fclose(fp);
        }
    }
};

TEST_F(ScannerTest, FindDumpsEmptyDirectory) {
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps(test_dir, &dumps, &count);
    
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 0);
}

TEST_F(ScannerTest, FindDumpsWithMinidumps) {
    create_test_file("test1.dmp", 1024);
    create_test_file("test2.dmp", 2048);
    create_test_file("readme.txt", 100);  // Should be ignored
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps(test_dir, &dumps, &count);
    
    EXPECT_EQ(result, 2);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(dumps[0].is_minidump, 1);
    EXPECT_EQ(dumps[1].is_minidump, 1);
}

TEST_F(ScannerTest, FindDumpsWithCoredumps) {
    create_test_file("app.core", 5000);
    create_test_file("core.12345", 3000);
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps(test_dir, &dumps, &count);
    
    EXPECT_EQ(result, 2);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(dumps[0].is_minidump, 0);
    EXPECT_EQ(dumps[1].is_minidump, 0);
}

TEST_F(ScannerTest, FindDumpsMixedTypes) {
    create_test_file("crash.dmp", 1024);
    create_test_file("app.core", 2048);
    create_test_file("test.log", 512);  // Should be ignored
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps(test_dir, &dumps, &count);
    
    EXPECT_EQ(result, 2);
    EXPECT_EQ(count, 2);
}

TEST_F(ScannerTest, SortDumpsByTime) {
    // Create files with known timestamps
    create_test_file("old.dmp", 100);
    sleep(1);
    create_test_file("new.dmp", 100);
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    scanner_find_dumps(test_dir, &dumps, &count);
    scanner_get_sorted_dumps(&dumps, &count);
    
    EXPECT_EQ(count, 2);
    // old.dmp should be first (oldest)
    EXPECT_TRUE(dumps[0].mtime <= dumps[1].mtime);
}

TEST_F(ScannerTest, InvalidParameters) {
    EXPECT_EQ(scanner_find_dumps(NULL, NULL, NULL), -1);
    
    dump_file_t *dumps = NULL;
    EXPECT_EQ(scanner_find_dumps(test_dir, NULL, NULL), -1);
}

TEST_F(ScannerTest, NonExistentDirectory) {
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps("/nonexistent/directory", &dumps, &count);
    
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, MaxDumpsLimit) {
    // Create more than MAX_DUMPS files
    for (int i = 0; i < 150; i++) {
        char filename[64];
        snprintf(filename, sizeof(filename), "dump%03d.dmp", i);
        create_test_file(filename, 100);
    }
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    int result = scanner_find_dumps(test_dir, &dumps, &count);
    
    // Should only find MAX_DUMPS (100)
    EXPECT_EQ(result, 100);
    EXPECT_EQ(count, 100);
}

TEST_F(ScannerTest, FileSizeRecorded) {
    create_test_file("test.dmp", 12345);
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    scanner_find_dumps(test_dir, &dumps, &count);
    
    EXPECT_EQ(count, 1);
    EXPECT_EQ(dumps[0].size, 12345);
}

TEST_F(ScannerTest, CleanupClearsState) {
    create_test_file("test.dmp", 100);
    
    dump_file_t *dumps = NULL;
    int count = 0;
    
    scanner_find_dumps(test_dir, &dumps, &count);
    EXPECT_EQ(count, 1);
    
    scanner_cleanup();
    
    // After cleanup, internal state should be cleared
    dump_file_t *dumps2 = NULL;
    int count2 = 0;
    scanner_get_sorted_dumps(&dumps2, &count2);
    EXPECT_EQ(count2, 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
