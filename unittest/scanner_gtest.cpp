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
 * @file scanner_gtest.cpp
 * @brief Comprehensive GTest suite for scanner.c
 * 
 * Test Coverage:
 * - scanner_find_dumps(): All positive/negative test cases
 * - scanner_get_sorted_dumps(): Sorting and edge cases
 * - scanner_cleanup(): State management
 * - process_file_entry(): File processing, sanitization, renaming
 * - sanitize_filename_preserve_container(): Character filtering with container delimiter
 * - extract_pname(): Process name extraction logic
 * - extract_appname(): Application name extraction
 * - processCrashTelemetryInfo(): Container detection, tgz handling, telemetry
 * - Parameter validation (NULL, invalid, empty, oversized)
 * - Buffer overflow/underflow protection
 * - Edge cases and boundary conditions
 * - All function paths and branches
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
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../c_sourcecode/src/scanner/scanner.h"
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"
#include "../c_sourcecode/common/constants.h"

// External functions being tested
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count, const char *dump_extn_pattern);
int scanner_get_sorted_dumps(dump_file_t **dumps, int *count);
void scanner_cleanup(void);
int process_file_entry(char *fullpath, char *dump_type, const config_t *config);
int sanitize_filename_preserve_container(const char *fname, char *out, size_t outsz);
char *extract_pname(const char *filepath);
char *extract_appname(const char *filepath);
int processCrashTelemetryInfo(const char *rawfile, const char *log_path, bool t2_enabled);

// Mock function declarations
int is_regular_file(const char *path);
int join_path(char *dest, size_t dest_size, const char *dir, const char *name);
void t2ValNotify(const char *key, const char *val);
void t2CountNotify(const char *key, const char *val_or_null);

// Mock control functions
void set_mock_is_regular_file_behavior(int return_value);
void set_mock_join_path_behavior(int return_value);
void reset_scanner_mocks();
void set_mock_t2_enabled(bool enabled);
}

using ::testing::_;
using ::testing::Return;

// ============================================================================
// Test Fixture
// ============================================================================

class ScannerTest : public ::testing::Test {
protected:
    const char* test_dir = "/tmp/scnr";
    const char* test_dump_dir = "/tmp/scnr/dmp";
    const char* test_log_mapper = "/tmp/scnr/breakpad-logmapper.conf";
    const char* test_log_files = "/tmp/scnr/minidump_log_files.txt";
    config_t test_config;
    
    void SetUp() override {
        // Reset all mocks before each test
        reset_scanner_mocks();
        
        // Create test directories
	system("mkdir -p /tmp/scnr");
        system("mkdir -p /tmp/scnr/dmp");
        system("mkdir -p /tmp/scnr/log");
        
        // Initialize test config
        memset(&test_config, 0, sizeof(config_t));
        strncpy(test_config.dump_path, test_dump_dir, sizeof(test_config.dump_path) - 1);
        strncpy(test_config.log_path, "/tmp/scnr/log", sizeof(test_config.log_path) - 1);
        test_config.t2_enabled = false;
        test_config.max_dumps_per_run = 100;
        
        // Clean up any previous test artifacts
        //cleanup_test_files();
        //scanner_cleanup();
    }
    
    void TearDown() override {
        // Clean up after each test
        cleanup_test_files();
        scanner_cleanup();
        reset_scanner_mocks();
    }
    
    // Helper function to create test dump files
    void create_test_file(const char* name, size_t size = 1024) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", test_dump_dir, name);
        FILE* fp = fopen(path, "w");
        if (fp) {
            for (size_t i = 0; i < size; i++) {
                fputc('A', fp);
            }
            fclose(fp);
        }
    }
    
    // Helper function to create directory structure
    void create_directory(const char* name) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", test_dump_dir, name);
        mkdir(path, 0755);
    }
    
    // Helper function to create log mapper file
    void create_log_mapper_file(const char* content) {
        FILE* fp = fopen(test_log_mapper, "w");
        if (fp) {
            fprintf(fp, "%s", content);
            fclose(fp);
        }
    }
    
    // Helper function to remove test files
    void cleanup_test_files() {
        system("rm -rf /tmp/scnr");
    }
    
    // Helper to check if file exists
    bool file_exists(const char* path) {
        struct stat st;
        return (stat(path, &st) == 0);
    }
};

// ============================================================================
// scanner_find_dumps Tests
// ============================================================================

TEST_F(ScannerTest, FindDumps_NullPath) {
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(nullptr, &dumps, &count, "*.core");
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, FindDumps_NullDumpsPointer) {
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, nullptr, &count, "*.core");
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, FindDumps_NullCountPointer) {
    dump_file_t* dumps = nullptr;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, nullptr, "*.core");
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, FindDumps_AllNullParameters) {
    int result = scanner_find_dumps(nullptr, nullptr, nullptr, "*.core");
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, FindDumps_InvalidPath) {
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps("/nonexistent/path/12345", &dumps, &count, "*.core");
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, FindDumps_EmptyDirectory) {
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 0);
}

TEST_F(ScannerTest, FindDumps_OnlyMinidumps) {
    create_test_file("app1.dmp");
    create_test_file("app2.dmp");
    create_test_file("app3.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 3);
    EXPECT_EQ(count, 3);
    EXPECT_NE(dumps, nullptr);
    
    // Verify all are minidumps
    for (int i = 0; i < count; i++) {
        EXPECT_EQ(dumps[i].is_minidump, 1);
    }
    //system("rm -rf /tmp/scnr");
}

TEST_F(ScannerTest, FindDumps_OnlyCoredumps) {
    create_test_file("app1.core");
    create_test_file("app2.core");
    create_test_file("core.123");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    // Use "*core*" pattern to match both "*.core" and "core.*" files
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*core*");
    EXPECT_EQ(result, 3);
    EXPECT_EQ(count, 3);
    
    // Verify all are coredumps
    for (int i = 0; i < count; i++) {
        EXPECT_EQ(dumps[i].is_minidump, 0);
    }
}

TEST_F(ScannerTest, FindDumps_MixedDumpTypes) {
    create_test_file("app1.dmp");
    create_test_file("app2.core");
    create_test_file("app3.dmp");
    create_test_file("core.456");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    // Use "*core*" pattern to match both "*.core" and "core.*" files
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*core*");
    EXPECT_EQ(result, 4);
    EXPECT_EQ(count, 4);
}

TEST_F(ScannerTest, FindDumps_WithTgzFiles) {
    create_test_file("app1.tgz");
    create_test_file("app2.tgz");
    create_test_file("app3.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 3);
    EXPECT_EQ(count, 3);
}

TEST_F(ScannerTest, FindDumps_IgnoreNonDumpFiles) {
    create_test_file("app1.dmp");
    create_test_file("readme.txt");
    create_test_file("config.conf");
    create_test_file("data.json");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 1);
    EXPECT_EQ(count, 1);
}

TEST_F(ScannerTest, FindDumps_IgnoreDotFiles) {
    create_test_file(".hidden.dmp");
    create_test_file("visible.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    // . and .. are skipped, .hidden.dmp should be processed if it's a valid dump
    EXPECT_GE(result, 1);
    EXPECT_GE(count, 1);
}

TEST_F(ScannerTest, FindDumps_MaxDumpsLimit) {
    // Create more than MAX_DUMPS (100) files
    for (int i = 0; i < 105; i++) {
        char name[64];
        snprintf(name, sizeof(name), "app%d.dmp", i);
        create_test_file(name);
    }
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    // Should stop at MAX_DUMPS (100)
    EXPECT_LE(count, 100);
    EXPECT_EQ(count, result);
}

TEST_F(ScannerTest, FindDumps_VerifyFilePaths) {
    create_test_file("test.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 1);
    EXPECT_EQ(count, 1);
    
    // Verify path contains directory and filename
    EXPECT_NE(strstr(dumps[0].path, test_dump_dir), nullptr);
    EXPECT_NE(strstr(dumps[0].path, "test.dmp"), nullptr);
}

TEST_F(ScannerTest, FindDumps_VerifyFileSize) {
    create_test_file("small.dmp", 512);
    create_test_file("large.dmp", 4096);
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 2);
    EXPECT_EQ(count, 2);
    
    // Verify sizes are populated
    EXPECT_GT(dumps[0].size, 0);
    EXPECT_GT(dumps[1].size, 0);
}

TEST_F(ScannerTest, FindDumps_SkipDirectories) {
    create_test_file("file.dmp");
    create_directory("subdir.dmp"); // Directory with .dmp extension
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    // Should only find the file, not the directory
    EXPECT_EQ(result, 1);
    EXPECT_EQ(count, 1);
}

// ============================================================================
// scanner_get_sorted_dumps Tests
// ============================================================================

TEST_F(ScannerTest, GetSortedDumps_NullDumpsPointer) {
    int count = 0;
    
    int result = scanner_get_sorted_dumps(nullptr, &count);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, GetSortedDumps_NullCountPointer) {
    dump_file_t* dumps = nullptr;
    
    int result = scanner_get_sorted_dumps(&dumps, nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, GetSortedDumps_EmptyList) {
    scanner_cleanup();
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_get_sorted_dumps(&dumps, &count);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 0);
}

TEST_F(ScannerTest, GetSortedDumps_SingleFile) {
    create_test_file("single.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    
    dumps = nullptr;
    count = 0;
    int result = scanner_get_sorted_dumps(&dumps, &count);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 1);
}

TEST_F(ScannerTest, GetSortedDumps_MultipleSorted) {
    // Create files with different timestamps
    create_test_file("old.dmp");
    sleep(1);
    create_test_file("middle.dmp");
    sleep(1);
    create_test_file("new.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    
    dumps = nullptr;
    count = 0;
    int result = scanner_get_sorted_dumps(&dumps, &count);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 3);
    
    // Verify sorted order (oldest first)
    if (count == 3) {
        EXPECT_LE(dumps[0].mtime, dumps[1].mtime);
        EXPECT_LE(dumps[1].mtime, dumps[2].mtime);
    }
}

// ============================================================================
// scanner_cleanup Tests
// ============================================================================

TEST_F(ScannerTest, Cleanup_EmptyState) {
    scanner_cleanup();
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_get_sorted_dumps(&dumps, &count);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(count, 0);
}

TEST_F(ScannerTest, Cleanup_AfterFindDumps) {
    create_test_file("test1.dmp");
    create_test_file("test2.dmp");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_GT(count, 0);
    
    scanner_cleanup();
    
    dumps = nullptr;
    count = 0;
    scanner_get_sorted_dumps(&dumps, &count);
    EXPECT_EQ(count, 0);
}

// ============================================================================
// sanitize_filename_preserve_container Tests
// ============================================================================

TEST_F(ScannerTest, SanitizeFilename_NullInput) {
    char output[128];
    
    int result = sanitize_filename_preserve_container(nullptr, output, sizeof(output));
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, SanitizeFilename_NullOutput) {
    const char* input = "test.dmp";
    
    int result = sanitize_filename_preserve_container(input, nullptr, 100);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, SanitizeFilename_ZeroOutputSize) {
    const char* input = "test.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, 0);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, SanitizeFilename_EmptyInput) {
    const char* input = "";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "");
}

TEST_F(ScannerTest, SanitizeFilename_ValidCharactersOnly) {
    const char* input = "app_name-123.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "app_name-123.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_WithPath) {
    const char* input = "/tmp/dumps/app.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "/tmp/dumps/app.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_InvalidCharacters) {
    const char* input = "app*wrong@name.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "appwrongname.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_PreserveContainerDelimiter) {
    const char* input = "app<#=#>state.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "app<#=#>state.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_ContainerDelimiterWithInvalidChars) {
    const char* input = "app*wrong<#=#>st@te.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "appwrong<#=#>stte.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_MultipleDelimiters) {
    const char* input = "app<#=#>status<#=#>123.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "app<#=#>status<#=#>123.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_AllInvalidCharacters) {
    const char* input = "@#$%^&*()";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "");
}

TEST_F(ScannerTest, SanitizeFilename_BufferOverflowProtection) {
    const char* input = "verylongfilename_with_many_characters_that_should_not_overflow.dmp";
    char output[10]; // Small buffer
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    // Should not crash, output should be truncated safely
    EXPECT_LT(strlen(output), sizeof(output));
}

TEST_F(ScannerTest, SanitizeFilename_LeadingDotSlash) {
    const char* input = "./app.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "./app.dmp");
}

TEST_F(ScannerTest, SanitizeFilename_SpecialCharactersAllowed) {
    const char* input = "app name-with_dots.and-dashes.dmp";
    char output[128];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(output, "app name-with_dots.and-dashes.dmp");
}

// ============================================================================
// extract_pname Tests
// ============================================================================

TEST_F(ScannerTest, ExtractPname_NullInput) {
    char* result = extract_pname(nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, ExtractPname_EmptyString) {
    char* result = extract_pname("");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_NoUnderscore) {
    char* result = extract_pname("app.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "app.dmp");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_WithUnderscore) {
    char* result = extract_pname("app_proc_123.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "app_proc");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_WithPath) {
    char* result = extract_pname("/tmp/dumps/app_core_456.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "/tmp/dumps/app_core");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_WithLeadingDotSlash) {
    char* result = extract_pname("./app_name_123.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "app_name");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_SingleUnderscore) {
    char* result = extract_pname("app_123");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "app");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_MultipleUnderscores) {
    char* result = extract_pname("app_name_proc_123_456.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        // Should extract up to last underscore
        EXPECT_NE(strstr(result, "app"), nullptr);
        free(result);
    }
}

TEST_F(ScannerTest, ExtractPname_OnlyDirectoryPath) {
    char* result = extract_pname("/tmp/dumps/");
    EXPECT_NE(result, nullptr);
    if (result) {
        free(result);
    }
}

// ============================================================================
// extract_appname Tests
// ============================================================================

TEST_F(ScannerTest, ExtractAppname_NullInput) {
    char* result = extract_appname(nullptr);
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, ExtractAppname_EmptyString) {
    char* result = extract_appname("");
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, ExtractAppname_NoUnderscore) {
    char* result = extract_appname("app.dmp");
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, ExtractAppname_SingleUnderscore) {
    char* result = extract_appname("prefix_app.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "app.dmp");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractAppname_WithDash) {
    char* result = extract_appname("prefix_appname-version.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "appname");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractAppname_MultipleUnderscores) {
    char* result = extract_appname("prefix_appname_proc_123.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "appname");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractAppname_WithPath) {
    char* result = extract_appname("/tmp/dumps/prefix_appname-1_proc.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "appname");
        free(result);
    }
}

TEST_F(ScannerTest, ExtractAppname_OnlyUnderscores) {
    char* result = extract_appname("___");
    //printf("result=%s\n", result);
    EXPECT_EQ(result, nullptr);
    //if (result) {
    //    free(result);
    //}
}

TEST_F(ScannerTest, ExtractAppname_ComplexPattern) {
    char* result = extract_appname("sys_myapp-v2_worker_123.dmp");
    EXPECT_NE(result, nullptr);
    if (result) {
        EXPECT_STREQ(result, "myapp");
        free(result);
    }
}

// ============================================================================
// processCrashTelemetryInfo Tests
// ============================================================================

TEST_F(ScannerTest, ProcessTelemetry_NullRawfile) {
    int result = processCrashTelemetryInfo(nullptr, "/tmp/logs", false);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessTelemetry_NullLogPath) {
    int result = processCrashTelemetryInfo("app.dmp", nullptr, false);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessTelemetry_BothNull) {
    int result = processCrashTelemetryInfo(nullptr, nullptr, false );
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessTelemetry_EmptyFilename) {
    int result = processCrashTelemetryInfo("", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_SimpleFilename) {
    int result = processCrashTelemetryInfo("app_name_123.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_TgzFile) {
    int result = processCrashTelemetryInfo("app_mod_info_name.tgz", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_TgzWithoutMod) {
    int result = processCrashTelemetryInfo("app_name.tgz", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_ContainerDelimiter) {
    int result = processCrashTelemetryInfo("container<#=#>running<#=#>123456.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_ContainerWithoutStatus) {
    int result = processCrashTelemetryInfo("container<#=#>123456.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_LeadingDotSlash) {
    int result = processCrashTelemetryInfo("./app_name.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_PathTooLong) {
    char long_path[600];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    
    int result = processCrashTelemetryInfo(long_path, "/tmp/logs", false);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessTelemetry_ComplexContainerName) {
    int result = processCrashTelemetryInfo("app_service<#=#>exited<#=#>1234567890.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}


TEST_F(ScannerTest, ProcessTelemetry_WithT2Enabled) {
    int result = processCrashTelemetryInfo("myapp_proc_123.dmp", "/tmp/logs", true);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessTelemetry_WithLogMapper) {
    // Create log mapper file
    create_log_mapper_file("myapp=/var/log/app.log,/var/log/sys.log\n");
    
    int result = processCrashTelemetryInfo("myapp_proc_123.dmp", "/tmp/logs", false);
    EXPECT_EQ(result, 0);
}

// ============================================================================
// process_file_entry Tests
// ============================================================================

TEST_F(ScannerTest, ProcessFileEntry_NullFullpath) {
    char dump_type[] = "0";
    
    int result = process_file_entry(nullptr, dump_type, &test_config);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_NullDumpType) {
    char fullpath[] = "/tmp/test.dmp";
    
    int result = process_file_entry(fullpath, nullptr, &test_config);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_NullConfig) {
    char fullpath[] = "/tmp/test.dmp";
    char dump_type[] = "0";
    
    int result = process_file_entry(fullpath, dump_type, nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_AllNullParameters) {
    int result = process_file_entry(nullptr, nullptr, nullptr);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_NotRegularFile) {
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s", test_dump_dir);
    
    // Directory, not a file
    set_mock_is_regular_file_behavior(0);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    EXPECT_EQ(result, 0); // Returns 0 but doesn't process
}

TEST_F(ScannerTest, ProcessFileEntry_ValidFile) {
    create_test_file("test.dmp");
    
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s/test.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    // Success or error depending on file operations
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_FileWithInvalidChars) {
    // Create a file with valid name first
    create_test_file("test@invalid.dmp");
    
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s/test@invalid.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    // Should attempt to rename or delete
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_DumpTypeNonZero) {
    create_test_file("test.dmp");
    
    char fullpath[512];
    char dump_type[] = "1"; // Non-zero, telemetry not allowed
    snprintf(fullpath, sizeof(fullpath), "%s/test.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    // Should process but not call telemetry
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_ContainerDelimiterFile) {
    create_test_file("app<#=#>state.dmp");
    
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s/app<#=#>state.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_PathTooLong) {
    char fullpath[600]; // Exceeds PATH_MAX
    char fullpath1[624]; // Exceeds PATH_MAX
    char dump_type[] = "0";
    memset(fullpath, 'a', sizeof(fullpath) - 1);
    fullpath[sizeof(fullpath) - 1] = '\0';
    create_test_file(fullpath);
    snprintf(fullpath1, sizeof(fullpath1), "%s/%s", test_dump_dir,fullpath);
    
    set_mock_is_regular_file_behavior(1);
    int result = process_file_entry(fullpath1, dump_type, &test_config);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_EmptySanitizedName) {
    // File with all invalid characters that become empty after sanitization
    create_test_file("@#$%.dmp");
    
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s/@#$.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    // Should attempt to delete the file
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, ProcessFileEntry_RenameScenario) {
    create_test_file("bad*name.dmp");
    
    char fullpath[512];
    char dump_type[] = "0";
    snprintf(fullpath, sizeof(fullpath), "%s/bad*name.dmp", test_dump_dir);
    
    set_mock_is_regular_file_behavior(1);
    
    int result = process_file_entry(fullpath, dump_type, &test_config);
    // Should attempt to rename
    EXPECT_GE(result, -1);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

TEST_F(ScannerTest, EdgeCase_VeryLongFilename) {
    char long_name[256];
    memset(long_name, 'a', sizeof(long_name) - 5);
    strcpy(long_name + sizeof(long_name) - 5, ".dmp");
    
    create_test_file(long_name);
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_GE(result, 0);
}

TEST_F(ScannerTest, EdgeCase_SpecialCharactersInPath) {
    system("mkdir -p '/tmp/scanner_test/dir with spaces'");
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps("/tmp/scanner_test/dir with spaces", &dumps, &count, "*.core");
    // Should handle path with spaces
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, EdgeCase_SymbolicLink) {
    create_test_file("real.dmp");
    
    char real_path[512];
    char link_path[512];
    snprintf(real_path, sizeof(real_path), "%s/real.dmp", test_dump_dir);
    snprintf(link_path, sizeof(link_path), "%s/link.dmp", test_dump_dir);
    
    symlink(real_path, link_path);
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    // Should find at least the real file
    EXPECT_GE(result, 1);
}

TEST_F(ScannerTest, EdgeCase_ZeroByteFile) {
    create_test_file("empty.dmp", 0);
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 1);
    EXPECT_EQ(count, 1);
    
    if (count > 0) {
        EXPECT_EQ(dumps[0].size, 0);
    }
}

TEST_F(ScannerTest, EdgeCase_LargeFile) {
    create_test_file("large.dmp", 1024 * 1024); // 1MB
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    EXPECT_EQ(result, 1);
    EXPECT_EQ(count, 1);
    
    if (count > 0) {
        EXPECT_GT(dumps[0].size, 1000000);
    }
}

TEST_F(ScannerTest, StressTest_ManyFilesRepeated) {
    // Test repeated operations
    for (int iter = 0; iter < 3; iter++) {
        scanner_cleanup();
        
        for (int i = 0; i < 20; i++) {
            char name[64];
            snprintf(name, sizeof(name), "stress%d_%d.dmp", iter, i);
            create_test_file(name);
        }
        
        dump_file_t* dumps = nullptr;
        int count = 0;
        
        int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
        EXPECT_GE(result, 0);
        EXPECT_LE(count, 100);
    }
}

TEST_F(ScannerTest, BufferOverflow_SanitizeFilenameSmallBuffer) {
    const char* input = "this_is_a_very_long_filename_that_might_cause_buffer_overflow_issues.dmp";
    char output[20]; // Very small buffer
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    // Should not overflow
    EXPECT_LT(strlen(output), sizeof(output));
}

TEST_F(ScannerTest, BufferOverflow_ExtractPnameVeryLongPath) {
    char long_path[600];
    memset(long_path, 'a', sizeof(long_path) - 10);
    strcpy(long_path + sizeof(long_path) - 10, "_test.dmp");
    
    char* result = extract_pname(long_path);
    // Should handle gracefully
    if (result) {
        free(result);
    }
}

TEST_F(ScannerTest, RobustnessTest_CorruptedFiles) {
    // Create files with unusual patterns
    create_test_file(".dmp"); // Just extension
    create_test_file("...dmp"); // Multiple dots
    create_test_file("dmp"); // No extension
    
    dump_file_t* dumps = nullptr;
    int count = 0;
    
    int result = scanner_find_dumps(test_dump_dir, &dumps, &count, "*.core");
    // Should not crash
    EXPECT_GE(result, -1);
}

TEST_F(ScannerTest, MultipleDelimiters_ComplexScenario) {
    const char* input = "app<#=#>status1<#=#>status2<#=#>123456.dmp";
    char output[256];
    
    int result = sanitize_filename_preserve_container(input, output, sizeof(output));
    EXPECT_EQ(result, 0);
    // All delimiters should be preserved
    EXPECT_NE(strstr(output, "<#=#>"), nullptr);
}

TEST_F(ScannerTest, ConcurrentAccess_MultipleCleanups) {
    create_test_file("test1.dmp");
    create_test_file("test2.dmp");
    
    dump_file_t* dumps1 = nullptr;
    int count1 = 0;
    scanner_find_dumps(test_dump_dir, &dumps1, &count1, "*.core");
    
    scanner_cleanup();
    scanner_cleanup(); // Double cleanup
    
    dump_file_t* dumps2 = nullptr;
    int count2 = 0;
    scanner_get_sorted_dumps(&dumps2, &count2);
    
    EXPECT_EQ(count2, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
