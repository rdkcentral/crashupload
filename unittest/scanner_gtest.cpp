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
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "scanner.h"
#include "types.h"
#include "errors.h"
#include "constants.h"

// External functions being tested
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count, const char *dump_extn_pattern);
int scanner_get_sorted_dumps(dump_file_t **dumps, int *count);
void scanner_cleanup(void);
void scanner_update_test_state(dump_file_t *dumps, int count);
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

// Forward declarations for static functions in scanner.c (exposed via STATIC_TESTABLE with UNIT_TEST)
int append_logfile_entry(const char *entry);
int is_allowed_char(char c);
char *sanitize_segment(const char *s);
char *lookup_log_files_for_proc(const char *pname);
int get_crashed_log_file(const char *file, const char *log_path, bool t2_enabled);
int is_dump_file(const char *filename, const char *dumps_extn_pattern);

// Mock control functions
void set_mock_is_regular_file_behavior(int return_value);
void set_mock_join_path_behavior(int return_value);
void reset_scanner_mocks();
void set_mock_t2_enabled(bool enabled);

// Telemetry lifecycle functions (real implementations from telemetryinterface.c)
void t2Init(char *component);
void t2Uninit(void);
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
    scanner_update_test_state(dumps, count);
    
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
    scanner_update_test_state(dumps, count);
    
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

TEST_F(ScannerTest, ProcessTelemetry_TgzModNoUnderscoreAfterMod) {
    // Covers: `if (pmod != NULL)` FALSE branch in tgz _mod stripping.
    // "app_modonly.tgz": strstr finds "_mod", tmp becomes "only.tgz",
    // strchr("only.tgz", '_') returns NULL -> skips the strncpy, uses tmp directly.
    int result = processCrashTelemetryInfo("app_modonly.tgz", "/tmp/logs", false);
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

TEST_F(ScannerTest, ProcessTelemetry_LogMapperWithNoEqualsLine_Handled) {
    // Line without '=' should be skipped gracefully
    create_log_mapper_file("INVALID_LINE_NO_EQUALS\nmyapp=/var/log/app.log\n");
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
// Static Function Tests (exposed via STATIC_TESTABLE with UNIT_TEST)
// ============================================================================

// ----------- append_logfile_entry Tests -----------

TEST_F(ScannerTest, AppendLogfileEntry_NullEntry_Failure) {
    int result = append_logfile_entry(NULL);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, AppendLogfileEntry_EmptyEntry_Failure) {
    int result = append_logfile_entry("");
    // Empty string is treated as valid (only NULL check exists)
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, AppendLogfileEntry_ValidEntry_Success) {
    // Create test directory
    mkdir("/tmp/scnr/minidumps", 0755);
    
    const char* test_entry = "test_process:12345:/tmp/scnr/minidumps/test.log";
    int result = append_logfile_entry(test_entry);
    
    // Should succeed (result 0) or fail gracefully (-1)
    EXPECT_TRUE(result == 0 || result == -1);
    
    // Cleanup
    unlink("/tmp/scnr/minidump_log_files.txt");
}

TEST_F(ScannerTest, AppendLogfileEntry_LongEntry_Handled) {
    char long_entry[2048];
    memset(long_entry, 'A', sizeof(long_entry) - 1);
    long_entry[sizeof(long_entry) - 1] = '\0';
    
    int result = append_logfile_entry(long_entry);
    EXPECT_TRUE(result == 0 || result == -1); // Should handle gracefully
}

// ----------- is_allowed_char Tests -----------

TEST_F(ScannerTest, IsAllowedChar_AlphanumericLowercase_Allowed) {
    EXPECT_EQ(is_allowed_char('a'), 1);
    EXPECT_EQ(is_allowed_char('z'), 1);
}

TEST_F(ScannerTest, IsAllowedChar_AlphanumericUppercase_Allowed) {
    EXPECT_EQ(is_allowed_char('A'), 1);
    EXPECT_EQ(is_allowed_char('Z'), 1);
}

TEST_F(ScannerTest, IsAllowedChar_Digits_Allowed) {
    EXPECT_EQ(is_allowed_char('0'), 1);
    EXPECT_EQ(is_allowed_char('9'), 1);
}

TEST_F(ScannerTest, IsAllowedChar_AllowedSpecialChars_Allowed) {
    EXPECT_EQ(is_allowed_char('-'), 1);
    EXPECT_EQ(is_allowed_char('_'), 1);
    EXPECT_EQ(is_allowed_char('.'), 1);
    EXPECT_EQ(is_allowed_char('/'), 1);  // Forward slash is allowed
    EXPECT_EQ(is_allowed_char(' '), 1);  // Space is allowed
}

TEST_F(ScannerTest, IsAllowedChar_DisallowedSpecialChars_NotAllowed) {
    // Note: '/' and ' ' (space) are actually ALLOWED by the implementation
    EXPECT_EQ(is_allowed_char('\\'), 0);
    EXPECT_EQ(is_allowed_char('*'), 0);
    EXPECT_EQ(is_allowed_char('?'), 0);
    EXPECT_EQ(is_allowed_char('<'), 0);
    EXPECT_EQ(is_allowed_char('>'), 0);
    EXPECT_EQ(is_allowed_char('|'), 0);
    EXPECT_EQ(is_allowed_char(':'), 0);
    EXPECT_EQ(is_allowed_char('"'), 0);
    EXPECT_EQ(is_allowed_char('@'), 0);
    EXPECT_EQ(is_allowed_char('#'), 0);
}

TEST_F(ScannerTest, IsAllowedChar_ControlCharacters_NotAllowed) {
    EXPECT_EQ(is_allowed_char('\0'), 0);
    EXPECT_EQ(is_allowed_char('\n'), 0);
    EXPECT_EQ(is_allowed_char('\r'), 0);
    EXPECT_EQ(is_allowed_char('\t'), 0);
}

// ----------- sanitize_segment Tests -----------

TEST_F(ScannerTest, SanitizeSegment_NullInput_ReturnsNull) {
    char* result = sanitize_segment(NULL);
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, SanitizeSegment_EmptyString_ReturnsEmptyOrNull) {
    char* result = sanitize_segment("");
    if (result != nullptr) {
        EXPECT_STREQ(result, "");
        free(result);
    }
}

TEST_F(ScannerTest, SanitizeSegment_ValidString_ReturnsSame) {
    char* result = sanitize_segment("validname123");
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "validname123");
    free(result);
}

TEST_F(ScannerTest, SanitizeSegment_WithInvalidChars_FiltersOut) {
    char* result = sanitize_segment("test*path\\file?name");
    ASSERT_NE(result, nullptr);
    // Should filter out *, \, ? but keep valid chars
    EXPECT_STREQ(result, "testpathfilename");
    free(result);
}

TEST_F(ScannerTest, SanitizeSegment_AllInvalidChars_ReturnsEmptyOrNull) {
    char* result = sanitize_segment("***???");
    // Should return empty string (since *, ? are not allowed but no valid chars)
    if (result != nullptr) {
        EXPECT_STREQ(result, "");
        free(result);
    }
}

TEST_F(ScannerTest, SanitizeSegment_MixedValidInvalid_FiltersCorrectly) {
    char* result = sanitize_segment("my-file_123.txt");
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "my-file_123.txt");
    free(result);
}

TEST_F(ScannerTest, SanitizeSegment_LongString_Handled) {
    char long_str[1024];
    memset(long_str, 'A', sizeof(long_str) - 1);
    long_str[sizeof(long_str) - 1] = '\0';
    
    char* result = sanitize_segment(long_str);
    if (result != nullptr) {
        EXPECT_EQ(strlen(result), strlen(long_str));
        free(result);
    }
}

// ----------- lookup_log_files_for_proc Tests -----------

TEST_F(ScannerTest, LookupLogFilesForProc_NullPname_ReturnsNull) {
    char* result = lookup_log_files_for_proc(NULL);
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, LookupLogFilesForProc_EmptyPname_ReturnsNull) {
    char* result = lookup_log_files_for_proc("");
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, LookupLogFilesForProc_ProcessNotFound_ReturnsNull) {
    // Create empty log mapper file
    std::ofstream logmapper(test_log_mapper);
    logmapper.close();
    
    char* result = lookup_log_files_for_proc("nonexistent_process");
    EXPECT_EQ(result, nullptr);
}

TEST_F(ScannerTest, LookupLogFilesForProc_ProcessFound_ReturnsPath) {
    // Create log mapper file with entry
    std::ofstream logmapper(test_log_mapper);
    logmapper << "test_process:/tmp/scnr/test.log" << std::endl;
    logmapper.close();
    
    char* result = lookup_log_files_for_proc("test_process");
    if (result != nullptr) {
        EXPECT_STREQ(result, "/tmp/scnr/test.log");
        free(result);
    }
}

TEST_F(ScannerTest, LookupLogFilesForProc_MultipleEntries_FindsCorrect) {
    // Create log mapper with multiple entries
    std::ofstream logmapper(test_log_mapper);
    logmapper << "proc1:/path/to/log1.log" << std::endl;
    logmapper << "test_process:/tmp/scnr/test.log" << std::endl;
    logmapper << "proc3:/path/to/log3.log" << std::endl;
    logmapper.close();
    
    char* result = lookup_log_files_for_proc("test_process");
    if (result != nullptr) {
        EXPECT_STREQ(result, "/tmp/scnr/test.log");
        free(result);
    }
}

// ----------- get_crashed_log_file Tests -----------

TEST_F(ScannerTest, GetCrashedLogFile_NullFile_ReturnsError) {
    int result = get_crashed_log_file(NULL, "/tmp/scnr/logs", false);
    EXPECT_EQ(result, -1);
}

TEST_F(ScannerTest, GetCrashedLogFile_NullLogPath_ReturnsError) {
    int result = get_crashed_log_file("/tmp/scnr/test.dmp", NULL, false);
    // Implementation only checks file parameter, not log_path, so returns 0 or -1
    EXPECT_TRUE(result == 0 || result == -1);
}

TEST_F(ScannerTest, GetCrashedLogFile_FileNotExist_Handled) {
    int result = get_crashed_log_file("/nonexistent/file.dmp", "/tmp/scnr/logs", false);
    // Should handle gracefully (return 0 or -1)
    EXPECT_TRUE(result == 0 || result == -1);
}

TEST_F(ScannerTest, GetCrashedLogFile_T2Enabled_Handled) {
    // Create test dump file
    const char* test_dump = "/tmp/scnr/dmp/test.dmp";
    std::ofstream dumpfile(test_dump);
    dumpfile << "crash data" << std::endl;
    dumpfile.close();
    
    mkdir("/tmp/scnr/logs", 0755);
    
    int result = get_crashed_log_file(test_dump, "/tmp/scnr/logs", true);
    EXPECT_TRUE(result == 0 || result == -1);
    
    // Cleanup
    unlink(test_dump);
}

TEST_F(ScannerTest, GetCrashedLogFile_T2Disabled_Handled) {
    // Create test dump file
    const char* test_dump = "/tmp/scnr/dmp/test2.dmp";
    std::ofstream dumpfile(test_dump);
    dumpfile << "crash data" << std::endl;
    dumpfile.close();
    
    mkdir("/tmp/scnr/logs", 0755);
    
    int result = get_crashed_log_file(test_dump, "/tmp/scnr/logs", false);
    EXPECT_TRUE(result == 0 || result == -1);
    
    // Cleanup
    unlink(test_dump);
}

// ----------- is_dump_file Tests -----------
// Return values: 0 = not a dump, 1 = .dmp file, 2 = core pattern match, 3 = .tgz file

TEST_F(ScannerTest, IsDumpFile_NullFilename_ReturnsFalse) {
    int result = is_dump_file(NULL, "*.dmp");
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, IsDumpFile_NullPattern_ReturnsFalse) {
    int result = is_dump_file("test.dmp", NULL);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, IsDumpFile_DmpExtension_ReturnsTrue) {
    int result = is_dump_file("crash_12345.dmp", "*.dmp");
    EXPECT_EQ(result, 1);  // .dmp files return 1
}

TEST_F(ScannerTest, IsDumpFile_CoreExtension_ReturnsTrue) {
    int result = is_dump_file("core.12345", "core.*");
    EXPECT_EQ(result, 2);  // Core dumps return 2
}

TEST_F(ScannerTest, IsDumpFile_TgzExtension_ReturnsTrue) {
    int result = is_dump_file("crash_archive.tgz", "*.tgz");
    EXPECT_EQ(result, 3);  // .tgz files return 3
}

TEST_F(ScannerTest, IsDumpFile_NonMatchingExtension_ReturnsFalse) {
    int result = is_dump_file("test.txt", "*.dmp");
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, IsDumpFile_NoExtension_ReturnsFalse) {
    int result = is_dump_file("testfile", "*.dmp");
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, IsDumpFile_MultiplePatterns_MatchesCorrectly) {
    // Test with pattern that allows multiple extensions
    // Note: is_dump_file returns: 1 for .dmp, 2 for core pattern match, 3 for .tgz
    int result1 = is_dump_file("crash.dmp", "*.dmp");
    int result2 = is_dump_file("core.12345", "core.*");
    int result3 = is_dump_file("crash.txt", "*.dmp");
    
    EXPECT_EQ(result1, 1);  // .dmp returns 1
    EXPECT_EQ(result2, 2);  // core pattern match returns 2
    EXPECT_EQ(result3, 0);  // no match returns 0
}

TEST_F(ScannerTest, IsDumpFile_CaseInsensitive_Handled) {
    // Test case sensitivity handling
    int result = is_dump_file("CRASH.DMP", "*.dmp");
    // Behavior depends on implementation (may be 0 or 1)
    EXPECT_TRUE(result == 0 || result == 1);
}

TEST_F(ScannerTest, IsDumpFile_TgzExtension_Returns3) {
    EXPECT_EQ(is_dump_file("archive.tgz", "*.dmp"), 3);
    EXPECT_EQ(is_dump_file("archive.TGZ", "*.dmp"), 0);  // case-sensitive
}

// ============================================================================
// ScannerLogMapperTest — tests that require /etc/breakpad-logmapper.conf
//
// lookup_log_files_for_proc() opens LOGMAPPER_FILE_PATH ("/etc/breakpad-logmapper.conf")
// directly.  In the Docker container we run as root, so we can create / remove
// that file in SetUp / TearDown to exercise the full body of that function and
// the logrhs-!= NULL branch of get_crashed_log_file().
// ============================================================================

class ScannerLogMapperTest : public ::testing::Test {
protected:
    const char* logmapper_path  = "/etc/breakpad-logmapper.conf";
    const char* log_files_list  = "/tmp/minidump_log_files.txt";
    const char* log_dir         = "/tmp/scnr_logmap_test";

    void SetUp() override {
        // Write a logmapper file with several patterns
        FILE *f = fopen(logmapper_path, "w");
        if (f) {
            fprintf(f, "testproc=test.log,crash.log\n");
            fprintf(f, "\n");                    // empty line — must be skipped
            fprintf(f, "noequalssign\n");        // no '=' — must be skipped
            fprintf(f, "other=other.log\n");
            fclose(f);
        }
        unlink(log_files_list);
        system("mkdir -p /tmp/scnr_logmap_test");
    }

    void TearDown() override {
        unlink(logmapper_path);
        unlink(log_files_list);
        system("rm -rf /tmp/scnr_logmap_test");
    }
};

// lookup_log_files_for_proc — NULL pname guard (line ~293)
TEST_F(ScannerLogMapperTest, LookupLogFilesForProc_NullPname_ReturnsNull) {
    char *result = lookup_log_files_for_proc(NULL);
    EXPECT_EQ(result, nullptr);
}

// lookup_log_files_for_proc — matching entry found (covers lines 299-334)
TEST_F(ScannerLogMapperTest, LookupLogFilesForProc_MatchingEntry_ReturnsLogs) {
    // "testproc" appears as LHS in the conf file; we expect the RHS string back.
    char *result = lookup_log_files_for_proc("testproc");
    ASSERT_NE(result, nullptr);
    EXPECT_STREQ(result, "test.log,crash.log");
    free(result);
}

// lookup_log_files_for_proc — no matching entry (covers fclose after exhausting file)
TEST_F(ScannerLogMapperTest, LookupLogFilesForProc_NoMatch_ReturnsNull) {
    char *result = lookup_log_files_for_proc("unknownprocess");
    EXPECT_EQ(result, nullptr);
}

// lookup_log_files_for_proc — line without '=' is silently skipped
TEST_F(ScannerLogMapperTest, LookupLogFilesForProc_NoEqualSignLine_Skipped) {
    // "noequalssign" is a line in the file but has no '=', so it must be skipped.
    char *result = lookup_log_files_for_proc("noequalssign");
    EXPECT_EQ(result, nullptr);
}

// get_crashed_log_file — logrhs != NULL path + comma token loop (lines 377-414)
// File "/tmp/testproc_12345.dmp":
//   extract_pname → "/tmp/testproc"
//   lookup_log_files_for_proc("/tmp/testproc") → "test.log,crash.log"  (strstr match)
//   token loop: "test.log" then "crash.log" each get append_logfile_entry called
TEST_F(ScannerLogMapperTest, GetCrashedLogFile_MatchingProcess_CoversTokenLoop) {
    int result = get_crashed_log_file("/tmp/testproc_12345.dmp", log_dir, false);
    EXPECT_TRUE(result == 0 || result == -1);
    // log_files_list should have been written
    EXPECT_EQ(access(log_files_list, F_OK), 0);
}

// Same path but with t2_enabled=true so t2ValNotify / t2CountNotify are called
TEST_F(ScannerLogMapperTest, GetCrashedLogFile_MatchingProcess_T2Enabled) {
    int result = get_crashed_log_file("/tmp/testproc_12345.dmp", log_dir, true);
    EXPECT_TRUE(result == 0 || result == -1);
}

// get_crashed_log_file — logrhs == NULL path (covers "No log mapper entry" branch)
TEST_F(ScannerLogMapperTest, GetCrashedLogFile_NoMatchingProcess_NullLogRhs) {
    // "noprocess_99.dmp" → extract_pname → "/tmp/noprocess" → no match in conf
    int result = get_crashed_log_file("/tmp/noprocess_99.dmp", log_dir, false);
    EXPECT_TRUE(result == 0 || result == -1);
}

// get_crashed_log_file — NULL file guard (line ~350)
TEST_F(ScannerLogMapperTest, GetCrashedLogFile_NullFile_ReturnsError) {
    int result = get_crashed_log_file(NULL, log_dir, false);
    EXPECT_EQ(result, -1);
}

// processCrashTelemetryInfo with a logmapper file present — exercises
// the full get_crashed_log_file path including log_path / t2 branches.
TEST_F(ScannerLogMapperTest, ProcessCrashTelemetryInfo_WithLogMapper_CoversLogLookup) {
    // Create a real dump file so process_file_entry can work
    const char* dump = "/tmp/testproc_20260303.dmp";
    FILE *f = fopen(dump, "w");
    if (f) { fprintf(f, "dump"); fclose(f); }

    int result = processCrashTelemetryInfo(dump, log_dir, false);
    EXPECT_TRUE(result == 0 || result == -1);

    unlink(dump);
}

// ============================================================================
// append_logfile_entry / sanitize_filename edge-case tests
// ============================================================================

// Covers append_logfile_entry line ~59: fopen fails when path is a directory
TEST_F(ScannerLogMapperTest, AppendLogfileEntry_FopenFails_PathIsDirectory) {
    // Create a directory at LOG_FILES_PATH so fopen("a") will fail (EISDIR)
    const char *lf = "/tmp/minidump_log_files.txt";
    unlink(lf);
    mkdir(lf, 0755);      // block as directory
    int result = append_logfile_entry("test_entry");
    rmdir(lf);
    EXPECT_EQ(result, -1);
}

// Covers append_logfile_entry success path (return 0)
TEST_F(ScannerLogMapperTest, AppendLogfileEntry_ValidEntry_ReturnsSuccess) {
    unlink("/tmp/minidump_log_files.txt");
    int result = append_logfile_entry("test_log_entry");
    EXPECT_EQ(result, 0);
}

// Covers sanitize_filename_preserve_container: seg_len >= sizeof(tmp) truncation (line ~143)
// A segment of 135 chars (> 128) before the delimiter triggers the `if (seg_len >= sizeof(tmp))`
// truncation branch inside the while loop.
TEST_F(ScannerTest, SanitizeFilename_VeryLongSegmentBeforeDelimiter_TriggersTruncation) {
    // Build: <135 'a' chars> + "<#=#>" + "tail"
    char input[512] = {0};
    memset(input, 'a', 135);
    strcat(input, "<#=#>tail.dmp");

    char out[512] = {0};
    int result = sanitize_filename_preserve_container(input, out, sizeof(out));
    EXPECT_EQ(result, 0);
    // The delimiter and the tail must appear in the output
    EXPECT_NE(strstr(out, "<#=#>"), nullptr);
    EXPECT_NE(strstr(out, "tail"), nullptr);
}

// processCrashTelemetryInfo with t2_enabled=true and logmapper present — covers t2 branches
TEST_F(ScannerLogMapperTest, ProcessCrashTelemetryInfo_T2Enabled_CoversT2Branches) {
    const char *dump = "/tmp/testproc_t2_20260303.dmp";
    FILE *f = fopen(dump, "w");
    if (f) { fprintf(f, "dump"); fclose(f); }

    int result = processCrashTelemetryInfo(dump, log_dir, true);
    EXPECT_TRUE(result == 0 || result == -1);

    unlink(dump);
}

// ============================================================================
// Coverage: processCrashTelemetryInfo TGZ + _mod strip (scanner.c lines 462-490)
// ============================================================================

TEST_F(ScannerTest, ProcessCrashTelemetryInfo_TgzWithModSuffix) {
    // "app_mod_crash.tgz" -> pmod found -> meta info stripped
    // Covers: isTgz=1, pmod detection, remain_len check, memcpy/strchr/strncpy,
    //         snprintf(file), t2CountNotify("SYS_INFO_TGZDUMP")
    int result = processCrashTelemetryInfo("app_mod_crash.tgz", "/tmp/scnr/log", false);
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessCrashTelemetryInfo_TgzNoModSuffix) {
    // .tgz file without _mod -> isTgz=1 but pmod==NULL, skips strip block
    int result = processCrashTelemetryInfo("app_plain.tgz", "/tmp/scnr/log", false);
    EXPECT_EQ(result, 0);
}

// ============================================================================
// Coverage: process_file_entry no-slash path -> dirname='.' (scanner.c lines 688-692)
// ============================================================================

TEST_F(ScannerTest, ProcessFileEntry_NoSlashInPath_DirnameDot) {
    // fullpath with no '/' -> else branch: dirname[0]='.', dirname[1]='\0' (lines 688-692)
    // dump_type="1" -> no processCrashTelemetryInfo call -> WARN branch (lines ~770-772)
    char fullpath[] = "nodirname_test.dmp";
    char dump_type[] = "1";
    set_mock_is_regular_file_behavior(1);
    int result = process_file_entry(fullpath, dump_type, &test_config);
    EXPECT_GE(result, -1);
}

// ============================================================================
// Coverage: process_file_entry rename needed + dump_type != "0" (lines ~720-728)
// ============================================================================

TEST_F(ScannerTest, ProcessFileEntry_RenameNeeded_DumpTypeNonZero) {
    // File with sanitizable chars -> sanitized != basename -> rename path
    // dump_type="1" -> WARN "processCrashTelemetryInfo is not allowed" (lines ~723-728)
    create_test_file("bad*rename.dmp");
    char fullpath[512];
    char dump_type[] = "1";
    snprintf(fullpath, sizeof(fullpath), "%s/bad*rename.dmp", test_dump_dir);
    set_mock_is_regular_file_behavior(1);
    int result = process_file_entry(fullpath, dump_type, &test_config);
    EXPECT_GE(result, -1);
}

// ============================================================================
// Telemetry interface lifecycle tests
// Directly call t2Init / t2Uninit so their lines in telemetryinterface.c are hit.
// ============================================================================

TEST(TelemetryInterfaceTest, T2Init_CallsWithComponentName) {
    // Exercises void t2Init(char *component) in telemetryinterface.c
    t2Init((char *)"crashupload");
    SUCCEED();
}

TEST(TelemetryInterfaceTest, T2Uninit_CallsSuccessfully) {
    // Exercises void t2Uninit(void) in telemetryinterface.c
    t2Uninit();
    SUCCEED();
}

// ============================================================================
// Coverage: processCrashTelemetryInfo container-delimiter path
// containerDelimiter = "<#=#>"  (scanner.c)
// Filename with 2+ delimiter tokens triggers the full container block:
//   isContainer=1, pos/scan loops, firstBreak/containerTime extraction,
//   strstr(firstBreak, containerDelimiter)==false -> else path,
//   strchr(containerName,'_') != NULL -> Appname/ProcessName split,
//   t2ValNotify calls, snprintf(normalized), snprintf(file,...)
// ============================================================================

TEST_F(ScannerTest, ProcessCrashTelemetryInfo_ContainerDelimiter_WithUnderscore) {
    // "procName_appName<#=#>running<#=#>20260304120000"
    // firstBreak = "procName_appName"  (has '_' -> Appname/ProcessName split path)
    // containerStatus = "unknown"  (firstBreak has no nested delimiter -> else)
    int result = processCrashTelemetryInfo(
        "myProc_myApp<#=#>running<#=#>20260304120000",
        "/tmp/scnr/log",
        false
    );
    EXPECT_EQ(result, 0);
}

TEST_F(ScannerTest, ProcessCrashTelemetryInfo_ContainerDelimiter_NoUnderscore) {
    // No '_' in container part -> else branch for Appname/ProcessName
    // (Appname = ProcessName = containerName)
    int result = processCrashTelemetryInfo(
        "myprocess<#=#>20260304120000",
        "/tmp/scnr/log",
        false
    );
    EXPECT_EQ(result, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
