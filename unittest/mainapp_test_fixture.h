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
 */

/**
 * @file mainapp_test_fixture.h
 * @brief Shared fixture + mock declarations for mainapp GTest files.
 *
 * Included by both mainapp_gtest.cpp and mainapp_extra_gtest.cpp so that
 * both translation units use the same MainAppTest fixture class and the
 * same extern "C" mock-control declarations.  Each source file is compiled
 * independently, so neither is responsible for *defining* any symbol found
 * here – definitions live in mainapp_gmock.cpp.
 */

#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

extern "C" {
#include "../c_sourcecode/src/init/system_init.h"
#include "../c_sourcecode/common/types.h"
#include "../c_sourcecode/common/errors.h"
#include "../c_sourcecode/common/constants.h"

int main_test(int argc, char *argv[]);
void handle_signal(int no, siginfo_t* info, void* uc);

/* Mock control functions */
void set_mock_config_init_load_behavior(int return_value);
void set_mock_platform_initialize_behavior(int return_value);
void set_mock_file_present_check_behavior(int return_value);
void set_mock_lock_acquire_behavior(int return_value);
void set_mock_prerequisites_wait_behavior(int return_value);
void set_mock_privacy_uploads_blocked_behavior(bool return_value);
void set_mock_get_privacy_control_mode_behavior(privacy_control_t return_value);
void set_mock_scanner_find_dumps_behavior(int return_value, int output_count);
void set_mock_scanner_tgz_behavior(int count);
void set_mock_scanner_mpeos_behavior(int count);
void set_mock_config_coredump_behavior(void);
void set_mock_archive_core_behavior(void);
void set_mock_config_unknown_dump_type_behavior(void);
void set_mock_process_file_entry_behavior(int return_value);
void set_mock_file_get_mtime_formatted_behavior(int return_value, const char* output);
void set_mock_get_crash_timestamp_utc_behavior(int return_value, const char* output);
void set_mock_check_process_dmp_file_behavior(bool return_value);
void set_mock_extract_pname_behavior(const char* return_value);
void set_mock_trim_process_name_in_path_behavior(int return_value, const char* output);
void set_mock_archive_create_smart_behavior(int return_value);
void set_mock_is_box_rebooting_behavior(bool return_value);
void set_mock_ratelimit_check_unified_behavior(int return_value);
void set_mock_upload_process_behavior(int return_value);
int  get_logger_error_call_count();
int  get_logger_info_call_count();
int  get_logger_warn_call_count();
int  get_cleanup_batch_call_count();
void set_mock_logger_init_fail_behavior(void);
void set_mock_scanner_long_plain_path_behavior(int count);
void set_mock_invalid_working_dir_behavior(void);
void reset_mainapp_mocks();
} // extern "C"

extern int lock_dir_prefix;

using ::testing::_;
using ::testing::Return;

// ============================================================================
// Test Fixture
// ============================================================================

class MainAppTest : public ::testing::Test {
protected:
    const char* test_dir            = "/tmp/mainapp_test";
    const char* test_lock_file_minidump = "/tmp/.uploadMinidumps";
    const char* test_lock_file_coredump = "/tmp/.uploadCoredumps";

    void SetUp() override {
        reset_mainapp_mocks();
        system("mkdir -p /tmp/mainapp_test");
        system("mkdir -p /tmp/test_dumps");
        unlink(test_lock_file_minidump);
        unlink(test_lock_file_coredump);
    }

    void TearDown() override {
        cleanup_test_files();
        reset_mainapp_mocks();
        unlink(test_lock_file_minidump);
        unlink(test_lock_file_coredump);
    }

    void create_test_file(const char* path, size_t size = 1024) {
        FILE* fp = fopen(path, "w");
        if (fp) {
            for (size_t i = 0; i < size; i++) fputc('A', fp);
            fclose(fp);
        }
    }

    void cleanup_test_files() {
        system("rm -rf /tmp/mainapp_test");
        system("rm -rf /tmp/test_dumps");
    }

    bool file_exists(const char* path) {
        struct stat st;
        return (stat(path, &st) == 0);
    }
};
