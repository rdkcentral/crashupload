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
 * @file mainapp_extra_gtest.cpp
 * @brief Additional GTest cases for main.c covering privacy-mode, TGZ, and
 *        coredump branches.  Compiled as a separate translation unit and
 *        linked into the same mainapp_gtest binary to avoid a compiler
 *        segfault that occurs when mainapp_gtest.cpp grows too large under
 *        -O0 -fprofile-arcs -ftest-coverage.
 *
 * NOTE: No main() in this file – the entry point lives in mainapp_gtest.cpp.
 */

#include "mainapp_test_fixture.h"

// ============================================================================
// main_test Tests – Privacy Mode: DO_NOT_SHARE
// ============================================================================

TEST_F(MainAppTest, MainTest_DoNotSharePrivacyMode_SkipsUploadsAndSetsCleanup) {
    // config_init_load mock sets device_type = DEVICE_TYPE_MEDIACLIENT by default,
    // so get_privacy_control_mode() IS called in main.c, and we force it to DO_NOT_SHARE.
    // Covers:
    //   - `if (config.device_type == DEVICE_TYPE_MEDIACLIENT)` → get_privacy_control_mode()
    //   - `if (config.privacy_mode == DO_NOT_SHARE) { continue; }` inside dump loop
    //   - `if (config.privacy_mode == DO_NOT_SHARE) { do_not_share_cleanup = true; goto cleanup; }` after loop
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(DO_NOT_SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1); // 1 dump found → loop executes
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_SharePrivacyMode_ProceedsToUpload) {
    // Verify SHARE privacy mode (default) reaches upload loop -
    // ensures the MEDIACLIENT privacy check branch is exercised for SHARE too.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(0);
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

// ============================================================================
// main_test Tests – TGZ / COREDUMP path coverage
// ============================================================================

TEST_F(MainAppTest, MainTest_TgzDump_SkipsArchivingAndUploads) {
    // Covers: `if (len > 4 && strcmp(path + len - 4, ".tgz") == 0)` → snprintf + continue
    // The archive_name is set directly to the .tgz path; archive_create_smart is NOT called.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_tgz_behavior(1);          // returns /tmp/test_dump_0.tgz
    set_mock_process_file_entry_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(0);
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_CoredumpType_SetsExtensionPattern) {
    // Covers: `else if (config.dump_type == DUMP_TYPE_COREDUMP)` branch that sets
    // dump_extn_pattern = "*core.prog*.gz*" and timestamp file "/tmp/.coredump_upload_timestamps".
    // No dumps found so we go to cleanup immediately after setting the pattern.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"1"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_config_coredump_behavior();           // DUMP_TYPE_COREDUMP
    set_mock_scanner_find_dumps_behavior(0, 0);   // no dumps → goto cleanup

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_CoredumpMpeosDump_UsesMtimeDateInName) {
    // Covers: `if (NULL != (strstr((dumps+i)->path, "mpeos-main")))` TRUE branch
    // which uses mtime_date instead of crashts for new_dump_name construction.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"1"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_config_coredump_behavior();           // DUMP_TYPE_COREDUMP
    set_mock_scanner_mpeos_behavior(1);            // path contains "mpeos-main"
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(0);
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_CoredumpNonMpeos_UsesCrashtsInName) {
    // Covers: `if (NULL != strstr(path, "mpeos-main"))` FALSE branch (regular coredump)
    // which uses crashts for new_dump_name construction.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"1"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_config_coredump_behavior();           // DUMP_TYPE_COREDUMP
    set_mock_scanner_find_dumps_behavior(1, 1);   // regular .dmp path (no mpeos-main)
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(0);
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_ArchiveNameHasCore_TelemetryLogged) {
    // Covers: `if (strstr(archive[i].archive_name, "_core"))` TRUE branch
    // in the upload loop, which logs "Coredump File".
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_core_behavior();             // archive_name gets "_core" in it
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // 1 != RATELIMIT_BLOCK(0) → allow upload loop
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

// ============================================================================
// main_test Tests – Upload path / box-rebooting / error branches
// ============================================================================

TEST_F(MainAppTest, MainTest_UploadSucceeds_CoversUploadLoop) {
    // Covers: the upload loop body when ratelimit allows.
    // ratelimit_check_unified returns 1 (≠ RATELIMIT_BLOCK=0) so the
    // ratelimit-block condition is false and we proceed to upload_process.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // 1 != RATELIMIT_BLOCK(0) → allow upload
    set_mock_upload_process_behavior(0);           // success

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_UploadFails_BreakFromLoop) {
    // Covers: `if (ret != 0) { break; }` when upload_process fails.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // allow upload
    set_mock_upload_process_behavior(1);           // failure → ret != 0 → break

    EXPECT_NE(main_test(3, argv), 0); // failure propagates to return value
}

TEST_F(MainAppTest, MainTest_IsBoxRebooting_SkipsUpload) {
    // Covers: `if (true == is_box_rebooting(...)) { ret=0; goto cleanup; }`
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(true);  // box is rebooting → skip upload

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_IsProcessDmpFile_UsesOriginalName) {
    // Covers: `if (is_process_dmp_file == true)` branch –
    //   strncpy(new_dump_name, dump_file_name, ...)
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(true);  // already-processed dump
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // allow upload
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_MtimeFormattedFails_LogsError) {
    // Covers: `else { CRASHUPLOAD_ERROR("file_get_mtime_formatted() return fail") }`
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_find_dumps_behavior(1, 1);
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(1, ""); // non-zero → error branch
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1);
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_InvalidDumpType_LogsError) {
    // Covers: `else { CRASHUPLOAD_ERROR("Invalid Dump Type") }` when
    // config.dump_type is neither MINIDUMP nor COREDUMP.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_config_unknown_dump_type_behavior();    // sets DUMP_TYPE_UNKNOWN
    set_mock_scanner_find_dumps_behavior(0, 0);      // no dumps → goto cleanup

    EXPECT_EQ(main_test(3, argv), 0);
}

// ============================================================================
// main_test Tests – logger_init failure, chdir failure, long-path trim
// ============================================================================

TEST_F(MainAppTest, MainTest_LoggerInitFail_PrintsWarningAndContinues) {
    // Covers: `if (logger_init() != 0) { printf("WARNING: ..."); }`  (line 88)
    // main_test must still continue and return 0 even when logger_init fails.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_logger_init_fail_behavior();         // logger_init returns 1
    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_scanner_find_dumps_behavior(0, 0);   // no dumps → goto cleanup

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_ChdirFails_GotoCleanup) {
    // Covers: `if (0 != chdir(...)) { CRASHUPLOAD_ERROR(...); goto cleanup; }` (lines 215-216)
    // config_init_load mock sets working_dir_path to a non-existent directory so
    // the real chdir() syscall fails.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_invalid_working_dir_behavior();      // working_dir_path = /nonexistent_xyz…

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_LongPlainPath_NullExtractPname_CoversFirstAndSecondTrim) {
    // Covers (in main.c dump loop):
    //   - `else { snprintf(dump_file_name, …, path); }` (no '/' in path, line ~280)
    //   - First strlen(new_dump_name) >= 135 block  (lines ~313-317)
    //   - Second strlen >= 135 block, extract_pname returns NULL path (lines ~322-324)
    // extract_pname mock returns nullptr by default → `if (!pname)` TRUE branch.
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_long_plain_path_behavior(1); // 85-char path, no '/'
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    // extract_pname_behavior NOT set → default returns nullptr → covers "pname not found" branch
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // allow upload
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}

TEST_F(MainAppTest, MainTest_LongPlainPath_ValidExtractPname_CoversTrimElseBranch) {
    // Same scenario as above but extract_pname returns a valid pname string so that
    // the `else { trim_process_name_in_path(…); strncpy(…); }` block is hit (lines ~325-334).
    char* argv[] = {(char*)"crashupload", (char*)"/tmp/test", (char*)"0"};

    set_mock_config_init_load_behavior(0);
    set_mock_platform_initialize_behavior(0);
    set_mock_file_present_check_behavior(-1);
    set_mock_lock_acquire_behavior(10);
    set_mock_prerequisites_wait_behavior(0);
    set_mock_get_privacy_control_mode_behavior(SHARE);
    set_mock_scanner_long_plain_path_behavior(1); // 85-char path, no '/'
    set_mock_process_file_entry_behavior(0);
    set_mock_file_get_mtime_formatted_behavior(0, "2026-01-07-10-30-45");
    set_mock_get_crash_timestamp_utc_behavior(0, "20260107_103045");
    set_mock_check_process_dmp_file_behavior(false);
    set_mock_extract_pname_behavior("myprocname"); // non-null → else branch covered
    set_mock_archive_create_smart_behavior(0);
    set_mock_is_box_rebooting_behavior(false);
    set_mock_ratelimit_check_unified_behavior(1); // allow upload
    set_mock_upload_process_behavior(0);

    EXPECT_EQ(main_test(3, argv), 0);
}
