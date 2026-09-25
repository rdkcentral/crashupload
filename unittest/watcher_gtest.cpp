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
 * @file watcher_gtest.cpp
 * @brief L1 GTest suite for inotify-minidump-watcher
 *
 * Compiles inotify-minidump-watcher.c with -DGTEST_ENABLE.
 * Extender builds omit that flag, so production behavior is unchanged.
 */

#include <gtest/gtest.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <string>
#include <sys/inotify.h>

extern "C" {
int watcher_main(int argc, const char *const *argv);
int directory_watcher(const char *directory,
                      const char *command_to_run,
                      const char *command_args,
                      const char *const *patterns,
                      size_t pattern_count);
void process_interrupt_handler(int s);
void watcher_test_reset(void);

void watcher_mock_reset(void);
void watcher_mock_set_inotify_init(int ret, int err);
void watcher_mock_set_add_watch(int ret, int err);
void watcher_mock_push_read_event(int wd, uint32_t mask, const char *name);
void watcher_mock_push_read_fail(int err);
void watcher_mock_push_close(int ret);
void watcher_mock_set_close_errno(int err);
void watcher_mock_set_system_ret(int ret);
const char *watcher_mock_last_system_cmd(void);
void watcher_mock_set_printf_fail(int fail);
void watcher_mock_set_fnmatch_result(int use_override, int value);
void watcher_mock_set_sigaction_ret(int ret, int err);
}

class WatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        watcher_mock_reset();
        watcher_test_reset();
    }
};

TEST_F(WatcherTest, WatcherMain_TooFewArgs_ReturnsFailure) {
    const char *argv[] = {"inotify-minidump-watcher", "/tmp", "cmd", "args"};
    EXPECT_EQ(watcher_main(4, argv), EXIT_FAILURE);
}

TEST_F(WatcherTest, WatcherMain_SigactionFails) {
    watcher_mock_set_sigaction_ret(-1, EINVAL);
    const char *argv[] = {
        "inotify-minidump-watcher", "/minidumps", "/bin/true", "0", "*.dmp"
    };
    /* Production ignores sigaction() return and still enters the watcher. */
    watcher_mock_set_inotify_init(-1, EMFILE);
    EXPECT_EQ(watcher_main(5, argv), EXIT_FAILURE);
}

TEST_F(WatcherTest, WatcherMain_DirectoryWatcherFailure) {
    watcher_mock_set_inotify_init(-1, EMFILE);
    const char *argv[] = {
        "inotify-minidump-watcher", "/minidumps", "/bin/true", "0", "*.dmp"
    };
    EXPECT_EQ(watcher_main(5, argv), EXIT_FAILURE);
}

TEST_F(WatcherTest, WatcherMain_MatchingDump_RunsCommand) {
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    process_interrupt_handler(SIGINT);
    watcher_mock_push_read_fail(EINTR);
    const char *argv[] = {
        "inotify-minidump-watcher", "/minidumps", "/bin/true", "0", "*.dmp"
    };
    EXPECT_EQ(watcher_main(5, argv), EXIT_SUCCESS);
    EXPECT_STREQ(watcher_mock_last_system_cmd(), "sh -c '/bin/true 0'");
}

TEST_F(WatcherTest, DirectoryWatcher_InotifyInitFails) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_set_inotify_init(-1, EMFILE);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_AddWatchFails) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_set_add_watch(-1, ENOENT);
    EXPECT_EQ(directory_watcher("/missing", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_ReadErrorWithoutInterrupt) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_fail(EIO);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_ReadErrorWithInterrupt) {
    const char *patterns[] = {"*.dmp"};
    process_interrupt_handler(SIGINT);
    watcher_mock_push_read_fail(EINTR);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), 0);
}

TEST_F(WatcherTest, DirectoryWatcher_NonSigintDoesNotInterrupt) {
    const char *patterns[] = {"*.dmp"};
    process_interrupt_handler(SIGTERM);
    watcher_mock_push_read_fail(EIO);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_EmptyNameThenNullCommand) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "");
    watcher_mock_push_read_event(2, IN_CREATE, "flag.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "NULL", "", patterns, 1), 0);
}

TEST_F(WatcherTest, DirectoryWatcher_NoMatchThenMatch) {
    const char *patterns[] = {"*.txt", "*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "notes.txt");
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "NULL", "", patterns, 2), 0);
}

TEST_F(WatcherTest, DirectoryWatcher_FnmatchError) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_set_fnmatch_result(1, -1);
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_PrintfFailure) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_set_printf_fail(1);
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_NullCommandArgs) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "cmd", nullptr, patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_CommandOverflow) {
    const char *patterns[] = {"*.dmp"};
    std::string long_cmd(60, 'A');
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    EXPECT_EQ(directory_watcher("/tmp", long_cmd.c_str(), "args", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_SystemThenReadError) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_set_system_ret(-1);
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    watcher_mock_push_read_fail(EIO);
    EXPECT_EQ(directory_watcher("/tmp", "/bin/false", "1", patterns, 1), -1);
    EXPECT_STREQ(watcher_mock_last_system_cmd(), "sh -c '/bin/false 1'");
}

TEST_F(WatcherTest, DirectoryWatcher_NullCommandExitsOnFirstMatch) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "first.dmp");
    watcher_mock_push_read_event(2, IN_CREATE, "second.dmp");
    EXPECT_EQ(directory_watcher("/tmp", "NULL", "", patterns, 1), 0);
}

TEST_F(WatcherTest, DirectoryWatcher_RunsSystemThenInterruptExits) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "first.dmp");
    watcher_mock_set_system_ret(0);
    process_interrupt_handler(SIGINT);
    watcher_mock_push_read_fail(EINTR);
    EXPECT_EQ(directory_watcher("/tmp", "/lib/rdk/uploadDumps.sh", "0", patterns, 1), 0);
    EXPECT_STREQ(watcher_mock_last_system_cmd(), "sh -c '/lib/rdk/uploadDumps.sh 0'");
}

TEST_F(WatcherTest, DirectoryWatcher_CloseWatchFdFails) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "flag.dmp");
    watcher_mock_push_close(-1);
    watcher_mock_set_close_errno(EIO);
    EXPECT_EQ(directory_watcher("/tmp", "NULL", "", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_CloseNotifyFdFails) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "flag.dmp");
    watcher_mock_push_close(0);
    watcher_mock_push_close(-1);
    watcher_mock_set_close_errno(EIO);
    EXPECT_EQ(directory_watcher("/tmp", "NULL", "", patterns, 1), -1);
}

TEST_F(WatcherTest, DirectoryWatcher_ZeroPatternCountThenInterrupt) {
    const char *patterns[] = {"*.dmp"};
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    process_interrupt_handler(SIGINT);
    watcher_mock_push_read_fail(EINTR);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 0), 0);
}

TEST_F(WatcherTest, DirectoryWatcher_FnmatchNomatchOnlyThenInterrupt) {
    const char *patterns[] = {"*.core"};
    watcher_mock_push_read_event(2, IN_CREATE, "crash.dmp");
    process_interrupt_handler(SIGINT);
    watcher_mock_push_read_fail(EINTR);
    EXPECT_EQ(directory_watcher("/tmp", "cmd", "args", patterns, 1), 0);
}
