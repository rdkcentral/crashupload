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
 * @file lock_manager_gtest.cpp
 * @brief Comprehensive GTest suite for lock manager functions
 * 
 * Tests all lock management logic including:
 * - lock_acquire()
 * - lock_release()
 * - acquire_process_lock_or_wait()
 * - release_process_lock()
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/wait.h>

extern "C" {
#include "lock_manager.h"

// Forward declarations for internal functions not in header
int acquire_process_lock_or_wait(const char *lock_path, int wait_time);
void release_process_lock(int lock_fd);
}

// ============================================================================
// Test Fixture
// ============================================================================

class LockManagerTest : public ::testing::Test {
protected:
    const char* test_lock_file = "/tmp/test_lock_file.lock";
    
    void SetUp() override {
        // Clean up any existing test files
        unlink(test_lock_file);
    }

    void TearDown() override {
        // Clean up test files
        unlink(test_lock_file);
    }
};

// ============================================================================
// Tests for lock_acquire() with timeout_sec > 0 (wait mode)
// ============================================================================

TEST_F(LockManagerTest, LockAcquire_WithTimeout_Success) {
    int fd = lock_acquire(test_lock_file, 1, false);
    
    EXPECT_GE(fd, 0);
    EXPECT_TRUE(access(test_lock_file, F_OK) == 0);
    
    // Cleanup
    lock_release(fd, test_lock_file);
}

TEST_F(LockManagerTest, LockAcquire_WithTimeout_MultipleAcquire) {
    // First acquire
    int fd1 = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd1, 0);
    
    // Release first
    lock_release(fd1, test_lock_file);
    
    // Second acquire should succeed
    int fd2 = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd2, 0);
    
    // Cleanup
    lock_release(fd2, test_lock_file);
}

// ============================================================================
// Tests for lock_acquire() with timeout_sec = 0 (exit mode)
// ============================================================================

TEST_F(LockManagerTest, LockAcquire_NoTimeout_Success) {
    int fd = lock_acquire(test_lock_file, 0, false);
    
    EXPECT_GE(fd, 0);
    EXPECT_TRUE(access(test_lock_file, F_OK) == 0);
    
    // Cleanup
    lock_release(fd, test_lock_file);
}

TEST_F(LockManagerTest, LockAcquire_NoTimeout_T2Enabled) {
    int fd = lock_acquire(test_lock_file, 0, true);
    
    EXPECT_GE(fd, 0);
    
    // Cleanup
    lock_release(fd, test_lock_file);
}

// ============================================================================
// Tests for lock_acquire() - Negative Cases
// ============================================================================

TEST_F(LockManagerTest, LockAcquire_NullFile_Failure) {
    int fd = lock_acquire(NULL, 1, false);
    
    EXPECT_EQ(fd, -1);
}

TEST_F(LockManagerTest, LockAcquire_NullFileNoTimeout_Failure) {
    int fd = lock_acquire(NULL, 0, false);
    
    EXPECT_EQ(fd, -1);
}

// ============================================================================
// Tests for lock_release()
// ============================================================================

TEST_F(LockManagerTest, LockRelease_ValidFd_Success) {
    int fd = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd, 0);
    
    lock_release(fd, test_lock_file);
    
    // Lock file should be removed
    EXPECT_FALSE(access(test_lock_file, F_OK) == 0);
}

TEST_F(LockManagerTest, LockRelease_InvalidFd_NoError) {
    // Should handle gracefully
    lock_release(-1, test_lock_file);
    
    // Should not crash
    SUCCEED();
}

TEST_F(LockManagerTest, LockRelease_NullFile_NoError) {
    int fd = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd, 0);
    
    // Should handle NULL file gracefully
    lock_release(fd, NULL);
    
    // Cleanup manually
    unlink(test_lock_file);
}

TEST_F(LockManagerTest, LockRelease_NullFile_InvalidFd_NoError) {
    // Covers: lock_file==NULL with fd<0 -> the `if (fd >= 0)` FALSE branch inside null/empty check
    lock_release(-1, NULL);
    SUCCEED();
}

TEST_F(LockManagerTest, LockRelease_EmptyFile_ValidFd_ReleasesAndReturns) {
    // Covers: lock_file[0]=='\0' with fd>=0 -> calls release_process_lock(fd) then returns
    int fd = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd, 0);
    // empty string triggers the '\0' branch; release_process_lock is called for the fd
    lock_release(fd, "");
    // test_lock_file still exists (no unlink); TearDown cleans it up
    SUCCEED();
}

TEST_F(LockManagerTest, LockRelease_EmptyFile_InvalidFd_NoError) {
    // Covers: lock_file[0]=='\0' with fd<0 -> hits empty-string branch, skips release_process_lock
    lock_release(-1, "");
    SUCCEED();
}

// ============================================================================
// Tests for acquire_process_lock_or_wait()
// ============================================================================

TEST_F(LockManagerTest, AcquireProcessLockOrWait_Success) {
    int fd = acquire_process_lock_or_wait(test_lock_file, 1);
    
    EXPECT_GE(fd, 0);
    EXPECT_TRUE(access(test_lock_file, F_OK) == 0);
    
    // Cleanup
    release_process_lock(fd);
    unlink(test_lock_file);
}

TEST_F(LockManagerTest, AcquireProcessLockOrWait_InvalidPath_Failure) {
    int fd = acquire_process_lock_or_wait("/nonexistent/dir/lock.file", 1);
    
    EXPECT_EQ(fd, -1);
}

// ============================================================================
// Tests for release_process_lock()
// ============================================================================

TEST_F(LockManagerTest, ReleaseProcessLock_ValidFd_Success) {
    int fd = acquire_process_lock_or_wait(test_lock_file, 1);
    EXPECT_GE(fd, 0);
    
    release_process_lock(fd);
    
    // Lock should be released (file still exists but unlocked)
    EXPECT_TRUE(access(test_lock_file, F_OK) == 0);
    
    // Cleanup
    unlink(test_lock_file);
}

TEST_F(LockManagerTest, ReleaseProcessLock_InvalidFd_NoError) {
    // Should handle gracefully
    release_process_lock(-1);
    
    // Should not crash
    SUCCEED();
}

TEST_F(LockManagerTest, ReleaseProcessLock_AlreadyClosed_NoError) {
    int fd = acquire_process_lock_or_wait(test_lock_file, 1);
    EXPECT_GE(fd, 0);
    
    // Release once
    release_process_lock(fd);
    
    // Release again - should handle gracefully
    release_process_lock(fd);
    
    // Cleanup
    unlink(test_lock_file);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(LockManagerTest, Integration_AcquireAndReleaseCycle) {
    // Acquire
    int fd = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd, 0);
    EXPECT_TRUE(access(test_lock_file, F_OK) == 0);
    
    // Release
    lock_release(fd, test_lock_file);
    EXPECT_FALSE(access(test_lock_file, F_OK) == 0);
}

TEST_F(LockManagerTest, Integration_MultipleLockCycles) {
    for (int i = 0; i < 5; i++) {
        int fd = lock_acquire(test_lock_file, 1, false);
        EXPECT_GE(fd, 0);
        lock_release(fd, test_lock_file);
    }
    
    // Should succeed 5 times
    SUCCEED();
}

TEST_F(LockManagerTest, Integration_DifferentModes) {
    // Test with timeout
    int fd1 = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd1, 0);
    lock_release(fd1, test_lock_file);
    
    // Test without timeout
    int fd2 = lock_acquire(test_lock_file, 0, false);
    EXPECT_GE(fd2, 0);
    lock_release(fd2, test_lock_file);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(LockManagerTest, EdgeCase_VeryShortWaitTime) {
    int fd = lock_acquire(test_lock_file, 1, false);
    
    EXPECT_GE(fd, 0);
    
    lock_release(fd, test_lock_file);
}

TEST_F(LockManagerTest, EdgeCase_ZeroFd_IsInvalid) {
    // FD 0 is stdin, should not be used as lock
    release_process_lock(0);
    
    // Should handle gracefully
    SUCCEED();
}

TEST_F(LockManagerTest, EdgeCase_LargeTimeout) {
    // Large timeout value (won't actually wait)
    int fd = lock_acquire(test_lock_file, 9999, false);
    
    EXPECT_GE(fd, 0);
    
    lock_release(fd, test_lock_file);
}

TEST_F(LockManagerTest, EdgeCase_NegativeTimeout) {
    // Negative timeout should trigger exit mode
    int fd = lock_acquire(test_lock_file, -1, false);
    
    EXPECT_GE(fd, 0);
    
    lock_release(fd, test_lock_file);
}

// ============================================================================
// Concurrency Tests (using fork)
// ============================================================================

TEST_F(LockManagerTest, Concurrency_LockIsExclusive) {
    int fd1 = lock_acquire(test_lock_file, 1, false);
    EXPECT_GE(fd1, 0);
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - try to acquire same lock with non-blocking
        int fd2 = open(test_lock_file, O_RDWR);
        if (fd2 >= 0) {
            int result = flock(fd2, LOCK_EX | LOCK_NB);
            close(fd2);
            // Should fail to acquire (parent holds lock)
            exit(result == 0 ? 1 : 0);
        }
        exit(1);
    } else {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);
        
        // Child should have exited with 0 (lock was blocked)
        EXPECT_EQ(WEXITSTATUS(status), 0);
        
        // Cleanup
        lock_release(fd1, test_lock_file);
    }
}

// ============================================================================
// Coverage: acquire_process_lock_or_exit flock-fail path (lock_manager.c lines 38-44)
// ============================================================================

TEST_F(LockManagerTest, AcquireProcessLockOrExit_WhenLockHeld_ChildExitsZero) {
    // Parent holds LOCK_EX on the test lock file.
    // Child calls lock_acquire(timeout=0, t2_enabled=true) which calls
    // acquire_process_lock_or_exit() -> flock(LOCK_EX|LOCK_NB) fails because
    // parent holds the lock -> logs, calls t2CountNotify (t2_enabled=true), exit(0).
    // Covers: lock_manager.c lines 38-44
    int fd = open(test_lock_file, O_CREAT | O_RDWR, 0644);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(flock(fd, LOCK_EX), 0);

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        // Child: attempt non-blocking exclusive lock - will fail
        // lock_acquire(timeout=0) -> acquire_process_lock_or_exit -> exit(0)
        lock_acquire(test_lock_file, 0, true);
        // Should never reach here
        _exit(99);
    }
    // Parent: wait for child
    int status = 0;
    waitpid(pid, &status, 0);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0); // exit(0) from acquire_process_lock_or_exit

    flock(fd, LOCK_UN);
    close(fd);
    unlink(test_lock_file);
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
