##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

"""
Functional tests verifying that SIGTERM causes the binary to remove its lock file.

SIG-01 — SIGTERM delivered after the binary has acquired the minidump lock
  → handle_signal() calls unlink(MINIDUMP_LOCK_FILE)
  → binary reaches cleanup: → lock_release() closes the fd
  → lock file is gone.

SIG-02 — Same for the coredump lock file.

Test strategy
─────────────
1. Place a valid .dmp (or _core) file in the dump directory so the binary passes
   prerequisites_wait() and reaches the dump-processing loop (long-running).
2. Start the binary with Popen (no wait_for_lock needed — default LOCK_MODE_EXIT).
3. Poll until the lock file appears on disk, confirming the binary has acquired it.
4. Send SIGTERM.  handle_signal() in main.c unlinks the lock file immediately.
   The binary then continues to the cleanup: label and lock_release() closes the fd.
5. Poll until the lock file is absent on disk.
6. proc.wait() reaps the binary.

Signal-handler + cleanup reference (main.c):
    void handle_signal(int no, siginfo_t *info, void *uc)
    {
        if (lock_dir_prefix == 1)   unlink(COREDUMP_LOCK_FILE);
        else                        unlink(MINIDUMP_LOCK_FILE);
    }

    cleanup:
        if (lock_fd >= 0)
            lock_release(lock_fd, lock_file_path);  // flock(LOCK_UN) + close + unlink

    lock_dir_prefix is set from argv[2]: "1" → coredump, "0" → minidump.
"""

import os
import signal
import subprocess
import time
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump, wait_for_path,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE,
    SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH,
)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestSignalLockCleanup:
    """
    Verify that SIGTERM causes the binary to unlink the appropriate lock file.

    Both tests follow the same pattern:
      start binary → wait for lock file to appear (binary owns it) →
      send SIGTERM → wait for lock file to disappear → wait for binary exit.
    """

    # ------------------------------------------------------------------
    # SIG-01: SIGTERM removes minidump lock file
    # ------------------------------------------------------------------
    def test_sigterm_removes_minidump_lock(self, binary_path, cleanup_pytest_cache):
        """
        SIG-01 — binary acquires /tmp/.uploadMinidumps, processes a .dmp file
        (long enough for SIGTERM to interrupt it).  SIGTERM triggers handle_signal()
        which unlinks MINIDUMP_LOCK_FILE; the cleanup path then calls lock_release()
        to close the fd.  The lock file must be absent after the binary exits.
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "test_app_sig01.dmp")

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "0", "secure"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait until the binary creates and acquires the lock file
            assert wait_for_path(MINIDUMP_LOCK_FILE, present=True, timeout=10.0), (
                "Binary did not create the minidump lock file within 10 s"
            )

            assert proc.poll() is None, "Binary exited before SIGTERM could be sent"

            # Deliver SIGTERM — binary's handle_signal() unlinks the lock file
            proc.send_signal(signal.SIGTERM)

            # Wait for the lock file to disappear (handle_signal + cleanup release)
            assert wait_for_path(MINIDUMP_LOCK_FILE, present=False, timeout=10.0), (
                f"Lock file {MINIDUMP_LOCK_FILE} was not removed after SIGTERM"
            )

        finally:
            if proc is not None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            if os.path.exists(dump_path):
                os.unlink(dump_path)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # SIG-02: SIGTERM removes coredump lock file
    # ------------------------------------------------------------------
    def test_sigterm_removes_coredump_lock(self, binary_path, cleanup_pytest_cache):
        """
        SIG-02 — binary acquires /tmp/.uploadCoredumps, processes a _core file
        (long enough for SIGTERM to interrupt it).  SIGTERM triggers handle_signal()
        which unlinks COREDUMP_LOCK_FILE; the cleanup path then calls lock_release()
        to close the fd.  The lock file must be absent after the binary exits.
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        # Coredump pattern: directory_has_pattern(core_path, "_core")
        dump_path = create_dummy_dump(
            SECURE_COREDUMP_PATH, "app_core.prog.1234.gz"
        )

        if os.path.exists(COREDUMP_LOCK_FILE):
            os.unlink(COREDUMP_LOCK_FILE)

        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "1", "secure"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait until the binary creates and acquires the lock file
            assert wait_for_path(COREDUMP_LOCK_FILE, present=True, timeout=10.0), (
                "Binary did not create the coredump lock file within 10 s"
            )

            assert proc.poll() is None, "Binary exited before SIGTERM could be sent"

            # Deliver SIGTERM — binary's handle_signal() unlinks the lock file
            proc.send_signal(signal.SIGTERM)

            # Wait for the lock file to disappear (handle_signal + cleanup release)
            assert wait_for_path(COREDUMP_LOCK_FILE, present=False, timeout=10.0), (
                f"Lock file {COREDUMP_LOCK_FILE} was not removed after SIGTERM"
            )

        finally:
            if proc is not None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            if os.path.exists(dump_path):
                os.unlink(dump_path)
            if os.path.exists(COREDUMP_LOCK_FILE):
                os.unlink(COREDUMP_LOCK_FILE)
