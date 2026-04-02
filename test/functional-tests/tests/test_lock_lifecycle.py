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
Functional tests for crashupload lock lifecycle behaviour.

TC-011 — First instance successfully acquires the process lock
    lock_acquire() in main.c creates the lock file and holds an exclusive
    flock(LOCK_EX|LOCK_NB) for the entire duration of the run.  The test
    starts the binary with a .dmp file present (so it has processing work to
    do), then polls until the lock file appears on disk.

TC-014 — Lock file removed on clean exit
    lock_release() at the cleanup: label calls flock(LOCK_UN), close(), and
    unlink().  After the binary exits cleanly (NO_DUMPS_FOUND path), the lock
    file must be absent.

TC-016 — SIGKILL does not remove the lock file
    SIGKILL cannot be caught by a user-space handler.  After kill -9, the
    kernel reclaims the fd (flock released automatically) but the lock FILE
    on disk is never unlinked.  A subsequent binary invocation must therefore
    still be able to acquire the lock (flock is gone) yet the file may still
    be present depending on timing.  The test verifies the binary survives
    SIGKILL without undefined behaviour and the lock file may persist.

Lock file reference (lock_manager.h / main.c):
    MINIDUMP_LOCK_FILE = "/tmp/.uploadMinidumps"
    COREDUMP_LOCK_FILE = "/tmp/.uploadCoredumps"
"""

import os
import signal
import subprocess
import time
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump,
    stash_dir_dumps, restore_stashed_dumps,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH,
    MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE,
)


def _ensure_system_init_prereqs():
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestLockLifecycle:
    """Test crashupload lock acquisition, release, and SIGKILL behaviour."""

    # ------------------------------------------------------------------
    # TC-011: First instance acquires lock — minidump
    # ------------------------------------------------------------------
    def test_first_instance_acquires_minidump_lock(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-011-A — First binary invocation creates and holds /tmp/.uploadMinidumps.

        A .dmp file is placed in /opt/secure/minidumps so the binary has work
        to do (keeps it alive longer than a quick NO_DUMPS_FOUND exit).  The
        binary is launched with Popen and we poll for the lock file.  Its
        presence confirms lock_acquire() succeeded.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc011_minidump.dmp")
        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "0", "secure"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Poll for the lock file to appear (lock is acquired early in main)
            deadline = time.time() + 10.0
            lock_observed = False
            while time.time() < deadline:
                if os.path.exists(MINIDUMP_LOCK_FILE):
                    lock_observed = True
                    break
                time.sleep(0.05)

            assert lock_observed, (
                "Lock file /tmp/.uploadMinidumps never appeared — "
                "lock_acquire() may have failed or binary exited too quickly"
            )
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if os.path.exists(dump):
                os.unlink(dump)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-011: First instance acquires lock — coredump
    # ------------------------------------------------------------------
    def test_first_instance_acquires_coredump_lock(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-011-B — First binary invocation creates and holds /tmp/.uploadCoredumps.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)

        if os.path.exists(COREDUMP_LOCK_FILE):
            os.unlink(COREDUMP_LOCK_FILE)

        core = os.path.join(SECURE_COREDUMP_PATH, "testproc_tc011_core.prog.gz")
        Path(core).write_bytes(b"COREDUMP\x00" * 128)
        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "1", "secure"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.time() + 10.0
            lock_observed = False
            while time.time() < deadline:
                if os.path.exists(COREDUMP_LOCK_FILE):
                    lock_observed = True
                    break
                time.sleep(0.05)

            assert lock_observed, (
                "Lock file /tmp/.uploadCoredumps never appeared — "
                "lock_acquire() may have failed or binary exited too quickly"
            )
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if os.path.exists(core):
                os.unlink(core)
            if os.path.exists(COREDUMP_LOCK_FILE):
                os.unlink(COREDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-014: Lock file removed on clean exit — minidump
    # ------------------------------------------------------------------
    def test_lock_removed_on_clean_exit_minidump(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-014-A — After the binary exits cleanly, /tmp/.uploadMinidumps is unlinked.

        The binary is invoked with an empty minidump dir  →  NO_DUMPS_FOUND
        →  goto cleanup  →  lock_release()  →  unlink(MINIDUMP_LOCK_FILE).
        After process exit, the file must not exist.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        try:
            stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")

            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 (NO_DUMPS_FOUND), got {result.returncode}"
            )
            assert not os.path.exists(MINIDUMP_LOCK_FILE), (
                "Lock file /tmp/.uploadMinidumps still exists after clean exit — "
                "lock_release() / unlink() did not run"
            )
        finally:
            restore_stashed_dumps(stashed)

    # ------------------------------------------------------------------
    # TC-014: Lock file removed on clean exit — coredump
    # ------------------------------------------------------------------
    def test_lock_removed_on_clean_exit_coredump(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-014-B — After the binary exits cleanly, /tmp/.uploadCoredumps is unlinked.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        if os.path.exists(COREDUMP_LOCK_FILE):
            os.unlink(COREDUMP_LOCK_FILE)

        try:
            stashed = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")

            result = subprocess.run(
                [binary_path, "", "1", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 (NO_DUMPS_FOUND), got {result.returncode}"
            )
            assert not os.path.exists(COREDUMP_LOCK_FILE), (
                "Lock file /tmp/.uploadCoredumps still exists after clean exit — "
                "lock_release() / unlink() did not run"
            )
        finally:
            restore_stashed_dumps(stashed)

    # ------------------------------------------------------------------
    # TC-016: SIGKILL does not remove the lock file — minidump
    # ------------------------------------------------------------------
    def test_sigkill_lock_file_persists_minidump(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-016-A — SIGKILL cannot be caught; handle_signal() is never called.

        Strategy:
          1. Place a .dmp file so the binary has work to do and stays running.
          2. Popen the binary with minidump mode.
          3. Poll until lock file appears (binary has acquired the lock).
          4. Send SIGKILL (kill -9).
          5. Assert the lock FILE still exists on disk.

        Note: The kernel releases the flock() automatically (so a new binary
        can acquire the lock), but unlink() of the file never ran.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc016_minidump.dmp")
        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "0", "secure"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Wait for lock file to appear
            deadline = time.time() + 10.0
            lock_appeared = False
            while time.time() < deadline:
                if os.path.exists(MINIDUMP_LOCK_FILE):
                    lock_appeared = True
                    break
                time.sleep(0.05)

            if not lock_appeared:
                pytest.skip(
                    "Lock file never appeared — binary may have exited too quickly "
                    "to observe SIGKILL behavior"
                )

            # SIGKILL — uncatchable
            proc.kill()
            proc.wait(timeout=5)

            assert os.path.exists(MINIDUMP_LOCK_FILE), (
                "Lock file /tmp/.uploadMinidumps was removed after SIGKILL — "
                "this should NOT happen since SIGKILL cannot be caught"
            )
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            if os.path.exists(dump):
                os.unlink(dump)
            # Clean up the lock file left by SIGKILL so next test starts clean
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-016: SIGKILL lock file persists — coredump
    # ------------------------------------------------------------------
    def test_sigkill_lock_file_persists_coredump(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-016-B — SIGKILL on coredump mode binary; /tmp/.uploadCoredumps persists.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        if os.path.exists(COREDUMP_LOCK_FILE):
            os.unlink(COREDUMP_LOCK_FILE)

        core = os.path.join(SECURE_COREDUMP_PATH, "testproc_tc016_core.prog.gz")
        Path(core).write_bytes(b"COREDUMP\x00" * 128)
        proc = None
        try:
            proc = subprocess.Popen(
                [binary_path, "", "1", "secure"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            deadline = time.time() + 10.0
            lock_appeared = False
            while time.time() < deadline:
                if os.path.exists(COREDUMP_LOCK_FILE):
                    lock_appeared = True
                    break
                time.sleep(0.05)

            if not lock_appeared:
                pytest.skip(
                    "Coredump lock file never appeared — binary exited too quickly"
                )

            proc.kill()
            proc.wait(timeout=5)

            assert os.path.exists(COREDUMP_LOCK_FILE), (
                "Lock file /tmp/.uploadCoredumps was removed after SIGKILL — "
                "this should NOT happen since SIGKILL cannot be caught"
            )
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            if os.path.exists(core):
                os.unlink(core)
            if os.path.exists(COREDUMP_LOCK_FILE):
                os.unlink(COREDUMP_LOCK_FILE)
