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
Functional tests for crashupload failure return codes.

Test 4 — system_initialize() failure  → exit code 1
Test 5 — prerequisites_wait() returns NO_DUMPS_FOUND (5) → exit code 0

Exit-code reference (main.c):
    system_initialize() != SYSTEM_INIT_SUCCESS  →  exit(1)
    prerequisites_wait() != PREREQUISITES_SUCCESS
        → goto cleanup → exit(ret) where ret == 0

system_init.c failure path:
    filePresentCheck(core_log_file) != 0   (file absent)
        → open(core_log_file, O_CREAT) fails   (parent dir not writable/missing)
        → return -1

prerequisites.c NO_DUMPS_FOUND path:
    directory_has_pattern(minidump_path, ".dmp") returns 0 or -1
        (empty or missing dump directory)
        → return NO_DUMPS_FOUND (5)
"""

import os
import stat
import shutil
import subprocess
import time
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path,
    DEFAULT_LOG_PATH, CORE_LOG_FILE, MINIDUMP_LOCK_FILE,
    SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH, NO_DUMPS_FOUND,
)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestFailureReturn:
    """Test crashupload behaviour when internal functions fail."""

    # ------------------------------------------------------------------
    # Test 4: system_initialize() fails → exit code 1
    # ------------------------------------------------------------------
    def test_system_initialize_failure_exits_with_1(self, binary_path, cleanup_pytest_cache):
        """
        Test FAIL-01: Force system_initialize() to return -1 by making
        open(core_log_file) fail, then assert exit code == 1.

        Mechanism
        ---------
        system_init.c:
            if (filePresentCheck(core_log_file) != 0)   ← file absent
                fd = open(core_log_file, O_CREAT ...)
                if (fd < 0)  → return -1                ← open fails

        open() fails when the parent directory (/opt/logs) either:
          (a) does not exist, or
          (b) has no write permission (mode 0555).

        The test removes the core_log.txt file first (so filePresentCheck
        returns non-zero, which causes the open() branch to execute), then
        removes write permission from /opt/logs (or removes the directory
        entirely when running as root, where chmod is bypassed).

        Teardown restores /opt/logs and core_log.txt to their original state.
        """
        print(f"\n{'='*70}")
        print("TEST FAIL-01: system_initialize() failure → expect exit code 1")
        print(f"{'='*70}")

        log_dir = Path(DEFAULT_LOG_PATH)
        core_log = Path(CORE_LOG_FILE)

        # --- Save original state -----------------------------------------
        log_dir_existed = log_dir.exists()
        core_log_existed = core_log.exists()
        original_log_dir_mode = log_dir.stat().st_mode if log_dir_existed else None
        is_root = (os.getuid() == 0)

        # --- Setup: make open(core_log_file) fail -------------------------
        try:
            # Step 1: remove core_log.txt so filePresentCheck returns non-zero
            if core_log.exists():
                core_log.unlink()
                print(f"Removed {core_log} to force open() branch")

            if is_root:
                # chmod(0555) is ignored for root; remove the directory instead
                print("Running as root: removing /opt/logs so open() returns ENOENT")
                if log_dir.exists():
                    shutil.rmtree(str(log_dir))
            else:
                # Step 2: make /opt/logs non-writable so open(O_CREAT) → EACCES
                if log_dir.exists():
                    os.chmod(str(log_dir), 0o555)
                    print(f"Set {log_dir} mode to 0555 (read-only)")
                else:
                    # Directory absent → open() will fail with ENOENT
                    print(f"{log_dir} does not exist; open() will fail with ENOENT")

            # --- Run binary ----------------------------------------------
            print(f"Running: {binary_path} secure 0")
            result = subprocess.run(
                [binary_path, "secure", "0"],
                capture_output=True,
                text=True,
                timeout=15,
            )

            print(f"Exit code : {result.returncode}")
            print(f"Stdout    : {result.stdout.strip()}")
            print(f"Stderr    : {result.stderr.strip()}")

            assert result.returncode == 1, (
                f"Expected exit code 1 when system_initialize() fails "
                f"(open() on core_log_file should fail), "
                f"got {result.returncode}"
            )
            print("✓ Binary correctly returned exit code 1 "
                  "when system_initialize() failed")

        finally:
            # --- Teardown: restore original state -------------------------
            if is_root:
                if log_dir_existed:
                    log_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(str(log_dir), original_log_dir_mode or 0o755)
                    print(f"Restored {log_dir}")
            else:
                if log_dir_existed and original_log_dir_mode is not None:
                    os.chmod(str(log_dir), original_log_dir_mode)
                    print(f"Restored {log_dir} mode to "
                          f"{oct(original_log_dir_mode)}")
                elif not log_dir_existed:
                    pass  # directory was not there originally; leave it absent

            if core_log_existed:
                # Re-create the file so the environment is back to normal
                core_log.parent.mkdir(parents=True, exist_ok=True)
                core_log.touch()
                print(f"Restored {core_log}")

    # ------------------------------------------------------------------
    # Test 5: prerequisites_wait() returns NO_DUMPS_FOUND (5) → exit 0
    # ------------------------------------------------------------------
    def test_prerequisites_no_dumps_exits_with_0(self, binary_path, cleanup_pytest_cache):
        """
        Test FAIL-02: Run the binary with an empty secure dump directory so
        that prerequisites_wait() returns NO_DUMPS_FOUND (5), which is
        != PREREQUISITES_SUCCESS (0), causing main.c to jump to the
        cleanup label and exit with ret == 0.

        Mechanism
        ---------
        argv[3] = "secure"  →  config_init_load() sets:
            minidump_path = /opt/secure/minidumps  (config_manager.c)

        prerequisites.c:
            directory_has_pattern("/opt/secure/minidumps", ".dmp") → 0
            → return NO_DUMPS_FOUND  (== 5)

        main.c:
            if (prerequisites_wait(...) != PREREQUISITES_SUCCESS)
                goto cleanup          ← ret is still 0 here
            ...
        cleanup:
            exit(ret)                 ← exit(0)

        The binary is invoked as:  crashupload  ''  0  secure
          argv[1] = ""      (not used internally by the C code)
          argv[2] = "0"     (DUMP_TYPE_MINIDUMP)
          argv[3] = "secure" (selects /opt/secure/minidumps)

        Prerequisites for this test
        ---------------------------
        system_initialize() must succeed, which requires:
          - /opt/logs directory to be writable
          - core_log.txt to either already exist (filePresentCheck returns 0,
            skipping the open() branch) OR /opt/logs to be writable so that
            open(O_CREAT) can create it.
        """
        print(f"\n{'='*70}")
        print("TEST FAIL-02: prerequisites_wait() returns NO_DUMPS_FOUND "
              "→ expect exit code 0")
        print(f"{'='*70}")

        # argv[3]="secure" causes config_init_load() to set
        # minidump_path = /opt/secure/minidumps (config_manager.c).
        # Ensure that directory exists and contains no .dmp files so
        # directory_has_pattern() returns 0, triggering NO_DUMPS_FOUND.
        minidump_dir = Path(SECURE_MINIDUMP_PATH)
        minidump_dir_created_by_test = False
        pre_existing_dmps = []

        # Ensure /opt/logs exists and core_log.txt is present so that
        # system_initialize() succeeds (filePresentCheck returns 0 → open()
        # branch is skipped entirely)
        log_dir = Path(DEFAULT_LOG_PATH)
        core_log = Path(CORE_LOG_FILE)

        log_dir_created_by_test = False
        core_log_created_by_test = False

        try:
            # Ensure /opt/minidumps exists and has no .dmp files
            if not minidump_dir.exists():
                minidump_dir.mkdir(parents=True, exist_ok=True)
                minidump_dir_created_by_test = True
                print(f"Created {minidump_dir}")
            else:
                # Stash any existing .dmp files to restore after the test
                pre_existing_dmps = list(minidump_dir.glob("*.dmp*"))
                for f in pre_existing_dmps:
                    f.rename(str(f) + ".bak")
                if pre_existing_dmps:
                    print(f"Temporarily renamed {len(pre_existing_dmps)} "
                          f".dmp file(s) in {minidump_dir}")

            if not log_dir.exists():
                log_dir.mkdir(parents=True, exist_ok=True)
                log_dir_created_by_test = True
                print(f"Created {log_dir}")

            if not core_log.exists():
                core_log.touch()
                core_log_created_by_test = True
                print(f"Created {core_log} so system_initialize() succeeds")

            # Remove lock file so the binary is not blocked at Step 2
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.remove(MINIDUMP_LOCK_FILE)
                print(f"Removed stale lock file {MINIDUMP_LOCK_FILE}")

            # --- Run binary: argv[1]="", argv[2]="0", argv[3]="secure" -----
            # "secure" at argv[3] makes config_init_load() route dumps to
            # /opt/secure/minidumps, which was set up empty above.
            print(f"Running: {binary_path} '' 0 secure")
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            print(f"Exit code : {result.returncode}")
            print(f"Stdout    : {result.stdout.strip()}")
            print(f"Stderr    : {result.stderr.strip()}")

            # Verify output contains no-dump indication (informational)
            combined = result.stdout + result.stderr
            no_dump_messages = [
                "no dump",
                "not found",
                "Exiting",
                "No dumps",
            ]
            found_msg = any(
                m.lower() in combined.lower() for m in no_dump_messages
            )
            if found_msg:
                print("✓ Binary output contains expected no-dump message")
            else:
                print("ℹ No-dump message not captured in stdout/stderr "
                      "(may be in RDK log)")

            assert result.returncode == 0, (
                f"Expected exit code 0 when prerequisites_wait() returns "
                f"NO_DUMPS_FOUND ({NO_DUMPS_FOUND}), "
                f"got {result.returncode}"
            )
            print("✓ Binary correctly returned exit code 0 "
                  "when no dump files were found")

        finally:
            # Clean up lock file in case the binary left it
            if os.path.exists(MINIDUMP_LOCK_FILE):
                try:
                    os.remove(MINIDUMP_LOCK_FILE)
                except Exception:
                    pass

            # Restore any .dmp files that were temporarily renamed
            for f in pre_existing_dmps:
                bak = Path(str(f) + ".bak")
                if bak.exists():
                    bak.rename(f)

            # Remove /opt/minidumps only if this test created it
            if minidump_dir_created_by_test and minidump_dir.exists():
                try:
                    minidump_dir.rmdir()
                    print(f"Removed test-created {minidump_dir}")
                except OSError:
                    pass  # not empty; leave it

            # Remove files/dirs only if this test created them
            if core_log_created_by_test and core_log.exists():
                core_log.unlink()
                print(f"Removed test-created {core_log}")

            if log_dir_created_by_test and log_dir.exists():
                try:
                    log_dir.rmdir()  # only removes if empty
                    print(f"Removed test-created {log_dir}")
                except OSError:
                    pass  # not empty; leave it
