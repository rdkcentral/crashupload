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
Functional tests for crashupload upload-deferral (uptime-based) behaviour.

TC-035 — Defer upload when uptime < 480 s
    defer_upload_if_needed() in prerequisites.c reads UPTIME_FILE.
    When built with -DL2_TEST, UPTIME_FILE = /opt/uptime (controlled value).
    uptime < 480  →  sleep(480 - uptime) seconds then check reboot flag.
    If the reboot flag is present after sleeping, the binary calls exit(0).

    Test strategy:
      • Write 479 to /opt/uptime  (sleep_time = 1 s)
      • Set /tmp/set_crash_reboot_flag BEFORE starting the binary
      • Place a .dmp file so prerequisites_wait() passes
      • Start binary, measure wall-clock elapsed time
      • Assert elapsed >= 1 s (sleep DID happen)
      • Assert exit code == 0 (reboot flag triggered exit after sleep)

TC-036 — No deferral when uptime >= 480 s
    uptime >= 480  →  defer_upload_if_needed() returns immediately (no sleep).

    Test strategy:
      • /opt/uptime already contains 600 (set by run_l2.sh), but we write
        it explicitly here for test isolation
      • Empty dump dir  →  NO_DUMPS_FOUND  →  exit(0)
      • Assert execution completes in < 5 s (no 480-second sleep occurred)

Build requirement: binary MUST be compiled with -DL2_TEST so it reads
/opt/uptime instead of /proc/uptime.
"""

import os
import subprocess
import time
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump,
    stash_dir_dumps, restore_stashed_dumps,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH,
    MINIDUMP_LOCK_FILE,
    REBOOT_FLAG_FILE,
    L2_UPTIME_FILE,
)


def _ensure_system_init_prereqs():
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestUploadDeferral:
    """Test crashupload uptime-based upload deferral (L2_TEST build required)."""

    # ------------------------------------------------------------------
    # TC-035: Defer when uptime < 480 s
    # ------------------------------------------------------------------
    def test_deferred_when_uptime_below_threshold(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-035 — Binary sleeps when box uptime < 480 s (MEDIACLIENT device type).

        /opt/uptime is written with "479.0 958.0"  →  uptime_val = 479
        →  sleep_time = 1 second.  After sleeping, the reboot flag is checked
        and the binary exits(0).

        The test measures elapsed time to confirm that at least 1 second passed
        (the sleep DID occur), then verifies exit(0).

        Requires: binary built with -DL2_TEST  (sh cov_build.sh --l2-test)
        Device type: test relies on DEVICE_TYPE being MEDIACLIENT; if the device
        type is not MEDIACLIENT, defer_upload_if_needed() is skipped and the
        test is marked as expected-skip.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Write controlled uptime: 479 s  →  sleep_time = 1 s
        Path(L2_UPTIME_FILE).write_text("479.0 958.0\n")

        # Reboot flag causes exit(0) immediately AFTER the sleep
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        # Need a dump so prerequisites_wait() passes dump-detection check
        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc035_defer.dmp")

        try:
            start = time.monotonic()
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            elapsed = time.monotonic() - start

            assert result.returncode == 0, (
                f"Expected exit 0 after deferral + reboot flag, "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
            # Confirm the sleep actually happened (elapsed ≥ 1 s)
            assert elapsed >= 1.0, (
                f"Binary completed in {elapsed:.2f}s — expected at least 1 s delay "
                f"from defer_upload_if_needed(). "
                f"Ensure binary was built with -DL2_TEST (sh cov_build.sh --l2-test) "
                f"and device type is MEDIACLIENT."
            )
        finally:
            if os.path.exists(REBOOT_FLAG_FILE):
                os.unlink(REBOOT_FLAG_FILE)
            if os.path.exists(dump):
                os.unlink(dump)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)
            # Restore /opt/uptime to safe default used by run_l2.sh
            Path(L2_UPTIME_FILE).write_text("600.0 1200.0\n")

    # ------------------------------------------------------------------
    # TC-036: No deferral when uptime >= 480 s
    # ------------------------------------------------------------------
    def test_no_deferral_when_uptime_above_threshold(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-036 — Binary exits promptly (no sleep) when uptime >= 480 s.

        /opt/uptime is written with "600.0 1200.0"  →  uptime_val = 600
        →  defer_upload_if_needed() skips the sleep branch entirely.
        The dump dir is empty  →  NO_DUMPS_FOUND  →  exit(0).

        Wall-clock time must be < 5 s confirming no 480-second sleep occurred.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Write safe uptime (above threshold)
        Path(L2_UPTIME_FILE).write_text("600.0 1200.0\n")

        try:
            stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")

            start = time.monotonic()
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            elapsed = time.monotonic() - start

            assert result.returncode == 0, (
                f"Expected exit 0 (NO_DUMPS_FOUND), got {result.returncode}"
            )
            assert elapsed < 5.0, (
                f"Binary took {elapsed:.2f}s — expected < 5 s when uptime >= 480 s. "
                f"A long delay suggests defer_upload_if_needed() slept unexpectedly."
            )
        finally:
            restore_stashed_dumps(stashed)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)
            # Leave /opt/uptime at safe default
            Path(L2_UPTIME_FILE).write_text("600.0 1200.0\n")
