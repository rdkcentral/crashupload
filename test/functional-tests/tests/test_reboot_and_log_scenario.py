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
Functional tests for crashupload reboot-flag behaviour and log output.

REBOOT-01 — reboot flag present, dump available → binary skips upload, exits 0
  is_box_rebooting() in system_utils.c uses filePresentCheck("/tmp/set_crash_reboot_flag").
  When the flag file exists and the binary has passed prerequisites (dump found), it
  reaches the is_box_rebooting() check (main.c), sets ret=0, and jumps to cleanup.

LOG-01 — binary always emits log lines to stdout regardless of dump presence
  logger.c writes "[CRASHUPLOAD] ..." or RDK-formatted lines to stdout/stderr.
  At minimum, logger_init() / logger_exit() always produce stdout output.

Exit-code reference (main.c):
    is_box_rebooting() == true  →  ret = 0  →  goto cleanup  →  exit(0)
    prerequisites_wait() != PREREQUISITES_SUCCESS  →  goto cleanup  →  exit(0)
"""

import os
import subprocess
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump,
    DEFAULT_LOG_PATH, CORE_LOG_FILE, MINIDUMP_LOCK_FILE,
    SECURE_MINIDUMP_PATH,
)


# ---------------------------------------------------------------------------
# Constants specific to this module
# ---------------------------------------------------------------------------

# Reboot flag file checked by is_box_rebooting() / defer_upload_if_needed()
REBOOT_FLAG_FILE = "/tmp/set_crash_reboot_flag"
DUMMY_DUMP_NAME  = "test_app.dmp"


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestRebootAndLogScenario:
    """
    Binary-level tests covering reboot-flag skip behaviour and log output.
    """

    # ------------------------------------------------------------------
    # REBOOT-01: Reboot flag present → binary skips upload and exits 0
    # ------------------------------------------------------------------
    def test_reboot_flag_present_skips_upload_exits_0(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        REBOOT-01 — /tmp/set_crash_reboot_flag exists, a valid .dmp file is present
        so prerequisites_wait() succeeds.  After the archive loop, is_box_rebooting()
        detects the flag and the binary exits 0 without attempting any upload.
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, DUMMY_DUMP_NAME)

        # Create the reboot flag
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 when reboot flag is set, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            # Remove reboot flag
            if os.path.exists(REBOOT_FLAG_FILE):
                os.unlink(REBOOT_FLAG_FILE)
            # Clean up the dummy dump (binary may have renamed it after sanitization)
            for fname in os.listdir(SECURE_MINIDUMP_PATH):
                if DUMMY_DUMP_NAME.split(".")[0] in fname or fname.endswith(".dmp"):
                    candidate = os.path.join(SECURE_MINIDUMP_PATH, fname)
                    if os.path.exists(candidate):
                        os.unlink(candidate)
            # Also attempt original path in case it was not renamed
            if os.path.exists(dump_path):
                os.unlink(dump_path)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # LOG-01: Binary always produces log output on stdout
    # ------------------------------------------------------------------
    def test_binary_produces_log_output(self, binary_path, cleanup_pytest_cache):
        """
        LOG-01 — Regardless of dump presence, the binary emits log lines to stdout.

        logger.c always prints at init/exit time:
          - Without RDK_LOGGER:  "CRASHUPLOAD: Using fallback logger"
          - With    RDK_LOGGER:  "RDK logger standard init with <debug.ini>"
          and at exit:           "CRASHUPLOAD: RDK Logger cleaned up" or
                                 "CRASHUPLOAD: Fallback logger cleanup (no-op)"

        Even if init fails, main.c prints:
          "WARNING: RDK Logger initialization failed, using fallback logger"

        The test runs the binary against an empty minidump directory so it exits
        quickly (exit 0, NO_DUMPS_FOUND) and checks that stdout contains content.
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        # Hide any pre-existing .dmp files so the binary exits fast
        stashed = []
        try:
            for f in os.listdir(SECURE_MINIDUMP_PATH):
                if ".dmp" in f:
                    src = os.path.join(SECURE_MINIDUMP_PATH, f)
                    dst = f"{src}.log01_bak"
                    os.rename(src, dst)
                    stashed.append((dst, src))

            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )

            combined_output = result.stdout + result.stderr
            assert len(combined_output) > 0, (
                "Expected binary to emit log output to stdout/stderr, but both were empty.\n"
                f"returncode: {result.returncode}"
            )
        finally:
            for (backed_up, original) in stashed:
                if os.path.exists(backed_up):
                    os.rename(backed_up, original)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)
