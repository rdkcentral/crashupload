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
Functional tests for crashupload rate-limiting behaviour.

ratelimit_check_unified() in ratelimit.c enforces two independent limits:

1. Recovery-time deny window (DENY_UPLOADS_FILE):
     /tmp/.deny_dump_uploads_till  contains a Unix timestamp (future epoch).
     While  now <= deny_until  the function returns RATELIMIT_BLOCK.
     Source: is_recovery_time_reached().

2. Per-minidump upload-count window (minidump timestamps file):
     /tmp/.minidump_upload_timestamps  contains one Unix timestamp per line.
     When the file has > 10 lines AND the FIRST timestamp is within
     RECOVERY_DELAY_SEC (600 s) of now, the function returns STOP_UPLOAD,
     which ratelimit_check_unified() converts to RATELIMIT_BLOCK and creates
     a new DENY_UPLOADS_FILE entry.
     Source: is_upload_limit_reached().

When ratelimit_check_unified() returns RATELIMIT_BLOCK, main.c calls:
    remove_pending_dumps(working_dir, dump_extn_pattern)
which deletes all *.dmp* and *.tgz files from the working directory.

Note: archive_create_smart() runs BEFORE the rate-limit check.  The original
.dmp file is renamed to a *_mac*_dat* name and then removed inside
archive_create_smart().  Even if archiving FAILS (rename error → return -1),
the subsequent remove_pending_dumps() call still cleans up any remaining
.dmp files from the working directory.

TC-049 — Upload count > 10 within window → RATELIMIT_BLOCK
    Precondition: /tmp/.minidump_upload_timestamps has 11 lines with
    the first timestamp ≤ now - 1  (still within 600-second window).
    Assertions:
      • Binary exits 0 (goto cleanup with ret == 0).
      • Working directory contains no .dmp or .tgz files.
      • /tmp/.deny_dump_uploads_till is created with a future timestamp
        (set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) was called).

TC-051 — Recovery time not yet reached → uploads still blocked
    Precondition: /tmp/.deny_dump_uploads_till contains  now + 3600
    (one hour in the future, well within the deny window).
    Assertions:
      • Binary exits 0.
      • Working directory contains no .dmp or .tgz files.
"""

import os
import subprocess
import time
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH,
    MINIDUMP_LOCK_FILE,
    DENY_UPLOADS_FILE,
    MINIDUMP_TIMESTAMPS_FILE,
    RECOVERY_DELAY_SEC,
    ON_STARTUP_CLEANED_UP_BASE,
)

_ON_STARTUP_FLAG_MINI = f"{ON_STARTUP_CLEANED_UP_BASE}_0"


def _ensure_system_init_prereqs():
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


def _assert_working_dir_empty_of_dumps(dump_dir: str) -> None:
    """
    Assert that no .dmp or .tgz files remain in dump_dir.
    Indicates remove_pending_dumps() was called after RATELIMIT_BLOCK.
    """
    if not os.path.isdir(dump_dir):
        return
    leftovers = [
        f for f in os.listdir(dump_dir)
        if ".dmp" in f or f.endswith(".tgz")
    ]
    assert not leftovers, (
        f"Expected dump directory to be empty of .dmp/.tgz files after "
        f"rate-limit block, but found: {leftovers}"
    )


def _count_dir_dumps_and_archives(dump_dir: str):
    """Return counts of (dmp_files, tgz_files) in dump_dir."""
    if not os.path.isdir(dump_dir):
        return (0, 0)
    entries = os.listdir(dump_dir)
    return (
        sum(1 for f in entries if ".dmp" in f),
        sum(1 for f in entries if f.endswith(".tgz")),
    )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestRateLimit:
    """
    Functional tests for the ratelimit_check_unified() function.

    All tests run the binary in minidump-secure mode:
        argv = [binary, "", "0", "secure"]
    working_dir = /opt/secure/minidumps
    """

    # ------------------------------------------------------------------
    # TC-049: upload count > 10 within window → RATELIMIT_BLOCK
    # ------------------------------------------------------------------
    def test_upload_blocked_when_count_exceeds_10(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-049 — Upload count > 10 within RECOVERY_DELAY_SEC window → blocked.

        /tmp/.minidump_upload_timestamps is pre-populated with 11 timestamps
        where the FIRST line is within the last 600 seconds (is_upload_limit_reached
        returns STOP_UPLOAD → binary calls remove_pending_dumps and exits 0).

        Verified:
          1. Binary exits 0.
          2. No .dmp or .tgz files remain in the working directory.
          3. /tmp/.deny_dump_uploads_till was written by set_time(RECOVERY_TIME)
             with a future timestamp (proves ratelimit path was taken).
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Clear previous rate-limit state
        for f in [DENY_UPLOADS_FILE, MINIDUMP_TIMESTAMPS_FILE]:
            if os.path.exists(f):
                os.unlink(f)

        # Write 11 timestamps: first = 5 minutes ago (within 600s window)
        now_ts = int(time.time())
        first_ts = now_ts - 300  # 5 minutes ago, still within 600s window
        lines = [str(first_ts)] + [str(now_ts)] * 10  # 11 total lines
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text("\n".join(lines) + "\n")

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc049_dump.dmp")

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 after rate-limit block, "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )

            _assert_working_dir_empty_of_dumps(SECURE_MINIDUMP_PATH)

            # DENY_UPLOADS_FILE must have been created/updated by set_time(RECOVERY_TIME)
            assert os.path.exists(DENY_UPLOADS_FILE), (
                f"{DENY_UPLOADS_FILE} must be created after rate-limit block "
                "(set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) was not called)"
            )
            deny_ts = int(Path(DENY_UPLOADS_FILE).read_text().strip())
            assert deny_ts > now_ts, (
                f"Deny-until timestamp {deny_ts} must be > now ({now_ts}); "
                f"set_time(RECOVERY_TIME) should write now + RECOVERY_DELAY_SEC"
            )
        finally:
            for path in [dump, DENY_UPLOADS_FILE, MINIDUMP_TIMESTAMPS_FILE,
                         _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-051: recovery time not yet reached → uploads still blocked
    # ------------------------------------------------------------------
    def test_upload_blocked_when_deny_file_active(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-051 — Recovery time not yet reached → uploads are still blocked.

        /tmp/.deny_dump_uploads_till is pre-populated with a timestamp
        1 hour in the future.  is_recovery_time_reached() returns STOP_UPLOAD
        → ratelimit_check_unified() returns RATELIMIT_BLOCK → binary calls
        remove_pending_dumps and exits 0.

        Verified:
          1. Binary exits 0.
          2. No .dmp or .tgz files remain in the working directory.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Clear previous state
        if os.path.exists(MINIDUMP_TIMESTAMPS_FILE):
            os.unlink(MINIDUMP_TIMESTAMPS_FILE)

        # Write a deny-until timestamp 1 hour from now
        deny_until = int(time.time()) + 3600
        Path(DENY_UPLOADS_FILE).write_text(f"{deny_until}\n")

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc051_dump.dmp")

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 after deny-file block, "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )

            _assert_working_dir_empty_of_dumps(SECURE_MINIDUMP_PATH)
        finally:
            for path in [dump, DENY_UPLOADS_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-055: set_time() writes timestamps as truncated integers
    #         (no fractional seconds / decimal point in output)
    # ------------------------------------------------------------------
    def test_set_time_writes_integer_format_timestamp(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-055 — set_time() uses %ld format; timestamp is a truncated integer.

        set_time() always writes via:
            fprintf(fp, "%ld\n", deny_until)
        where deny_until is cast to long — fractional seconds are dropped.

        This test exercises the RECOVERY_TIME path (called when RATELIMIT_BLOCK
        fires due to > 10 timestamps within the window) and explicitly verifies
        that the written value is a pure integer:
          • Contains only digit characters (raw.isdigit())
          • No decimal point
          • Parseable as Python int() without error
          • Value is approximately now + RECOVERY_DELAY_SEC (within 5 s tolerance)

        Note: The CURRENT_TIME path (timestamp appended to the minidump timestamps
        file after a successful upload) uses the exact same fprintf() call.  Testing
        RECOVERY_TIME is sufficient to validate the format; the CURRENT_TIME path
        requires a live mock HTTP server to exercise.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Clear previous rate-limit state
        for f in [DENY_UPLOADS_FILE, MINIDUMP_TIMESTAMPS_FILE]:
            if os.path.exists(f):
                os.unlink(f)

        # 11 timestamps with first entry within the 600-second window
        # → is_upload_limit_reached() returns STOP_UPLOAD
        # → ratelimit_check_unified() calls set_time(DENY_UPLOADS_FILE, RECOVERY_TIME)
        now_ts = int(time.time())
        first_ts = now_ts - 300   # 5 minutes ago — within 600s window
        lines = [str(first_ts)] + [str(now_ts)] * 10   # 11 lines total
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text("\n".join(lines) + "\n")

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc055_ts.dmp")

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 via rate-limit block, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )

            assert os.path.exists(DENY_UPLOADS_FILE), (
                "TC-055: DENY_UPLOADS_FILE not created — set_time(RECOVERY_TIME) "
                "was not called; cannot verify timestamp format"
            )

            raw = Path(DENY_UPLOADS_FILE).read_text().strip()

            # Format check: pure digits only — no decimal point, no scientific notation
            assert raw.isdigit(), (
                f"TC-055: deny-file content '{raw}' is not a pure integer — "
                "set_time() must write %ld format (no fractional seconds)"
            )
            assert "." not in raw, (
                f"TC-055: deny-file content '{raw}' contains a decimal point — "
                "timestamp must be a truncated (floor) integer, not a float"
            )

            written_ts = int(raw)
            assert written_ts > now_ts, (
                f"TC-055: written timestamp {written_ts} is not > now ({now_ts}) — "
                "RECOVERY_TIME path should write now + RECOVERY_DELAY_SEC"
            )
            assert written_ts <= now_ts + RECOVERY_DELAY_SEC + 5, (
                f"TC-055: written timestamp {written_ts} is unexpectedly large "
                f"(expected ~{now_ts + RECOVERY_DELAY_SEC})"
            )
        finally:
            for path in [dump, DENY_UPLOADS_FILE, MINIDUMP_TIMESTAMPS_FILE,
                         _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)
