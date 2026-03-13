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
test_ratelimit_allow.py — Rate-limiting allow-path functional tests.

Background
----------
`ratelimit_check_unified()` in `ratelimit.c` enforces two checks in sequence:

  Step 1 — deny-window check (is_recovery_time_reached):
    Reads `/tmp/.deny_dump_uploads_till`.  If absent OR expired → ALLOW_UPLOAD.

  Step 2 — per-minidump count check (is_upload_limit_reached):
    Reads `/tmp/.minidump_upload_timestamps`.
      • File absent OR line count ≤ 10 → ALLOW_UPLOAD
      • Line count > 10 AND first timestamp within RECOVERY_DELAY_SEC → STOP_UPLOAD
    This check is ONLY performed when dump_type == DUMP_TYPE_MINIDUMP.
    For DUMP_TYPE_COREDUMP the `else { status = ALLOW_UPLOAD; }` branch fires.

When both checks return ALLOW_UPLOAD the function returns ALLOW_UPLOAD (1).
main.c does NOT call `remove_pending_dumps()` and proceeds to the upload loop.
The upload loop is bypassed by the reboot flag (is_box_rebooting → exit(0)).

Observable when upload is NOT blocked:
  • Binary exits 0 (via reboot-flag path, not rate-limit path).
  • DENY_UPLOADS_FILE (/tmp/.deny_dump_uploads_till) is NOT created by the
    rate-limiter (set_time(RECOVERY_TIME) is only called on RATELIMIT_BLOCK).

TC-048  Upload count ≤ 10 → ALLOW_UPLOAD
  ─────────────────────────────────────────
  `/tmp/.minidump_upload_timestamps` is pre-populated with exactly 10 lines
  (boundary condition: the rate-limiter should NOT trigger at 10 or fewer).
  is_upload_limit_reached() returns ALLOW_UPLOAD → rate limit not triggered.

TC-050  Rate limiting applied to minidump path only
  ────────────────────────────────────────────────────
  Even when `/tmp/.minidump_upload_timestamps` has 11 lines (which would block
  a minidump run), a coredump run (argv[2]="1") skips the count check entirely
  inside ratelimit_check_unified() → ALLOW_UPLOAD returned → not blocked.
"""

import os
import subprocess
import time
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    create_dummy_dump,
    stash_dir_dumps,
    restore_stashed_dumps,
    DEFAULT_LOG_PATH,
    CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH,
    SECURE_COREDUMP_PATH,
    MINIDUMP_LOCK_FILE,
    COREDUMP_LOCK_FILE,
    DENY_UPLOADS_FILE,
    MINIDUMP_TIMESTAMPS_FILE,
    REBOOT_FLAG_FILE,
    ON_STARTUP_CLEANED_UP_BASE,
)

_ON_STARTUP_FLAG_MINI = f"{ON_STARTUP_CLEANED_UP_BASE}_0"
_ON_STARTUP_FLAG_CORE = f"{ON_STARTUP_CLEANED_UP_BASE}_1"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ensure_system_init_prereqs():
    """Create the log directory and core_log.txt required by system_initialize()."""
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


def _cleanup_tgz(directory: str) -> None:
    """Remove .tgz files left by the binary in *directory*."""
    if os.path.isdir(directory):
        for f in Path(directory).glob("*.tgz"):
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestRateLimitAllow:
    """
    TC-048 and TC-050 — rate-limit allow paths.

    These tests verify that the binary is NOT blocked by the rate limiter and
    proceeds normally (to the reboot-flag exit) when the count threshold is
    not exceeded (TC-048) or when the dump type is coredump (TC-050).
    """

    def test_upload_allowed_when_count_at_or_below_limit(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-048: timestamp file has exactly 10 lines → ALLOW_UPLOAD, no rate-limit block.

        `is_upload_limit_reached()` checks `line_cnt <= 10` — the boundary is
        inclusive.  10 entries must NOT trigger a block.

        Setup:
          • DENY_UPLOADS_FILE absent — deny-window check passes.
          • MINIDUMP_TIMESTAMPS_FILE contains exactly 10 recent timestamps.
          • One .dmp file planted in SECURE_MINIDUMP_PATH.
          • REBOOT_FLAG_FILE set so the upload loop exits cleanly without
            a network call.

        Assertions:
          • exit(0)
          • DENY_UPLOADS_FILE was NOT created by the rate limiter.
            (set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) is only called on
            RATELIMIT_BLOCK, never on ALLOW_UPLOAD.)
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

        # Ensure clean rate-limit state
        Path(DENY_UPLOADS_FILE).unlink(missing_ok=True)

        # 10 lines — boundary value: must NOT trigger block
        now_ts = int(time.time())
        timestamps = "\n".join([str(now_ts - i * 10) for i in range(10)]) + "\n"
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text(timestamps)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc048_allow.dmp")
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-048: expected exit(0) when count ≤ 10, got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            # Rate limiter must NOT have fired — deny file must be absent
            assert not os.path.exists(DENY_UPLOADS_FILE), (
                "TC-048: DENY_UPLOADS_FILE was created even though upload count "
                f"was ≤ 10 — rate limiter should have returned ALLOW_UPLOAD, "
                "not RATELIMIT_BLOCK"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(DENY_UPLOADS_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_TIMESTAMPS_FILE).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
            Path(_ON_STARTUP_FLAG_MINI).unlink(missing_ok=True)

    def test_coredump_not_rate_limited_by_minidump_counter(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-050: coredump run bypasses the minidump count check → ALLOW_UPLOAD.

        `ratelimit_check_unified(DUMP_TYPE_COREDUMP)` reaches the `else` branch
        and sets `status = ALLOW_UPLOAD` without reading MINIDUMP_TIMESTAMPS_FILE.

        A minidump run with the same precondition (11 entries, within window)
        WOULD be blocked (TC-049 verifies this).  This test confirms the
        symmetry: coredump ignores the minidump counters completely.

        Setup:
          • DENY_UPLOADS_FILE absent — deny-window check passes.
          • MINIDUMP_TIMESTAMPS_FILE contains 11 recent timestamps (would block
            a minidump run, but must be ignored for coredump).
          • One `_core` file planted in SECURE_COREDUMP_PATH.
          • REBOOT_FLAG_FILE set so the upload loop exits cleanly.

        Assertions:
          • exit(0)
          • DENY_UPLOADS_FILE was NOT created by the rate limiter.
            (For coredump ALLOW_UPLOAD path, set_time() is never called.)
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)

        # Ensure clean deny-window state
        Path(DENY_UPLOADS_FILE).unlink(missing_ok=True)

        # 11 lines within window — sufficient to block a minidump run
        now_ts = int(time.time())
        first_ts = now_ts - 60   # 1 minute ago, well within 600s window
        lines = [str(first_ts)] + [str(now_ts)] * 10    # 11 total
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text("\n".join(lines) + "\n")

        stashed = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")
        dump_path = create_dummy_dump(SECURE_COREDUMP_PATH, "proc_tc050_core.prog")
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "1", "secure"],   # "1" → DUMP_TYPE_COREDUMP
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-050: expected exit(0) for coredump run ignoring minidump "
                f"counter, got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            # Rate limiter must NOT have fired for coredump
            assert not os.path.exists(DENY_UPLOADS_FILE), (
                "TC-050: DENY_UPLOADS_FILE was created for a coredump run — "
                "ratelimit_check_unified(COREDUMP) should return ALLOW_UPLOAD "
                "regardless of minidump timestamp count"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_COREDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(DENY_UPLOADS_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_TIMESTAMPS_FILE).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)
            Path(_ON_STARTUP_FLAG_CORE).unlink(missing_ok=True)
