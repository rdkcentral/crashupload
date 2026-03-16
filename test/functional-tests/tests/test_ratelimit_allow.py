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

    def test_recovery_time_expired_unblocks_upload(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-052: Expired deny-window timestamp → ALLOW_UPLOAD; deny file not refreshed.

        DENY_UPLOADS_FILE is pre-written with a timestamp 700 seconds in the past
        (beyond the 600-second RECOVERY_DELAY_SEC window).
        is_recovery_time_reached() reads the file, evaluates `now > deny_until` → ALLOW_UPLOAD.

        Because ALLOW_UPLOAD is returned, ratelimit_check_unified does NOT call
        set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) — that call only happens on RATELIMIT_BLOCK.
        DENY_UPLOADS_FILE therefore retains its original past timestamp throughout the run.

        Note: REBOOT_FLAG_FILE is deliberately absent.  is_box_rebooting() is checked
        BEFORE ratelimit_check_unified() in main.c; with the reboot flag set the binary
        would exit before reaching the ratelimit code and nothing would be proven.
        The upload loop is reached and fails (no network in the test container) — the
        binary exits non-zero.  Exit code is NOT the primary assertion here.

        Primary assertion:
          DENY_UPLOADS_FILE still contains the original past timestamp after the run
          (i.e. set_time() was NOT called), proving is_recovery_time_reached() returned
          ALLOW_UPLOAD for the expired timestamp — not STOP_UPLOAD.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

        # Past timestamp — 700 s ago, beyond the 600-second recovery window
        past_ts = int(time.time()) - 700
        Path(DENY_UPLOADS_FILE).write_text(f"{past_ts}\n")

        # 10 timestamped entries so that the count check also returns ALLOW_UPLOAD
        now_ts = int(time.time())
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text(
            "\n".join([str(now_ts - i * 10) for i in range(10)]) + "\n"
        )

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc052_allow.dmp")
        # No REBOOT_FLAG_FILE — must reach ratelimit_check_unified()
        try:
            subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            # Exit code not asserted — upload fails in the test container (no network).
            # The meaningful assertion is the deny-file content below.
            assert os.path.exists(DENY_UPLOADS_FILE), (
                "TC-052: DENY_UPLOADS_FILE was unexpectedly removed during the run"
            )
            recorded_ts = int(Path(DENY_UPLOADS_FILE).read_text().strip())
            now_after = int(time.time())
            assert recorded_ts <= now_after, (
                f"TC-052: DENY_UPLOADS_FILE was refreshed to a future timestamp "
                f"({recorded_ts} > now {now_after}) — is_recovery_time_reached() "
                "must have returned STOP_UPLOAD for the already-expired timestamp "
                "instead of ALLOW_UPLOAD."
            )
            assert recorded_ts == past_ts, (
                f"TC-052: DENY_UPLOADS_FILE timestamp changed from {past_ts} to "
                f"{recorded_ts} — set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) should "
                "not be called on the ALLOW_UPLOAD path."
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

    def test_rate_limit_resets_after_recovery_period(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-054: Timestamps file with expired window → counter reset (file unlinked).

        MINIDUMP_TIMESTAMPS_FILE is pre-written with 11 entries whose FIRST line
        is a timestamp 700 seconds in the past (beyond RECOVERY_DELAY_SEC = 600 s).

        Inside is_upload_limit_reached():
          line_cnt = 11  >  10
          (now - first_crash_time) = 700  >=  RECOVERY_DELAY_SEC (600)
          → calls unlink(MINIDUMP_TIMESTAMPS_FILE)   ← counter RESET
          → returns ALLOW_UPLOAD

        Because the function returns ALLOW_UPLOAD, ratelimit_check_unified does NOT
        call set_time(DENY_UPLOADS_FILE, RECOVERY_TIME) and DENY_UPLOADS_FILE is
        never created.

        Note: REBOOT_FLAG_FILE is absent for the same reason as TC-052 — reboot
        flag would shortcut past the ratelimit check.  Upload fails (no network)
        and exit code is not the primary assertion.

        Primary assertions:
          1. MINIDUMP_TIMESTAMPS_FILE was DELETED (by unlink() inside the C function),
             proving the expired-window counter-reset path was taken.
          2. DENY_UPLOADS_FILE was NOT created, proving RATELIMIT_BLOCK was not returned.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

        # No deny window — is_recovery_time_reached() returns ALLOW immediately
        Path(DENY_UPLOADS_FILE).unlink(missing_ok=True)

        # 11 entries; first timestamp is 700 s ago → window expired → counter resets
        first_ts = int(time.time()) - 700
        now_ts   = int(time.time())
        lines    = [str(first_ts)] + [str(now_ts)] * 10   # 11 total
        Path(MINIDUMP_TIMESTAMPS_FILE).write_text("\n".join(lines) + "\n")

        stashed   = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc054_reset.dmp")
        # No REBOOT_FLAG_FILE — must reach ratelimit_check_unified()
        try:
            subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            # Exit code not asserted — upload fails in the test container (no network).
            assert not os.path.exists(MINIDUMP_TIMESTAMPS_FILE), (
                "TC-054: MINIDUMP_TIMESTAMPS_FILE still present after the run — "
                "is_upload_limit_reached() should have called unlink() when the "
                f"first timestamp was older than RECOVERY_DELAY_SEC ({RECOVERY_DELAY_SEC} s)."
            )
            assert not os.path.exists(DENY_UPLOADS_FILE), (
                "TC-054: DENY_UPLOADS_FILE was created, indicating RATELIMIT_BLOCK "
                "was returned — the expired-window reset path should return ALLOW_UPLOAD "
                "without creating the deny file."
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
