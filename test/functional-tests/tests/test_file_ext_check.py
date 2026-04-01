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
test_file_ext_check.py — Archive filename structure, truncation and mpeos-main tests.

Background
----------
After scanning, `main.c` constructs `new_dump_name` for each dump file:

    new_dump_name = "{sha1}_mac{mac}_dat{ts}_box{boxtype}_mod{model}_{dumpfile}"

For coredumps whose path contains "mpeos-main", the `{ts}` field is the file's
MTIME (from `file_get_mtime_formatted()`), not `crashts` (current wall-clock time).

If `strlen(new_dump_name) >= 135`, two successive truncation passes are applied:
  Pass 1: Strip everything before the first `_`  (removes the sha1 prefix).
  Pass 2: If still >= 135, trim the process name extracted by `extract_pname()`
          to 20 characters using `trim_process_name_in_path()`.

`archive_create_smart()` uses `new_dump_name` as the base for the archive:
  - Minidump:  `new_dump_name + ".tgz"`
  - Coredump:  `new_dump_name + ".core.tgz"`

All three tests use REBOOT_FLAG_FILE so that:
  1. The archive loop runs fully (archive_create_smart produces the .tgz).
  2. `is_box_rebooting()` returns true → binary exits 0 WITHOUT reaching the
     upload loop (no network calls, predictable exit(0)).

The archive appears in the dump working directory and the .tgz filename is
the observable for all three TCs.

TC-061  Archive filename includes MAC + timestamp + pname + version
  ────────────────────────────────────────────────────────────────────
  Plant a plain `tc061proc_12345.dmp`.  The binary constructs new_dump_name
  with all four field markers present.  The resulting `.tgz` basename must
  contain `_mac`, `_dat`, `_box`, `_mod` and the original basename (proves
  all metadata fields are embedded, not just some).

TC-062  Archive filename truncated at 135 characters
  ─────────────────────────────────────────────────────
  Plant a dump whose name produces new_dump_name > 135 chars.  A process name
  of 80 'x' characters is sufficient: the initial new_dump_name is ~160 chars,
  after pass-1 ~148 chars, after pass-2 (trim pname to 20 chars) ~30 chars.
  Assert: `.tgz` basename (without ".tgz") is strictly < 135 chars.

TC-063  `mpeos-main` process name mapped with file mtime, not crashts
  ─────────────────────────────────────────────────────────────────────
  Plant `mpeos-main_core.prog.gz` with its mtime set to exactly 1 hour ago.
  In `main.c`, the `strstr(path, "mpeos-main")` branch uses `dumps[i].mtime_date`
  (file mtime) instead of `crashts` (current time) in the `_dat` field.
  The produced `.core.tgz` name must contain `_dat{expected_dat}_` where
  `expected_dat` is the formatted mtime of the planted file.

  Proof of distinction: a normal coredump would have the current time in the
  `_dat` field.  The file's mtime is 1 hour in the past, so the two values
  differ by ~3600 formatted seconds — the assertion is unambiguous.
"""

import os
import subprocess
import time
from datetime import datetime
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
    REBOOT_FLAG_FILE,
    MINIDUMP_LOCK_FILE,
    COREDUMP_LOCK_FILE,
    ON_STARTUP_CLEANED_UP_BASE,
)

_ON_STARTUP_FLAG_MINI = f"{ON_STARTUP_CLEANED_UP_BASE}_0"
_ON_STARTUP_FLAG_CORE = f"{ON_STARTUP_CLEANED_UP_BASE}_1"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ensure_file(path: str, content: bytes = b"DUMMY\n") -> str:
    """Create *path* (and parent dirs) if it does not exist; return *path*."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(content)
    return path


def _cleanup_tgz(directory: str) -> None:
    """Remove all *.tgz files (including *.core.tgz) from *directory*."""
    if os.path.isdir(directory):
        for f in Path(directory).glob("*.tgz"):
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestArchiveNaming:
    """
    TC-061 / TC-062 / TC-063 — archive filename structural, truncation and
    mpeos-main mtime tests.

    All tests set REBOOT_FLAG_FILE before running the binary so that:
      • archive_create_smart() runs and produces the .tgz  (archive loop first)
      • is_box_rebooting() returns true → goto cleanup → exit(0)  (no upload)
    """

    def test_archive_filename_contains_required_fields(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-061: Archive filename embeds all four required metadata fields.

        new_dump_name format:
            {sha1}_mac{mac}_dat{ts}_box{boxtype}_mod{model}_{dumpfile}

        The .tgz basename (without ".tgz") must contain all four field markers
        (_mac, _dat, _box, _mod) and the original process name from the dump
        filename, proving that every metadata component was included.

        Primary:   exit(0)
        Secondary: produced .tgz basename contains _mac, _dat, _box, _mod, tc061proc
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

        _cleanup_tgz(SECURE_MINIDUMP_PATH)
        stashed   = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc061proc_12345.dmp")
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-061: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            tgz_files = [
                f for f in Path(SECURE_MINIDUMP_PATH).glob("*.tgz")
                if not f.name.endswith(".core.tgz")
            ]
            assert len(tgz_files) >= 1, (
                "TC-061: no .tgz produced in SECURE_MINIDUMP_PATH — "
                "archive_create_smart() may have failed"
            )
            tgz_name = tgz_files[0].name
            basename = tgz_name[: -len(".tgz")]   # strip ".tgz"
            for marker in ("_mac", "_dat", "_box", "_mod"):
                assert marker in basename, (
                    f"TC-061: field marker '{marker}' missing from archive name "
                    f"'{basename}' — metadata field was not embedded in new_dump_name."
                )
            assert "tc061proc" in basename, (
                f"TC-061: original process name 'tc061proc' missing from archive name "
                f"'{basename}' — dump basename was not appended to new_dump_name."
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
            Path(_ON_STARTUP_FLAG_MINI).unlink(missing_ok=True)

    def test_archive_filename_truncated_at_135_chars(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-062: Archive basename is < 135 chars when the constructed name exceeds that.

        A process name of 80 'x' characters is used:
          new_dump_name (initial) ≈ 160 chars  (sha1 + metadata + 80x_name)
          After pass-1 (strip sha1)             ≈ 148 chars  (still ≥ 135)
          After pass-2 (trim pname to 20 chars) ≈  30 chars  (< 135)

        The .tgz basename (without ".tgz") must be strictly less than 135 characters,
        proving both truncation passes ran.

        Primary:   exit(0)
        Secondary: len(tgz_basename_without_tgz_extension) < 135
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

        # 80-char process name guarantees new_dump_name >> 135 chars before truncation
        long_pname = "x" * 80
        dump_name  = f"{long_pname}_99999.dmp"

        _cleanup_tgz(SECURE_MINIDUMP_PATH)
        stashed   = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, dump_name)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-062: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            tgz_files = [
                f for f in Path(SECURE_MINIDUMP_PATH).glob("*.tgz")
                if not f.name.endswith(".core.tgz")
            ]
            assert len(tgz_files) >= 1, (
                "TC-062: no .tgz produced in SECURE_MINIDUMP_PATH — "
                "archive_create_smart() may have failed"
            )
            tgz_name = tgz_files[0].name
            base_len = len(tgz_name) - len(".tgz")
            assert base_len < 135, (
                f"TC-062: archive basename length {base_len} is not < 135 — "
                f"trim_process_name_in_path() may not have shortened the name "
                f"correctly.  Archive name: '{tgz_name}'"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            # The renamed dump (new_dump_name) is also cleaned up via _cleanup_tgz
            # but the intermediate renamed .dmp may remain if archiving failed:
            for f in Path(SECURE_MINIDUMP_PATH).glob(f"{long_pname[:20]}*"):
                f.unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
            Path(_ON_STARTUP_FLAG_MINI).unlink(missing_ok=True)

    def test_mpeos_main_uses_mtime_not_crashts(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-063: mpeos-main coredump archive uses file mtime in _dat, not current time.

        For coredump files whose path contains "mpeos-main", main.c uses
        `dumps[i].mtime_date` (the file's own mtime) in the _dat field instead
        of `crashts` (the wall-clock time at scan).

        The dump file's mtime is set to exactly 1 hour in the past so that the
        expected string (`expected_dat`) differs unambiguously from the current
        time (~3600 formatted seconds apart).

        Mechanism:
          file_get_mtime_formatted() formats mtime as "%Y-%m-%d-%H-%M-%S".
          Python's `datetime.fromtimestamp(mtime).strftime(fmt)` produces the
          same string (both use local timezone).

        Primary:   exit(0)
        Secondary: produced .core.tgz name contains `_dat{expected_dat}_`
                   (proves the mtime-branch was taken, not the crashts branch)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)

        # File mtime set to exactly 1 hour ago — unambiguously different from now
        past_mtime   = int(time.time()) - 3600
        expected_dat = datetime.fromtimestamp(past_mtime).strftime("%Y-%m-%d-%H-%M-%S")

        _cleanup_tgz(SECURE_COREDUMP_PATH)
        stashed   = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")
        dump_path = os.path.join(SECURE_COREDUMP_PATH, "mpeos-main_core.prog.gz")
        with open(dump_path, "wb") as fh:
            fh.write(b"COREDUMP_HEADER" + b"\x00" * 4096)
        # Set mtime to the known past value
        os.utime(dump_path, (past_mtime, past_mtime))

        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "1", "secure"],   # "1" → DUMP_TYPE_COREDUMP
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-063: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            core_tgz_files = list(Path(SECURE_COREDUMP_PATH).glob("*.core.tgz"))
            assert len(core_tgz_files) >= 1, (
                "TC-063: no .core.tgz produced in SECURE_COREDUMP_PATH — "
                "archive_create_smart() may have failed for the coredump"
            )
            found = any(f"_dat{expected_dat}_" in f.name for f in core_tgz_files)
            assert found, (
                f"TC-063: expected '_dat{expected_dat}_' (1-hour-ago mtime) in a "
                f".core.tgz name, but not found.\n"
                f"Archive names: {[f.name for f in core_tgz_files]}\n"
                "This suggests main.c used 'crashts' (current time) instead of "
                "'mtime_date' for the mpeos-main coredump — strstr(path, 'mpeos-main') "
                "branch may not have been taken."
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_COREDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)
            Path(_ON_STARTUP_FLAG_CORE).unlink(missing_ok=True)
