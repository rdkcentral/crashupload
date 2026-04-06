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
test_dump_processing.py — Dump Processing functional tests.

Background
----------
After acquiring the lock and passing prerequisites, main.c iterates over
the files returned by scanner_find_dumps() and applies two operations
before archiving:

  1. process_file_entry()  — sanitise filename, fire telemetry
  2. archive_create_smart() — rename dump, assemble .tgz

Two behaviours tested here require only filesystem state to observe:

TC-060  Skip existing `.tgz` archive files
  ─────────────────────────────────────────
  scanner_find_dumps() calls is_dump_file(), which returns 3 for files
  whose extension is ".tgz".  Back in the main.c dump loop (lines 246-250):

      if (len > 4 && strcmp(path + len - 4, ".tgz") == 0) {
          archive[i].archive_name = path;   // pass as-is
          continue;                         // skip archive_create_smart
      }

  The .tgz is treated as an already-archived artefact — archive_create_smart
  is never called on it, so no .tgz.tgz double-archive is ever produced.

TC-071  Zero-size dump file skipped (handled gracefully)
  ───────────────────────────────────────────────────────
  wait_for_file_size_stable() in scanner.c returns 0 (success) for a
  zero-byte file — the size is stable at 0, satisfying the stability
  criterion.  The file is therefore picked up by the scanner and passed
  to archive_create_smart().

  archive_create_smart() in archive.c:
    • calls file_get_size() → size_dump_u64 = 0
    • if T2 enabled: fires t2CountNotify("SYST_ERR_MINIDPZEROSIZE", 1)
    • does NOT return early — archiving is still attempted
    • for non-MEDIACLIENT device type (typical L2 container): no
      create_tarball() branch is reached; the renamed dump is deleted;
      function returns (implicit 0 / ARCHIVE_SUCCESS)

  The binary exits cleanly (exit(0)) regardless of device type.
"""

import os
import subprocess
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    stash_dir_dumps,
    restore_stashed_dumps,
    SECURE_MINIDUMP_PATH,
    CORE_LOG_FILE,
    REBOOT_FLAG_FILE,
    MINIDUMP_LOCK_FILE,
)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ensure_file(path: str) -> None:
    """Create *path* (and its parent directories) if it does not already exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).touch()


def _cleanup_tgz(directory: str) -> None:
    """Remove all .tgz files from *directory* (archive leftovers from the binary)."""
    for f in Path(directory).glob("*.tgz"):
        f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestDumpProcessing:
    """
    TC-060 / TC-071

    Both tests use secure-minidump mode (argv = ["", "0", "secure"]) with the
    reboot flag set so that upload is always skipped and exit(0) is guaranteed
    as the primary observable, independent of network availability.
    """

    def test_existing_tgz_not_re_archived(self, binary_path, cleanup_pytest_cache):
        """TC-060: Pre-existing .tgz in scan directory → skipped by archive loop → exit(0).

        The dump-processing loop in main.c checks the extension of every file
        returned by scanner_find_dumps().  When a file ends in ".tgz" it copies
        the path directly into archive[i].archive_name and calls `continue`,
        bypassing archive_create_smart() entirely.

        Precondition:  one .tgz file planted in SECURE_MINIDUMP_PATH, all
                       other .dmp/.tgz files stashed.
        Primary:       exit(0)
        Secondary:     no *.tgz.tgz file produced — confirms archive_create_smart
                       was NOT called on the pre-existing archive.
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed_dmp = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        stashed_tgz = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".tgz")

        tgz_path = os.path.join(SECURE_MINIDUMP_PATH, "tc060_already_archived.tgz")
        with open(tgz_path, "wb") as fh:
            fh.write(b"FAKE_TGZ_CONTENT_TC060")

        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"TC-060: expected exit(0) with pre-existing .tgz, got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            # Confirm archive_create_smart was NOT invoked on the .tgz
            double_archives = list(Path(SECURE_MINIDUMP_PATH).glob("*.tgz.tgz"))
            assert len(double_archives) == 0, (
                "TC-060: .tgz.tgz file(s) found — existing archive was incorrectly "
                f"re-archived: {[str(p) for p in double_archives]}"
            )
        finally:
            Path(tgz_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed_dmp)
            restore_stashed_dumps(stashed_tgz)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_zero_size_dump_handled_gracefully(self, binary_path, cleanup_pytest_cache):
        """TC-071: Zero-byte .dmp file → processed without crash/hang → exit(0).

        wait_for_file_size_stable() (scanner.c) polls at 1-second intervals
        with stability_checks=2.  For a zero-byte file the size is 0 on all
        readings; stability is reached after ~2 iterations (~2 s) and the
        function returns success.

        archive_create_smart() (archive.c) then:
          • renames the zero-byte dump to its full archive name
          • calls file_get_size() → size_dump_u64 = 0
          • fires SYST_ERR_MINIDPZEROSIZE telemetry (if T2 enabled)
          • proceeds to tgz creation — no early return

        The binary exits cleanly at the reboot-flag check after the archive
        loop, regardless of whether the tgz succeeded (device-type dependent).

        Precondition:  one zero-byte .dmp file in SECURE_MINIDUMP_PATH.
        Primary:       exit(0)  (binary did not crash, segfault, or hang)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")

        zero_dump_path = os.path.join(SECURE_MINIDUMP_PATH, "tc071_zero_size.dmp")
        open(zero_dump_path, "wb").close()
        assert os.path.getsize(zero_dump_path) == 0, (
            f"Precondition failed: {zero_dump_path} is not zero bytes"
        )

        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-071: expected exit(0) for zero-size dump, got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            Path(zero_dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
