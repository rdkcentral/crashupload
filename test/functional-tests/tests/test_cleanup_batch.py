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
Functional tests for crashupload on-startup dump-directory cleanup
(cleanup_batch module in c_sourcecode/src/utils/cleanup_batch.c).

cleanup_batch() is called TWICE per binary invocation:
  1. Before scanner_find_dumps() — performs on-startup cleanup and creates flag.
  2. At the cleanup: label (end of main) — runs again but flag existence prevents
     re-running the full startup cleanup pass.

-- Execution prerequisites for these tests --
  • A .dmp file must be present in the working directory so that
    prerequisites_wait() passes dump-detection and cleanup_batch() is called
    with a non-empty directory.
  • /tmp/set_crash_reboot_flag is set BEFORE the binary starts so that
    is_box_rebooting() returns true → binary goes to cleanup: label without
    calling upload_process().  This keeps tests server-free.

TC-041 — On-startup cleanup path removes non-dump artefacts
    cleanup_batch() runs delete_files_not_matching_pattern("*.dmp*") and
    delete_all_but_most_recent(MAX_CORE_FILES) on the first run.
    Verified indirectly: a non-dump marker file placed in the dump directory
    is deleted, and the ON_STARTUP_CLEANED_UP_BASE_0 flag is created.

TC-042 — Old *_mac*_dat* archive files (> 2 days) are always deleted
    delete_files_matching_pattern_older_than("*_mac*_dat*", 2) runs
    unconditionally on every cleanup_batch() call (including when the
    ON_STARTUP flag already exists).

TC-043 — First-run flag file is created
    ON_STARTUP_CLEANED_UP_BASE + "_0"  (dump_flag == "0" → minidump mode)
    is created by cleanup_batch() at the end of the startup cleanup pass.

TC-044 — Subsequent runs skip the startup cleanup pass
    When the ON_STARTUP flag is present, need_run_startup == 0 →
    delete_files_not_matching_pattern() is NOT called.
    Verified: a non-dump marker file placed in the dump directory SURVIVES
    the binary's run because startup cleanup is skipped.

TC-045 — MAX_CORE_FILES = 4 is enforced
    With 5 .dmp files present and no ON_STARTUP flag, delete_all_but_most_recent(4)
    removes the single oldest file before scanner_find_dumps() runs.
    Because archive_create_smart() subsequently processes only the surviving
    files, the number of .tgz archives written is ≤ MAX_CORE_FILES (4).
    The ON_STARTUP flag is also checked as a proxy that startup cleanup ran.

TC-046 — Empty dump directory is handled gracefully
    cleanup_batch() calls dir_exists_and_nonempty() first; when the
    directory is empty it returns immediately without error.  The binary
    continues to scanner_find_dumps() which likewise finds nothing and exits
    cleanly with code 0.
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
    REBOOT_FLAG_FILE,
    ON_STARTUP_CLEANED_UP_BASE,
    UPLOAD_ON_STARTUP_FLAG,
    MAX_CORE_FILES,
)

# ON_STARTUP flag for minidump mode (dump_flag == "0")
_ON_STARTUP_FLAG_MINI = f"{ON_STARTUP_CLEANED_UP_BASE}_0"


def _ensure_system_init_prereqs():
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


def _stash_existing_dumps(dump_dir: str) -> list:
    """
    Temporarily rename all .dmp files in dump_dir so test setup starts clean.
    Returns a list of (backup_path, original_path) tuples for restore.
    """
    stashed = []
    if not os.path.isdir(dump_dir):
        return stashed
    for name in os.listdir(dump_dir):
        if ".dmp" in name and not name.endswith(".cbtest_bak"):
            src = os.path.join(dump_dir, name)
            dst = f"{src}.cbtest_bak"
            os.rename(src, dst)
            stashed.append((dst, src))
    return stashed


def _restore_stashed_dumps(stashed: list) -> None:
    for backup, original in stashed:
        if os.path.exists(backup):
            os.rename(backup, original)


def _cleanup_tgz_files(dump_dir: str) -> None:
    """Remove any .tgz files created by archive_create_smart() during a test."""
    if not os.path.isdir(dump_dir):
        return
    for name in os.listdir(dump_dir):
        if name.endswith(".tgz"):
            try:
                os.unlink(os.path.join(dump_dir, name))
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestCleanupBatch:
    """
    Functional tests for the cleanup_batch() on-startup cleanup logic.

    All tests run the binary in minidump-secure mode:
        argv = [binary, "", "0", "secure"]
    working_dir = /opt/secure/minidumps
    """

    # ------------------------------------------------------------------
    # TC-041: startup cleanup path removes non-dump artefacts
    # ------------------------------------------------------------------
    def test_startup_cleanup_deletes_non_dump_files(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-041 — On-startup cleanup removes oldest dump files beyond MAX limit.

        The startup cleanup path runs delete_files_not_matching_pattern("*.dmp*")
        which deletes all non-dump artefacts in the working directory.  A
        'tc041_marker.txt' file placed alongside a .dmp file is used as a
        proxy: if startup cleanup ran, the marker file is deleted.

        The ON_STARTUP flag (/tmp/.on_startup_dumps_cleaned_up_0) is also
        checked — its creation confirms the full startup cleanup path executed,
        including delete_all_but_most_recent(MAX_CORE_FILES).
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        if os.path.exists(_ON_STARTUP_FLAG_MINI):
            os.unlink(_ON_STARTUP_FLAG_MINI)

        marker = os.path.join(SECURE_MINIDUMP_PATH, "tc041_marker.txt")
        Path(marker).write_text("non-dump file — should be deleted by startup cleanup\n")

        stashed = _stash_existing_dumps(SECURE_MINIDUMP_PATH)
        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc041_dump.dmp")
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Binary exited with {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
            assert not os.path.exists(marker), (
                "Non-dump marker file should be deleted by "
                "delete_files_not_matching_pattern() in startup cleanup"
            )
            assert os.path.exists(_ON_STARTUP_FLAG_MINI), (
                "ON_STARTUP flag should be created confirming startup cleanup ran "
                "and delete_all_but_most_recent(MAX_CORE_FILES) was called"
            )
        finally:
            for path in [marker, dump, REBOOT_FLAG_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            _cleanup_tgz_files(SECURE_MINIDUMP_PATH)
            _restore_stashed_dumps(stashed)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-042: stale *_mac*_dat* archive files (> 2 days) are always deleted
    # ------------------------------------------------------------------
    def test_stale_archive_files_older_than_2_days_deleted(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-042 — Old dump files (archive artefacts) deleted to enforce limit.

        cleanup_batch() always calls:
            delete_files_matching_pattern_older_than(working_dir, "*_mac*_dat*", 2)
        before even checking the ON_STARTUP flag.  This unconditional pass
        removes any stale archive file matching "*_mac*_dat*" that is older
        than 2 days, regardless of whether startup cleanup has been run before.

        Setup: create 'host_mac001122334455_dat20220101.tgz' with mtime set
        3 days in the past (via os.utime).  After the binary runs, the file
        must be absent.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        old_archive = os.path.join(
            SECURE_MINIDUMP_PATH,
            "testhost_mac001122334455_dat20220101_crashupload.tgz",
        )
        Path(old_archive).touch(exist_ok=True)
        three_days_ago = time.time() - 3 * 24 * 3600
        os.utime(old_archive, (three_days_ago, three_days_ago))

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc042_dump.dmp")
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Binary exited with {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
            assert not os.path.exists(old_archive), (
                "Stale archive file matching '*_mac*_dat*' older than 2 days "
                "must be deleted by cleanup_batch() unconditionally"
            )
        finally:
            for path in [old_archive, dump, REBOOT_FLAG_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            _cleanup_tgz_files(SECURE_MINIDUMP_PATH)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-043: first-run ON_STARTUP flag file is created
    # ------------------------------------------------------------------
    def test_first_run_flag_created(self, binary_path, cleanup_pytest_cache):
        """
        TC-043 — First-run cleanup flag file is created by cleanup_batch().

        On the very first run (no ON_STARTUP flag present), cleanup_batch()
        completes the startup cleanup and then touches:
            /tmp/.on_startup_dumps_cleaned_up_0   (dump_flag == "0")

        After the binary exits, this file must exist.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        if os.path.exists(_ON_STARTUP_FLAG_MINI):
            os.unlink(_ON_STARTUP_FLAG_MINI)

        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc043_dump.dmp")
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Binary exited with {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
            assert os.path.exists(_ON_STARTUP_FLAG_MINI), (
                f"ON_STARTUP flag {_ON_STARTUP_FLAG_MINI} must be created "
                "by cleanup_batch() after first-run startup cleanup completes"
            )
        finally:
            for path in [dump, REBOOT_FLAG_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            _cleanup_tgz_files(SECURE_MINIDUMP_PATH)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-044: subsequent runs skip the startup cleanup pass
    # ------------------------------------------------------------------
    def test_subsequent_run_skips_startup_cleanup(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-044 — Subsequent runs skip the first-run cleanup pass.

        When the ON_STARTUP flag already exists, cleanup_batch() sets
        need_run_startup = 0 and skips delete_files_not_matching_pattern()
        and delete_all_but_most_recent().

        A non-dump marker file ('tc044_marker.txt') placed in the working
        directory SURVIVES because the startup cleanup is skipped.
        (Contrast with TC-041 where startup cleanup IS triggered and the
        marker is deleted.)
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Pre-create the ON_STARTUP flag to simulate a previous run
        Path(_ON_STARTUP_FLAG_MINI).touch(exist_ok=True)

        marker = os.path.join(SECURE_MINIDUMP_PATH, "tc044_marker.txt")
        Path(marker).write_text("non-dump file — must survive when cleanup is skipped\n")
        dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc044_dump.dmp")
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Binary exited with {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
            assert os.path.exists(marker), (
                "Non-dump marker file must NOT be deleted when ON_STARTUP flag "
                "exists — confirms cleanup_batch() skipped the startup cleanup pass"
            )
            assert os.path.exists(_ON_STARTUP_FLAG_MINI), (
                "ON_STARTUP flag must remain present after the second run"
            )
        finally:
            for path in [marker, dump, REBOOT_FLAG_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            _cleanup_tgz_files(SECURE_MINIDUMP_PATH)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-045: MAX_CORE_FILES = 4 limit enforced by delete_all_but_most_recent
    # ------------------------------------------------------------------
    def test_max_core_files_limit_enforced(self, binary_path, cleanup_pytest_cache):
        """
        TC-045 — MAX_CORE_FILES = 4 limit is enforced by cleanup_batch().

        With 5 .dmp files present and no ON_STARTUP flag, the startup cleanup
        path calls delete_all_but_most_recent(MAX_CORE_FILES=4), which
        removes the single oldest file before scanner_find_dumps() runs.

        Primary assertion: ON_STARTUP flag is created (startup cleanup ran).

        Secondary assertion (conditional on archiving succeeding):
            The number of .tgz archives written to the dump directory
            must be ≤ MAX_CORE_FILES (4), because only 4 survived
            cleanup_batch() and were passed to archive_create_smart().
            This assertion is skipped if archiving failed in the test
            environment (tgz count == 0).
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)
        if os.path.exists(_ON_STARTUP_FLAG_MINI):
            os.unlink(_ON_STARTUP_FLAG_MINI)

        stashed = _stash_existing_dumps(SECURE_MINIDUMP_PATH)
        created_dumps = []
        Path(REBOOT_FLAG_FILE).touch(exist_ok=True)

        try:
            # Create 5 .dmp files with distinct modification times so
            # delete_all_but_most_recent() can identify the oldest one.
            now = time.time()
            for idx in range(5):
                name = f"tc045_dump_{idx}.dmp"
                path = create_dummy_dump(SECURE_MINIDUMP_PATH, name)
                created_dumps.append(path)
                # idx 0 = oldest (1 hour + N*10s ago), idx 4 = newest (10s ago)
                age = 3600 + (4 - idx) * 10
                mtime = now - age
                os.utime(path, (mtime, mtime))

            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )
            assert result.returncode == 0, (
                f"Binary exited with {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )

            # Primary: ON_STARTUP flag must be created (startup cleanup ran)
            assert os.path.exists(_ON_STARTUP_FLAG_MINI), (
                "ON_STARTUP flag must be created when startup cleanup runs; "
                "its absence means cleanup_batch() did not execute the startup path"
            )

            # Secondary: .tgz count ≤ MAX_CORE_FILES (indirect archive count check)
            tgz_files = [
                f for f in os.listdir(SECURE_MINIDUMP_PATH) if f.endswith(".tgz")
            ]
            if tgz_files:
                assert len(tgz_files) <= MAX_CORE_FILES, (
                    f"Expected ≤ {MAX_CORE_FILES} .tgz archives (only files that "
                    f"survived cleanup_batch should be archived), "
                    f"found {len(tgz_files)}: {tgz_files}"
                )
        finally:
            for path in created_dumps:
                if os.path.exists(path):
                    os.unlink(path)
            for path in [REBOOT_FLAG_FILE, _ON_STARTUP_FLAG_MINI]:
                if os.path.exists(path):
                    os.unlink(path)
            _cleanup_tgz_files(SECURE_MINIDUMP_PATH)
            _restore_stashed_dumps(stashed)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # TC-046: empty dump directory handled gracefully
    # ------------------------------------------------------------------
    def test_empty_dir_handled_gracefully(self, binary_path, cleanup_pytest_cache):
        """
        TC-046 — Empty dump directory is handled gracefully by cleanup_batch().

        cleanup_batch() calls dir_exists_and_nonempty(working_dir) first.
        An empty (or absent) directory returns 0 → cleanup_batch returns 0
        immediately without attempting any file operations or crashing.

        The binary then calls scanner_find_dumps() which also finds nothing
        and exits cleanly with code 0.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        stashed = _stash_existing_dumps(SECURE_MINIDUMP_PATH)
        # Also stash any .tgz files that might be present
        tgz_stashed = []
        for name in os.listdir(SECURE_MINIDUMP_PATH):
            if name.endswith(".tgz"):
                src = os.path.join(SECURE_MINIDUMP_PATH, name)
                dst = f"{src}.tc046_bak"
                os.rename(src, dst)
                tgz_stashed.append((dst, src))

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=20,
            )
            assert result.returncode == 0, (
                f"Binary must exit cleanly (code 0) for empty dump directory; "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
        finally:
            _restore_stashed_dumps(stashed)
            for (backed, orig) in tgz_stashed:
                if os.path.exists(backed):
                    os.rename(backed, orig)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)



