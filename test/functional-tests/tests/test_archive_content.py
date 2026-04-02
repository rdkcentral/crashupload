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
test_archive_content.py — Archive creation and log-file mapping tests.

Observation mechanism
---------------------
All five TCs use REBOOT_FLAG_FILE so the binary exits cleanly after the
archive loop without attempting an upload.  The observable side-effect is the
`.tgz` file produced in SECURE_MINIDUMP_PATH and — for log-mapping TCs — the
set of member names within that tarball.

Archive member naming
---------------------
For DEVICE_TYPE_MEDIACLIENT (the default in the test container), the binary
calls archive_create_smart() which bundles:

  arch_files_list[0]  =  new_dump_name  (relative path; contains the original
                                         dump basename as its trailing field)
  arch_files_list[1]  =  /version.txt   (absolute; only added if file exists)
  arch_files_list[2]  =  config->core_log_file  = /opt/logs/core_log.txt

For each log file recorded in LOG_FILES_PATH (written by
get_crashed_log_file() after a logmapper hit), add_crashed_process_log_file()
copies it to a renamed destination:

    {working_dir}/mac{mac}_dat{mtime}_box{boxtype}_mod{model}_{log_basename}

That *copy path* — not the original path — is added to the archive.  Therefore
the original log file basename (e.g. "tc075test.log") always appears as a
suffix in the archive member name.

LOG_FILES_PATH (/tmp/minidump_log_files.txt) is unlink()'d by the binary after
the loop, so it is gone by the time the binary exits.  The .tgz member list is
the only persisting observable for log-mapping assertions.

TC-065  Archive produced for a single dump file
  ──────────────────────────────────────────────
  Plant tc065proc_99999.dmp + set REBOOT_FLAG.
  Assert: exit(0) and at least one .tgz file appears in SECURE_MINIDUMP_PATH.

TC-066  Archive contains the required baseline members
  ──────────────────────────────────────────────────────
  Plant tc066proc_99999.dmp, pre-create /version.txt and core_log.txt.
  Assert: .tgz members include the original dump basename, "version.txt",
          and "core_log.txt".

TC-075  Log file mapped for the crashed process is bundled into the archive
  ──────────────────────────────────────────────────────────────────────────
  Write logmapper entry "tc075proc=tc075test.log", pre-create the source log.
  Plant tc075proc_99999.dmp + REBOOT_FLAG.
  Assert: exit(0) and a .tgz member name contains "tc075test.log".

TC-080  All comma-separated log files appear in the archive
  ─────────────────────────────────────────────────────────
  Write logmapper "tc080proc=tc080a.log,tc080b.log", pre-create both logs.
  Plant tc080proc_99999.dmp + REBOOT_FLAG.
  Assert: .tgz contains members for BOTH tc080a.log and tc080b.log.

TC-078  Missing mapped log file handled gracefully — no crash
  ────────────────────────────────────────────────────────────
  Write logmapper "tc078proc=tc078missing.log"; do NOT create the source log.
  Plant tc078proc_99999.dmp + REBOOT_FLAG.
  add_crashed_process_log_file() calls extract_tail() on the absent file;
  fopen() returns NULL → returns -1 → error logged → archive loop continues.
  Assert: exit(0) (binary does not crash on missing mapped log).
"""

import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    stash_dir_dumps,
    restore_stashed_dumps,
    DEFAULT_LOG_PATH,
    CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH,
    REBOOT_FLAG_FILE,
    MINIDUMP_LOCK_FILE,
)

# Constants from C source
LOGMAPPER_FILE_PATH = "/etc/breakpad-logmapper.conf"
LOG_FILES_PATH      = "/tmp/minidump_log_files.txt"
VERSION_TXT         = "/version.txt"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ensure_file(path: str) -> None:
    """Create *path* (and parent dirs) if absent."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).touch()


def _cleanup_tgz(directory: str) -> None:
    """Remove .tgz files left by the binary in *directory*."""
    if os.path.isdir(directory):
        for f in Path(directory).glob("*.tgz"):
            f.unlink(missing_ok=True)


def _write_logmapper(content: str) -> str | None:
    """
    Overwrite LOGMAPPER_FILE_PATH with *content*.

    Returns the original file content (str) if it existed, else None.
    Caller must call _restore_logmapper(original) in the finally block.
    """
    original = None
    if os.path.exists(LOGMAPPER_FILE_PATH):
        original = Path(LOGMAPPER_FILE_PATH).read_text()
    os.makedirs(os.path.dirname(LOGMAPPER_FILE_PATH), exist_ok=True)
    Path(LOGMAPPER_FILE_PATH).write_text(content)
    return original


def _restore_logmapper(original: str | None) -> None:
    """Restore LOGMAPPER_FILE_PATH to *original* content (or remove if it was absent)."""
    if original is None:
        Path(LOGMAPPER_FILE_PATH).unlink(missing_ok=True)
    else:
        Path(LOGMAPPER_FILE_PATH).write_text(original)


def _create_file(path: str, content: bytes = b"DUMMY") -> str:
    """Create a file at *path* with *content*; return the path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)
    return path


def _run_binary(bp: str, dump_dir: str) -> subprocess.CompletedProcess:
    """Run the binary targeting *dump_dir* as a secure minidump scan."""
    return subprocess.run(
        [bp, "", "0", "secure"],
        capture_output=True, text=True, timeout=60,
    )


def _tgz_members(directory: str) -> list:
    """Return all member names from every .tgz found in *directory*."""
    names = []
    for tgz_path in Path(directory).glob("*.tgz"):
        try:
            with tarfile.open(str(tgz_path)) as tf:
                names.extend(tf.getnames())
        except Exception:
            pass
    return names


# ---------------------------------------------------------------------------
# TC-065 / TC-066 — Archive Creation
# ---------------------------------------------------------------------------

class TestArchiveCreation:
    """
    TC-065 / TC-066

    Verify that archive_create_smart() produces a .tgz containing the expected
    baseline files.  REBOOT_FLAG_FILE is set so the binary exits cleanly after
    the archive loop, without attempting a network upload.
    """

    def test_archive_created_for_dump(self, binary_path, cleanup_pytest_cache):
        """TC-065: A .tgz archive is created for a discovered dump file.

        A single dump is planted in SECURE_MINIDUMP_PATH.  The REBOOT_FLAG
        causes the binary to exit(0) after archiving.

        Primary:    exit(0)
        Secondary:  At least one .tgz file exists in SECURE_MINIDUMP_PATH
                    (proves archive_create_smart() ran and completed)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc065proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-065: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            tgz_files = list(Path(SECURE_MINIDUMP_PATH).glob("*.tgz"))
            assert tgz_files, (
                "TC-065: no .tgz file found in SECURE_MINIDUMP_PATH — "
                "archive_create_smart() may not have been called or failed silently."
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_archive_contains_required_members(self, binary_path, cleanup_pytest_cache):
        """TC-066: The produced .tgz contains the dump, /version.txt, and core_log.txt.

        archive_create_smart() assembles arch_files_list as:
          [0]  new_dump_name       — the renamed dump (contains original basename)
          [1]  /version.txt        — firmware version file
          [2]  /opt/logs/core_log.txt  — crash log file

        Only files that pass is_regular_file() are added, so all three must
        exist on disk before the binary runs.

        Primary:    exit(0)
        Secondary:  .tgz member names contain:
                    - the original dump basename ("tc066proc_99999.dmp")
                    - "version.txt"
                    - "core_log.txt"
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        # Track whether we create /version.txt so we can clean it up
        version_txt_was_absent = not os.path.exists(VERSION_TXT)
        _ensure_file(VERSION_TXT)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc066proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-066: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            members = _tgz_members(SECURE_MINIDUMP_PATH)
            assert members, (
                "TC-066: no .tgz produced — archive_create_smart() may not have run."
            )
            assert any("tc066proc_99999.dmp" in m for m in members), (
                f"TC-066: renamed dump not found in archive members.\n"
                f"Members: {members}"
            )
            assert any("version.txt" in m for m in members), (
                f"TC-066: /version.txt not found in archive members.\n"
                f"Members: {members}"
            )
            assert any("core_log.txt" in m for m in members), (
                f"TC-066: core_log.txt (config->core_log_file) not found in archive members.\n"
                f"Members: {members}"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
            if version_txt_was_absent:
                Path(VERSION_TXT).unlink(missing_ok=True)

    def test_crashed_url_file_included_in_archive(self, binary_path, cleanup_pytest_cache):
        """TC-079: crashed_url.txt is included in the archive when the file exists.

        archive_create_smart() (archive.c) checks for crashed_url.txt at
        {config->log_path}/crashed_url.txt = /opt/logs/crashed_url.txt.
        When filePresentCheck() succeeds the path is appended to arch_files_list
        and bundled into the .tgz.

        The source URL file is pre-created with dummy content.  If it already
        exists in the environment (e.g. from a prior upload) it is left as-is
        and never removed by this test.

        Primary:    exit(0)
        Secondary:  .tgz member name contains "crashed_url.txt"
                    (proves filePresentCheck passed and the file was added to
                    the archive by archive_create_smart())
        """
        CRASHED_URL_FILE = "/opt/logs/crashed_url.txt"

        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        url_file_was_absent = not os.path.exists(CRASHED_URL_FILE)
        if url_file_was_absent:
            _create_file(CRASHED_URL_FILE, b"https://crashupload.example.com/tc079\n")

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc079proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-079: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            members = _tgz_members(SECURE_MINIDUMP_PATH)
            assert any("crashed_url.txt" in m for m in members), (
                "TC-079: 'crashed_url.txt' not found in any .tgz member — "
                "filePresentCheck() may have failed or the file was not added "
                "to arch_files_list in archive_create_smart().\n"
                f"Members: {members}"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
            if url_file_was_absent:
                Path(CRASHED_URL_FILE).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TC-075 / TC-080 / TC-078 — Log File Mapping
# ---------------------------------------------------------------------------

class TestLogFilesMapping:
    """
    TC-075 / TC-080 / TC-078

    Verify the logmapper-driven log-bundling behaviour.  Each test writes a
    unique entry to LOGMAPPER_FILE_PATH, plants a matching dump, and inspects
    the .tgz member list.

    Mechanism recap (DEVICE_TYPE_MEDIACLIENT minidump path):
      get_crashed_log_file() → strstr(pname, logmapper_key) → match →
        append_logfile_entry() writes /opt/logs/<log> to LOG_FILES_PATH.
      archive_create_smart() reads LOG_FILES_PATH line by line →
        add_crashed_process_log_file() copies each log to a renamed file in
        working_dir: mac{mac}_dat{mtime}_box{box}_mod{model}_{log_basename}
      The renamed copy path is the archive member name.
      LOG_FILES_PATH is unlink()'d after the loop — gone before binary exits.

    Since the member name carries the original basename as its trailing
    component, assertions use `any(basename in m for m in members)`.
    """

    def test_log_files_mapped_for_crashed_process(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-075: A log file mapped in logmapper for the crashed process appears in the archive.

        Logmapper entry "tc075proc=tc075test.log" maps process "tc075proc" to
        log file "/opt/logs/tc075test.log".  The source log is pre-created so
        extract_tail() can copy it.  After archiving, the .tgz must contain a
        member whose name ends with "tc075test.log" (the renamed copy path).

        Primary:    exit(0)
        Secondary:  .tgz member name contains "tc075test.log"
                    (proves logmapper hit → add_crashed_process_log_file()
                    succeeded → copy bundled in archive)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc075proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc075test.log"),
            b"tc075 dummy log content\n",
        )
        original_logmapper = _write_logmapper("tc075proc=tc075test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-075: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            members = _tgz_members(SECURE_MINIDUMP_PATH)
            assert any("tc075test.log" in m for m in members), (
                "TC-075: 'tc075test.log' not found in any .tgz member — "
                "logmapper lookup or add_crashed_process_log_file() may have failed.\n"
                f"Members: {members}"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            Path(log_file_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_all_mapped_log_files_added_to_archive(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-080: All comma-separated log files in the logmapper entry are bundled.

        Logmapper entry "tc080proc=tc080a.log,tc080b.log" maps "tc080proc" to
        two log files.  get_logfiles() splits the RHS on commas and calls
        append_logfile_entry() for each; archive_create_smart() then calls
        add_crashed_process_log_file() for each line in LOG_FILES_PATH.

        Both source logs are pre-created so the copy succeeds.

        Primary:    exit(0)
        Secondary:  .tgz member names contain BOTH "tc080a.log" AND "tc080b.log"
                    (proves all comma-separated entries are processed)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc080proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_a_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc080a.log"),
            b"tc080a dummy log content\n",
        )
        log_b_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc080b.log"),
            b"tc080b dummy log content\n",
        )
        original_logmapper = _write_logmapper("tc080proc=tc080a.log,tc080b.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-080: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            members = _tgz_members(SECURE_MINIDUMP_PATH)
            assert any("tc080a.log" in m for m in members), (
                "TC-080: 'tc080a.log' not found in any .tgz member — "
                "first comma-separated log entry may not have been processed.\n"
                f"Members: {members}"
            )
            assert any("tc080b.log" in m for m in members), (
                "TC-080: 'tc080b.log' not found in any .tgz member — "
                "second comma-separated log entry may not have been processed.\n"
                f"Members: {members}"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            Path(log_a_path).unlink(missing_ok=True)
            Path(log_b_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_missing_log_file_handled_gracefully(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-078: A log file referenced in the logmapper but absent from disk does not crash the binary.

        Logmapper entry "tc078proc=tc078missing.log" produces a LOG_FILES_PATH
        entry for "/opt/logs/tc078missing.log".  That file deliberately does
        NOT exist.

        add_crashed_process_log_file() calls extract_tail(source, dest, N):
          fopen(source, "r") returns NULL → extract_tail() returns -1.
        add_crashed_process_log_file() returns -1 (non-zero); the if(!ret)
        guard in archive_create_smart() falls to the else branch which logs
        CRASHUPLOAD_ERROR and continues — the archive is still produced without
        that log.

        Primary:    exit(0)
                    (binary handles the missing mapped log gracefully; no crash)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc078proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        missing_log = os.path.join(DEFAULT_LOG_PATH, "tc078missing.log")
        # Explicitly ensure the file is absent — this is the condition under test
        Path(missing_log).unlink(missing_ok=True)

        original_logmapper = _write_logmapper("tc078proc=tc078missing.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-078: expected exit(0) even with a missing mapped log, "
                f"got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
