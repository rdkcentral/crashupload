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
test_telemetry.py — Crash telemetry code-path tests.

Observation mechanism
---------------------
All CRASHUPLOAD_INFO output is routed through the RDK logger to a log file,
not to the process stdout.  Only two lines appear in stdout:
  "RDK logger standard init with /etc/debug.ini"
  "CRASHUPLOAD: RDK Logger cleaned up"

The telemetry stubs (T2_EVENT_ENABLED undefined) are no-ops, so no external
side-effect is produced by t2ValNotify / t2CountNotify.

The reliable observable is the same .tgz-member pattern used by
test_scanner_behaviour.py:

  Process-crash path (TC-072):
    processCrashTelemetryInfo() → get_crashed_log_file() → extract_pname()
    → lookup_log_files_for_proc() → logmapper hit → append_logfile_entry()
    → archive_create_smart() copies the log → .tgz member contains log basename.

  Container-crash path (TC-073):
    processCrashTelemetryInfo() detects <#=#> → builds containerName/
    containerTime → normalises file to "containerName-containerTime.dmp"
    → calls get_crashed_log_file(normalized, ...) → same logmapper hit path.
    containerName for "tc073proc<#=#>container_123.dmp":
      firstBreak (before first <#=#>) = "tc073proc" → no nested <#=#>
      → containerName = "tc073proc"
    normalized = "tc073proc-container_123.dmp"
    extract_pname("tc073proc-container_123.dmp") → strips "_123.dmp"
    → pname = "tc073proc-container"
    strstr("tc073proc-container", "tc073proc") → match → logmapper hit.

Both TCs pre-create the source log file so add_crashed_process_log_file()
(extract_tail) can copy it, and assert the copy's basename is present in the
.tgz member list.
"""

import os
import tarfile
import subprocess
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

LOGMAPPER_FILE_PATH = "/etc/breakpad-logmapper.conf"
LOG_FILES_PATH      = "/tmp/minidump_log_files.txt"


# ---------------------------------------------------------------------------
# Module-level helpers  (mirror test_scanner_behaviour.py)
# ---------------------------------------------------------------------------

def _ensure_file(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).touch()


def _create_file(path: str, content: bytes = b"DUMMY") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)
    return path


def _cleanup_tgz(directory: str) -> None:
    if os.path.isdir(directory):
        for f in Path(directory).glob("*.tgz"):
            f.unlink(missing_ok=True)


def _write_logmapper(content: str) -> str | None:
    original = None
    if os.path.exists(LOGMAPPER_FILE_PATH):
        original = Path(LOGMAPPER_FILE_PATH).read_text()
    os.makedirs(os.path.dirname(LOGMAPPER_FILE_PATH), exist_ok=True)
    Path(LOGMAPPER_FILE_PATH).write_text(content)
    return original


def _restore_logmapper(original: str | None) -> None:
    if original is None:
        Path(LOGMAPPER_FILE_PATH).unlink(missing_ok=True)
    else:
        Path(LOGMAPPER_FILE_PATH).write_text(original)


def _tgz_contains_log(directory: str, log_basename: str) -> bool:
    """Return True if any .tgz in *directory* has a member whose name contains *log_basename*."""
    for tgz_path in Path(directory).glob("*.tgz"):
        try:
            with tarfile.open(str(tgz_path)) as tf:
                if any(log_basename in m for m in tf.getnames()):
                    return True
        except Exception:
            pass
    return False


def _run_binary(bp: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [bp, "", "0", "secure"],
        capture_output=True, text=True, timeout=60,
    )


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestCrashTelemetry:
    """
    TC-072 / TC-073

    Both tests use the .tgz member list as the observable (CRASHUPLOAD_INFO
    goes to RDK logger file, not stdout).  The logmapper is set so that the
    expected pname produces a log-file hit, which is copied by
    add_crashed_process_log_file() into the archive.  Presence of the log
    basename in the tarball proves the telemetry code path was exercised.
    """

    def test_process_crash_telemetry_path_exercised(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-072: Process crash telemetry code path exercised for a plain dump.

        Dump "tc072proc_99999.dmp" has no container delimiter, so
        processCrashTelemetryInfo() takes the non-container branch:
          get_crashed_log_file() → extract_pname() → "tc072proc"
          lookup_log_files_for_proc() → logmapper key "tc072proc" matches
          append_logfile_entry() writes "/opt/logs/tc072test.log" to LOG_FILES_PATH
          archive_create_smart() → add_crashed_process_log_file() → copy bundled.

        Primary:    exit(0)
        Secondary:  .tgz member contains "tc072test.log"
                    (proves get_crashed_log_file() ran and pname was extracted)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc072proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc072test.log"),
            b"tc072 dummy log content\n",
        )
        original_logmapper = _write_logmapper("tc072proc=tc072test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path)
            assert result.returncode == 0, (
                f"TC-072: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc072test.log")
            assert found, (
                "TC-072: 'tc072test.log' not found in any .tgz member — "
                "the process-crash telemetry code path (get_crashed_log_file, "
                "logmapper lookup) may not have been exercised."
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

    def test_container_crash_telemetry_path_exercised(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-073: Container crash telemetry code path exercised for a container dump.

        Dump "tc073proc<#=#>container_123.dmp" contains <#=#>.
        sanitize_filename_preserve_container() leaves it unchanged (all chars
        outside the delimiter are allowed) → no rename.

        processCrashTelemetryInfo() detects the delimiter:
          containerName = "tc073proc"   (text before first <#=#>)
          containerTime = "container_123.dmp"  (text after last <#=#>)
          normalized    = "tc073proc-container_123.dmp"
          → calls get_crashed_log_file("tc073proc-container_123.dmp", ...)
          extract_pname("tc073proc-container_123.dmp") → "tc073proc-container"
          strstr("tc073proc-container", "tc073proc") → logmapper hit
          → "tc073test.log" written to LOG_FILES_PATH
          → add_crashed_process_log_file() copies it into the archive.

        Primary:    exit(0)
        Secondary:  .tgz member contains "tc073test.log"
                    (proves the container detection branch was exercised all
                    the way through to get_crashed_log_file and logmapper hit)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc073proc<#=#>container_123.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc073test.log"),
            b"tc073 dummy log content\n",
        )
        # logmapper key "tc073proc" matches pname "tc073proc-container" via strstr
        original_logmapper = _write_logmapper("tc073proc=tc073test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path)
            assert result.returncode == 0, (
                f"TC-073: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc073test.log")
            assert found, (
                "TC-073: 'tc073test.log' not found in any .tgz member — "
                "the container-crash telemetry code path (<#=#> detection, "
                "normalization, get_crashed_log_file) may not have been exercised."
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            Path(log_file_path).unlink(missing_ok=True)
            for leftover in Path(SECURE_MINIDUMP_PATH).glob("*tc073proc*"):
                leftover.unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

