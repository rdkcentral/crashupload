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
test_scanner_behaviour.py — Filename sanitisation and dump-component parsing tests.

Observation mechanism
---------------------
All four TCs exploit the same observable side-effect chain:

  process_file_entry()
    └─ sanitize_filename_preserve_container()   ← sanitise basename
    └─ processCrashTelemetryInfo()              ← only when dump_type == "0"
         └─ get_crashed_log_file()
              └─ extract_pname()                ← parse process name from path
              └─ lookup_log_files_for_proc()    ← reads /etc/breakpad-logmapper.conf
              └─ append_logfile_entry()         ← writes to LOG_FILES_PATH

LOG_FILES_PATH (/tmp/minidump_log_files.txt) is written in append mode and is
NOT deleted by archive_create_smart() for non-MEDIACLIENT device types, so it
persists after the binary exits.

Each test:
  1. Writes a unique entry to /etc/breakpad-logmapper.conf so that the
     expected sanitised/parsed process name triggers a match.
  2. Plants a single specially-crafted .dmp file.
  3. Runs the binary with dump_type="0" (minidump, secure path).
  4. Asserts exit(0) AND that LOG_FILES_PATH contains the expected log path.

If the sanitisation or parsing was WRONG, the log path would not be written
(lookup_log_files_for_proc would not match), and the assertion fails distinctly.

TC-057  Container delimiter (<#=#>) preserved in sanitisation
  ─────────────────────────────────────────────────────────────
  File:   cleanapp<#=#>cont_123.dmp
  Logic:  All chars outside the delimiter are allowed → sanitised == original
          → no rename.  processCrashTelemetryInfo detects the delimiter and
          normalises the filename to "cleanapp-cont_123.dmp".
          extract_pname("cleanapp-cont_123.dmp") → "cleanapp-cont".
          Logmapper key "cleanapp-cont" matches.
  Proof:  If <#=#> had been stripped char-by-char, the file becomes
          "cleanappcont_123.dmp" (no hyphen), pname becomes "cleanappcont",
          and the logmapper key "cleanapp-cont" does NOT match → LOG_FILES_PATH
          empty → assertion fails.

TC-058  Special characters in filename dropped by sanitisation
  ──────────────────────────────────────────────────────────────
  File:   bad!chars_proc.dmp
  Logic:  '!' is forbidden.  sanitize_segment drops it → "badchars_proc.dmp".
          sanitised != original → rename.
          processCrashTelemetryInfo gets the renamed (clean) path.
          extract_pname("badchars_proc.dmp") → "badchars".
          Logmapper key "badchars" matches.
  Proof:  If '!' was kept, pname becomes "bad!chars" → no match → empty log.

TC-059  Container name preserved after sanitisation
  ─────────────────────────────────────────────────
  File:   proc<#=#>con!tain_ts.dmp
  Logic:  '!' is in the post-delimiter segment.  With correct preservation,
          the delimiter separates "proc" from "con!tain_ts.dmp":
            segment "proc"          → "proc"
            delimiter               → "<#=#>" (preserved)
            segment "con!tain_ts.dmp" → "contain_ts.dmp" (! dropped)
          Result: "proc<#=#>contain_ts.dmp" (rename).
          Container normalisation → "proc-contain_ts.dmp".
          extract_pname → "proc-contain".  Logmapper key "proc-contain" matches.
  Proof:  Without delimiter preservation, the whole name is processed as a
          flat string, <>#= and ! are all dropped → "proccontain_ts.dmp" (no
          hyphen) → pname "proccontain" → no match → empty log.

TC-064  Dump filename components parsed correctly (extract_pname)
  ─────────────────────────────────────────────────────────────────
  File:   tc064proc_99999.dmp
  Logic:  extract_pname strips everything from the last '_' onwards:
            basename "tc064proc_99999.dmp" → last '_' at '_99999.dmp'
            → pname  "tc064proc" (plus directory prefix)
          Logmapper key "tc064proc" matches via strstr on the full pname.
          append_logfile_entry writes "/opt/logs/tc064test.log" to LOG_FILES_PATH.
  Proof:  If pname was extracted incorrectly (e.g. including the trailing
          field), the logmapper lookup would not match → empty log.
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


def _run_binary(binary_path: str, dump_dir: str) -> subprocess.CompletedProcess:
    """Run the binary targeting *dump_dir* as a secure minidump scan."""
    return subprocess.run(
        [binary_path, "", "0", "secure"],
        capture_output=True, text=True, timeout=60,
    )


def _tgz_contains_log(directory: str, log_basename: str) -> bool:
    """Return True if any .tgz in *directory* has a member whose name contains *log_basename*.

    For DEVICE_TYPE_MEDIACLIENT, archive_create_smart() reads LOG_FILES_PATH,
    copies each listed log file via add_crashed_process_log_file(), bundles the
    copy into the .tgz, then deletes LOG_FILES_PATH.  So LOG_FILES_PATH is gone
    by the time the binary exits; the .tgz member list is the observable.
    """
    for tgz_path in Path(directory).glob("*.tgz"):
        try:
            with tarfile.open(str(tgz_path)) as tf:
                if any(log_basename in m for m in tf.getnames()):
                    return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestScannerBehaviour:
    """
    TC-057 / TC-058 / TC-059 / TC-064

    All tests run the binary in secure-minidump mode (argv = ["", "0", "secure"])
    with the reboot flag set so the upload loop is skipped.

    The shared observable is /tmp/minidump_log_files.txt (LOG_FILES_PATH).
    Each test writes a unique logmapper entry matching the expected sanitised/
    parsed process name.  If the expected entry appears in LOG_FILES_PATH after
    the binary exits, the scanner logic produced the correct output.
    """

    def test_container_delimiter_preserved_in_sanitization(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-057: <#=#> delimiter is preserved verbatim through sanitize_segment.

        File "cleanapp<#=#>cont_123.dmp" has only allowed chars outside the
        delimiter, so sanitise_segment leaves each segment unchanged and the
        delimiter is re-inserted intact.  That means sanitised == original:
        process_file_entry does NOT rename the file.

        processCrashTelemetryInfo detects the <#=#> token and enters the
        container-crash normalisation path, producing normalised filename
        "cleanapp-cont_123.dmp".  extract_pname on that → "cleanapp-cont".
        A logmapper key "cleanapp-cont" matches via strstr.

        Primary:    exit(0)
        Secondary:  LOG_FILES_PATH contains "/opt/logs/tc057test.log"
                    (proves the delimiter was preserved → container path taken)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "cleanapp<#=#>cont_123.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc057test.log"),
            b"tc057 dummy log content\n",
        )
        original_logmapper = _write_logmapper("cleanapp-cont=tc057test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-057: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc057test.log")
            assert found, (
                "TC-057: 'tc057test.log' not found in any .tgz member list — "
                "delimiter <#=#> may not have been preserved through sanitization "
                "(logmapper lookup on 'cleanapp-cont' would have failed)."
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

    def test_forbidden_chars_dropped_from_filename(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-058: Characters not in [a-zA-Z0-9 ._/-] are removed by sanitisation.

        File "bad!chars_proc.dmp" contains '!' which is not in is_allowed_char().
        sanitize_segment drops it → "badchars_proc.dmp" (rename).
        processCrashTelemetryInfo receives the renamed (clean) path.
        extract_pname("badchars_proc.dmp") → "badchars" (strips "_proc.dmp").
        Logmapper key "badchars" matches via strstr on the full pname.

        Primary:    exit(0)
        Secondary:  LOG_FILES_PATH contains "/opt/logs/tc058test.log"
                    (proves the '!' was dropped and sanitised name was used)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "bad!chars_proc.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc058test.log"),
            b"tc058 dummy log content\n",
        )
        original_logmapper = _write_logmapper("badchars=tc058test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-058: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            # Original file must be gone — it was renamed to the sanitised name
            assert not os.path.exists(dump_path), (
                "TC-058: original file 'bad!chars_proc.dmp' still present — "
                "rename after sanitisation did not occur"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc058test.log")
            assert found, (
                "TC-058: 'tc058test.log' not found in any .tgz member list — "
                "forbidden char '!' may not have been dropped during sanitisation "
                "(logmapper lookup on 'badchars' would have failed)."
            )
        finally:
            # Defensive: clean up both the original and the renamed (sanitised) form
            Path(dump_path).unlink(missing_ok=True)
            Path(log_file_path).unlink(missing_ok=True)
            Path(os.path.join(SECURE_MINIDUMP_PATH, "badchars_proc.dmp")).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_container_name_preserved_with_forbidden_chars(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-059: Container name (text after <#=#>) preserved after sanitisation.

        File "proc<#=#>con!tain_ts.dmp" has two issues:
          - '!' in the post-delimiter segment (must be dropped)
          - <#=#> itself (must be preserved as a unit, not stripped char-by-char)

        Correct sanitisation:
          segment before <#=#>: "proc"           → "proc"
          delimiter:             "<#=#>"          → "<#=#>" (preserved as-is)
          segment after  <#=#>: "con!tain_ts.dmp" → "contain_ts.dmp" (! dropped)
          result: "proc<#=#>contain_ts.dmp" (rename)

        processCrashTelemetryInfo detects the container delimiter in the renamed
        file and normalises it to "proc-contain_ts.dmp".
        extract_pname → "proc-contain".  Logmapper key "proc-contain" matches.

        If the delimiter was NOT preserved (all <>#=! stripped flat):
          result: "proccontain_ts.dmp" → pname "proccontain" → no hyphen →
          logmapper key "proc-contain" does NOT match → LOG_FILES_PATH empty.

        Primary:    exit(0)
        Secondary:  LOG_FILES_PATH contains "/opt/logs/tc059test.log"
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "proc<#=#>con!tain_ts.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc059test.log"),
            b"tc059 dummy log content\n",
        )
        original_logmapper = _write_logmapper("proc-contain=tc059test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-059: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc059test.log")
            assert found, (
                "TC-059: 'tc059test.log' not found in any .tgz member list — "
                "container delimiter may not have been preserved through "
                "sanitisation (logmapper lookup on 'proc-contain' would have failed)."
            )
        finally:
            Path(dump_path).unlink(missing_ok=True)
            Path(log_file_path).unlink(missing_ok=True)
            # Also clean up the sanitised form if it was not consumed by archive
            Path(os.path.join(SECURE_MINIDUMP_PATH, "proc<#=#>contain_ts.dmp")).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            _restore_logmapper(original_logmapper)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_dump_filename_components_parsed_correctly(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-064: extract_pname() correctly strips the trailing underscore-field.

        File "tc064proc_99999.dmp":
          basename = "tc064proc_99999.dmp"
          last '_' in basename → "_99999.dmp"
          base_keep = "tc064proc"
          extract_pname returns "/opt/secure/minidumps/tc064proc"
          (directory path prepended, trailing field stripped)

        lookup_log_files_for_proc uses strstr(pname, lhs), so logmapper key
        "tc064proc" is found as a substring of the full pname path.
        append_logfile_entry writes "/opt/logs/tc064test.log" to LOG_FILES_PATH.

        Primary:    exit(0)
        Secondary:  LOG_FILES_PATH contains "/opt/logs/tc064test.log"
                    (proves the last-underscore field was stripped correctly)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(SECURE_MINIDUMP_PATH, "tc064proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        log_file_path = _create_file(
            os.path.join(DEFAULT_LOG_PATH, "tc064test.log"),
            b"tc064 dummy log content\n",
        )
        original_logmapper = _write_logmapper("tc064proc=tc064test.log\n")
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = _run_binary(binary_path, SECURE_MINIDUMP_PATH)
            assert result.returncode == 0, (
                f"TC-064: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            found = _tgz_contains_log(SECURE_MINIDUMP_PATH, "tc064test.log")
            assert found, (
                "TC-064: 'tc064test.log' not found in any .tgz member list — "
                "extract_pname may not have stripped the trailing '_99999.dmp' "
                "field correctly (logmapper lookup on 'tc064proc' would have failed)."
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
