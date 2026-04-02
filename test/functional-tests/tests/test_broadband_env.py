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
test_broadband_env.py — Broadband device-type archive behaviour test.

Background
----------
For DEVICE_TYPE=mediaclient the minidump archive path in archive_create_smart()
(archive.c) produces a .tgz via create_tarball().

For DEVICE_TYPE=broadband the config paths diverge:
  config_manager.c: working_dir_path = minidump_path = "/minidumps"
  (This override applies regardless of whether argv[3]=="secure" is passed.)

archive_create_smart() enters the outer "inside minidump" branch but the only
tarball-creation code is inside:
    if (config->device_type == DEVICE_TYPE_MEDIACLIENT) { ... }

There is no else branch for DEVICE_TYPE_BROADBAND.  tar_status therefore
remains -1 for the entirety of archive_create_smart(), which returns -1.

main.c treats that as ARCHIVE_ERROR and continues to the next dump.  After all
dumps have been iterated, is_box_rebooting() is checked; with REBOOT_FLAG_FILE
present, main() exits 0.

TC-067  Broadband device type does not produce a .tgz for a minidump
  ────────────────────────────────────────────────────────────────────
  Setup:
    - DEVICE_TYPE overridden to "broadband" in /etc/device.properties
    - /minidumps directory created
    - tc067proc_99999.dmp planted in /minidumps
    - REBOOT_FLAG_FILE set

  Binary invoked as: [binary, "", "0"]
    (no "secure" argument; broadband always uses /minidumps regardless)

  Flow:
    chdir("/minidumps") → scanner finds tc067proc_99999.dmp →
    archive_create_smart() → DEVICE_TYPE != MEDIACLIENT → no tarball →
    returns -1 → main.c continues → is_box_rebooting() → exit(0)

  Assert:
    1. exit(0)                    — binary exits cleanly
    2. no .tgz in /minidumps     — confirms broadband archive path is a no-op
                                    (different from mediaclient behaviour)
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    stash_dir_dumps,
    restore_stashed_dumps,
    CORE_LOG_FILE,
    REBOOT_FLAG_FILE,
    MINIDUMP_LOCK_FILE,
    DEVICE_PROPERTIES,
)

# Broadband minidump/working directory (hardcoded in config_manager.c for broadband)
BROADBAND_MINIDUMP_PATH = "/minidumps"

# LOG_FILES_PATH written by get_crashed_log_file()
LOG_FILES_PATH = "/tmp/minidump_log_files.txt"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _ensure_file(path: str) -> None:
    """Create *path* (and parent dirs) if absent."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).touch()


def _create_file(path: str, content: bytes = b"DUMMY") -> str:
    """Create a file at *path* with *content*; return the path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content)
    return path


def _cleanup_tgz(directory: str) -> None:
    """Remove .tgz files in *directory* (defensive cleanup)."""
    if os.path.isdir(directory):
        for f in Path(directory).glob("*.tgz"):
            f.unlink(missing_ok=True)


def _read_device_properties() -> str:
    """Return current /etc/device.properties content, or a mediaclient default."""
    try:
        with open(DEVICE_PROPERTIES) as fh:
            return fh.read()
    except FileNotFoundError:
        return "DEVICE_TYPE=mediaclient\n"


def _write_device_properties(content: str) -> None:
    os.makedirs(os.path.dirname(DEVICE_PROPERTIES), exist_ok=True)
    with open(DEVICE_PROPERTIES, "w") as fh:
        fh.write(content)


def _override_device_type(device_type: str) -> str:
    """
    Replace the DEVICE_TYPE line in /etc/device.properties.

    Returns the original file content so the caller can restore it in a
    finally block via _write_device_properties(original).
    """
    original = _read_device_properties()
    new_content = re.sub(r"(?m)^DEVICE_TYPE=.*", f"DEVICE_TYPE={device_type}", original)
    if "DEVICE_TYPE=" not in new_content:
        new_content += f"DEVICE_TYPE={device_type}\n"
    _write_device_properties(new_content)
    return original


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestBroadbandEnv:
    """
    TC-067

    Verifies that the broadband device type follows a different archive code
    path than mediaclient: archive_create_smart() is entered but no tarball
    is produced, because the DEVICE_TYPE_MEDIACLIENT guard inside the minidump
    branch is not satisfied.
    """

    def test_broadband_minidump_archive_not_created(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-067: Broadband minidump archive path does not produce a .tgz.

        For DEVICE_TYPE=broadband, config_manager.c sets:
          working_dir_path = "/minidumps"
          minidump_path    = "/minidumps"

        archive_create_smart() enters the outer minidump branch but there is
        no tarball-creation code for non-MEDIACLIENT device types.  The rename
        of the dump file succeeds (both paths are inside /minidumps after
        chdir), but tar_status remains -1 → function returns -1.

        main.c logs "Archive creation failed" and moves on.  With REBOOT_FLAG
        set, is_box_rebooting() returns true and the binary exits 0.

        Primary:    exit(0)
        Secondary:  no .tgz file in /minidumps
                    (confirms the broadband archive path differs from
                    mediaclient: no tarball is ever created or written)
        """
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(BROADBAND_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(BROADBAND_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(BROADBAND_MINIDUMP_PATH, "tc067proc_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        original_props = _override_device_type("broadband")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True, text=True, timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-067: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            tgz_files = list(Path(BROADBAND_MINIDUMP_PATH).glob("*.tgz"))
            assert not tgz_files, (
                "TC-067: unexpected .tgz found in /minidumps — "
                "broadband archive path should NOT produce a tarball.\n"
                f"Found: {[str(f) for f in tgz_files]}"
            )
        finally:
            _write_device_properties(original_props)
            Path(dump_path).unlink(missing_ok=True)
            # Clean up the renamed dump (archive_create_smart renames it before
            # discovering no tarball code path exists for broadband)
            for leftover in Path(BROADBAND_MINIDUMP_PATH).glob("*tc067*"):
                leftover.unlink(missing_ok=True)
            _cleanup_tgz(BROADBAND_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
