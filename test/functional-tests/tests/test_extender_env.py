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
test_extender_env.py - Extender device-type archive behavior test.

TC-068 validates current extender minidump behavior:
    1. binary exits cleanly
    2. a .tgz archive is created in /minidumps
"""

import os
import re
import subprocess
from pathlib import Path

from testUtility import (
    binary_path,
    cleanup_pytest_cache,
    stash_dir_dumps,
    restore_stashed_dumps,
    CORE_LOG_FILE,
    REBOOT_FLAG_FILE,
    MINIDUMP_LOCK_FILE,
    DEVICE_PROPERTIES,
)

# Extender minidump/working directory (hardcoded in config_manager.c for extender)
EXTENDER_MINIDUMP_PATH = "/minidumps"

# Extender core log file path used by config_manager.c
EXTENDER_CORE_LOG_FILE = "/var/log/messages"

# LOG_FILES_PATH written by get_crashed_log_file()
LOG_FILES_PATH = "/tmp/minidump_log_files.txt"


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


class TestExtenderEnv:
    """TC-068: Verifies extender minidump flow creates a tarball in /minidumps."""

    def test_extender_minidump_archive_created(self, binary_path, cleanup_pytest_cache):
        """TC-068: Extender minidump flow creates a .tgz archive in /minidumps."""
        _ensure_file(CORE_LOG_FILE)
        _ensure_file(EXTENDER_CORE_LOG_FILE)
        os.makedirs(EXTENDER_MINIDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(EXTENDER_MINIDUMP_PATH, ".dmp")
        dump_path = _create_file(
            os.path.join(EXTENDER_MINIDUMP_PATH, "tc068_extender_99999.dmp"),
            b"MINIDUMP_HEADER" + b"\x00" * 4096,
        )
        Path(LOG_FILES_PATH).unlink(missing_ok=True)
        Path(REBOOT_FLAG_FILE).touch()
        original_props = _override_device_type("extender")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert result.returncode == 0, (
                f"TC-068: expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            tgz_files = list(Path(EXTENDER_MINIDUMP_PATH).glob("*.tgz"))
            assert tgz_files, (
                "TC-068: expected .tgz archive in /minidumps for extender flow, found none.\n"
                f"Directory: {EXTENDER_MINIDUMP_PATH}"
            )
        finally:
            _write_device_properties(original_props)
            Path(dump_path).unlink(missing_ok=True)
            for leftover in Path(EXTENDER_MINIDUMP_PATH).glob("*tc068*"):
                leftover.unlink(missing_ok=True)
            _cleanup_tgz(EXTENDER_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(LOG_FILES_PATH).unlink(missing_ok=True)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
