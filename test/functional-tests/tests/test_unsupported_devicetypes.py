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
test_unsupported_devicetypes.py

Validates exit behaviour when DEVICE_TYPE is set to a non-mediaclient value.

For both broadband and extender device types the binary:
  • scans core_path (/var/lib/systemd/coredump) for ".dmp" files
    (unlike mediaclient which scans /opt/minidumps)
  • sets working_dir_path to "/minidumps"
  • attempts chdir("/minidumps"), which fails in the L2 container (directory
    absent) → goto cleanup → exit(0)

TC-004  DEVICE_TYPE=broadband, no .dmp files  → NO_DUMPS_FOUND   → exit(0)
TC-005  DEVICE_TYPE=extender,  no .dmp files  → NO_DUMPS_FOUND   → exit(0)
TC-017  DEVICE_TYPE=broadband, dump present   → chdir failure    → exit(0)
TC-018  DEVICE_TYPE=extender,  dump present   → chdir failure    → exit(0)

The reboot flag is set for TC-017/TC-018 as a safety net: if /minidumps ever
exists in the test environment, the flag prevents any network upload and
still guarantees exit(0).
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    create_dummy_dump,
    stash_dir_dumps,
    restore_stashed_dumps,
    NORMAL_COREDUMP_PATH,
    CORE_LOG_FILE,
    MINIDUMP_LOCK_FILE,
    REBOOT_FLAG_FILE,
    DEVICE_PROPERTIES,
)

# core_log_file used by extender device type (config_manager.c)
_EXTENDER_LOG_FILE = "/var/log/messages"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    finally block.
    """
    original = _read_device_properties()
    new_content = re.sub(r"(?m)^DEVICE_TYPE=.*", f"DEVICE_TYPE={device_type}", original)
    if "DEVICE_TYPE=" not in new_content:
        new_content += f"DEVICE_TYPE={device_type}\n"
    _write_device_properties(new_content)
    return original


def _ensure_file(path: str) -> None:
    """Create *path* (and parent directories) if it does not already exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        Path(path).touch()


# ---------------------------------------------------------------------------
# TC-004 / TC-017  —  Broadband
# ---------------------------------------------------------------------------

class TestBroadbandDeviceType:
    """DEVICE_TYPE=broadband: no-dump and dump-present exit paths."""

    def test_broadband_device_type_no_dumps_exits_0(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-004: broadband with no .dmp files → NO_DUMPS_FOUND → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)

        # Stash any pre-existing .dmp files so prerequisites_wait() finds nothing
        stashed = stash_dir_dumps(NORMAL_COREDUMP_PATH, ".dmp")
        original = _override_device_type("broadband")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"TC-004: broadband+no dumps expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            _write_device_properties(original)
            restore_stashed_dumps(stashed)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_broadband_minidump_detection_in_core_path(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-017: broadband finds .dmp; chdir(/minidumps) absent → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)

        # Reboot flag: safety net in case /minidumps exists in this environment
        Path(REBOOT_FLAG_FILE).touch()
        stashed = stash_dir_dumps(NORMAL_COREDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(NORMAL_COREDUMP_PATH, "tc017_broadband.dmp")
        original = _override_device_type("broadband")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"TC-017: broadband+dump expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            _write_device_properties(original)
            # Remove any files the binary may have created for this dump
            for extra in Path(NORMAL_COREDUMP_PATH).glob("tc017*"):
                extra.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TC-005 / TC-018  —  Extender
# ---------------------------------------------------------------------------

class TestExtenderDeviceType:
    """DEVICE_TYPE=extender: no-dump and dump-present exit paths."""

    def test_extender_device_type_no_dumps_exits_0(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-005: extender with no .dmp files → NO_DUMPS_FOUND → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        _ensure_file(_EXTENDER_LOG_FILE)   # extender uses /var/log/messages as core_log_file
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)

        stashed = stash_dir_dumps(NORMAL_COREDUMP_PATH, ".dmp")
        original = _override_device_type("extender")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"TC-005: extender+no dumps expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            _write_device_properties(original)
            restore_stashed_dumps(stashed)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_extender_minidump_detection_in_core_path(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-018: extender finds .dmp; chdir(/minidumps) absent → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        _ensure_file(_EXTENDER_LOG_FILE)
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)

        # Reboot flag: safety net in case /minidumps exists in this environment
        Path(REBOOT_FLAG_FILE).touch()
        stashed = stash_dir_dumps(NORMAL_COREDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(NORMAL_COREDUMP_PATH, "tc018_extender.dmp")
        original = _override_device_type("extender")
        try:
            result = subprocess.run(
                [binary_path, "", "0"],
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                f"TC-018: extender+dump expected exit(0), got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            _write_device_properties(original)
            for extra in Path(NORMAL_COREDUMP_PATH).glob("tc018*"):
                extra.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)
