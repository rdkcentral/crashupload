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
test_config_checks_and_baseline.py

Dump Detection (TC-019 / TC-020 / TC-021):
  Verify the binary finds dump files at every configured scan directory.
  The reboot flag (/tmp/set_crash_reboot_flag) prevents any actual network
  upload; the primary assertion is always exit(0).

    TC-019  Non-secure coredump: file with '_core' at /var/lib/systemd/coredump
    TC-020  Secure minidump:     .dmp file at /opt/secure/minidumps
    TC-021  Secure coredump:     file with '_core' at /opt/secure/corefiles

Platform Baseline (TC-023 / TC-024 / TC-025 / TC-026 / TC-028):
  Verify that MAC address, model number, and firmware SHA1 are collected and
  encoded correctly in the archive name.

  Archive name format (archive.c): <sha1>_mac<MAC>_dat<ts>_box<type>_mod<model>_<file>.tgz

  When archive creation succeeds and a .tgz file appears in the working
  directory, secondary assertions check the embedded field values.  If no
  .tgz is produced (e.g. libarchive unavailable, required log files absent)
  the secondary assertions are skipped and only exit(0) is verified.

    TC-023  MAC aa:bb:cc:dd:ee:ff normalised → AABBCCDDEEFF in archive name
    TC-024  Empty/missing /tmp/.macAddress   → default '000000000000'
    TC-025  Model number present in archive name (actual device model)
    TC-026  Model number defaults to 'UNKNOWN' when device API unavailable
    TC-028  /version.txt SHA1 encoded as leading field in archive name
"""

import hashlib
import os
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
    SECURE_MINIDUMP_PATH,
    SECURE_COREDUMP_PATH,
    CORE_LOG_FILE,
    REBOOT_FLAG_FILE,
    COREDUMP_LOCK_FILE,
    MINIDUMP_LOCK_FILE,
)

# Platform source files read by the binary (platform.c)
MAC_FILE    = "/tmp/.macAddress"
VERSION_TXT = "/version.txt"


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


# ============================================================================
# Dump Detection
# ============================================================================

class TestDumpDetection:
    """
    TC-019 / TC-020 / TC-021

    Each test:
      1. Stashes any pre-existing matching files so the scan directory is clean.
      2. Creates a single test-specific dump file.
      3. Sets the reboot flag so the binary exits before attempting an upload.
      4. Asserts exit(0) — the only guaranteed observable in all environments.
      5. Restores stashed files and removes test artefacts unconditionally.
    """

    def test_coredump_detection_normal_path(self, binary_path, cleanup_pytest_cache):
        """TC-019: file containing '_core' at /var/lib/systemd/coredump detected → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)
        Path(REBOOT_FLAG_FILE).touch()

        stashed = stash_dir_dumps(NORMAL_COREDUMP_PATH, "_core")
        dump_path = create_dummy_dump(NORMAL_COREDUMP_PATH, "proc_tc019_core.prog")
        try:
            result = subprocess.run(
                [binary_path, "", "1"],          # argv[2]="1" → coredump mode
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                "TC-019: coredump at normal path expected exit(0), "
                f"got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            for f in Path(NORMAL_COREDUMP_PATH).glob("*tc019*"):
                f.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(NORMAL_COREDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_minidump_detection_secure_path(self, binary_path, cleanup_pytest_cache):
        """TC-020: .dmp file at /opt/secure/minidumps detected → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        Path(REBOOT_FLAG_FILE).touch()

        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc020_minidump.dmp")
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],  # secure minidump mode
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                "TC-020: secure minidump expected exit(0), "
                f"got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            for f in Path(SECURE_MINIDUMP_PATH).glob("tc020*"):
                f.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_coredump_detection_secure_path(self, binary_path, cleanup_pytest_cache):
        """TC-021: file containing '_core' at /opt/secure/corefiles detected → exit(0)."""
        _ensure_file(CORE_LOG_FILE)
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        Path(REBOOT_FLAG_FILE).touch()

        stashed = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")
        dump_path = create_dummy_dump(SECURE_COREDUMP_PATH, "proc_tc021_core.prog")
        try:
            result = subprocess.run(
                [binary_path, "", "1", "secure"],  # secure coredump mode
                capture_output=True, text=True, timeout=30,
            )
            assert result.returncode == 0, (
                "TC-021: secure coredump expected exit(0), "
                f"got {result.returncode}\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
        finally:
            for f in Path(SECURE_COREDUMP_PATH).glob("*tc021*"):
                f.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_COREDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(COREDUMP_LOCK_FILE).unlink(missing_ok=True)


# ============================================================================
# Platform Baseline
# ============================================================================

class TestPlatformInfo:
    """
    TC-023 / TC-024 / TC-025 / TC-026 / TC-028

    All tests use secure-minidump mode and the reboot flag to prevent upload.
    _run_with_dump_and_reboot() is a shared helper that:
      • stashes any pre-existing .dmp files in SECURE_MINIDUMP_PATH
      • places a single test .dmp
      • runs the binary
      • captures any .tgz files created in SECURE_MINIDUMP_PATH
      • cleans up (dump, .tgz files, restored stash, reboot flag) in its
        own finally block, so callers need only restore any files they modified
        (e.g. MAC_FILE, VERSION_TXT)
    """

    # The tgz_files list (Path objects) is captured before the helper's
    # finally block deletes the .tgz files.  Only .name is used afterwards so
    # the files do not need to exist at assertion time.

    def _run_with_dump_and_reboot(self, binary_path: str) -> tuple:
        """
        Place a .dmp in SECURE_MINIDUMP_PATH, arm the reboot flag, run the
        binary, then clean up.  Returns (returncode, list_of_tgz_Path_objects).
        """
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        stashed = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")
        dump_path = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc_platform_info.dmp")
        Path(REBOOT_FLAG_FILE).touch()
        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True, text=True, timeout=30,
            )
            tgz_files = list(Path(SECURE_MINIDUMP_PATH).glob("*.tgz"))
            return result.returncode, tgz_files
        finally:
            for f in Path(SECURE_MINIDUMP_PATH).glob("tc_platform_info*"):
                f.unlink(missing_ok=True)
            Path(dump_path).unlink(missing_ok=True)
            _cleanup_tgz(SECURE_MINIDUMP_PATH)
            restore_stashed_dumps(stashed)
            Path(REBOOT_FLAG_FILE).unlink(missing_ok=True)
            Path(MINIDUMP_LOCK_FILE).unlink(missing_ok=True)

    def test_mac_address_read_and_normalised(self, binary_path, cleanup_pytest_cache):
        """TC-023: MAC aa:bb:cc:dd:ee:ff read from /tmp/.macAddress, normalised to AABBCCDDEEFF."""
        _ensure_file(CORE_LOG_FILE)

        original_mac = Path(MAC_FILE).read_text() if os.path.exists(MAC_FILE) else None
        Path(MAC_FILE).write_text("aa:bb:cc:dd:ee:ff")
        try:
            rc, tgz_files = self._run_with_dump_and_reboot(binary_path)

            assert rc == 0, f"TC-023: expected exit(0), got {rc}"
            if tgz_files:
                archive_name = tgz_files[0].name
                print(f"[TC-023] Archive: {archive_name}")
                assert "_macAABBCCDDEEFF_" in archive_name, (
                    f"TC-023: MAC not normalised correctly in archive name: {archive_name}"
                )
        finally:
            if original_mac is not None:
                Path(MAC_FILE).write_text(original_mac)
            else:
                Path(MAC_FILE).unlink(missing_ok=True)

    def test_mac_fallback_when_file_missing_or_empty(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-024: empty /tmp/.macAddress → binary defaults MAC to '000000000000'."""
        _ensure_file(CORE_LOG_FILE)

        original_mac = Path(MAC_FILE).read_text() if os.path.exists(MAC_FILE) else None
        Path(MAC_FILE).write_text("")  # empty string triggers GetEstbMac() fallback
        try:
            rc, tgz_files = self._run_with_dump_and_reboot(binary_path)

            assert rc == 0, f"TC-024: expected exit(0), got {rc}"
            if tgz_files:
                archive_name = tgz_files[0].name
                print(f"[TC-024] Archive: {archive_name}")
                assert "_mac000000000000_" in archive_name, (
                    f"TC-024: expected default MAC '000000000000', got: {archive_name}"
                )
        finally:
            if original_mac is not None:
                Path(MAC_FILE).write_text(original_mac)
            else:
                Path(MAC_FILE).unlink(missing_ok=True)

    def test_model_number_retrieved(self, binary_path, cleanup_pytest_cache):
        """TC-025 / TC-026: model field present in archive name (device model or 'UNKNOWN')."""
        _ensure_file(CORE_LOG_FILE)

        rc, tgz_files = self._run_with_dump_and_reboot(binary_path)

        assert rc == 0, f"TC-025/026: expected exit(0), got {rc}"
        if tgz_files:
            archive_name = tgz_files[0].name
            print(f"[TC-025/026] Archive: {archive_name}")
            assert "_mod" in archive_name, (
                f"TC-025/026: model field ('_mod') missing from archive name: {archive_name}"
            )

    def test_sha1_firmware_hash_from_version_txt(
        self, binary_path, cleanup_pytest_cache
    ):
        """TC-028: SHA1 of /version.txt content encoded as the leading field in archive name."""
        _ensure_file(CORE_LOG_FILE)

        original_version = (
            Path(VERSION_TXT).read_bytes() if os.path.exists(VERSION_TXT) else None
        )

        # Write a known version file and pre-compute its SHA1
        version_content = b"imagename:RDKTEST_TC028_VERSION\n"
        expected_sha1   = hashlib.sha1(version_content).hexdigest()  # 40 hex chars
        Path(VERSION_TXT).write_bytes(version_content)
        try:
            rc, tgz_files = self._run_with_dump_and_reboot(binary_path)

            assert rc == 0, f"TC-028: expected exit(0), got {rc}"
            if tgz_files:
                archive_name = tgz_files[0].name
                # Archive format: <sha1>_mac<..>_dat<..>_box<..>_mod<..>_<file>.tgz
                sha1_field = archive_name.split("_")[0]
                print(
                    f"[TC-028] Archive: {archive_name}\n"
                    f"[TC-028] Expected SHA1: {expected_sha1}\n"
                    f"[TC-028] Archive SHA1 field: {sha1_field}"
                )
                assert sha1_field == expected_sha1, (
                    f"TC-028: SHA1 mismatch in archive name.\n"
                    f"Expected: {expected_sha1}\nFirst field: {sha1_field}"
                )
        finally:
            if original_version is not None:
                Path(VERSION_TXT).write_bytes(original_version)
            else:
                Path(VERSION_TXT).unlink(missing_ok=True)
