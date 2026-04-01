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
Functional tests for crashupload config path selection and dump type selection.

TC-006 — Secure mode path selection
    argv[3]=="secure"  →  config_init_load() selects:
        minidump_path = /opt/secure/minidumps
        core_path     = /opt/secure/corefiles
    Verified by placing a dump ONLY in the non-secure path and confirming the
    binary still returns NO_DUMPS_FOUND (exit 0), proving it scanned the secure
    path exclusively.

TC-007 — Normal (non-secure) mode path selection
    argv[3] absent (only 3 args total)  →  config_init_load() selects:
        minidump_path = /opt/minidumps
        core_path     = /var/lib/systemd/coredump
    Verified by placing a dump ONLY in the secure path and confirming the
    binary returns NO_DUMPS_FOUND, proving it scanned the normal path.

TC-009 — Dump type selection
    argv[2]=="0"  →  DUMP_TYPE_MINIDUMP : scans for ".dmp" pattern
    argv[2]=="1"  →  DUMP_TYPE_COREDUMP : scans for "_core" pattern
    Each subtest places the wrong dump type and confirms NO_DUMPS_FOUND.
"""

import os
import subprocess
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path, create_dummy_dump,
    stash_dir_dumps, restore_stashed_dumps,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH,
    NORMAL_MINIDUMP_PATH, NORMAL_COREDUMP_PATH,
    MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE,
)


def _ensure_system_init_prereqs():
    """Ensure /opt/logs and core_log.txt exist so system_initialize() passes."""
    os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
    Path(CORE_LOG_FILE).touch(exist_ok=True)


def _remove_lock_files():
    for lf in (MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE):
        if os.path.exists(lf):
            os.unlink(lf)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestConfigAndPath:
    """Test crashupload config path and dump-type selection."""

    # ------------------------------------------------------------------
    # TC-006: Secure mode path selection (minidump)
    # ------------------------------------------------------------------
    def test_secure_mode_selects_secure_minidump_path(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-006-A — 'secure' arg selects /opt/secure/minidumps for minidump scan.

        A .dmp file is placed ONLY in /opt/minidumps (non-secure path).
        The binary is invoked with argv[3]='secure', so it scans the secure
        path /opt/secure/minidumps and finds nothing  →  NO_DUMPS_FOUND  →
        exit(0).  Proves the secure path is selected and the non-secure path
        is NOT scanned.
        """
        _ensure_system_init_prereqs()
        os.makedirs(NORMAL_MINIDUMP_PATH, exist_ok=True)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        _remove_lock_files()

        # Place decoy dump in NORMAL path (binary must NOT find this)
        decoy = os.path.join(NORMAL_MINIDUMP_PATH, "decoy_app.dmp")
        stashed_normal = [decoy]
        try:
            Path(decoy).write_bytes(b"MINIDUMP_HEADER\x00" * 128)

            # Ensure secure minidump dir is empty — move files to /tmp so the
            # backup names don't contain '.dmp' and trick directory_has_pattern()
            stashed_secure = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")

            result = subprocess.run(
                [binary_path, "", "0", "secure"],

                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 (secure path empty → NO_DUMPS_FOUND), "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            for path in stashed_normal:
                if os.path.exists(path):
                    os.unlink(path)
            restore_stashed_dumps(stashed_secure)
            _remove_lock_files()

    # ------------------------------------------------------------------
    # TC-006: Secure mode path selection (coredump)
    # ------------------------------------------------------------------
    def test_secure_mode_selects_secure_coredump_path(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-006-B — 'secure' arg selects /opt/secure/corefiles for coredump scan.

        A _core file is placed ONLY in /var/lib/systemd/coredump (non-secure).
        Binary invoked with argv[2]='1' (coredump) + argv[3]='secure'  →
        scans /opt/secure/corefiles, finds nothing  →  NO_DUMPS_FOUND  →  exit(0).
        """
        _ensure_system_init_prereqs()
        os.makedirs(NORMAL_COREDUMP_PATH, exist_ok=True)
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        _remove_lock_files()

        decoy = os.path.join(NORMAL_COREDUMP_PATH, "testproc_core.prog.gz")
        try:
            Path(decoy).write_bytes(b"COREDUMP\x00" * 128)

            stashed_secure = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")

            result = subprocess.run(
                [binary_path, "", "1", "secure"],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 (secure corefiles empty → NO_DUMPS_FOUND), "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
        finally:
            if os.path.exists(decoy):
                os.unlink(decoy)
            restore_stashed_dumps(stashed_secure)
            _remove_lock_files()

    # ------------------------------------------------------------------
    # TC-007: Normal mode path selection
    # ------------------------------------------------------------------
    def test_normal_mode_selects_normal_minidump_path(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-007 — No 'secure' arg selects /opt/minidumps for minidump scan.

        A .dmp file is placed ONLY in /opt/secure/minidumps.
        Binary invoked WITHOUT argv[3]='secure'  →  scans /opt/minidumps,
        finds nothing  →  NO_DUMPS_FOUND  →  exit(0).  Proves normal mode
        scans the non-secure path and ignores /opt/secure/minidumps.
        """
        _ensure_system_init_prereqs()
        os.makedirs(NORMAL_MINIDUMP_PATH, exist_ok=True)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        _remove_lock_files()

        decoy = create_dummy_dump(SECURE_MINIDUMP_PATH, "decoy_normal_test.dmp")
        stashed_normal = []
        try:
            # Ensure normal minidump dir has no .dmp files
            for f in os.listdir(NORMAL_MINIDUMP_PATH):
                if ".dmp" in f:
                    src = os.path.join(NORMAL_MINIDUMP_PATH, f)
                    dst = f"{src}.cfg007_bak"
                    os.rename(src, dst)
                    stashed_normal.append((dst, src))

            result = subprocess.run(
                [binary_path, "", "0"],   # only 3 args — no "secure"
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 (normal /opt/minidumps empty → NO_DUMPS_FOUND), "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
        finally:
            if os.path.exists(decoy):
                os.unlink(decoy)
            for (backed, orig) in stashed_normal:
                if os.path.exists(backed):
                    os.rename(backed, orig)
            _remove_lock_files()

    # ------------------------------------------------------------------
    # TC-009-A: Dump type selection — coredump mode ignores .dmp files
    # ------------------------------------------------------------------
    def test_coredump_mode_ignores_minidump_files(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-009-A — argv[2]=='1' (coredump) scans for '_core' pattern only.

        A .dmp file is present in /opt/secure/minidumps.
        Binary invoked with dump type '1' (coredump) + 'secure'  →  scans
        /opt/secure/corefiles for '_core'  →  not found  →  NO_DUMPS_FOUND
        →  exit(0).  Proves coredump mode does NOT pick up .dmp files.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        _remove_lock_files()

        # Place .dmp (minidump) in secure dir — must be IGNORED by coredump mode
        dummy_dmp = create_dummy_dump(SECURE_MINIDUMP_PATH, "test_app_tc009a.dmp")
        try:
            stashed_core = stash_dir_dumps(SECURE_COREDUMP_PATH, "_core")

            result = subprocess.run(
                [binary_path, "", "1", "secure"],   # coredump mode
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 (coredump mode, no _core files → NO_DUMPS_FOUND), "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
        finally:
            if os.path.exists(dummy_dmp):
                os.unlink(dummy_dmp)
            restore_stashed_dumps(stashed_core)
            _remove_lock_files()

    # ------------------------------------------------------------------
    # TC-009-B: Dump type selection — minidump mode ignores _core files
    # ------------------------------------------------------------------
    def test_minidump_mode_ignores_coredump_files(
        self, binary_path, cleanup_pytest_cache
    ):
        """
        TC-009-B — argv[2]=='0' (minidump) scans for '.dmp' pattern only.

        A _core file is present in /opt/secure/corefiles.
        Binary invoked with dump type '0' (minidump) + 'secure'  →  scans
        /opt/secure/minidumps for '.dmp'  →  not found  →  NO_DUMPS_FOUND
        →  exit(0).  Proves minidump mode does NOT pick up _core files.
        """
        _ensure_system_init_prereqs()
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        _remove_lock_files()

        # Place _core (coredump) file — must be IGNORED by minidump mode
        core_file = os.path.join(SECURE_COREDUMP_PATH, "testproc_core.prog.gz")
        try:
            Path(core_file).write_bytes(b"COREDUMP\x00" * 64)

            stashed_mini = stash_dir_dumps(SECURE_MINIDUMP_PATH, ".dmp")

            result = subprocess.run(
                [binary_path, "", "0", "secure"],   # minidump mode
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                f"Expected exit 0 (minidump mode, no .dmp files → NO_DUMPS_FOUND), "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}"
            )
        finally:
            if os.path.exists(core_file):
                os.unlink(core_file)
            restore_stashed_dumps(stashed_mini)
            _remove_lock_files()
