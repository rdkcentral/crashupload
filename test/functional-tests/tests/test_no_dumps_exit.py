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
Functional tests for crashupload "no dumps found" exit behaviour.

All four tests verify that the binary exits with code 0 (success) whenever
prerequisites_wait() returns NO_DUMPS_FOUND (5), which happens when:
  - The dump directory is empty (no ".dmp" or "_core" file names)
  - The dump directory contains only files with wrong extensions
  - The dump directory does not exist at all

Exit-code reference (main.c + prerequisites.c):
    prerequisites_wait() != PREREQUISITES_SUCCESS
        → goto cleanup → exit(ret) where ret == 0

directory_has_pattern() (prerequisites.c):
    opendir() fails                → returns -1  → NO_DUMPS_FOUND
    no file with pattern substring → returns  0  → NO_DUMPS_FOUND
    pattern found in at least one filename → returns 1 → success
"""

import os
import shutil
import subprocess
import pytest
from pathlib import Path
from testUtility import (
    cleanup_pytest_cache, binary_path,
    DEFAULT_LOG_PATH, CORE_LOG_FILE,
    MINIDUMP_LOCK_FILE, COREDUMP_LOCK_FILE,
    SECURE_MINIDUMP_PATH, SECURE_COREDUMP_PATH,
    NO_DUMPS_FOUND,
)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestNoDumpsExit:
    """
    Binary-level tests: all scenarios where no dump files are discovered
    → binary must exit with returncode 0 (NO_DUMPS_FOUND → goto cleanup → ret=0).
    """

    # ------------------------------------------------------------------
    # NODMP-01: Empty minidump directory
    # ------------------------------------------------------------------
    def test_empty_minidump_dir_exits_with_0(self, binary_path, cleanup_pytest_cache):
        """
        NODMP-01 — empty /opt/secure/minidumps → directory_has_pattern returns 0
        → NO_DUMPS_FOUND → prerequisites_wait fails → exit(0).
        """
        # Pre-condition: log dir and log file must exist for system_initialize to pass
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        # Ensure the minidump directory exists but contains no .dmp files
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
        stashed = []
        try:
            for f in os.listdir(SECURE_MINIDUMP_PATH):
                if ".dmp" in f:
                    src = os.path.join(SECURE_MINIDUMP_PATH, f)
                    dst = f"{src}.nodmp01_bak"
                    os.rename(src, dst)
                    stashed.append((dst, src))

            # Remove leftover lock file from a previous run
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 for empty minidump dir, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            for (backed_up, original) in stashed:
                if os.path.exists(backed_up):
                    os.rename(backed_up, original)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # NODMP-02: Empty coredump directory
    # ------------------------------------------------------------------
    def test_empty_corefiles_dir_exits_with_0(self, binary_path, cleanup_pytest_cache):
        """
        NODMP-02 — empty /opt/secure/corefiles → directory_has_pattern("_core") returns 0
        → NO_DUMPS_FOUND → prerequisites_wait fails → exit(0).
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        os.makedirs(SECURE_COREDUMP_PATH, exist_ok=True)
        stashed = []
        try:
            for f in os.listdir(SECURE_COREDUMP_PATH):
                if "_core" in f:
                    src = os.path.join(SECURE_COREDUMP_PATH, f)
                    dst = f"{src}.nodmp02_bak"
                    os.rename(src, dst)
                    stashed.append((dst, src))

            if os.path.exists(COREDUMP_LOCK_FILE):
                os.unlink(COREDUMP_LOCK_FILE)

            result = subprocess.run(
                [binary_path, "", "1", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 for empty corefiles dir, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            for (backed_up, original) in stashed:
                if os.path.exists(backed_up):
                    os.rename(backed_up, original)
            if os.path.exists(COREDUMP_LOCK_FILE):
                os.unlink(COREDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # NODMP-03: Wrong-extension file in minidump directory
    # ------------------------------------------------------------------
    def test_wrong_extension_file_exits_with_0(self, binary_path, cleanup_pytest_cache):
        """
        NODMP-03 — /opt/secure/minidumps contains only a .txt file (no ".dmp" substring)
        → directory_has_pattern(".dmp") returns 0 → NO_DUMPS_FOUND → exit(0).
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)
        os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)

        wrong_ext_file = os.path.join(SECURE_MINIDUMP_PATH, "test_app_crash.txt")
        stashed = []
        try:
            # Hide any pre-existing .dmp files
            for f in os.listdir(SECURE_MINIDUMP_PATH):
                if ".dmp" in f:
                    src = os.path.join(SECURE_MINIDUMP_PATH, f)
                    dst = f"{src}.nodmp03_bak"
                    os.rename(src, dst)
                    stashed.append((dst, src))

            # Place a file with the wrong extension
            Path(wrong_ext_file).write_text("not a dump file\n")

            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 with wrong-extension file, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            if os.path.exists(wrong_ext_file):
                os.unlink(wrong_ext_file)
            for (backed_up, original) in stashed:
                if os.path.exists(backed_up):
                    os.rename(backed_up, original)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)

    # ------------------------------------------------------------------
    # NODMP-04: Minidump directory does not exist
    # ------------------------------------------------------------------
    def test_nonexistent_dump_dir_exits_with_0(self, binary_path, cleanup_pytest_cache):
        """
        NODMP-04 — /opt/secure/minidumps directory is absent
        → directory_has_pattern() calls opendir() which returns NULL → returns -1
        → NO_DUMPS_FOUND → prerequisites_wait fails → exit(0).
        """
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)

        # Save any existing dump files before temporarily removing the directory
        saved_files = []
        if os.path.exists(SECURE_MINIDUMP_PATH):
            for fname in os.listdir(SECURE_MINIDUMP_PATH):
                src = os.path.join(SECURE_MINIDUMP_PATH, fname)
                dst = f"/tmp/.nodmp04_{fname}"
                shutil.copy2(src, dst)
                saved_files.append((dst, fname))
            shutil.rmtree(SECURE_MINIDUMP_PATH)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=30,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 for nonexistent dump dir, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        finally:
            # Restore directory and files
            os.makedirs(SECURE_MINIDUMP_PATH, exist_ok=True)
            for (tmp_file, orig_fname) in saved_files:
                dst = os.path.join(SECURE_MINIDUMP_PATH, orig_fname)
                if os.path.exists(tmp_file):
                    shutil.copy2(tmp_file, dst)
                    os.unlink(tmp_file)
            if os.path.exists(MINIDUMP_LOCK_FILE):
                os.unlink(MINIDUMP_LOCK_FILE)
