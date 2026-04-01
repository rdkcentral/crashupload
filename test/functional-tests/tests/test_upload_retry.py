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
TC-082: Upload retried up to 3 times on failure — succeeds on the final retry (Positive)
TC-083: Upload Permanent Failure — all retries exhausted (Negative)

Both tests control retry behaviour via sentinel files checked by the L2_TEST
build inside upload_file(), requiring no server-side configuration:

  /tmp/cu_fail_n   (TC-082) — contains a failure count N; each iteration
                              decrements the counter and force-fails when N > 0;
                              the 3rd attempt (N==0) uses the real network result.
  /tmp/cu_all_fail (TC-083) — when present, every iteration is force-failed
                              (http_code=500, curl_ret=-1), exhausting all retries.

Design notes:
  - sleep(2) is called in the C source after each failed attempt.
  - No mockxconf admin calls or server restarts required.
"""

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from testUtility import (
    cleanup_pytest_cache,
    binary_path,
    create_dummy_dump,
    SECURE_MINIDUMP_PATH,
    MINIDUMP_LOCK_FILE,
    DEFAULT_LOG_PATH,
    CORE_LOG_FILE,
    DEVICE_PROPERTIES,
    UPLOADED_CRASHES_DIR,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sentinel file checked by the L2_TEST build inside upload_file().
# When present, every metadata attempt is force-failed (http_code=500,
# curl_ret=-1) so all MAX_RETRIES=3 iterations are exhausted.
CU_ALL_FAIL_FLAG = "/tmp/cu_all_fail"

# Counter file for TC-082: write the desired failure count (e.g. "2") here.
# Each iteration decrements the value; when it reaches 0 the real network
# result is used, allowing the final attempt to succeed.
CU_FAIL_N_FLAG = "/tmp/cu_fail_n"


def _read_core_log() -> str:
    """Return the combined text of core_log.txt.0 and core_log.txt (both may exist)."""
    text = ""
    for name in ("core_log.txt.0", "core_log.txt"):
        path = Path(DEFAULT_LOG_PATH) / name
        if path.exists():
            try:
                text += path.read_text(errors="replace")
            except OSError:
                pass
    return text


def _clear_core_logs():
    """Truncate both log files so a subsequent read is fresh for this test only."""
    for name in ("core_log.txt", "core_log.txt.0"):
        path = Path(DEFAULT_LOG_PATH) / name
        try:
            path.write_text("")
        except OSError:
            pass


def _setup_device_props(pid: int):
    """Backup device.properties and install a test version; return (backup, path)."""
    device_props = Path(DEVICE_PROPERTIES)
    backup_props = None
    if device_props.exists():
        backup_props = device_props.with_name(f"device.properties.l2bak_{pid}")
        device_props.rename(backup_props)
    device_props.write_text(
        "DEVICE_TYPE=mediaclient\nS3_AMAZON_SIGNING_URL=https://mockxconf:50059\n"
    )
    return backup_props, device_props


def _restore_device_props(backup_props, device_props: Path):
    """Restore device.properties from backup (best-effort)."""
    try:
        if backup_props and backup_props.exists():
            if device_props.exists():
                device_props.unlink()
            backup_props.rename(device_props)
        else:
            if device_props.exists():
                device_props.unlink()
    except Exception:
        pass


def _clean_working_dir():
    """Remove stale .dmp / .tgz files left by a failed binary run."""
    try:
        for p in Path(SECURE_MINIDUMP_PATH).iterdir():
            if p.is_file():
                p.unlink()
    except Exception:
        pass


def _clean_upload_dir(upload_dir: Path):
    try:
        for p in upload_dir.iterdir():
            if p.is_file():
                p.unlink()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestUploadPermanentFailure:
    """TC-083: upload permanent failure — all MAX_RETRIES exhausted."""

    def _common_setup(self, upload_dir: Path):
        """Prepare log / lock / upload directories for a clean run."""
        if upload_dir.exists():
            _clean_upload_dir(upload_dir)
        else:
            upload_dir.mkdir(parents=True, exist_ok=True)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)
        try:
            os.chmod(DEFAULT_LOG_PATH, 0o755)
            os.chmod(CORE_LOG_FILE, 0o644)
        except Exception:
            pass

    def test_upload_fails_after_max_retries(self, binary_path, cleanup_pytest_cache):
        """TC-083: /tmp/cu_all_fail forces all 3 retries to fail → non-zero exit,
        3 retry log entries, and no file written to the shared upload directory.
        """
        upload_dir = Path(UPLOADED_CRASHES_DIR)
        self._common_setup(upload_dir)

        # Truncate logs so we only see entries from this invocation
        _clear_core_logs()

        # Create the sentinel — the L2_TEST binary checks this on every iteration
        Path(CU_ALL_FAIL_FLAG).touch()

        backup_props, device_props = _setup_device_props(os.getpid())
        dump = None
        try:
            dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc083_fail.dmp")
        except Exception:
            dump = None

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                # Generous timeout: ~3 s file-stability + 3 * sleep(2) = ~9 s extra
                timeout=60,
            )

            assert result.returncode != 0, (
                f"Expected non-zero exit after all retries exhausted, "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )

            # Verify all 3 retry messages were logged
            log_text = _read_core_log()
            retry_hits = re.findall(r"\d+: \(Retry\), minidump S3 Upload", log_text)
            assert len(retry_hits) >= 3, (
                f"Expected ≥ 3 retry log entries, found {len(retry_hits)}.\n"
                f"Log tail:\n{log_text[-2000:]}"
            )

            # Nothing must have reached the shared upload directory
            uploaded = (
                [p for p in upload_dir.iterdir() if p.is_file()]
                if upload_dir.exists()
                else []
            )
            assert uploaded == [], (
                f"Expected no uploaded files but found: {[p.name for p in uploaded]}"
            )

        finally:
            # Always remove the sentinel so subsequent tests are unaffected
            try:
                os.unlink(CU_ALL_FAIL_FLAG)
            except FileNotFoundError:
                pass
            _restore_device_props(backup_props, device_props)
            _clean_working_dir()
            _clean_upload_dir(upload_dir)


class TestUploadSuccessAfterRetries:
    """TC-082: upload succeeds on a retry — first 2 attempts are injected-fail
    via /tmp/cu_fail_n, the 3rd attempt reaches the real server and succeeds.
    """

    def _common_setup(self, upload_dir: Path):
        if upload_dir.exists():
            _clean_upload_dir(upload_dir)
        else:
            upload_dir.mkdir(parents=True, exist_ok=True)

        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)
        try:
            os.chmod(DEFAULT_LOG_PATH, 0o755)
            os.chmod(CORE_LOG_FILE, 0o644)
        except Exception:
            pass

    def test_upload_succeeds_after_retries(self, binary_path, cleanup_pytest_cache):
        """TC-082: /tmp/cu_fail_n=2 forces iterations 1 and 2 to fail; iteration 3
        reaches the real server → exit 0, ≥ 2 retry log entries, file present
        in the shared upload directory.
        """
        upload_dir = Path(UPLOADED_CRASHES_DIR)
        self._common_setup(upload_dir)
        _clear_core_logs()

        # Arm the partial-fail hook: fail iterations 1 and 2, succeed on 3
        cu_fail_n_path = Path(CU_FAIL_N_FLAG)
        cu_fail_n_path.write_text("2\n")

        backup_props, device_props = _setup_device_props(os.getpid())
        try:
            create_dummy_dump(SECURE_MINIDUMP_PATH, "tc082_retry.dmp")
        except Exception:
            pass

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                # ~3 s file-stability + 2 × sleep(2) retry delays
                timeout=60,
            )

            assert result.returncode == 0, (
                f"Expected exit 0 after eventual success on retry, "
                f"got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )

            log_text = _read_core_log()
            retry_hits = re.findall(r"\d+: \(Retry\), minidump S3 Upload", log_text)
            assert len(retry_hits) >= 2, (
                f"Expected ≥ 2 retry log entries, found {len(retry_hits)}.\n"
                f"Log tail:\n{log_text[-2000:]}"
            )

            uploaded = (
                [p for p in upload_dir.iterdir() if p.is_file()]
                if upload_dir.exists()
                else []
            )
            assert len(uploaded) >= 1, (
                f"Expected at least 1 uploaded file but found none"
            )

        finally:
            try:
                cu_fail_n_path.unlink()
            except FileNotFoundError:
                pass
            _restore_device_props(backup_props, device_props)
            _clean_working_dir()
            _clean_upload_dir(upload_dir)
