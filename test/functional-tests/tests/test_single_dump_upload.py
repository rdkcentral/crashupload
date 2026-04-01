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
TC-081: S3 Upload - First Attempt Success (Positive)

This functional test exercises a single end-to-end upload:
  - create a dummy dump in the controlled secure dump path
  - run the crashupload binary (secure mode)
  - assert that the mock S3 server saved an uploaded file to the
    shared `uploaded_crashes` directory on the host

Requires: the test environment's mock-xconf and native-platform are up
and `CRASHUPLOAD_BINARY` points to a test-built crashupload binary.
"""

import os
import subprocess
import time
import shutil
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


class TestUpload:
    """TC-081: verify a single successful upload is saved by mock S3."""

    def test_single_successful_upload(self, binary_path, cleanup_pytest_cache):
        # Shared directory where mock-xconf saves uploaded dumps
        upload_dir = Path(UPLOADED_CRASHES_DIR)

        # Ensure clean upload directory
        if upload_dir.exists():
            for p in upload_dir.iterdir():
                try:
                    if p.is_file():
                        p.unlink()
                except Exception:
                    pass
        else:
            upload_dir.mkdir(parents=True, exist_ok=True)

        # Ensure no leftover lock file
        if os.path.exists(MINIDUMP_LOCK_FILE):
            os.unlink(MINIDUMP_LOCK_FILE)

        # Ensure logging path and core log exist and are writable for system init
        os.makedirs(DEFAULT_LOG_PATH, exist_ok=True)
        Path(CORE_LOG_FILE).touch(exist_ok=True)
        try:
            os.chmod(DEFAULT_LOG_PATH, 0o755)
        except Exception:
            pass
        try:
            os.chmod(CORE_LOG_FILE, 0o644)
        except Exception:
            pass

        # Temporarily set device.properties S3 signing URL for this test only
        device_props = Path(DEVICE_PROPERTIES)
        backup_props = None
        try:
            if device_props.exists():
                backup_props = device_props.with_name(f"device.properties.l2bak_{os.getpid()}")
                device_props.rename(backup_props)
            # Ensure DEVICE_TYPE is present so getDevicePropertyData() succeeds
            device_props.write_text(
                "DEVICE_TYPE=mediaclient\nS3_AMAZON_SIGNING_URL=https://mockxconf:50059\n"
            )

            # Create a dummy dump and invoke the binary in secure mode
            dump = create_dummy_dump(SECURE_MINIDUMP_PATH, "tc081_single.dmp")
        except Exception:
            # Ensure we still attempt to run cleanup in finally
            dump = None

        try:
            result = subprocess.run(
                [binary_path, "", "0", "secure"],
                capture_output=True,
                timeout=60,
            )

            assert result.returncode == 0, (
                f"Expected crashupload to exit 0, got {result.returncode}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )

            # Wait for an uploaded file to appear (mock-xconf saves uploads here)
            deadline = time.monotonic() + 15.0
            found = None
            while time.monotonic() < deadline:
                files = [p for p in upload_dir.iterdir() if p.is_file()]
                if files:
                    found = files[0]
                    break
                time.sleep(0.2)

            assert found is not None, f"No uploaded file found in {upload_dir}"
            assert found.stat().st_size > 0, "Uploaded file has zero size"

        finally:
            # Cleanup created artifacts
            try:
                if os.path.exists(dump):
                    os.unlink(dump)
            except Exception:
                pass
            # Restore original device.properties
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
            try:
                for p in upload_dir.iterdir():
                    if p.is_file():
                        p.unlink()
            except Exception:
                pass
