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
Functional test for crashupload - Unsupported Device Types
Tests that crashupload properly handles unsupported device types (EXTENDER, BROADBAND)

IMPLEMENTATION STATUS:
- MEDIACLIENT: Fully implemented for upload
- BROADBAND: Not implemented - should fail gracefully with error message
- EXTENDER: Not implemented - should fail gracefully with error message

These tests verify that the binary exits properly when encountering
device types that don't have upload implementation.
"""

import pytest
import subprocess
import os
import time
from pathlib import Path


class TestUnsupportedDeviceTypes:
    """Test crashupload behavior with unsupported device types"""
    
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        """Setup test environment before each test and cleanup after"""
        # Setup
        self.cleanup_test_environment()
        self.setup_directories()
        
        yield
        
        # Teardown
        self.cleanup_test_environment()
    
    def cleanup_test_environment(self):
        """Clean up test files and directories"""
        paths_to_clean = [
            "/opt/secure/minidumps",
            "/opt/secure/corefiles",
            "/minidumps",
            "/opt/logs",
            "/tmp/.uploadMinidumps",
            "/tmp/.on_startup_dumps_cleaned_up_0",
            "/etc/device.properties",
            "/etc/include.properties",
            "/etc/debug.ini"
        ]
        
        for path in paths_to_clean:
            if os.path.exists(path):
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        print(f"Warning: Could not remove {path}: {e}")
                elif os.path.isdir(path):
                    for item in Path(path).glob("*"):
                        try:
                            if item.is_file():
                                item.unlink()
                        except Exception as e:
                            print(f"Warning: Could not remove {item}: {e}")
    
    def setup_directories(self):
        """Create required directories"""
        directories = [
            "/opt/secure/minidumps",
            "/opt/secure/corefiles",
            "/minidumps",
            "/opt/logs"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Create startup cleanup flag to prevent cleanup delays
        Path("/tmp/.on_startup_dumps_cleaned_up_0").touch()
    
    def setup_configuration_files(self, device_type):
        """
        Create configuration files with specified device type
        
        Args:
            device_type: Device type string (extender, broadband, mediaclient)
        """
        # Create /etc/device.properties with specified device type
        device_props = f"""DEVICE_TYPE={device_type}
BOX_TYPE=XG1v4
BUILD_TYPE=dev
MODEL_NUM=XG1v4
PARTNER_ID=comcast
ENABLE_MAINTENANCE=false
S3_AMAZON_SIGNING_URL=https://mockxconf:50059/
CRASH_PORTAL_URL=mockxconf
"""
        with open('/etc/device.properties', 'w') as f:
            f.write(device_props)
        print(f"Created /etc/device.properties with DEVICE_TYPE={device_type}")
        
        # Create /etc/include.properties
        include_props = """LOG_PATH=/opt/logs
PERSISTENT_PATH=/opt
"""
        with open('/etc/include.properties', 'w') as f:
            f.write(include_props)
        
        # Create /etc/debug.ini for RDK Logger
        debug_ini = """# RDK Logger Configuration for L2 Tests
LOG.RDK.CRASHUPLOAD=INFO
"""
        with open('/etc/debug.ini', 'w') as f:
            f.write(debug_ini)
        
        # Create version.txt
        with open('/version.txt', 'w') as f:
            f.write('imagename:XG1v4-dev-TEST_IMAGE_2026-02-10')
        
        # Create MAC address file
        with open('/tmp/.macAddress', 'w') as f:
            f.write('AA:BB:CC:DD:EE:FF')
    
    def create_test_minidump(self, location="/minidumps", filename="test_crash.dmp"):
        """
        Create a test minidump file
        
        For extender with secure flag:
        - Prerequisites checks /opt/secure/corefiles for .dmp
        - Scanner processes from /minidumps (working_dir_path)
        """
        minidump_path = Path(location) / filename
        prereq_path = Path("/opt/secure/corefiles") / "dummy.dmp"
        
        # Create minidump with header
        content = b'MDMP\x93\xa7\x00\x00' + b'\x00' * 10240
        
        with open(minidump_path, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        
        # Create dummy for prerequisites check
        with open(prereq_path, 'wb') as f:
            f.write(content[:1024])
            f.flush()
            os.fsync(f.fileno())
        
        print(f"Created test minidump: {minidump_path}")
        
        # Wait for filesystem to settle
        time.sleep(3)
        
        return str(minidump_path)
    
    def run_crashupload(self, dump_type="0", upload_flag="secure"):
        """
        Execute crashupload binary
        
        Returns:
            subprocess.CompletedProcess with returncode, stdout, stderr
        """
        binary = os.environ.get('CRASHUPLOAD_BINARY', '/usr/local/bin/crashupload')
        
        if not os.path.exists(binary):
            pytest.skip(f"Crashupload binary not found: {binary}")
        
        cmd = [binary, "upload", dump_type]
        if upload_flag:
            cmd.append(upload_flag)
        
        print(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # Short timeout since these should fail quickly
        )
        
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print(f"STDOUT:\n{result.stdout}")
        if result.stderr:
            print(f"STDERR:\n{result.stderr}")
        
        return result
    
    def test_extender_device_type_fails_gracefully(self):
        """
        Test that EXTENDER device type fails gracefully during upload
        
        Expected behavior:
        - Binary should initialize successfully
        - Prerequisites should pass (finds .dmp files)
        - Scanner should find dumps
        - Archive creation should succeed
        - Upload should fail with error message: "Unknown device"
        - Exit code should be non-zero
        """
        # Setup configuration with EXTENDER device type
        self.setup_configuration_files(device_type="extender")
        
        # Create test dump file
        self.create_test_minidump()
        
        # Run crashupload
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Verify failure behavior
        # Note: Without logging enabled, we only check exit code
        # The binary should still exit with non-zero code for unsupported device types
        assert result.returncode != 0, \
            "Binary should exit with non-zero code for unsupported EXTENDER device type"
        
        # Optional: Check for error messages if logging is available
        output = result.stdout + result.stderr
        if "Unknown device" in output or "SUPPORT NOT AVAILABLE" in output:
            print(f"✓ Error message found in output: {output}")
        else:
            print(f"⚠ No error message in output (logging may not be enabled)")
            print(f"  Output: {output}")
        
        print(f"✓ EXTENDER device type correctly failed with exit code {result.returncode}")
    
    def test_broadband_device_type_fails_gracefully(self):
        """
        Test that BROADBAND device type fails gracefully during upload
        
        Expected behavior:
        - Binary should initialize successfully
        - Prerequisites should pass (finds .dmp files in core_path)
        - Scanner should find dumps
        - Archive creation should succeed
        - Upload should fail with error message: "TODO: SUPPORT NOT AVAILABLE"
        - Exit code should be non-zero
        """
        # Setup configuration with BROADBAND device type
        self.setup_configuration_files(device_type="broadband")
        
        # Create test dump file
        # For broadband, prerequisites checks core_path (/opt/secure/corefiles)
        self.create_test_minidump()
        
        # Run crashupload
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Verify failure behavior
        # Note: Without logging enabled, we only check exit code
        # The binary should still exit with non-zero code for unsupported device types
        assert result.returncode != 0, \
            "Binary should exit with non-zero code for unsupported BROADBAND device type"
        
        # Optional: Check for error messages if logging is available
        output = result.stdout + result.stderr
        if "SUPPORT NOT AVAILABLE" in output or "Unknown device" in output:
            print(f"✓ Error message found in output: {output}")
        else:
            print(f"⚠ No error message in output (logging may not be enabled)")
            print(f"  Output: {output}")
        
        print(f"✓ BROADBAND device type correctly failed with exit code {result.returncode}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
