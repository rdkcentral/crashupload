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
Functional test for crashupload multiple instance prevention
Tests that crashupload properly detects and prevents multiple concurrent instances
"""

import pytest
import subprocess
import os
import fcntl
import time
import threading
import shutil
from pathlib import Path


class TestMultipleInstancePrevention:
    """Test crashupload lock mechanism to prevent multiple instances"""
    
    @pytest.fixture(scope="session", autouse=True)
    def cleanup_pytest_cache(self):
        """Cleanup pytest cache directories after all tests complete"""
        yield  # Run all tests first
        
        # Cleanup after all tests in this session
        test_dir = Path(__file__).parent
        cache_dirs = [
            test_dir / "__pycache__",
            test_dir / ".pytest_cache",
            test_dir.parent / "__pycache__",
            test_dir.parent / ".pytest_cache",
        ]
        
        for cache_dir in cache_dirs:
            if cache_dir.exists():
                try:
                    shutil.rmtree(cache_dir)
                    print(f"Cleaned up: {cache_dir}")
                except Exception as e:
                    print(f"Warning: Could not remove {cache_dir}: {e}")
    
    @pytest.fixture
    def binary_path(self):
        """Get path to crashupload binary"""
        binary = os.environ.get('CRASHUPLOAD_BINARY', '/usr/local/bin/crashupload')
        if not os.path.exists(binary):
            pytest.skip(f"Crashupload binary not found at {binary}")
        return binary
    
    @pytest.fixture
    def minidump_dir(self):
        """Setup minidump directory"""
        dump_dir = Path("/opt/secure/minidumps")
        dump_dir.mkdir(parents=True, exist_ok=True)
        return str(dump_dir)
    
    @pytest.fixture
    def lock_file_path(self):
        """Return the minidump lock file path"""
        return "/tmp/.uploadMinidumps"
    
    def create_dummy_dump(self, dump_dir, dump_name="multi_instance.dmp", size_kb=1):
        """Create a dummy dump file with specified size"""
        dump_path = Path(dump_dir) / dump_name
        # Create file with at least 1KB of data
        with open(dump_path, 'wb') as f:
            f.write(b'MINIDUMP_HEADER' + b'\x00' * (size_kb * 1024))
        
        assert dump_path.exists(), f"Failed to create dump file {dump_path}"
        assert dump_path.stat().st_size > 0, f"Dump file {dump_path} has zero size"
        return str(dump_path)
    
    def hold_lock(self, lock_file_path, duration_sec, lock_acquired_event):
        """Hold an exclusive lock on the lock file for specified duration"""
        try:
            # Create lock file if it doesn't exist
            lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_RDWR, 0o644)
            
            # Acquire exclusive lock (non-blocking test first)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(f"Lock acquired on {lock_file_path}")
            
            # Signal that lock is acquired
            lock_acquired_event.set()
            
            # Hold lock for specified duration
            time.sleep(duration_sec)
            
            # Release lock
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            print(f"Lock released on {lock_file_path}")
            
        except BlockingIOError:
            print(f"Could not acquire lock on {lock_file_path} - already locked")
            lock_acquired_event.set()  # Signal anyway to not block test
        except Exception as e:
            print(f"Error in lock thread: {e}")
            lock_acquired_event.set()
    
    def test_multiple_instance_prevention_minidump(self, binary_path, minidump_dir, lock_file_path):
        """
        Test LOCK-03: Verify that second instance exits when lock is already held
        
        Test Steps:
        1. Acquire exclusive lock on /tmp/.uploadMinidumps
        2. Create a dummy minidump file
        3. Run crashupload binary with minidump arguments
        4. Verify binary exits with "already working" message
        """
        # Clean up any existing lock file
        if os.path.exists(lock_file_path):
            try:
                os.remove(lock_file_path)
            except:
                pass
        
        # Create dummy dump file
        dump_file = self.create_dummy_dump(minidump_dir, "multi_instance.dmp", size_kb=1)
        print(f"Created dummy dump file: {dump_file}")
        
        # Event to signal when lock is acquired
        lock_acquired = threading.Event()
        
        # Start thread to hold lock for 60 seconds
        lock_duration = 60
        lock_thread = threading.Thread(
            target=self.hold_lock,
            args=(lock_file_path, lock_duration, lock_acquired),
            daemon=True
        )
        lock_thread.start()
        
        # Wait for lock to be acquired (with timeout)
        assert lock_acquired.wait(timeout=5), "Lock was not acquired within timeout"
        
        # Give a moment for lock to be fully established
        time.sleep(0.5)
        
        try:
            # Now try to run crashupload - it should detect the lock and exit
            print(f"Running: {binary_path} {minidump_dir} 0")
            result = subprocess.run(
                [binary_path, minidump_dir, "0"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            print(f"Exit code: {result.returncode}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            
            # Verify exit code is 0 (graceful exit when lock exists)
            assert result.returncode == 0, \
                f"Expected exit code 0, got {result.returncode}"
            
            # Verify output contains lock detection message
            combined_output = result.stdout + result.stderr
            
            # Check for various possible lock messages
            lock_messages = [
                "Failed to acquire lock",
                "already working",
                "Skip launch another instance",
                "lock.d"
            ]
            
            found_lock_message = any(msg.lower() in combined_output.lower() 
                                    for msg in lock_messages)
            
            assert found_lock_message, \
                f"Expected lock detection message in output. Got:\n{combined_output}"
            
            print("✓ Binary correctly detected existing lock and exited")
            
        finally:
            # Cleanup: wait for lock thread to finish or force cleanup
            lock_thread.join(timeout=2)
            
            # Clean up dump file
            if os.path.exists(dump_file):
                os.remove(dump_file)
            
            # Clean up lock file if it still exists
            if os.path.exists(lock_file_path):
                try:
                    os.remove(lock_file_path)
                except:
                    pass
    
    def test_multiple_instance_prevention_coredump(self, binary_path):
        """
        Test LOCK-01: Verify coredump uses different lock file
        
        Test Steps:
        1. Acquire exclusive lock on /tmp/.uploadCoredumps
        2. Run crashupload binary with coredump arguments
        3. Verify binary exits with "already working" message
        """
        lock_file_path = "/tmp/.uploadCoredumps"
        coredump_dir = "/opt/secure/coredumps"
        
        # Setup coredump directory
        Path(coredump_dir).mkdir(parents=True, exist_ok=True)
        
        # Clean up any existing lock file
        if os.path.exists(lock_file_path):
            try:
                os.remove(lock_file_path)
            except:
                pass
        
        # Event to signal when lock is acquired
        lock_acquired = threading.Event()
        
        # Start thread to hold lock
        lock_thread = threading.Thread(
            target=self.hold_lock,
            args=(lock_file_path, 60, lock_acquired),
            daemon=True
        )
        lock_thread.start()
        
        # Wait for lock to be acquired
        assert lock_acquired.wait(timeout=5), "Lock was not acquired within timeout"
        time.sleep(0.5)
        
        try:
            # Try to run crashupload with coredump type
            result = subprocess.run(
                [binary_path, coredump_dir, "1"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            print(f"Coredump test - Exit code: {result.returncode}")
            print(f"Stdout: {result.stdout}")
            
            # Should exit gracefully when lock exists
            assert result.returncode == 0, \
                f"Expected exit code 0, got {result.returncode}"
            
            combined_output = result.stdout + result.stderr
            lock_messages = ["Failed to acquire lock", "already working"]
            
            found_lock_message = any(msg.lower() in combined_output.lower() 
                                    for msg in lock_messages)
            
            assert found_lock_message, \
                f"Expected lock detection message in output"
            
            print("✓ Coredump correctly uses separate lock file")
            
        finally:
            lock_thread.join(timeout=2)
            if os.path.exists(lock_file_path):
                try:
                    os.remove(lock_file_path)
                except:
                    pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
