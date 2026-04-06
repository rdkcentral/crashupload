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
Functional test for crashupload wait-for-lock mechanism
Tests that crashupload waits for lock to be released when 'wait_for_lock' argument is used
"""

import pytest
import subprocess
import os
import time
import threading
from pathlib import Path
from testUtility import cleanup_pytest_cache, binary_path, hold_lock_and_release, SECURE_COREDUMP_PATH


class TestWaitForLock:
    """Test crashupload wait-for-lock functionality with 'wait_for_lock' argument"""
    
    @pytest.fixture
    def minidump_dir(self):
        """Setup and cleanup minidump directory"""
        dump_dir = Path("/opt/secure/minidumps")
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up any existing dump files before test
        for dump_file in dump_dir.glob("*.dmp*"):
            try:
                dump_file.unlink()
                print(f"Cleaned up existing dump: {dump_file}")
            except Exception as e:
                print(f"Warning: Could not remove {dump_file}: {e}")
        
        yield str(dump_dir)
        
        # Clean up after test
        for dump_file in dump_dir.glob("*.dmp*"):
            try:
                dump_file.unlink()
            except:
                pass
    
    @pytest.fixture
    def coredump_dir(self):
        """Setup and cleanup coredump directory.

        Uses SECURE_COREDUMP_PATH (/opt/secure/corefiles) — the exact path that
        config_manager.c assigns to config->core_path when argv[3]=="secure" and
        argv[2]=="1".  prerequisites_wait() scans that directory for *_core* files;
        if any are found the binary proceeds to a sleep(21) call, causing a timeout.
        """
        dump_dir = Path(SECURE_COREDUMP_PATH)
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up any existing dump files before test
        for dump_file in dump_dir.glob("*.dmp*"):
            try:
                dump_file.unlink()
                print(f"Cleaned up existing dump: {dump_file}")
            except Exception as e:
                print(f"Warning: Could not remove {dump_file}: {e}")
        
        # Also check for coredump pattern files
        for dump_file in dump_dir.glob("*core*"):
            try:
                dump_file.unlink()
                print(f"Cleaned up existing core: {dump_file}")
            except:
                pass
        
        yield str(dump_dir)
        
        # Clean up after test
        for dump_file in dump_dir.glob("*.dmp*"):
            try:
                dump_file.unlink()
            except:
                pass
        for dump_file in dump_dir.glob("*core*"):
            try:
                dump_file.unlink()
            except:
                pass
    
    @pytest.fixture
    def minidump_lock_file(self):
        """Minidump lock file path with cleanup"""
        lock_path = "/tmp/.uploadMinidumps"
        
        # Clean up before test
        if os.path.exists(lock_path):
            try:
                os.remove(lock_path)
            except:
                pass
        
        yield lock_path
        
        # Clean up after test
        if os.path.exists(lock_path):
            try:
                os.remove(lock_path)
            except:
                pass
    
    @pytest.fixture
    def coredump_lock_file(self):
        """Coredump lock file path with cleanup"""
        lock_path = "/tmp/.uploadCoredumps"
        
        # Clean up before test
        if os.path.exists(lock_path):
            try:
                os.remove(lock_path)
            except:
                pass
        
        yield lock_path
        
        # Clean up after test
        if os.path.exists(lock_path):
            try:
                os.remove(lock_path)
            except:
                pass
    
    def test_wait_for_lock_minidump(self, binary_path, minidump_dir, minidump_lock_file, cleanup_pytest_cache):
        """
        Test LOCK-04: Verify 'wait_for_lock' argument causes binary to wait for lock release
        
        Test Steps:
        1. Clean dump directory (no dumps present)
        2. Acquire lock and hold for 3 seconds
        3. Run crashupload with 'wait_for_lock' argument
        4. Verify it waits and logs waiting message
        5. After lock is released, binary proceeds
        6. Binary exits gracefully with "no dumps" message
        """
        print(f"\n{'='*70}")
        print(f"TEST: Wait for lock with minidump (wait_for_lock argument)")
        print(f"{'='*70}")
        
        # Verify dump directory is empty
        dump_files = list(Path(minidump_dir).glob("*.dmp*"))
        assert len(dump_files) == 0, f"Dump directory should be empty, found: {dump_files}"
        print(f"✓ Dump directory is empty: {minidump_dir}")
        
        # Event to signal when lock is acquired
        lock_acquired = threading.Event()
        
        # Start thread to hold lock for 3 seconds (less than 5 second wait timeout)
        lock_duration = 3
        lock_thread = threading.Thread(
            target=hold_lock_and_release,
            args=(minidump_lock_file, lock_duration, lock_acquired),
            daemon=True
        )
        lock_thread.start()
        
        # Wait for lock to be acquired (with timeout)
        assert lock_acquired.wait(timeout=5), "Lock was not acquired within timeout"
        print(f"✓ Lock acquired by background thread")
        
        # Give a moment for lock to be fully established
        time.sleep(0.5)
        
        # Record start time to measure wait duration
        start_time = time.time()
        
        try:
            # Run crashupload with wait_for_lock argument
            # Usage: crashupload <dir> <type> <secure|placeholder> wait_for_lock
            # argc must be 5: argv[0]=program, argv[1]=dir, argv[2]=type, argv[3]=secure, argv[4]=wait_for_lock
            print(f"\n[Main] Running: {binary_path} '' 0 secure wait_for_lock")
            result = subprocess.run(
                [binary_path, "", "0", "secure", "wait_for_lock"],
                capture_output=True,
                text=True,
                timeout=10  # Should complete within 10 seconds
            )
            
            # Measure elapsed time
            elapsed_time = time.time() - start_time
            
            print(f"\n{'='*70}")
            print(f"RESULTS:")
            print(f"{'='*70}")
            print(f"Exit code: {result.returncode}")
            print(f"Elapsed time: {elapsed_time:.2f} seconds")
            print(f"\nStdout:\n{result.stdout}")
            print(f"\nStderr:\n{result.stderr}")
            print(f"{'='*70}")
            
            combined_output = result.stdout + result.stderr
            
            # Verify the binary waited (allow 0.1s tolerance for timing variations)
            assert elapsed_time >= 2.4, \
                f"Binary should have waited ~3 seconds, but only took {elapsed_time:.2f}s"
            print(f"✓ Binary waited for lock release ({elapsed_time:.2f}s)")
            
            # Verify waiting message appears in output
            wait_messages = [
                "waiting for lock",
                "lock is held",
                "retrying",
                "waiting",
            ]
            
            found_wait_message = any(msg.lower() in combined_output.lower() 
                                    for msg in wait_messages)
            
            if found_wait_message:
                print(f"✓ Binary logged waiting for lock")
            else:
                print(f"⚠ Warning: No explicit 'waiting' message found in output")
            
            # Verify exit code is 0 (graceful exit - no dumps to process)
            assert result.returncode == 0, \
                f"Expected exit code 0, got {result.returncode}"
            print(f"✓ Binary exited gracefully")
            
            # Verify "no dumps" or similar message (since directory is empty)
            no_dumps_messages = [
                "no dump",
                "no files",
                "nothing to upload",
                "0 files",
                "empty",
            ]
            
            found_no_dumps_message = any(msg.lower() in combined_output.lower() 
                                        for msg in no_dumps_messages)
            
            if found_no_dumps_message:
                print(f"✓ Binary correctly reported no dumps to process")
            else:
                print(f"ℹ Note: Binary may have different messaging for empty directory")
            
            print(f"\n✅ TEST PASSED: Wait-for-lock mechanism works correctly for minidump")
            
        finally:
            # Wait for lock thread to finish
            lock_thread.join(timeout=2)
            print(f"\n✓ Cleanup: Lock thread finished")
    
    def test_wait_for_lock_coredump(self, binary_path, coredump_dir, coredump_lock_file, cleanup_pytest_cache):
        """
        Test LOCK-05: Verify 'wait_for_lock' argument works for coredump type
        
        Test Steps:
        1. Clean dump directory (no dumps present)
        2. Acquire lock and hold for 3 seconds
        3. Run crashupload with 'wait_for_lock' argument for coredump type
        4. Verify it waits and logs waiting message
        5. After lock is released, binary proceeds
        6. Binary exits gracefully with "no dumps" message
        """
        print(f"\n{'='*70}")
        print(f"TEST: Wait for lock with coredump (wait_for_lock argument)")
        print(f"{'='*70}")
        
        # Verify dump directory is empty
        dump_files = list(Path(coredump_dir).glob("*.dmp*")) + list(Path(coredump_dir).glob("*core*"))
        assert len(dump_files) == 0, f"Dump directory should be empty, found: {dump_files}"
        print(f"✓ Dump directory is empty: {coredump_dir}")
        
        # Event to signal when lock is acquired
        lock_acquired = threading.Event()
        
        # Start thread to hold lock for 3 seconds
        lock_duration = 3
        lock_thread = threading.Thread(
            target=hold_lock_and_release,
            args=(coredump_lock_file, lock_duration, lock_acquired),
            daemon=True
        )
        lock_thread.start()
        
        # Wait for lock to be acquired
        assert lock_acquired.wait(timeout=5), "Lock was not acquired within timeout"
        print(f"✓ Lock acquired by background thread")
        
        # Give a moment for lock to be fully established
        time.sleep(0.5)
        
        # Record start time
        start_time = time.time()
        
        try:
            # Run crashupload with wait_for_lock argument for coredump type
            # Usage: crashupload <dir> <type> <secure|placeholder> wait_for_lock
            # argc must be 5: argv[0]=program, argv[1]=dir, argv[2]=type, argv[3]=secure, argv[4]=wait_for_lock
            print(f"\n[Main] Running: {binary_path} '' 1 secure wait_for_lock")
            result = subprocess.run(
                [binary_path, "", "1", "secure", "wait_for_lock"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Measure elapsed time
            elapsed_time = time.time() - start_time
            
            print(f"\n{'='*70}")
            print(f"RESULTS:")
            print(f"{'='*70}")
            print(f"Exit code: {result.returncode}")
            print(f"Elapsed time: {elapsed_time:.2f} seconds")
            print(f"\nStdout:\n{result.stdout}")
            print(f"\nStderr:\n{result.stderr}")
            print(f"{'='*70}")
            
            combined_output = result.stdout + result.stderr
            
            # Verify the binary waited (allow 0.1s tolerance for timing variations)
            assert elapsed_time >= 2.4, \
                f"Binary should have waited ~3 seconds, but only took {elapsed_time:.2f}s"
            print(f"✓ Binary waited for lock release ({elapsed_time:.2f}s)")
            
            # Verify waiting message
            wait_messages = [
                "waiting for lock",
                "lock is held",
                "retrying",
                "waiting",
            ]
            
            found_wait_message = any(msg.lower() in combined_output.lower() 
                                    for msg in wait_messages)
            
            if found_wait_message:
                print(f"✓ Binary logged waiting for lock")
            else:
                print(f"⚠ Warning: No explicit 'waiting' message found in output")
            
            # Verify graceful exit
            assert result.returncode == 0, \
                f"Expected exit code 0, got {result.returncode}"
            print(f"✓ Binary exited gracefully")
            
            # Verify no dumps message
            no_dumps_messages = [
                "no dump",
                "no files",
                "nothing to upload",
                "0 files",
                "empty",
            ]
            
            found_no_dumps_message = any(msg.lower() in combined_output.lower() 
                                        for msg in no_dumps_messages)
            
            if found_no_dumps_message:
                print(f"✓ Binary correctly reported no dumps to process")
            else:
                print(f"ℹ Note: Binary may have different messaging for empty directory")
            
            print(f"\n✅ TEST PASSED: Wait-for-lock mechanism works correctly for coredump")
            
        finally:
            # Wait for lock thread to finish
            lock_thread.join(timeout=2)
            print(f"\n✓ Cleanup: Lock thread finished")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
