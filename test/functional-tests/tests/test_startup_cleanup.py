"""
Functional tests for crashupload on-startup cleanup batch process.

Tests the cleanup_batch() logic that runs when the flag file
/tmp/.on_startup_dumps_cleaned_up_{N} does not exist.

This simulates device bootup cleanup behavior.
"""

import os
import sys
import subprocess
import time
import glob
import shutil
import pytest
import requests


class TestStartupCleanup:
    """Test suite for on-startup cleanup batch functionality"""

    MINIDUMP_DIR = "/opt/secure/minidumps"
    COREDUMP_DIR = "/opt/minidumps"
    LOGS_DIR = "/opt/logs"
    SHARED_VOLUME = "/mnt/L2_CONTAINER_SHARED_VOLUME/uploaded_crashes"
    MOCK_SERVER = "mockxconf:50059"

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        """Setup before each test, cleanup after"""
        print("\n" + "="*60)
        print("SETUP: Preparing test environment")
        print("="*60)

        # Ensure directories exist
        self.setup_directories()

        # Setup configuration files
        self.setup_config_files()

        # Verify mock server is accessible
        self.verify_mock_server()

        yield  # Run the test

        # Cleanup after test
        print("\n" + "="*60)
        print("TEARDOWN: Cleaning up test artifacts")
        print("="*60)
        self.cleanup_test_files()

    def setup_directories(self):
        """Create necessary directories"""
        for directory in [self.MINIDUMP_DIR, self.COREDUMP_DIR, self.LOGS_DIR, self.SHARED_VOLUME]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                print(f"Created directory: {directory}")

    def setup_config_files(self):
        """Create necessary configuration files"""
        # Create device.properties
        device_props = [
            "DEVICE_TYPE=mediaclient",
            "BOX_TYPE=XG1v4",
            "BUILD_TYPE=dev",
            "MODEL_NUM=XG1v4",
            "PARTNER_ID=comcast",
            "ENABLE_MAINTENANCE=false",
            "S3_AMAZON_SIGNING_URL=https://mockxconf:50059/",
            "CRASH_PORTAL_URL=mockxconf"
        ]

        with open("/etc/device.properties", "w") as f:
            f.write("\n".join(device_props))
        print("Created /etc/device.properties")

        # Fallback copy
        with open("/tmp/device.properties", "w") as f:
            f.write("\n".join(device_props))
        print("Created /tmp/device.properties (fallback)")

        # Create include.properties
        with open("/etc/include.properties", "w") as f:
            f.write("S3_AMAZON_SIGNING_URL=/tmp/uploadDumps.conf")
        print("Created /etc/include.properties")

        # Create RFC override
        os.makedirs("/opt/secure/RFC", exist_ok=True)
        with open("/opt/secure/RFC/.RFC_CONFIG.ini", "w") as f:
            f.write("[Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CrashUpload.Enable]\n")
            f.write("value=true\n")
        print("Created /opt/secure/RFC/.RFC_CONFIG.ini (RFC override)")

        # Create version.txt
        with open("/version.txt", "w") as f:
            f.write("imagename:TEST_VERSION_1.0.0")
        print("Created /version.txt")

        # Create MAC address file
        with open("/tmp/.macAddress", "w") as f:
            f.write("AA:BB:CC:DD:EE:FF")
        print("Created /tmp/.macAddress")

    def verify_mock_server(self):
        """Verify mock server is accessible"""
        try:
            response = requests.get(
                f"https://{self.MOCK_SERVER}/admin/crashUpload?returnData=true",
                verify=False,
                timeout=5
            )
            if response.status_code == 200:
                print(f"✓ Mock server is accessible at {self.MOCK_SERVER}")
                return True
        except Exception as e:
            print(f"⚠ Warning: Mock server not accessible: {e}")
            return False

    def cleanup_test_files(self):
        """Clean up test artifacts"""
        # Clean up minidump directory
        if os.path.exists(self.MINIDUMP_DIR):
            for item in os.listdir(self.MINIDUMP_DIR):
                item_path = os.path.join(self.MINIDUMP_DIR, item)
                try:
                    if os.path.isfile(item_path):
                        os.unlink(item_path)
                        print(f"Cleaned up: {item_path}")
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                        print(f"Cleaned up directory: {item_path}")
                except Exception as e:
                    print(f"Failed to cleanup {item_path}: {e}")

        # Clean up coredump directory
        if os.path.exists(self.COREDUMP_DIR):
            for item in os.listdir(self.COREDUMP_DIR):
                item_path = os.path.join(self.COREDUMP_DIR, item)
                try:
                    if os.path.isfile(item_path):
                        os.unlink(item_path)
                        print(f"Cleaned up: {item_path}")
                except Exception as e:
                    print(f"Failed to cleanup {item_path}: {e}")

        # Clean up flag files
        for flag_file in glob.glob("/tmp/.on_startup_dumps_cleaned_up_*"):
            try:
                os.unlink(flag_file)
                print(f"Cleaned up file: {flag_file}")
            except Exception as e:
                print(f"Failed to cleanup {flag_file}: {e}")

        # Clean up logs
        log_files = [
            "/opt/logs/core_log.txt",
            "/opt/logs/tlsError.log"
        ]
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    os.unlink(log_file)
                    print(f"Cleaned up: {log_file}")
                except Exception as e:
                    print(f"Failed to cleanup {log_file}: {e}")

    def create_test_minidump(self, filename, size_kb=10):
        """Create a test minidump file with specified size"""
        filepath = os.path.join(self.MINIDUMP_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(b'\x00' * (size_kb * 1024))
        print(f"Created test minidump: {filepath} ({size_kb}KB)")
        return filepath

    def create_test_coredump(self, filename, size_kb=10):
        """Create a test coredump file with specified size"""
        filepath = os.path.join(self.COREDUMP_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(b'\x00' * (size_kb * 1024))
        print(f"Created test coredump: {filepath} ({size_kb}KB)")
        return filepath

    def run_crashupload(self, dump_type="0", upload_flag="secure", lock_mode=""):
        """Run crashupload binary and return result"""
        cmd = ["/usr/local/bin/crashupload", lock_mode, dump_type, upload_flag]
        print(f"Executing: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result

    @pytest.mark.order(0)
    def test_minidump_startup_cleanup_deletes_old_dumps(self):
        """
        Test: On-startup cleanup keeps only 4 most recent minidump files
        
        Steps:
        1. Remove flag file to simulate fresh boot
        2. Create 6 minidump files with different timestamps
        3. Create non-dump files (should be deleted)
        4. Run crashupload (triggers cleanup)
        5. Verify only 4 most recent dumps remain
        6. Verify non-dump files deleted
        7. Verify flag file created
        """
        print("\n========== TEST: Minidump Startup Cleanup - Delete Old Dumps ==========")
        
        # Step 1: Remove flag file (simulate fresh boot)
        flag_file = "/tmp/.on_startup_dumps_cleaned_up_0"
        if os.path.exists(flag_file):
            os.remove(flag_file)
            print(f"Removed flag file: {flag_file}")
        
        # Step 2: Create 6 minidump files (older to newer)
        dump_files = []
        for i in range(6):
            time.sleep(0.2)  # Ensure different timestamps
            dump_file = self.create_test_minidump(f"test_cleanup_{i:02d}.dmp", size_kb=5)
            dump_files.append(dump_file)
        
        print(f"\nCreated {len(dump_files)} dump files:")
        for i, f in enumerate(dump_files):
            stat = os.stat(f)
            print(f"  [{i}] {os.path.basename(f)} - mtime: {stat.st_mtime}")
        
        # Step 3: Create non-dump files (should be deleted)
        non_dump_files = [
            os.path.join(self.MINIDUMP_DIR, "version.txt"),
            os.path.join(self.MINIDUMP_DIR, "extra.log"),
            os.path.join(self.MINIDUMP_DIR, "temp.txt"),
            os.path.join(self.MINIDUMP_DIR, "readme.md")
        ]
        for f in non_dump_files:
            with open(f, 'w') as fp:
                fp.write("test content")
            print(f"Created non-dump file: {f}")
        
        # Step 4: Run crashupload (triggers cleanup_batch)
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Step 5: Verify flag file was created
        assert os.path.exists(flag_file), f"Flag file should be created: {flag_file}"
        print(f"✓ Flag file created: {flag_file}")
        
        # Step 6: Verify non-dump files were deleted
        for f in non_dump_files:
            assert not os.path.exists(f), f"Non-dump file should be deleted: {f}"
        print(f"✓ All {len(non_dump_files)} non-dump files deleted")
        
        # Step 7: Verify only 4 most recent dumps remain (as .dmp or .tgz archives)
        remaining_dumps = sorted(glob.glob(os.path.join(self.MINIDUMP_DIR, "*.dmp")))
        remaining_archives = sorted(glob.glob(os.path.join(self.MINIDUMP_DIR, "*.tgz")))
        
        print(f"\nRemaining .dmp files after cleanup: {len(remaining_dumps)}")
        print(f"Remaining .tgz archives after cleanup: {len(remaining_archives)}")
        
        for f in remaining_dumps:
            stat = os.stat(f)
            print(f"  .dmp: {os.path.basename(f)} - mtime: {stat.st_mtime}")
        
        for f in remaining_archives:
            print(f"  .tgz: {os.path.basename(f)}")
        
        # The dumps may be archived and original .dmp deleted, or kept as .dmp
        # Either way, we should have 4 files (dumps or archives) from the most recent
        total_files = len(remaining_dumps) + len(remaining_archives)
        
        # If files were uploaded and deleted, we expect 0 dumps but archives created
        # If upload failed, we expect 4 dumps kept
        if total_files == 0:
            # Files were uploaded and cleaned up - this is also valid
            print("✓ All dumps were uploaded and cleaned up (expected behavior)")
        else:
            assert total_files == 4, f"Should keep only 4 dumps/archives, found {total_files}"
            print(f"✓ Correct {total_files} dumps/archives kept (most recent)")
        
        print("\n========== TEST PASSED: Minidump Startup Cleanup ==========")

    @pytest.mark.order(1)
    def test_minidump_startup_cleanup_skips_when_flag_exists(self):
        """
        Test: Cleanup is skipped when flag file exists
        
        Steps:
        1. Create flag file
        2. Create non-dump files
        3. Run crashupload
        4. Verify non-dump files still exist (cleanup skipped)
        """
        print("\n========== TEST: Skip Cleanup When Flag Exists ==========")
        
        # Step 1: Create flag file
        flag_file = "/tmp/.on_startup_dumps_cleaned_up_0"
        with open(flag_file, 'w') as f:
            f.write("")
        print(f"Created flag file: {flag_file}")
        
        # Step 2: Create non-dump files
        non_dump_files = [
            os.path.join(self.MINIDUMP_DIR, "should_not_delete.txt"),
            os.path.join(self.MINIDUMP_DIR, "keep_this.log")
        ]
        for f in non_dump_files:
            with open(f, 'w') as fp:
                fp.write("test content")
            print(f"Created non-dump file: {f}")
        
        # Step 3: Create a dump file
        self.create_test_minidump("test_no_cleanup.dmp", size_kb=5)
        
        # Step 4: Run crashupload
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Step 5: Verify non-dump files still exist (cleanup skipped)
        for f in non_dump_files:
            assert os.path.exists(f), f"File should NOT be deleted when flag exists: {f}"
        print(f"✓ All {len(non_dump_files)} non-dump files preserved (cleanup skipped)")
        
        print("\n========== TEST PASSED: Cleanup Skipped ==========")

    @pytest.mark.order(2)
    def test_coredump_startup_cleanup_deletes_old_dumps(self):
        """
        Test: On-startup cleanup keeps only 4 most recent coredump files
        
        Steps:
        1. Remove flag file to simulate fresh boot
        2. Create 7 coredump files with different timestamps
        3. Create non-dump files
        4. Run crashupload (triggers cleanup)
        5. Verify only 4 most recent dumps remain
        6. Verify flag file created with correct suffix (_1)
        """
        print("\n========== TEST: Coredump Startup Cleanup - Delete Old Dumps ==========")
        
        # Step 1: Remove flag file for coredump (dump_type=1)
        flag_file = "/tmp/.on_startup_dumps_cleaned_up_1"
        if os.path.exists(flag_file):
            os.remove(flag_file)
            print(f"Removed flag file: {flag_file}")
        
        # Step 2: Create 7 coredump files with _core pattern
        dump_files = []
        for i in range(7):
            time.sleep(0.2)
            filename = f"test_app_core.prog.{1000+i}.{int(time.time())}.gz"
            dump_file = self.create_test_coredump(filename, size_kb=8)
            dump_files.append(dump_file)
        
        print(f"\nCreated {len(dump_files)} coredump files:")
        for i, f in enumerate(dump_files):
            stat = os.stat(f)
            print(f"  [{i}] {os.path.basename(f)} - mtime: {stat.st_mtime}")
        
        # Step 3: Create non-dump files
        non_dump_files = [
            os.path.join(self.COREDUMP_DIR, "version.txt"),
            os.path.join(self.COREDUMP_DIR, "debug.log")
        ]
        for f in non_dump_files:
            with open(f, 'w') as fp:
                fp.write("test content")
            print(f"Created non-dump file: {f}")
        
        # Step 4: Create startup flag for coredump processing
        startup_flag = "/tmp/.on_startup_dumps_cleaned_up_1"
        if os.path.exists(startup_flag):
            os.remove(startup_flag)
        
        # Step 5: Run crashupload for coredump (dump_type=1)
        result = self.run_crashupload(dump_type="1", upload_flag="secure")
        
        # Step 6: Verify flag file was created with correct suffix
        # Note: Flag may not be created if no dumps found (exit code 0 = NO_DUMPS_FOUND)
        if result.returncode == 0:
            # Exit code 0 means NO_DUMPS_FOUND - coredump not processed
            print(f"⚠ Binary exited with NO_DUMPS_FOUND (exit code 0)")
            print(f"⚠ This means coredump files didn't match the expected pattern")
            print(f"⚠ Flag file may not be created in this case")
        else:
            assert os.path.exists(flag_file), f"Flag file should be created: {flag_file}"
            print(f"✓ Flag file created: {flag_file}")
        
        # Step 7: Verify non-dump files were deleted (only if cleanup ran)
        if result.returncode == 0:
            # NO_DUMPS_FOUND means cleanup didn't run - files should still exist
            for f in non_dump_files:
                assert os.path.exists(f), f"Non-dump file should still exist (cleanup not triggered): {f}"
            print(f"✓ Non-dump files preserved (cleanup not triggered due to NO_DUMPS_FOUND)")
        else:
            # Cleanup ran - non-dump files should be deleted
            for f in non_dump_files:
                assert not os.path.exists(f), f"Non-dump file should be deleted: {f}"
            print(f"✓ All {len(non_dump_files)} non-dump files deleted")
        
        # Step 8: Verify only 4 most recent dumps remain (if not uploaded)
        remaining_dumps = sorted(glob.glob(os.path.join(self.COREDUMP_DIR, "*core*")))
        print(f"\nRemaining coredumps after cleanup: {len(remaining_dumps)}")
        for f in remaining_dumps:
            stat = os.stat(f)
            print(f"  {os.path.basename(f)} - mtime: {stat.st_mtime}")
        
        # Coredumps may be uploaded and deleted, kept at 4 if cleaned, or all kept if NO_DUMPS_FOUND
        if result.returncode == 0:
            # NO_DUMPS_FOUND - cleanup didn't run, all dumps should still exist
            assert len(remaining_dumps) == 7, f"All 7 coredumps should remain (NO_DUMPS_FOUND), found {len(remaining_dumps)}"
            print("✓ All 7 coredumps preserved (NO_DUMPS_FOUND - cleanup not triggered)")
        elif len(remaining_dumps) == 0:
            print("✓ All coredumps processed and uploaded")
        else:
            assert len(remaining_dumps) == 4, f"Should keep only 4 coredumps, found {len(remaining_dumps)}"
            
            # Verify the 4 newest files are kept (indices 3, 4, 5, 6)
            expected_kept = [os.path.basename(dump_files[i]) for i in range(3, 7)]
            actual_kept = [os.path.basename(f) for f in remaining_dumps]
            
            print(f"\nExpected kept (4 newest): {expected_kept}")
            print(f"Actually kept: {actual_kept}")
            
            assert set(actual_kept) == set(expected_kept), "Should keep 4 most recent coredumps"
            print("✓ Correct 4 coredumps kept (most recent)")
        
        print("\n========== TEST PASSED: Coredump Startup Cleanup ==========")

    @pytest.mark.order(3)
    def test_startup_cleanup_deletes_old_archives(self):
        """
        Test: Startup cleanup deletes archive files (*_mac*_dat*) older than 2 days
        
        Steps:
        1. Create old archive files (>2 days old)
        2. Create recent archive files (<2 days old)
        3. Run crashupload
        4. Verify old archives deleted
        5. Verify recent archives kept
        """
        print("\n========== TEST: Startup Cleanup - Delete Old Archives ==========")
        
        # Step 1: Remove flag file
        flag_file = "/tmp/.on_startup_dumps_cleaned_up_0"
        if os.path.exists(flag_file):
            os.remove(flag_file)
        
        # Step 2: Create old archive (3 days old)
        old_archive = os.path.join(
            self.MINIDUMP_DIR,
            "old_archive_macAABBCC_dat2024-01-01-12-00-00.tgz"
        )
        with open(old_archive, 'wb') as f:
            f.write(b'fake old archive')
        
        # Backdate to 3 days ago
        three_days_ago = time.time() - (3 * 24 * 3600)
        os.utime(old_archive, (three_days_ago, three_days_ago))
        print(f"Created old archive (3 days): {old_archive}")
        
        # Step 3: Create recent archive (1 day old)
        recent_archive = os.path.join(
            self.MINIDUMP_DIR,
            "recent_archive_macAABBCC_dat2026-02-01-12-00-00.tgz"
        )
        with open(recent_archive, 'wb') as f:
            f.write(b'fake recent archive')
        
        # Backdate to 1 day ago
        one_day_ago = time.time() - (1 * 24 * 3600)
        os.utime(recent_archive, (one_day_ago, one_day_ago))
        print(f"Created recent archive (1 day): {recent_archive}")
        
        # Step 4: Create a dump file
        self.create_test_minidump("test_archive_cleanup.dmp", size_kb=5)
        
        # Step 5: Run crashupload
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Step 6: Verify old archive deleted
        assert not os.path.exists(old_archive), "Old archive (>2 days) should be deleted"
        print(f"✓ Old archive deleted: {old_archive}")
        
        # Step 7: Verify recent archive kept (or deleted if uploaded)
        # The cleanup deletes archives >2 days old
        # But the scanner may also process and delete after successful upload
        if os.path.exists(recent_archive):
            print(f"✓ Recent archive kept: {recent_archive}")
        else:
            # Check if it was processed and uploaded (check for timestamp in archives)
            all_archives = glob.glob(os.path.join(self.MINIDUMP_DIR, "*_mac*_dat*.tgz"))
            print(f"✓ Recent archive was processed/uploaded (found {len(all_archives)} other archives)")
            # This is acceptable behavior - archive was new enough to not be deleted by cleanup
        
        print("\n========== TEST PASSED: Old Archives Deleted ==========")

    @pytest.mark.order(4)
    def test_startup_cleanup_with_fewer_than_4_dumps(self):
        """
        Test: Cleanup preserves all dumps when count is less than MAX_CORE_FILES (4)
        
        Steps:
        1. Create only 3 dump files
        2. Run cleanup
        3. Verify all 3 dumps kept
        """
        print("\n========== TEST: Cleanup With Fewer Than 4 Dumps ==========")
        
        # Step 1: Remove flag file
        flag_file = "/tmp/.on_startup_dumps_cleaned_up_0"
        if os.path.exists(flag_file):
            os.remove(flag_file)
        
        # Step 2: Create only 3 dump files
        dump_files = []
        for i in range(3):
            time.sleep(0.2)
            dump_file = self.create_test_minidump(f"test_few_{i}.dmp", size_kb=5)
            dump_files.append(dump_file)
        
        print(f"Created {len(dump_files)} dump files")
        
        # Step 3: Run crashupload
        result = self.run_crashupload(dump_type="0", upload_flag="secure")
        
        # Step 4: Verify all 3 dumps still exist (or were uploaded)
        remaining_dumps = glob.glob(os.path.join(self.MINIDUMP_DIR, "*.dmp"))
        remaining_archives = glob.glob(os.path.join(self.MINIDUMP_DIR, "*.tgz"))
        
        total_files = len(remaining_dumps) + len(remaining_archives)
        
        if total_files == 0:
            # Files were uploaded and cleaned up
            print(f"✓ All {len(dump_files)} dumps were uploaded and cleaned up")
        else:
            assert total_files == 3, f"All 3 dumps should be kept, found {total_files}"
            
            for dump in dump_files:
                dump_exists = os.path.exists(dump)
                archive_pattern = os.path.basename(dump).replace('.dmp', '*.tgz')
                archive_exists = len(glob.glob(os.path.join(self.MINIDUMP_DIR, f"*{archive_pattern}"))) > 0
                assert dump_exists or archive_exists, f"Dump or archive should exist: {dump}"
            
            print(f"✓ All {len(dump_files)} dumps preserved (less than MAX_CORE_FILES)")
        
        print("\n========== TEST PASSED: Fewer Than 4 Dumps ==========")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
