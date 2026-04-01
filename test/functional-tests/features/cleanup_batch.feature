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

# TC-041 / TC-042 / TC-043 / TC-044 / TC-045 / TC-046 / TC-047
Feature: On-startup dump directory cleanup batch

  cleanup_batch() is called twice per invocation: once before scan (startup
  pass) and once at the cleanup label.  On the startup pass it deletes
  non-dump artefacts, removes stale archives, enforces MAX_CORE_FILES=4, and
  creates the ON_STARTUP_CLEANED_UP_BASE flag.  Subsequent calls skip the
  startup pass once the flag exists.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set so the binary exits without uploading

  # TC-041
  Scenario: Startup cleanup removes non-dump artefacts from the dump directory
    Given a non-dump marker file (e.g. "marker.txt") is placed in the dump directory
    And a .dmp file is also present (so prerequisites_wait passes)
    When the binary runs
    Then delete_files_not_matching_pattern("*.dmp*") is called
    And the marker file is deleted
    And the ON_STARTUP_CLEANED_UP_BASE_0 flag is created

  # TC-042
  Scenario: Stale archive files older than 2 days are always deleted
    Given a _mac*_dat* archive file with mtime more than 2 days ago is present
    And a .dmp file is also present
    When the binary runs
    Then delete_files_matching_pattern_older_than("*_mac*_dat*", 2) is called unconditionally
    And the stale archive file is deleted

  # TC-043
  Scenario: First-run flag file is created after startup cleanup
    Given the ON_STARTUP_CLEANED_UP_BASE_0 flag does not exist
    And a .dmp file is present
    When the binary runs in minidump mode (dump_flag == "0")
    Then cleanup_batch creates ON_STARTUP_CLEANED_UP_BASE_0
    And the flag file exists after the binary exits

  # TC-044
  Scenario: Subsequent runs skip the startup cleanup pass
    Given the ON_STARTUP_CLEANED_UP_BASE_0 flag already exists
    And a non-dump marker file and a .dmp file are both present
    When the binary runs
    Then need_run_startup is 0 so delete_files_not_matching_pattern is NOT called
    And the non-dump marker file survives because startup cleanup was skipped

  # TC-045
  Scenario: MAX_CORE_FILES=4 is enforced — oldest dump removed when 5 are present
    Given exactly 5 .dmp files are present and ON_STARTUP_CLEANED_UP_BASE_0 does not exist
    When the binary runs
    Then delete_all_but_most_recent(4) removes the single oldest file
    And at most 4 .tgz archives are produced
    And the ON_STARTUP_CLEANED_UP_BASE_0 flag is created as a proxy that startup cleanup ran

  # TC-046
  Scenario: Empty dump directory is handled gracefully
    Given the dump directory is empty
    When the binary runs
    Then cleanup_batch detects an empty directory and returns immediately
    And the binary exits with return code 0

  # TC-047
  Scenario: /opt/.upload_on_startup flag is removed during coredump mode run
    Given /opt/.upload_on_startup exists
    And a .dmp file is present for prerequisites_wait to pass
    When the binary runs in coredump mode (dump_flag == "1")
    Then cleanup_batch calls unlink("/opt/.upload_on_startup") on the first call
    And /opt/.upload_on_startup does not exist after the binary exits
