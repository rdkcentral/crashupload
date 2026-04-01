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

# TC-065 / TC-066 / TC-075 / TC-079 / TC-078 / TC-080
Feature: Archive creation and log-file bundling

  archive_create_smart() produces a .tgz containing the renamed dump, the
  /version.txt, the core log, and any mapped log files found by the logmapper.
  The binary exits via is_box_rebooting when /tmp/set_crash_reboot_flag is set
  so the upload step is skipped and the .tgz is the only observable.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set

  # TC-065
  Scenario: Archive is produced for a single dump file
    Given a .dmp file is placed in the secure minidump path
    When the binary runs in secure minidump mode
    Then at least one .tgz file appears in the secure minidump path
    And the binary exits with return code 0

  # TC-066
  Scenario: Archive contains the required baseline members
    Given a .dmp file is placed in the secure minidump path
    And /version.txt exists with known content
    And core_log.txt exists in /opt/logs
    When the binary runs and produces a .tgz archive
    Then the archive contains a member whose name includes the original dump basename
    And the archive contains a member named "version.txt"
    And the archive contains a member named "core_log.txt"

  # TC-079
  Scenario: crashed_url.txt is included in the archive
    Given a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive contains a member named "crashed_url.txt"

  # TC-075
  Scenario: Log file mapped for the crashed process is bundled into the archive
    Given /etc/breakpad-logmapper.conf maps "tc075proc" to "tc075test.log"
    And /some/path/tc075test.log exists with content
    And a dump file named "tc075proc_99999.dmp" is placed in the scan directory
    When the binary runs
    Then the .tgz archive contains a member whose name includes "tc075test.log"
    And the binary exits with return code 0

  # TC-080
  Scenario: All comma-separated log files appear in the archive
    Given /etc/breakpad-logmapper.conf maps "tc080proc" to "tc080a.log,tc080b.log"
    And both /some/path/tc080a.log and /some/path/tc080b.log exist
    And a dump file named "tc080proc_99999.dmp" is placed in the scan directory
    When the binary runs
    Then the .tgz archive contains a member including "tc080a.log"
    And the .tgz archive contains a member including "tc080b.log"

  # TC-078
  Scenario: Missing mapped log file is handled gracefully — no crash
    Given /etc/breakpad-logmapper.conf maps "tc078proc" to "tc078missing.log"
    And tc078missing.log does NOT exist on the filesystem
    And a dump file named "tc078proc_99999.dmp" is placed in the scan directory
    When the binary runs
    Then archive_create_smart skips the missing log without crashing
    And at least one .tgz file is still produced
    And the binary exits with return code 0
