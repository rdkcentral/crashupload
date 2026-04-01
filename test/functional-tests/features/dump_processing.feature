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

# TC-060 / TC-071
Feature: Dump processing — pre-existing archives and zero-size dumps

  main.c inspects each file returned by scanner_find_dumps():
    - files ending in ".tgz" are passed through as-is (archive_create_smart skipped)
    - zero-size .dmp files are stable at size 0 and are passed to archive_create_smart,
      which handles them without crashing

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set

  # TC-060
  Scenario: Existing .tgz archive files are not re-archived
    Given a file ending in ".tgz" is present in the secure minidump directory
    When the binary runs in secure minidump mode
    Then is_dump_file returns 3 for the .tgz file
    And the main.c dump loop sets archive[i].archive_name = path and continues
    And archive_create_smart is never called for the .tgz file
    And no double-archived .tgz.tgz file is produced
    And the binary exits with return code 0

  # TC-071
  Scenario: Zero-size dump file is handled gracefully without crashing
    Given a zero-byte .dmp file is present in the secure minidump directory
    When the binary runs in secure minidump mode
    Then wait_for_file_size_stable returns success (size 0 is stable)
    And archive_create_smart receives the zero-size dump without panic
    And the binary exits with return code 0
