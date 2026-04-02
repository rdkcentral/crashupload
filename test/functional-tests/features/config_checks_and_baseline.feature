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

# TC-019 / TC-020 / TC-021 / TC-023 / TC-024 / TC-025 / TC-026 / TC-028
Feature: Dump detection and platform baseline metadata

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set so the binary skips the upload loop

  # TC-019
  Scenario: Non-secure coredump detected at normal coredump path
    Given a coredump file with "_core" in its name is placed in /var/lib/systemd/coredump
    When the binary is invoked with argv[2]="1" (coredump mode)
    Then prerequisites_wait succeeds
    And the binary exits with return code 0

  # TC-020
  Scenario: Secure minidump detected at secure minidump path
    Given a .dmp file is placed in /opt/secure/minidumps
    When the binary is invoked with argv[2]="0" and argv[3]="secure"
    Then prerequisites_wait succeeds
    And the binary exits with return code 0

  # TC-021
  Scenario: Secure coredump detected at secure corefiles path
    Given a coredump file with "_core" in its name is placed in /opt/secure/corefiles
    When the binary is invoked with argv[2]="1" and argv[3]="secure"
    Then prerequisites_wait succeeds
    And the binary exits with return code 0

  # TC-023
  Scenario: MAC address is normalised to uppercase hex in the archive filename
    Given /tmp/.macAddress contains "aa:bb:cc:dd:ee:ff"
    And a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename contains "_macAABBCCDDEEFF_"

  # TC-024
  Scenario: Missing MAC address file defaults to 000000000000 in archive filename
    Given /tmp/.macAddress does not exist or is empty
    And a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename contains "_mac000000000000_"

  # TC-025
  Scenario: Device model number is present in the archive filename
    Given the device model API returns a non-empty model string
    And a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename contains "_mod<model>_" with the actual model value

  # TC-026
  Scenario: Model defaults to UNKNOWN when device API is unavailable
    Given the device model API is unavailable or returns empty
    And a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename contains "_modUNKNOWN_"

  # TC-028
  Scenario: /version.txt SHA1 is encoded as the leading field of the archive filename
    Given /version.txt exists with known content
    And a .dmp file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename starts with the SHA1 hex digest of /version.txt
