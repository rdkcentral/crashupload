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

# TC-006 / TC-007 / TC-009
Feature: Config path selection and dump type routing

  config_init_load() resolves the scan path from argv[3] (secure/non-secure)
  and the dump type from argv[2] (0=minidump, 1=coredump).  Each combination
  maps to a distinct filesystem path that the scanner will inspect.

  # TC-006
  Scenario: Secure mode selects /opt/secure/minidumps for minidump scanning
    Given the crashupload binary exists
    And a dump file is placed only in the non-secure minidump path
    When the binary is invoked with argv[3]="secure" and argv[2]="0"
    Then the binary scans /opt/secure/minidumps
    And NO_DUMPS_FOUND is returned because the secure path is empty
    And the binary exits with return code 0

  Scenario: Secure mode selects /opt/secure/corefiles for coredump scanning
    Given the crashupload binary exists
    And a coredump file is placed only in the non-secure coredump path
    When the binary is invoked with argv[3]="secure" and argv[2]="1"
    Then the binary scans /opt/secure/corefiles
    And NO_DUMPS_FOUND is returned because the secure coredump path is empty
    And the binary exits with return code 0

  # TC-007
  Scenario: Normal mode selects /opt/minidumps for minidump scanning
    Given the crashupload binary exists
    And a dump file is placed only in the secure minidump path
    When the binary is invoked without argv[3] and argv[2]="0"
    Then the binary scans /opt/minidumps
    And NO_DUMPS_FOUND is returned because the normal path is empty
    And the binary exits with return code 0

  # TC-009
  Scenario: Coredump mode ignores .dmp files
    Given the crashupload binary exists
    And a .dmp file is present in the scan directory
    When the binary is invoked with argv[2]="1" (coredump mode)
    Then the scanner looks only for the "_core" filename pattern
    And the .dmp file is not matched
    And the binary exits with return code 0

  Scenario: Minidump mode ignores coredump files
    Given the crashupload binary exists
    And a _core file is present in the scan directory
    When the binary is invoked with argv[2]="0" (minidump mode)
    Then the scanner looks only for the ".dmp" filename pattern
    And the _core file is not matched
    And the binary exits with return code 0
