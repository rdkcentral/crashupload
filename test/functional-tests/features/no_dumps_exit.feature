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

Feature: Graceful exit when no dump files are found

  When prerequisites_wait() finds no files matching the dump pattern it
  returns NO_DUMPS_FOUND(5).  main.c treats this as a non-success and jumps
  to the cleanup label, exiting with return code 0 in all cases.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # NODMP-01
  Scenario: Empty minidump directory exits with 0
    Given /opt/secure/minidumps exists but contains no .dmp files
    When the binary is invoked in secure minidump mode
    Then directory_has_pattern returns 0 (pattern not found)
    And prerequisites_wait returns NO_DUMPS_FOUND
    And the binary exits with return code 0

  # NODMP-02
  Scenario: Empty corefiles directory exits with 0
    Given /opt/secure/corefiles exists but contains no _core files
    When the binary is invoked in secure coredump mode
    Then directory_has_pattern returns 0 (pattern not found)
    And prerequisites_wait returns NO_DUMPS_FOUND
    And the binary exits with return code 0

  # NODMP-03
  Scenario: File with wrong extension is not matched and binary exits with 0
    Given a file with an unrecognised extension (e.g. ".log") is in the scan directory
    When the binary is invoked in minidump mode
    Then directory_has_pattern returns 0 because ".dmp" is absent
    And prerequisites_wait returns NO_DUMPS_FOUND
    And the binary exits with return code 0

  # NODMP-04
  Scenario: Non-existent dump directory exits with 0
    Given the scan directory does not exist on the filesystem
    When the binary is invoked with the absent directory as the dump path
    Then opendir() fails and directory_has_pattern returns -1
    And prerequisites_wait returns NO_DUMPS_FOUND
    And the binary exits with return code 0
