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

Feature: Failure return codes for early-exit paths

  system_initialize() returns -1 when it cannot create the core log file
  (parent directory missing or unwritable) causing main.c to exit(1).
  prerequisites_wait() returns NO_DUMPS_FOUND(5) when no dump files exist
  in the scanned directory, causing main.c to goto cleanup and exit(0).

  # FAIL-01 — system_initialize() failure
  Scenario: system_initialize fails when log directory is unwritable
    Given the crashupload binary exists
    And the core log directory /opt/logs does not exist or is not writable
    When the binary is invoked with valid arguments
    Then system_initialize returns failure
    And the binary exits with return code 1

  # FAIL-02 — prerequisites_wait NO_DUMPS_FOUND
  Scenario: prerequisites_wait returns NO_DUMPS_FOUND when dump directory is empty
    Given the crashupload binary exists
    And /opt/logs exists and core_log.txt is present
    And the minidump directory is empty
    When the binary is invoked with valid arguments
    Then prerequisites_wait returns NO_DUMPS_FOUND
    And the binary exits with return code 0
