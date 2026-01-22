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

Feature: Multiple instance prevention via lock mechanism

  Scenario: Prevent concurrent minidump upload instances
    Given the crashupload binary exists
    And a minidump directory with dummy dump file exists
    When an exclusive lock is held on /tmp/.uploadMinidumps
    And a second crashupload instance is launched with minidump type
    Then the second instance should exit gracefully with code 0
    And the output should contain "already working" or "Failed to acquire lock" message
    And the lock file should remain intact

  Scenario: Prevent concurrent coredump upload instances
    Given the crashupload binary exists
    And a coredump directory exists
    When an exclusive lock is held on /tmp/.uploadCoredumps
    And a second crashupload instance is launched with coredump type
    Then the second instance should exit gracefully with code 0
    And the output should contain lock detection message
    And separate lock files are used for minidump and coredump
