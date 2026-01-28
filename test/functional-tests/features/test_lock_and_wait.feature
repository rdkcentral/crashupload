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

Feature: Wait for lock release with 'wait_for_lock' argument

  Scenario: Wait for minidump lock to be released
    Given the crashupload binary exists
    And the minidump directory is empty with no dump files
    When an exclusive lock is held on /tmp/.uploadMinidumps for 3 seconds
    And crashupload is launched with "minidump_dir 0 wait_for_lock" arguments
    Then the binary should log "waiting for lock" message
    And the binary should wait approximately 3 seconds for lock release
    And after lock is released the binary should proceed with execution
    And the binary should exit gracefully with code 0
    And the output should indicate no dumps to process

  Scenario: Wait for coredump lock to be released
    Given the crashupload binary exists
    And the coredump directory is empty with no dump files
    When an exclusive lock is held on /tmp/.uploadCoredumps for 3 seconds
    And crashupload is launched with "coredump_dir 1 wait_for_lock" arguments
    Then the binary should log "waiting for lock" message
    And the binary should wait approximately 3 seconds for lock release
    And after lock is released the binary should proceed with execution
    And the binary should exit gracefully with code 0
    And the output should indicate no dumps to process
