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

# REBOOT-01 / LOG-01
Feature: Reboot-flag skip behaviour and log output

  is_box_rebooting() in system_utils.c checks for /tmp/set_crash_reboot_flag.
  When present after the archive loop, main.c sets ret=0 and jumps to cleanup
  without entering the upload loop.  The binary always emits at least one line
  to stdout from logger_init / logger_exit regardless of dump presence.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # REBOOT-01
  Scenario: Reboot flag present with a valid dump — upload is skipped and binary exits 0
    Given /tmp/set_crash_reboot_flag exists
    And a valid .dmp file is present in /opt/secure/minidumps
    When the binary is invoked in secure minidump mode
    Then prerequisites_wait succeeds (dump found)
    And is_box_rebooting returns true
    And the upload loop is skipped
    And the binary exits with return code 0

  # LOG-01
  Scenario: Binary always produces stdout log output regardless of dump presence
    Given no dump files are present in the scan directory
    When the binary is invoked
    Then at least one log line is emitted to stdout
    And the binary exits with return code 0
