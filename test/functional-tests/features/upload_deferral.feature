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

# TC-035 / TC-036 / TC-037
Feature: Upload deferral based on system uptime

  defer_upload_if_needed() in prerequisites.c reads UPTIME_FILE.
  In an L2_TEST build UPTIME_FILE is /opt/uptime (controllable value)
  instead of /proc/uptime.  When uptime < 480 s the function sleeps for
  (480 - uptime) seconds, then re-checks is_box_rebooting().

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # TC-035
  Scenario: Upload is deferred when uptime is below the 480-second threshold
    Given /opt/uptime contains 479
    And /tmp/set_crash_reboot_flag exists so the binary exits after sleeping
    And a .dmp file is present in the secure minidump path
    When the binary is invoked in secure minidump mode
    Then defer_upload_if_needed sleeps for approximately 1 second
    And after waking is_box_rebooting returns true
    And the binary exits with return code 0
    And total elapsed wall-clock time is at least 1 second

  # TC-036
  Scenario: No deferral occurs when uptime is at or above the 480-second threshold
    Given /opt/uptime contains 600
    And the dump directory is empty (NO_DUMPS_FOUND path)
    When the binary is invoked
    Then defer_upload_if_needed returns immediately without sleeping
    And the binary completes in under 5 seconds
    And the binary exits with return code 0

  # TC-037
  Scenario: Upload deferral respects the exact 480-second boundary
    Given /opt/uptime contains 480
    And the dump directory is empty
    When the binary is invoked
    Then defer_upload_if_needed calculates sleep_time as 0 and does not sleep
    And the binary exits with return code 0
