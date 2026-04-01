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

# TC-067
Feature: Broadband device type does not produce a .tgz for a minidump

  For DEVICE_TYPE_BROADBAND, archive_create_smart() has no create_tarball()
  branch.  tar_status stays -1, archive_create_smart returns -1, and main.c
  continues to the next dump.  After all dumps, is_box_rebooting() exits cleanly.

  Background:
    Given the crashupload binary exists

  # TC-067
  Scenario: Broadband device type processes a minidump without creating an archive
    Given /etc/device.properties contains DEVICE_TYPE=broadband
    And /minidumps directory exists
    And a .dmp file named "tc067proc_99999.dmp" is placed in /minidumps
    And /tmp/set_crash_reboot_flag is set
    When the binary is invoked without "secure" argument
    Then config selects /minidumps as the working directory
    And archive_create_smart enters the mediaclient guard and returns -1 for broadband
    And no .tgz file is created in /minidumps
    And the binary exits with return code 0
