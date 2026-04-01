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

# TC-004 / TC-005 / TC-017 / TC-018
Feature: Unsupported device types exit cleanly

  For DEVICE_TYPE broadband and extender, config_manager.c sets
  working_dir_path = "/minidumps".  If /minidumps does not exist the binary
  fails chdir() and exits 0.  When dumps are present but /minidumps is absent
  the same path applies.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # TC-004
  Scenario: Broadband device type with no dump files exits with 0
    Given /etc/device.properties contains DEVICE_TYPE=broadband
    And no .dmp files are present in /var/lib/systemd/coredump
    When the binary is invoked
    Then NO_DUMPS_FOUND is returned
    And the binary exits with return code 0

  # TC-005
  Scenario: Extender device type with no dump files exits with 0
    Given /etc/device.properties contains DEVICE_TYPE=extender
    And no .dmp files are present in the coredump scan path
    When the binary is invoked
    Then NO_DUMPS_FOUND is returned
    And the binary exits with return code 0

  # TC-017
  Scenario: Broadband device type with a dump present exits with 0 (chdir failure)
    Given /etc/device.properties contains DEVICE_TYPE=broadband
    And a .dmp file is present in the scan path
    And /tmp/set_crash_reboot_flag is set as safety net
    When the binary is invoked
    Then chdir("/minidumps") fails because the directory is absent
    And the binary goes to the cleanup label
    And the binary exits with return code 0

  # TC-018
  Scenario: Extender device type with a dump present exits with 0 (chdir failure)
    Given /etc/device.properties contains DEVICE_TYPE=extender
    And a .dmp file is present in the scan path
    And /tmp/set_crash_reboot_flag is set as safety net
    When the binary is invoked
    Then chdir("/minidumps") fails because the directory is absent
    And the binary goes to the cleanup label
    And the binary exits with return code 0
