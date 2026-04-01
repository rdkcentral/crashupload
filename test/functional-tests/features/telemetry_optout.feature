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

# TC-038 / TC-039 / TC-040
Feature: Telemetry opt-out suppresses dump upload for mediaclient devices

  get_opt_out_status() in config_manager.c requires BOTH conditions true:
    1. RFC property "rfcTelemetryOptout" returns "true".
    2. /opt/tmtryoptout file contains the string "true".
  When opt_out is set for DEVICE_TYPE_MEDIACLIENT, prerequisites_wait()
  calls remove_pending_dumps() then returns non-SUCCESS → exit(0).
  Broadband and extender device types bypass the opt-out check entirely.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And a .dmp file is present in /opt/secure/minidumps

  # TC-038
  Scenario: RFC opt-out flag triggers dump suppression on mediaclient
    Given DEVICE_TYPE is set to mediaclient
    And the RFC "rfcTelemetryOptout" property returns "true"
    And /opt/tmtryoptout contains "true"
    When the binary is invoked in secure minidump mode
    Then get_opt_out_status sets opt_out=true
    And prerequisites_wait deletes pending dumps and returns non-SUCCESS
    And the binary exits with return code 0

  # TC-039
  Scenario: Opt-out file absent means uploads are not blocked
    Given DEVICE_TYPE is set to mediaclient
    And /opt/tmtryoptout does not exist
    When the binary is invoked in secure minidump mode
    Then opt_out remains false
    And the binary proceeds past prerequisites_wait
    And the binary exits with return code 0

  # TC-040
  Scenario: Opt-out check is bypassed for non-mediaclient device types
    Given DEVICE_TYPE is set to a non-mediaclient value (e.g. broadband)
    And /opt/tmtryoptout contains "true"
    When the binary is invoked
    Then the opt-out code path is never evaluated for broadband/extender
    And the binary exits with return code 0
