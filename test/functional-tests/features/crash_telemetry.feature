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

# TC-072 / TC-073
Feature: Crash telemetry code path coverage

  processCrashTelemetryInfo() is called for each dump.  For a standard dump
  it calls get_crashed_log_file() which runs extract_pname() and then looks
  up the logmapper.  For a container dump (filename contains <#=#>) it
  derives a normalised name and uses that for the lookup instead.
  A logmapper hit triggers add_crashed_process_log_file() which copies the
  source log so archive_create_smart() can include it in the .tgz.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set

  # TC-072
  Scenario: Process crash telemetry path is exercised and log file is bundled
    Given /etc/breakpad-logmapper.conf maps "tc072proc" to a source log file that exists
    And a dump file named "tc072proc_99999.dmp" is placed in the secure minidump path
    When the binary runs in secure minidump mode
    Then processCrashTelemetryInfo calls get_crashed_log_file for the standard filename
    And extract_pname produces "tc072proc"
    And lookup_log_files_for_proc finds a logmapper hit
    And the .tgz archive contains the mapped log file's basename
    And the binary exits with return code 0

  # TC-073
  Scenario: Container crash telemetry path is exercised and log file is bundled
    Given /etc/breakpad-logmapper.conf maps "tc073proc" to a source log file that exists
    And a dump file named "tc073proc<#=#>container_123.dmp" is placed in the secure minidump path
    When the binary runs in secure minidump mode
    Then processCrashTelemetryInfo detects the <#=#> delimiter and normalises to "tc073proc-container_123.dmp"
    And get_crashed_log_file is called with the normalised filename
    And extract_pname produces "tc073proc-container"
    And lookup_log_files_for_proc finds a match for "tc073proc"
    And the .tgz archive contains the mapped log file's basename
    And the binary exits with return code 0
