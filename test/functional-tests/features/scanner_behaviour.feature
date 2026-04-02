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

# TC-057 / TC-058 / TC-059 / TC-064
Feature: Dump filename sanitisation and crash component parsing

  process_file_entry() calls sanitize_filename_preserve_container() to clean
  the basename and then processCrashTelemetryInfo() to extract the process
  name, look up the log-mapper, and write to /tmp/minidump_log_files.txt.
  The content of that file after the binary exits is the observable for all
  four tests in this feature.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set

  # TC-057
  Scenario: Container delimiter <#=#> is preserved through sanitisation
    Given /etc/breakpad-logmapper.conf maps "cleanapp-cont" to a log file
    And a dump file named "cleanapp<#=#>cont_123.dmp" is placed in the scan directory
    When the binary runs in minidump mode
    Then sanitize_filename_preserve_container preserves the <#=#> delimiter
    And extract_pname(normalised) produces "cleanapp-cont"
    And lookup_log_files_for_proc finds a logmapper match
    And /tmp/minidump_log_files.txt contains the expected log path

  # TC-058
  Scenario: Forbidden characters are dropped from the dump filename
    Given /etc/breakpad-logmapper.conf maps "badchars" to a log file
    And a dump file named "bad!chars_proc.dmp" is placed in the scan directory
    When the binary runs in minidump mode
    Then sanitize_filename_preserve_container drops "!" producing "badchars_proc.dmp"
    And the file is renamed on disk
    And extract_pname produces "badchars"
    And /tmp/minidump_log_files.txt contains the expected log path

  # TC-059
  Scenario: Container name is preserved while forbidden chars are dropped from the suffix
    Given /etc/breakpad-logmapper.conf maps "proc" to a log file
    And a dump file named "proc<#=#>con!tain_ts.dmp" is placed in the scan directory
    When the binary runs in minidump mode
    Then sanitize_filename_preserve_container produces "proc<#=#>contain_ts.dmp"
    And the file is renamed on disk
    And /tmp/minidump_log_files.txt contains the expected log path for "proc"

  # TC-064
  Scenario: Dump filename components (process name, timestamp, pid) are parsed correctly
    Given /etc/breakpad-logmapper.conf maps the expected process name to a log file
    And a standard "procname_pid.dmp" file is placed in the scan directory
    When the binary runs in minidump mode
    Then extract_pname correctly identifies the process name before the underscore
    And /tmp/minidump_log_files.txt contains the log path associated with that process
