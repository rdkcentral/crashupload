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

# TC-061 / TC-062 / TC-063
Feature: Archive filename structure, metadata fields, and truncation

  main.c constructs new_dump_name for each dump file:
    {sha1}_mac{MAC}_dat{ts}_box{boxtype}_mod{model}_{dumpfile}
  If strlen(new_dump_name) >= 135, two truncation passes are applied.
  For mpeos-main coredumps the _dat field uses the file's mtime rather
  than the current wall-clock crashts.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And /tmp/set_crash_reboot_flag is set so archiving runs but upload does not

  # TC-061
  Scenario: Archive filename contains all required metadata fields
    Given a plain "tc061proc_12345.dmp" file is placed in the secure minidump path
    When the binary runs and produces a .tgz archive
    Then the archive filename (without .tgz) contains "_mac"
    And it contains "_dat"
    And it contains "_box"
    And it contains "_mod"
    And it contains the original dump basename as a suffix component

  # TC-062
  Scenario: Archive filename is truncated to under 135 characters when too long
    Given a dump file whose process name is 80 characters long is placed in the scan directory
    When the binary runs and produces a .tgz archive
    Then the initial new_dump_name exceeds 135 characters
    And pass 1 (strip sha1 prefix before first underscore) reduces the length
    And pass 2 (trim process name to 20 chars) reduces the length further
    And the final .tgz base name is strictly less than 135 characters

  # TC-063
  Scenario: mpeos-main coredump uses file mtime (not current time) for the _dat field
    Given a file named "mpeos-main_core.prog.gz" with its mtime set to 1 hour ago is present
    When the binary runs and produces a .core.tgz archive
    Then main.c takes the strstr "mpeos-main" branch and uses dumps[i].mtime_date
    And the archive filename _dat field matches the formatted mtime of the planted file
    And the _dat field does NOT match the current wall-clock time
