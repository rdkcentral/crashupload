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

# TC-048 / TC-049 / TC-050 / TC-051 / TC-052 / TC-053 / TC-055
Feature: Rate limiting — allow and block upload paths

  ratelimit_check_unified() enforces two independent limits:
    1. Deny-window check (is_recovery_time_reached): reads /tmp/.deny_dump_uploads_till.
    2. Per-minidump upload-count check (is_upload_limit_reached): reads
       /tmp/.minidump_upload_timestamps (minidump path only).
  When either check returns BLOCK, remove_pending_dumps() cleans the working dir.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist
    And a .dmp file is present so prerequisites_wait succeeds
    And /tmp/set_crash_reboot_flag is set to prevent actual network uploads

  # TC-048
  Scenario: Upload count at or below limit (10 entries) allows upload to proceed
    Given /tmp/.minidump_upload_timestamps contains exactly 10 lines
    And /tmp/.deny_dump_uploads_till does not exist
    When the binary runs in minidump mode
    Then is_upload_limit_reached returns ALLOW_UPLOAD
    And ratelimit_check_unified returns ALLOW_UPLOAD
    And /tmp/.deny_dump_uploads_till is NOT created
    And the binary exits with return code 0

  # TC-049
  Scenario: Upload count exceeding 10 within the window triggers rate-limit block
    Given /tmp/.minidump_upload_timestamps has 11 lines where the first timestamp is within 600 s
    When the binary runs in minidump mode
    Then is_upload_limit_reached returns STOP_UPLOAD
    And ratelimit_check_unified returns RATELIMIT_BLOCK
    And remove_pending_dumps deletes all .dmp and .tgz files from the working directory
    And /tmp/.deny_dump_uploads_till is created with a future timestamp
    And the binary exits with return code 0

  # TC-050
  Scenario: Rate-limit upload-count check is skipped for coredump mode
    Given /tmp/.minidump_upload_timestamps has 11 lines (would block a minidump run)
    When the binary runs in coredump mode
    Then the upload-count else-branch returns ALLOW_UPLOAD immediately
    And /tmp/.deny_dump_uploads_till is NOT created by the rate limiter
    And the binary exits with return code 0

  # TC-051
  Scenario: Active deny-window file blocks upload regardless of count
    Given /tmp/.deny_dump_uploads_till contains a timestamp 1 hour in the future
    When the binary runs in minidump mode
    Then is_recovery_time_reached returns false (still within deny window)
    And ratelimit_check_unified returns RATELIMIT_BLOCK
    And the working directory contains no .dmp or .tgz files after the run
    And the binary exits with return code 0

  # TC-053
  Scenario: No deny file present — is_recovery_time_reached passes and upload is allowed
    Given /tmp/.deny_dump_uploads_till does not exist
    And /tmp/.minidump_upload_timestamps does not exist
    When the binary runs in minidump mode
    Then is_recovery_time_reached returns ALLOW_UPLOAD (file absent)
    And the rate limiter does not block the upload
    And the binary exits with return code 0

  # TC-055
  Scenario: set_time() writes the deny-until timestamp as a plain integer (no fractional seconds)
    Given the rate limit has triggered (count > 10 within window)
    When the binary writes /tmp/.deny_dump_uploads_till
    Then the file contains a single integer Unix timestamp with no decimal point

  # TC-052
  Scenario: Expired deny-window file is ignored and upload proceeds
    Given /tmp/.deny_dump_uploads_till contains a timestamp 1 hour in the past
    When the binary runs in minidump mode
    Then is_recovery_time_reached returns ALLOW_UPLOAD (window expired)
    And the binary exits with return code 0

  # TC-054
  Scenario: Rate-limit counter resets after the recovery period elapses
    Given /tmp/.minidump_upload_timestamps has 11 lines where the first timestamp is older than 600 s
    When the binary runs in minidump mode
    Then is_upload_limit_reached sees the window as expired
    And ALLOW_UPLOAD is returned
    And the binary exits with return code 0
