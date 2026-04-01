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

# TC-011 / TC-014 / TC-016
Feature: Lock file lifecycle — acquisition, release, and SIGKILL behaviour

  lock_acquire() creates the lock file and holds an exclusive flock(LOCK_EX|LOCK_NB)
  for the duration of the run.  lock_release() at the cleanup label calls
  flock(LOCK_UN), close(), and unlink().  SIGKILL cannot be caught, so the
  kernel reclaims the fd but leaves the lock FILE on disk.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # TC-011
  Scenario: First instance acquires the minidump process lock
    Given no minidump lock file exists at /tmp/.uploadMinidumps
    And a .dmp file is present in /opt/secure/minidumps
    When the binary is started in minidump mode
    Then /tmp/.uploadMinidumps appears on disk within a few seconds
    And the binary holds an exclusive flock on it

  Scenario: First instance acquires the coredump process lock
    Given no coredump lock file exists at /tmp/.uploadCoredumps
    And a coredump file is present in /opt/secure/corefiles
    When the binary is started in coredump mode
    Then /tmp/.uploadCoredumps appears on disk within a few seconds
    And the binary holds an exclusive flock on it

  # TC-014
  Scenario: Minidump lock file is removed after clean exit
    Given the binary is invoked with no dump files (NO_DUMPS_FOUND path)
    When the binary exits cleanly with return code 0
    Then /tmp/.uploadMinidumps does not exist on disk

  Scenario: Coredump lock file is removed after clean exit
    Given the binary is invoked in coredump mode with no dump files
    When the binary exits cleanly with return code 0
    Then /tmp/.uploadCoredumps does not exist on disk

  # TC-016
  Scenario: SIGKILL does not remove the minidump lock file
    Given the binary has acquired the minidump lock and is processing
    When SIGKILL is sent to the binary process
    Then the kernel reclaims the file descriptor automatically
    But the lock file /tmp/.uploadMinidumps may remain on disk
    And a subsequent binary invocation can still acquire the lock (flock released)

  Scenario: SIGKILL does not remove the coredump lock file
    Given the binary has acquired the coredump lock and is processing
    When SIGKILL is sent to the binary process
    Then the kernel reclaims the file descriptor automatically
    But the lock file /tmp/.uploadCoredumps may remain on disk
    And a subsequent binary invocation can still acquire the lock
