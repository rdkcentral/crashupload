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

# SIG-01 / SIG-02
Feature: SIGTERM causes the binary to unlink its process lock file

  handle_signal() in main.c calls unlink(MINIDUMP_LOCK_FILE) or
  unlink(COREDUMP_LOCK_FILE) depending on argv[2], then execution
  continues to the cleanup label where lock_release() closes the fd.

  Background:
    Given the crashupload binary exists
    And /opt/logs directory and core_log.txt exist

  # SIG-01
  Scenario: SIGTERM removes the minidump lock file
    Given a valid .dmp file is placed in /opt/secure/minidumps
    And the binary is started in secure minidump mode
    When the minidump lock file /tmp/.uploadMinidumps appears on disk
    And SIGTERM is sent to the binary process
    Then handle_signal unlinks /tmp/.uploadMinidumps immediately
    And /tmp/.uploadMinidumps is absent within a few seconds
    And the binary exits (any code)

  # SIG-02
  Scenario: SIGTERM removes the coredump lock file
    Given a valid coredump file is placed in /opt/secure/corefiles
    And the binary is started in secure coredump mode
    When the coredump lock file /tmp/.uploadCoredumps appears on disk
    And SIGTERM is sent to the binary process
    Then handle_signal unlinks /tmp/.uploadCoredumps immediately
    And /tmp/.uploadCoredumps is absent within a few seconds
    And the binary exits (any code)
