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

# TC-008
Feature: Command-line argument validation

  The binary requires at least 3 arguments (binary + dump_dir + dump_type).
  When called with fewer arguments main.c prints "Number of parameter is less"
  and calls exit(1).

  Scenario: No arguments supplied
    Given the crashupload binary exists
    When the binary is invoked with no arguments
    Then the binary exits with return code 1

  Scenario: Only one argument supplied (dump directory missing dump type)
    Given the crashupload binary exists
    When the binary is invoked with only one argument
    Then the binary exits with return code 1

  Scenario: Only two arguments supplied (dump directory and dump type, no URL)
    Given the crashupload binary exists
    When the binary is invoked with two arguments
    Then the binary exits with return code 1
