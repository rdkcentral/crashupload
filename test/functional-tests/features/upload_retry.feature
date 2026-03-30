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

# TC-082 / TC-083
Feature: Upload retry behaviour — partial failure and complete failure

  upload_file() in upload.c retries up to MAX_RETRIES=3 times on failure.
  Two sentinel files in the L2_TEST build control the retry path without
  any server-side configuration:
    /tmp/cu_fail_n   — file contains an integer N; the first N iterations
                       are force-failed (http_code=500, curl_ret=-1);
                       iteration N+1 uses the real network result.
    /tmp/cu_all_fail — when present, every iteration is force-failed so
                       all retries are exhausted and the binary returns
                       a non-zero exit code.

  Requires: mockxconf container reachable at https://mockxconf:50059.

  Background:
    Given the crashupload binary exists built with L2_TEST flag
    And mockxconf is running and accessible
    And /opt/logs directory and core_log.txt exist
    And /etc/device.properties contains DEVICE_TYPE=mediaclient and S3_AMAZON_SIGNING_URL=https://mockxconf:50059

  # TC-082
  Scenario: Upload succeeds on the final retry after 2 injected failures
    Given the uploaded_crashes shared directory is empty
    And /tmp/cu_fail_n contains "2" (fail first 2 iterations, succeed on 3rd)
    And a dummy .dmp file is placed in /opt/secure/minidumps
    When the binary is invoked in secure minidump mode
    Then iterations 1 and 2 are force-failed via the cu_fail_n sentinel
    And at least 2 "(Retry)" log entries appear in the core log
    And iteration 3 uses the real upload path and succeeds
    And the binary exits with return code 0
    And at least one file appears in the uploaded_crashes shared directory

  # TC-083
  Scenario: Upload permanently fails after all MAX_RETRIES=3 are exhausted
    Given the uploaded_crashes shared directory is empty
    And /tmp/cu_all_fail exists (force-fail every iteration)
    And a dummy .dmp file is placed in /opt/secure/minidumps
    When the binary is invoked in secure minidump mode
    Then all 3 iterations are force-failed via the cu_all_fail sentinel
    And at least 3 "(Retry)" log entries appear in the core log
    And no file is saved to the uploaded_crashes shared directory
    And the binary exits with a non-zero return code
