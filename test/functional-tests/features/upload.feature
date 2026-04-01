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

# TC-081
Feature: Single successful dump upload to S3

  upload_file() in upload.c performs a metadata POST to obtain a signed S3 URL
  and then a PUT to upload the dump archive.  On success the binary removes the
  local archive and records a timestamp in the minidump upload timestamps file.
  The mock-xconf server saves the received file to the shared uploaded_crashes
  directory, which the test reads to confirm end-to-end delivery.

  Requires: mockxconf container reachable at https://mockxconf:50059 (ENABLE_MTLS=true).

  Background:
    Given the crashupload binary exists built with L2_TEST flag
    And mockxconf is running and accessible at mockxconf:50059 and mockxconf:50060
    And /opt/logs directory and core_log.txt exist
    And /etc/device.properties contains DEVICE_TYPE=mediaclient and S3_AMAZON_SIGNING_URL=https://mockxconf:50059

  # TC-081
  Scenario: First upload attempt succeeds — file appears in the uploaded_crashes directory
    Given the uploaded_crashes shared directory is empty
    And a dummy .dmp file is placed in /opt/secure/minidumps
    When the binary is invoked in secure minidump mode
    Then upload_file calls performMetadataPostWithCertRotationEx successfully
    And the S3 presigned URL is extracted from the response
    And performS3PutUpload transfers the archive to mockxconf
    And the binary exits with return code 0
    And at least one file appears in the uploaded_crashes shared directory
