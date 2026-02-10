#!/bin/sh
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

#
# Script: run_l2.sh
# Purpose: Run Level 2 (functional) tests for crashupload
# Usage: sh run_l2.sh
# Note: Binary must be built with --l2-test flag using: sh cov_build.sh --l2-test

set -e  # Exit on error

# Setup test environment
export top_srcdir="$(pwd)"
RESULT_DIR="/tmp/l2_test_report"
TEST_DIR="test/functional-tests/tests"

# Create result directory
mkdir -p "$RESULT_DIR"

# Setup test directories and environment
mkdir -p /opt/secure/minidumps
mkdir -p /opt/secure/coredumps
mkdir -p /opt/minidumps
mkdir -p /var/lib/systemd/coredump
mkdir -p /tmp
mkdir -p /opt/logs

# CRITICAL: Create /opt/uptime with high value to bypass 480-second boot deferral
# This file is used when binary is built with --l2-test flag
# Format: <uptime_seconds> <idle_time>  (same as /proc/uptime)
echo "600.0 1200.0" > /opt/uptime
echo "Created /opt/uptime with 600 seconds (bypasses 480s deferral check)"

# Clean up any existing lock files and test artifacts
rm -f /tmp/.uploadMinidumps
rm -f /tmp/.uploadCoredumps
rm -f /opt/secure/minidumps/*.dmp* 2>/dev/null || true
rm -f /opt/secure/coredumps/*.dmp* 2>/dev/null || true
rm -f /opt/minidumps/*.dmp* 2>/dev/null || true
rm -f /var/lib/systemd/coredump/*core* 2>/dev/null || true

# Find crashupload binary
if command -v crashupload >/dev/null 2>&1; then
    CRASHUPLOAD_BINARY=$(command -v crashupload)
elif [ -f "/usr/local/bin/crashupload" ]; then
    CRASHUPLOAD_BINARY="/usr/local/bin/crashupload"
elif [ -f "/usr/bin/crashupload" ]; then
    CRASHUPLOAD_BINARY="/usr/bin/crashupload"
else
    echo "Error: crashupload binary not found"
    exit 1
fi

export CRASHUPLOAD_BINARY

# Run functional tests with JSON reports
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_exit.json" "$TEST_DIR/test_lock_and_exit.py"
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_wait.json" "$TEST_DIR/test_lock_and_wait.py"
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/minidump_happy_path.json" "$TEST_DIR/test_minidump_happy_path.py"
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/coredump_happy_path.json" "$TEST_DIR/test_coredump_happy_path.py"
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/startup_cleanup.json" "$TEST_DIR/test_startup_cleanup.py"
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/unsupported_device_types.json" "$TEST_DIR/test_unsupported_device_types.py"

# Cleanup
rm -f /tmp/.uploadMinidumps
rm -f /tmp/.uploadCoredumps
rm -f /opt/secure/minidumps/*.dmp* 2>/dev/null || true
rm -f /opt/secure/coredumps/*.dmp* 2>/dev/null || true
rm -f /opt/uptime 2>/dev/null || true
echo "L2 tests completed successfully!"
