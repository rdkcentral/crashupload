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
# Note: Binary must be built with --l2-test flag before running this script:
#         sh cov_build.sh --l2-test
#       This enables -DL2_TEST so the binary reads uptime from /opt/uptime
#       instead of /proc/uptime, bypassing the 480-second deferral check.

# Do NOT use set -e here: individual test failures should not abort the run;
# we collect all results and print a consolidated summary at the end.

# Setup test environment
export top_srcdir="$(pwd)"
RESULT_DIR="/tmp/l2_test_report"
TEST_DIR="test/functional-tests/tests"
SUMMARY_FILE="/tmp/l2_test_summary.txt"
OVERALL_EXIT=0

# Create result directory
mkdir -p "$RESULT_DIR"

# Start with a clean summary file so results from a previous run never leak in
rm -f "$SUMMARY_FILE"

# Create controlled uptime file for L2_TEST mode.
# The binary is built with -DL2_TEST (via 'sh cov_build.sh --l2-test'), which
# makes prerequisites.c read /opt/uptime instead of /proc/uptime.  A value of
# 600 seconds is above the 480-second deferral threshold, so no sleep occurs.
echo "600.0 1200.0" > /opt/uptime
echo "Created /opt/uptime with 600 seconds (bypasses 480s deferral check)"

# Setup test directories and environment
mkdir -p /opt/secure/minidumps
mkdir -p /opt/secure/coredumps
mkdir -p /opt/secure/corefiles
mkdir -p /opt/minidumps
mkdir -p /var/lib/systemd/coredump
mkdir -p /tmp
mkdir -p /opt/logs
echo "LOG.RDK.DEFAULT" >> /etc/debug.ini

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
# '|| OVERALL_EXIT=1' ensures we always continue to the next file and still
# show the full summary table even when some tests fail.
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_exit.json" "$TEST_DIR/test_lock_and_exit.py"               || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_wait.json" "$TEST_DIR/test_lock_and_wait.py"              || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/failure_return.json" "$TEST_DIR/test_crashupload_failure_return.py" || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/arg_parsing.json" "$TEST_DIR/test_crashupload_arg_parsing.py"    || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/no_dumps_exit.json" "$TEST_DIR/test_no_dumps_exit.py"              || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/reboot_and_log.json" "$TEST_DIR/test_reboot_and_log_scenario.py"    || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/signal_lock.json" "$TEST_DIR/test_signal_lock_cleanup.py"        || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/config_and_path.json" "$TEST_DIR/test_config_and_path.py"            || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_lifecycle.json" "$TEST_DIR/test_lock_lifecycle.py"             || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/upload_deferral.json" "$TEST_DIR/test_upload_deferral.py"            || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/cleanup_batch.json" "$TEST_DIR/test_cleanup_batch.py"              || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/ratelimit.json" "$TEST_DIR/test_ratelimit.py"                       || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/unsupported_devices.json" "$TEST_DIR/test_unsupported_devicetypes.py"         || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/config_baseline.json" "$TEST_DIR/test_config_checks_and_baseline.py"     || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/t2_optout.json"        "$TEST_DIR/test_t2_optout.py"                       || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/dump_processing.json" "$TEST_DIR/test_dump_processing.py"               || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/ratelimit_allow.json"  "$TEST_DIR/test_ratelimit_allow.py"               || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/scanner_behaviour.json" "$TEST_DIR/test_scanner_behaviour.py"             || OVERALL_EXIT=1

# ---------------------------------------------------------------------------
# Print consolidated L2 summary table from the accumulated summary file, then
# clean up the file regardless of whether any tests failed.
# ---------------------------------------------------------------------------
python3 "$TEST_DIR/conftest.py" "$SUMMARY_FILE"

# Cleanup
rm -f /tmp/.uploadMinidumps
rm -f /tmp/.uploadCoredumps
rm -f /opt/secure/minidumps/*.dmp* 2>/dev/null || true
rm -f /opt/secure/coredumps/*.dmp* 2>/dev/null || true
rm -f /opt/uptime 2>/dev/null || true
echo "L2 tests completed."

exit $OVERALL_EXIT
