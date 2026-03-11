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
# Note: Binary must be built using cov_build.sh before running this script

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

# Setup test directories and environment
mkdir -p /opt/secure/minidumps
mkdir -p /opt/secure/coredumps
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
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_exit.json"    "$TEST_DIR/test_lock_and_exit.py"               || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/lock_and_wait.json"   "$TEST_DIR/test_lock_and_wait.py"              || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/failure_return.json"  "$TEST_DIR/test_crashupload_failure_return.py" || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/arg_parsing.json"     "$TEST_DIR/test_crashupload_arg_parsing.py"    || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/no_dumps_exit.json"   "$TEST_DIR/test_no_dumps_exit.py"              || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/reboot_and_log.json"  "$TEST_DIR/test_reboot_and_log_scenario.py"    || OVERALL_EXIT=1
pytest -v -s --json-report --json-report-summary --json-report-file "$RESULT_DIR/signal_lock.json"     "$TEST_DIR/test_signal_lock_cleanup.py"        || OVERALL_EXIT=1

# ---------------------------------------------------------------------------
# Print consolidated L2 summary table from the accumulated summary file, then
# clean up the file regardless of whether any tests failed.
# ---------------------------------------------------------------------------
python3 - "$SUMMARY_FILE" <<'EOF'
import sys, os

summary_file = sys.argv[1]
if not os.path.exists(summary_file):
    print("\n[run_l2] No summary file found — nothing to display.")
    sys.exit(0)

ordered, seen = [], {}
with open(summary_file) as fh:
    for raw in fh:
        line = raw.strip()
        if " = " not in line:
            continue
        name, result = line.split(" = ", 1)
        name, result = name.strip(), result.strip()
        if name not in seen:
            ordered.append(name)
        seen[name] = result

os.remove(summary_file)

entries = [(name, seen[name]) for name in ordered]
if not entries:
    sys.exit(0)

col_name   = max(max(len(n) for n, _ in entries), len("Test Case Name"))
col_result = max(max(len(r) for _, r in entries), len("Result"))

sep    = "+" + "-" * (col_name + 2) + "+" + "-" * (col_result + 2) + "+"
width  = len(sep)
header = "| " + "Test Case Name".ljust(col_name) + " | " + "Result".ljust(col_result) + " |"

passed = sum(1 for _, r in entries if r == "SUCCESS")
failed = len(entries) - passed

print()
print("=" * width)
print("  L2 FUNCTIONAL TEST SUMMARY")
print("=" * width)
print(sep)
print(header)
print(sep)
for name, result in entries:
    print("| " + name.ljust(col_name) + " | " + result.ljust(col_result) + " |")
print(sep)
print()
print("  Total : {}   Passed : {}   Failed : {}".format(len(entries), passed, failed))
print("=" * width)
print()
EOF

# Cleanup
rm -f /tmp/.uploadMinidumps
rm -f /tmp/.uploadCoredumps
rm -f /opt/secure/minidumps/*.dmp* 2>/dev/null || true
rm -f /opt/secure/coredumps/*.dmp* 2>/dev/null || true

exit $OVERALL_EXIT
