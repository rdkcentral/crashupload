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

"""
conftest.py — session-level pytest hooks for L2 functional test summary.

Flow:
  • pytest_runtest_logstart  → appends "<name> = RUNNING" to SUMMARY_FILE
  • pytest_runtest_logreport → appends "<name> = SUCCESS|FAIL" when the test
                               call (or setup) phase completes

The summary file (/tmp/l2_test_summary.txt) is intentionally left on disk
after each pytest session so that run_l2.sh can accumulate results across
all test files and print a single consolidated table at the very end.
"""

import os
import re
import pytest

SUMMARY_FILE = "/tmp/l2_test_summary.txt"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _camel_to_words(text: str) -> str:
    """Insert a space before each uppercase letter that starts a new word."""
    # "WaitForLock" → "Wait For Lock"
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)


def _descriptive_name(nodeid: str) -> str:
    """
    Build a human-readable test case label from a pytest node-id.

    Node-id examples:
      test_lock_and_wait.py::TestWaitForLock::test_wait_for_lock_coredump
      test_no_dumps_exit.py::TestNoDumpsExit::test_no_dumps_found_minidump

    Result examples:
      [Wait For Lock] Wait For Lock Coredump
      [No Dumps Exit] No Dumps Found Minidump
    """
    parts = nodeid.split("::")

    # Function portion — strip leading "test_", then title-case
    func = parts[-1]
    if func.startswith("test_"):
        func = func[5:]
    label = func.replace("_", " ").title()

    # Class portion — strip leading "Test", split CamelCase, wrap in brackets
    if len(parts) >= 3:
        cls = parts[-2]
        if cls.startswith("Test"):
            section = _camel_to_words(cls[4:]).strip()  # e.g. "Wait For Lock"
            if section:
                label = f"[{section}] {label}"

    return label


def _append_to_summary(name: str, result: str) -> None:
    """Thread-safe-enough append: one write per call, file is sequential."""
    try:
        with open(SUMMARY_FILE, "a") as fh:
            fh.write(f"{name} = {result}\n")
    except OSError as exc:
        print(f"\n[conftest] WARNING: could not write to {SUMMARY_FILE}: {exc}")


# ---------------------------------------------------------------------------
# Pytest hooks
# ---------------------------------------------------------------------------

def pytest_runtest_logstart(nodeid, location):
    """Called at the very beginning of each test item — record RUNNING."""
    _append_to_summary(_descriptive_name(nodeid), "RUNNING")


def pytest_runtest_logreport(report):
    """
    Called after each phase (setup / call / teardown).
    We record the final result after the 'call' phase, or FAIL if setup
    itself crashed (meaning the test never ran).
    """
    if report.when == "call":
        result = "SUCCESS" if report.passed else "FAIL"
        _append_to_summary(_descriptive_name(report.nodeid), result)
    elif report.when == "setup" and report.failed:
        _append_to_summary(_descriptive_name(report.nodeid), "FAIL (setup error)")


# pytest_sessionfinish is intentionally absent: run_l2.sh reads the accumulated
# summary file after all pytest invocations complete and prints the final table.
