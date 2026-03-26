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
import sys
import pytest

SUMMARY_FILE = "/tmp/l2_test_summary.txt"

# Total applicable TCs in uploadDumps_TestCases.md (kept in sync with L2_TESTS.md)
# TC-031/032/033 reclassified as ❌ Not Applicable (network-wait is an unimplemented TODO stub)
# TC-084 reclassified as ❌ Not Applicable (fallback upload path is TODO: SUPPORT NOT AVAILABLE)
#
# Ground-truth count breakdown (see L2_TESTS.md Not-Applicable TCs — Summary table):
#   Not Applicable (❌ No): TC-001,002,003,010,027,029,030,031,032,033,034,
#                           TC-056,068,069,070,074,076,077,084  = 19 TCs
#   Applicable (✅ Yes + ⚠️ Partial): 85 - 19                            = 66 TCs
#   Applicable & Implemented:                                             = 64 TCs
#   Applicable & Not Implemented: TC-082, TC-083                          =  2 TCs
_TC_TOTAL            = 85
_TC_NOT_APPLICABLE   = 19
_TC_TOTAL_APPLICABLE = 66  # _TC_TOTAL - _TC_NOT_APPLICABLE

# Session-level counters updated by pytest_runtest_logreport
_session_pass = 0
_session_fail = 0


# ---------------------------------------------------------------------------
# TC-ID mapping  (function name → TC-ID(s) from L2_TESTS.md)
# ---------------------------------------------------------------------------

_TC_MAP = {
    # Config & Init
    "test_no_args_exits_with_1":                     "TC-008",
    "test_one_arg_exits_with_1":                     "TC-008",
    "test_two_args_exits_with_1":                    "TC-008",
    # Lock Mechanism
    "test_multiple_instance_prevention_minidump":    "TC-012 / TC-085",
    "test_multiple_instance_prevention_coredump":    "TC-012 / TC-085",
    "test_wait_for_lock_minidump":                   "TC-013",
    "test_wait_for_lock_coredump":                   "TC-013",
    "test_sigterm_removes_minidump_lock":            "TC-015",
    "test_sigterm_removes_coredump_lock":            "TC-015",
    # Dump Detection
    "test_prerequisites_no_dumps_exits_with_0":      "TC-022",
    "test_empty_minidump_dir_exits_with_0":          "TC-022",
    "test_empty_corefiles_dir_exits_with_0":         "TC-022",
    "test_wrong_extension_file_exits_with_0":        "TC-022",
    "test_nonexistent_dump_dir_exits_with_0":        "TC-022",
    # Upload Deferral
    "test_reboot_flag_present_skips_upload_exits_0": "TC-037",
    # Config & Path Selection
    "test_secure_mode_selects_secure_minidump_path": "TC-006",
    "test_secure_mode_selects_secure_coredump_path": "TC-006",
    "test_normal_mode_selects_normal_minidump_path": "TC-007",
    "test_coredump_mode_ignores_minidump_files":     "TC-009",
    "test_minidump_mode_ignores_coredump_files":     "TC-009",
    # Lock Lifecycle
    "test_first_instance_acquires_minidump_lock":    "TC-011",
    "test_first_instance_acquires_coredump_lock":    "TC-011",
    "test_lock_removed_on_clean_exit_minidump":      "TC-014",
    "test_lock_removed_on_clean_exit_coredump":      "TC-014",
    "test_sigkill_lock_file_persists_minidump":      "TC-016",
    "test_sigkill_lock_file_persists_coredump":      "TC-016",
    # Upload Deferral
    "test_deferred_when_uptime_below_threshold":     "TC-035",
    "test_no_deferral_when_uptime_above_threshold":  "TC-036",
    # Cleanup Batch
    "test_startup_cleanup_deletes_non_dump_files":   "TC-041",
    "test_stale_archive_files_older_than_2_days_deleted": "TC-042",
    "test_first_run_flag_created":                   "TC-043",
    "test_subsequent_run_skips_startup_cleanup":     "TC-044",
    "test_max_core_files_limit_enforced":            "TC-045",
    "test_empty_dir_handled_gracefully":             "TC-046",
    "test_upload_on_startup_flag_removed_for_coredump_mode": "TC-047",
    # Rate Limiting
    "test_upload_blocked_when_count_exceeds_10":     "TC-049",
    "test_upload_blocked_when_deny_file_active":     "TC-051",
    "test_system_initialize_failure_exits_with_1":   "C-TC-001",
    "test_binary_produces_log_output":               "C-TC-002",
    # Telemetry Opt-Out
    "test_rfc_optout_set_mediaclient_exits_0":           "TC-038",
    "test_optout_file_absent_upload_not_blocked":        "TC-039",
    "test_optout_check_bypassed_for_nonmediaclient":     "TC-040",
    # Unsupported Device Types
    "test_broadband_device_type_no_dumps_exits_0":       "TC-004",
    "test_broadband_minidump_detection_in_core_path":    "TC-017",
    "test_extender_device_type_no_dumps_exits_0":        "TC-005",
    "test_extender_minidump_detection_in_core_path":     "TC-018",
    # Dump Detection Paths
    "test_coredump_detection_normal_path":               "TC-019",
    "test_minidump_detection_secure_path":               "TC-020",
    "test_coredump_detection_secure_path":               "TC-021",
    # Platform Baseline
    "test_mac_address_read_and_normalised":              "TC-023",
    "test_mac_fallback_when_file_missing_or_empty":      "TC-024",
    "test_model_number_retrieved":                       "TC-025 / TC-026",
    "test_sha1_firmware_hash_from_version_txt":          "TC-028",
    # Dump Processing
    "test_existing_tgz_not_re_archived":                 "TC-060",
    "test_zero_size_dump_handled_gracefully":            "TC-071",
    # Rate Limiting — allow paths
    "test_upload_allowed_when_count_at_or_below_limit":          "TC-048",
    "test_coredump_not_rate_limited_by_minidump_counter":        "TC-050",
    "test_recovery_time_expired_unblocks_upload":                "TC-052",
    "test_no_deny_file_allows_upload_to_proceed":                "TC-053",
    "test_rate_limit_resets_after_recovery_period":              "TC-054",
    "test_set_time_writes_integer_format_timestamp":             "TC-055",
    # Archive Naming
    "test_archive_filename_contains_required_fields":            "TC-061",
    "test_archive_filename_truncated_at_135_chars":              "TC-062",
    "test_mpeos_main_uses_mtime_not_crashts":                    "TC-063",
    # Scanner Behaviour
    "test_container_delimiter_preserved_in_sanitization":        "TC-057",
    "test_forbidden_chars_dropped_from_filename":                "TC-058",
    "test_container_name_preserved_with_forbidden_chars":        "TC-059",
    "test_dump_filename_components_parsed_correctly":            "TC-064",
    # Archive Content
    "test_archive_created_for_dump":                             "TC-065",
    "test_archive_contains_required_members":                    "TC-066",
    "test_crashed_url_file_included_in_archive":                 "TC-079",
    "test_log_files_mapped_for_crashed_process":                 "TC-075",
    "test_all_mapped_log_files_added_to_archive":                "TC-080",
    "test_missing_log_file_handled_gracefully":                  "TC-078",
    # Upload functionality
    "test_single_successful_upload":                             "TC-081",
    # Crash Telemetry
    "test_process_crash_telemetry_path_exercised":               "TC-072",
    "test_container_crash_telemetry_path_exercised":             "TC-073",
    # Broadband Env
    "test_broadband_minidump_archive_not_created":               "TC-067",
}


def _count_tc_coverage() -> int:
    """Return the number of unique TC-NNN IDs that have at least one test function."""
    seen: set = set()
    for val in _TC_MAP.values():
        for tc in val.split(" / "):
            tc = tc.strip()
            if re.match(r"^TC-\d+$", tc):
                seen.add(tc)
    return len(seen)


_TC_COVERAGE = _count_tc_coverage()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _camel_to_words(text: str) -> str:
    """Insert a space before each uppercase letter that starts a new word."""
    # "WaitForLock" → "Wait For Lock"
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)


def _descriptive_name(nodeid: str) -> tuple:
    """
    Build a (tc_id, human-readable label) pair from a pytest node-id.

    Node-id examples:
      test_lock_and_wait.py::TestWaitForLock::test_wait_for_lock_coredump
      test_no_dumps_exit.py::TestNoDumpsExit::test_no_dumps_found_minidump

    Label examples:
      [Wait For Lock] Wait For Lock Coredump
      [No Dumps Exit] No Dumps Found Minidump

    TC-ID sourced from _TC_MAP; falls back to "UNKNOWN" if not listed.
    """
    parts = nodeid.split("::")

    # Function portion — strip leading "test_", then title-case
    func = parts[-1]
    tc_id = _TC_MAP.get(func, "UNKNOWN")
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

    return tc_id, label


def _append_to_summary(tc_id: str, name: str, result: str) -> None:
    """Thread-safe-enough append: one write per call, file is sequential."""
    try:
        with open(SUMMARY_FILE, "a") as fh:
            fh.write(f"{tc_id} | {name} = {result}\n")
    except OSError as exc:
        print(f"\n[conftest] WARNING: could not write to {SUMMARY_FILE}: {exc}")


# ---------------------------------------------------------------------------
# Pytest hooks
# ---------------------------------------------------------------------------

def pytest_runtest_logstart(nodeid, location):
    """Called at the very beginning of each test item — record RUNNING."""
    tc_id, label = _descriptive_name(nodeid)
    _append_to_summary(tc_id, label, "RUNNING")


def pytest_runtest_logreport(report):
    """
    Called after each phase (setup / call / teardown).
    We record the final result after the 'call' phase, or FAIL if setup
    itself crashed (meaning the test never ran).
    """
    global _session_pass, _session_fail
    if report.when == "call":
        result = "SUCCESS" if report.passed else "FAIL"
        tc_id, label = _descriptive_name(report.nodeid)
        _append_to_summary(tc_id, label, result)
        if report.passed:
            _session_pass += 1
        else:
            _session_fail += 1
    elif report.when == "setup" and report.failed:
        tc_id, label = _descriptive_name(report.nodeid)
        _append_to_summary(tc_id, label, "FAIL (setup error)")
        _session_fail += 1


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print a compact coverage block at the end of every pytest session."""
    total = _session_pass + _session_fail
    not_implemented = _TC_TOTAL_APPLICABLE - _TC_COVERAGE

    lines = [
        f"Found TCs                       : {_TC_TOTAL}",
        f"Not Applicable TCs              : {_TC_NOT_APPLICABLE}",
        f"Applicable TCs                  : {_TC_TOTAL_APPLICABLE}  ({_TC_TOTAL} − {_TC_NOT_APPLICABLE})",
        f"  ✔ Applicable & Implemented    : {_TC_COVERAGE}",
        f"  ○ Applicable & Not Implemented : {not_implemented}",
        "",
        f"This run  :  {_session_pass} passed, {_session_fail} failed  ({total} test functions)",
    ]
    width = max(len(l) for l in lines) + 4
    sep = "─" * width
    terminalreporter.write_sep("=", "L2 Coverage Summary")
    terminalreporter.write_line(sep)
    for l in lines:
        terminalreporter.write_line(f"  {l}")
    terminalreporter.write_line(sep)


# pytest_sessionfinish is intentionally absent: run_l2.sh reads the accumulated
# summary file after all pytest invocations complete and prints the final table.


# ---------------------------------------------------------------------------
# Summary table printer — called by run_l2.sh via: python3 conftest.py <file>
# ---------------------------------------------------------------------------

def _print_summary(summary_file: str) -> None:
    """Parse the accumulated summary file and print a formatted results table."""
    if not os.path.exists(summary_file):
        print("\n[run_l2] No summary file found — nothing to display.")
        return

    ordered, seen = [], {}
    with open(summary_file) as fh:
        for raw in fh:
            line = raw.strip()
            if " = " not in line:
                continue
            # Format written by conftest hooks: "TC-XXX | <label> = RESULT"
            if " | " in line:
                tc_part, rest = line.split(" | ", 1)
                tc_id = tc_part.strip()
            else:
                tc_id = "-"
                rest = line
            name, result = rest.split(" = ", 1)
            name, result = name.strip(), result.strip()
            key = (tc_id, name)
            if key not in seen:
                ordered.append(key)
            seen[key] = result

    os.remove(summary_file)

    entries = [(tc_id, name, seen[(tc_id, name)]) for tc_id, name in ordered]
    if not entries:
        return

    col_tc     = max(max(len(t) for t, _, _ in entries), len("TC-ID"))
    col_name   = max(max(len(n) for _, n, _ in entries), len("Test Case Name"))
    col_result = max(max(len(r) for _, _, r in entries), len("Result"))

    sep    = ("+" + "-" * (col_tc + 2) +
              "+" + "-" * (col_name + 2) +
              "+" + "-" * (col_result + 2) + "+")
    width  = len(sep)
    header = ("| " + "TC-ID".ljust(col_tc) +
              " | " + "Test Case Name".ljust(col_name) +
              " | " + "Result".ljust(col_result) + " |")

    passed = sum(1 for _, _, r in entries if r == "SUCCESS")
    failed = len(entries) - passed

    print()
    print("=" * width)
    print("  L2 FUNCTIONAL TEST SUMMARY")
    print("=" * width)
    print(sep)
    print(header)
    print(sep)
    for tc_id, name, result in entries:
        print("| " + tc_id.ljust(col_tc) +
              " | " + name.ljust(col_name) +
              " | " + result.ljust(col_result) + " |")
    print(sep)
    print()
    print("  Total : {}   Passed : {}   Failed : {}".format(len(entries), passed, failed))
    print("=" * width)
    print()


if __name__ == "__main__":
    _print_summary(sys.argv[1])
