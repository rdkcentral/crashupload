# Functional Test Implementations

This directory contains the pytest-based L2 functional test suite for the
crasupload C binary.  Each `.py` file exercises one or more TC-IDs from
[uploadDumps_TestCases.md](../../../uploadDumps_TestCases.md) by running the
compiled binary directly against a set of controlled filesystem conditions.

Gherkin-format specifications for all tests are in [../features/](../features/).

---

## Running the Tests

```bash
# From the repository root inside the native-platform container:
sh run_l2.sh

# Individual test file
pytest -v -s test/functional-tests/tests/test_archive_content.py

# All tests with JSON report
pytest -v -s --json-report --json-report-summary \
    test/functional-tests/tests/
```

The binary under test is located at
`c_sourcecode/src/crashupload` (built by `sh cov_build.sh --l2-test`).
The `CRASHUPLOAD_BINARY` environment variable overrides the path.

---

## Test File Index

### Argument Parsing & Init

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_crashupload_arg_parsing.py` | TC-008 | Validates `argc < 3` exits with code 1 |
| `test_crashupload_failure_return.py` | FAIL-01/02 | `system_initialize` failure → exit 1; no-dumps → exit 0 |
| `test_reboot_and_log_scenario.py` | REBOOT-01, LOG-01 | Reboot flag skips upload; binary always emits log output |

### Configuration & Path Selection

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_config_and_path.py` | TC-006, TC-007, TC-009 | Secure/normal path selection; minidump vs coredump mode |
| `test_config_checks_and_baseline.py` | TC-019–021, TC-023–026, TC-028 | Dump detection and platform metadata (MAC, model, SHA1) |
| `test_unsupported_devicetypes.py` | TC-004, TC-005, TC-017, TC-018 | Broadband/extender device type exit behaviour |
| `test_broadband_env.py` | TC-067 | Broadband mode produces no .tgz |

### No Dumps / Prerequisites

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_no_dumps_exit.py` | NODMP-01..04 | Empty/missing/wrong-extension dump dir → exit 0 |
| `test_upload_deferral.py` | TC-035, TC-036, TC-037 | Uptime-based deferral (L2_TEST build reads `/opt/uptime`) |

### Lock Mechanism

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_lock_and_exit.py` | TC-012, TC-013, TC-015, TC-085 | Second instance exits when lock is held |
| `test_lock_and_wait.py` | TC-011 (wait mode) | `wait_for_lock` argument waits for lock release |
| `test_lock_lifecycle.py` | TC-011, TC-014, TC-016 | Lock acquired, removed on clean exit, persists after SIGKILL |
| `test_signal_lock_cleanup.py` | SIG-01, SIG-02 | SIGTERM unlinks the process lock file |

### Cleanup & Rate Limiting

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_cleanup_batch.py` | TC-041–047 | On-startup cleanup, stale archive removal, MAX_CORE_FILES |
| `test_ratelimit.py` | TC-049, TC-051, TC-055 | Rate-limit block path; deny-window; integer timestamp format |
| `test_ratelimit_allow.py` | TC-048, TC-050, TC-052, TC-053, TC-054 | Rate-limit allow path; coredump bypass; expired window |

### Telemetry

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_t2_optout.py` | TC-038, TC-039, TC-040 | RFC/file opt-out suppresses upload on mediaclient |
| `test_telemetry.py` | TC-072, TC-073 | Process and container crash telemetry log-mapper paths |

### Dump Scanning, Processing & Archiving

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_scanner_behaviour.py` | TC-057, TC-058, TC-059, TC-064 | Filename sanitisation and process-name extraction |
| `test_dump_processing.py` | TC-060, TC-071 | Pre-existing .tgz passthrough; zero-size dump handling |
| `test_file_ext_check.py` | TC-061, TC-062, TC-063 | Archive filename metadata fields, truncation, mpeos-main mtime |
| `test_archive_content.py` | TC-065, TC-066, TC-075, TC-078, TC-079, TC-080 | Archive creation and log-file bundling |

### Upload

| File | TC-IDs | Description |
|------|--------|-------------|
| `test_single_dump_upload.py` | TC-081 | End-to-end successful upload to mock S3 |
| `test_upload_retry.py` | TC-082, TC-083 | Retry succeeds on 3rd attempt; all retries exhausted |

---

## Shared Utilities

`testUtility.py` provides:
- `binary_path` fixture — resolves `CRASHUPLOAD_BINARY` env var or default build path
- `cleanup_pytest_cache` fixture — removes `.pytest_cache` after each test
- `create_dummy_dump()`, `stash_dir_dumps()`, `restore_stashed_dumps()`
- `hold_lock_and_release()`, `wait_for_path()`
- Constants: `SECURE_MINIDUMP_PATH`, `UPLOADED_CRASHES_DIR`, `DENY_UPLOADS_FILE`, …

`conftest.py` provides:
- Session-level pass/fail counters
- `_TC_MAP` (test function name → TC-ID) used to emit a coverage report
- `pytest_sessionfinish` hook that prints a TC coverage summary

---

## TC Coverage

- **Applicable TCs**: 66 / 85
- **Implemented**: 66 / 66 (100%)
- **Not applicable** (shell-only / unimplemented stubs): 19

See [../../../L2_TESTS.md](../../../L2_TESTS.md) for the full applicability matrix.
