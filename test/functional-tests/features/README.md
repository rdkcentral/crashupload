# Feature Files

This directory contains Gherkin-format specifications for every functional test
module in the crashupload L2 test suite.  Each `.feature` file is a human-readable
description of the behaviour under test and maps 1-to-1 with a Python test file
in [../tests/](../tests/).

The files are plain Gherkin documentation — they describe **what** the binary
must do, allowing the behaviour to be understood without reading C or Python source.

---

## Gherkin Keywords

| Keyword | Purpose |
|---------|--------|
| `Feature:` | Groups related scenarios under a module or capability |
| `Background:` | Shared preconditions applied to every scenario in the file |
| `Scenario:` | One concrete test case |
| `Given` | Precondition or initial state |
| `When` | Action under test |
| `Then` | Expected observable outcome |
| `And` / `But` | Continuation of the previous step type |

---

## Feature Files — Complete Index

### Argument Parsing & Startup

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `arg_parsing.feature` | TC-008 | `test_crashupload_arg_parsing.py` |
| `failure_return.feature` | FAIL-01, FAIL-02 | `test_crashupload_failure_return.py` |
| `reboot_and_log_scenario.feature` | REBOOT-01, LOG-01 | `test_reboot_and_log_scenario.py` |

### Configuration & Path Selection

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `config_and_path.feature` | TC-006, TC-007, TC-009 | `test_config_and_path.py` |
| `config_checks_and_baseline.feature` | TC-019, TC-020, TC-021, TC-023, TC-024, TC-025, TC-026, TC-028 | `test_config_checks_and_baseline.py` |
| `unsupported_device_types.feature` | TC-004, TC-005, TC-017, TC-018 | `test_unsupported_devicetypes.py` |
| `broadband_env.feature` | TC-067 | `test_broadband_env.py` |

### No Dumps / Prerequisites

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `no_dumps_exit.feature` | NODMP-01..04 | `test_no_dumps_exit.py` |
| `upload_deferral.feature` | TC-035, TC-036, TC-037 | `test_upload_deferral.py` |

### Lock Mechanism

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `test_lock_and_exit.feature` | TC-012, TC-013, TC-015, TC-085 | `test_lock_and_exit.py` |
| `test_lock_and_wait.feature` | TC-011 (wait mode) | `test_lock_and_wait.py` |
| `lock_lifecycle.feature` | TC-011, TC-014, TC-016 | `test_lock_lifecycle.py` |
| `signal_lock_cleanup.feature` | SIG-01, SIG-02 | `test_signal_lock_cleanup.py` |

### Cleanup & Rate Limiting

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `cleanup_batch.feature` | TC-041, TC-042, TC-043, TC-044, TC-045, TC-046, TC-047 | `test_cleanup_batch.py` |
| `ratelimit.feature` | TC-048, TC-049, TC-050, TC-051, TC-052, TC-053, TC-054, TC-055 | `test_ratelimit.py` + `test_ratelimit_allow.py` |

### Telemetry

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `telemetry_optout.feature` | TC-038, TC-039, TC-040 | `test_t2_optout.py` |
| `crash_telemetry.feature` | TC-072, TC-073 | `test_telemetry.py` |

### Dump Scanning, Processing & Archiving

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `scanner_behaviour.feature` | TC-057, TC-058, TC-059, TC-064 | `test_scanner_behaviour.py` |
| `dump_processing.feature` | TC-060, TC-071 | `test_dump_processing.py` |
| `archive_naming.feature` | TC-061, TC-062, TC-063 | `test_file_ext_check.py` |
| `archive_content.feature` | TC-065, TC-066, TC-075, TC-078, TC-079, TC-080 | `test_archive_content.py` |

### Upload

| Feature File | TC-IDs | Python Test File |
|---|---|---|
| `upload.feature` | TC-081 | `test_single_dump_upload.py` |
| `upload_retry.feature` | TC-082, TC-083 | `test_upload_retry.py` |

---

## TC Coverage Summary

- **Total applicable TCs**: 66 out of 85
- **Feature files**: 24 (all 66 applicable TCs covered)
- **Not-applicable TCs**: 19 (shell-only behaviours, unimplemented stubs — see `L2_TESTS.md`)

See [../../L2_TESTS.md](../../L2_TESTS.md) for the full TC applicability matrix and implementation status.
