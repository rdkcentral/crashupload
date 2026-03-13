# L2 Test Coverage — CrashUpload C Implementation

**Reference:** Original test cases defined in `uploadDumps_TestCases.md` (85 TCs for the
shell-script implementation of `uploadDumps.sh`).

**Purpose:** This document cross-references every TC against the C implementation
(`c_sourcecode/`) to determine applicability, and maps each applicable TC to any existing
L2 functional test in `test/functional-tests/tests/`.

**Build requirement:** L2 tests require a binary compiled with `-DL2_TEST`:
```bash
sh cov_build.sh --l2-test
```

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ Yes | TC is fully applicable to the C implementation |
| ⚠️ Partial | TC is partially applicable; C behavior differs from shell in some aspects |
| ❌ No | TC is not applicable; feature is shell-specific with no C equivalent |
| ✅ Implemented | One or more L2 functional tests cover this TC |
| 🔲 Not Yet | TC is applicable but no L2 functional test exists yet |
| — | Not applicable (N/A row) |

---

## Test Case Table

| TC-ID | Test Case Name | Category | Applicable to C Code | Reason if N/A / Notes | Implemented | Test File :: Function |
|-------|----------------|----------|----------------------|-----------------------|-------------|-----------------------|
| TC-001 | Source `device.properties` on startup | Config & Init | ❌ No | Shell `source device.properties` sets global vars; C uses `rf_hal_property_get()` internal API — no file sourcing | — | — |
| TC-002 | Source `include.properties` on startup | Config & Init | ❌ No | Shell global variable setup from `include.properties`; C uses compile-time / runtime config API | — | — |
| TC-003 | Source `t2Shared_api.sh` T2 library | Config & Init | ❌ No | Shell sources T2 helper script; C links directly to T2 library via `t2_event_s()` — no script dependency | — | — |
| TC-004 | Broadband device type path initialisation | Config & Init | ✅ Yes | `config_init_load()` in `config_manager.c` sets `/opt/minidumps` and `/opt/coredumps` for broadband | ✅ Implemented | `test_unsupported_devicetypes.py` :: `test_broadband_device_type_no_dumps_exits_0`, `test_broadband_minidump_detection_in_core_path` |
| TC-005 | Extender device type path initialisation | Config & Init | ✅ Yes | `config_init_load()` sets `DEVICE_TYPE_EXTENDER` paths (`/opt/minidumps`, `/opt/coredumps`) | ✅ Implemented | `test_unsupported_devicetypes.py` :: `test_extender_device_type_no_dumps_exits_0`, `test_extender_minidump_detection_in_core_path` |
| TC-006 | Secure mode path selection | Config & Init | ✅ Yes | `argv[3]=="secure"` causes `config_init_load()` to select `/opt/secure/minidumps` & `/opt/secure/corefiles` | ✅ Implemented | `test_config_and_path.py` :: `test_secure_mode_selects_secure_minidump_path`, `test_secure_mode_selects_secure_coredump_path` |
| TC-007 | Normal (non-secure) mode path selection | Config & Init | ✅ Yes | Default paths (`/opt/minidumps`, `/opt/coredumps`) used when `argv[3] != "secure"` | ✅ Implemented | `test_config_and_path.py` :: `test_normal_mode_selects_normal_minidump_path` |
| TC-008 | Insufficient arguments → exit(1) | Config & Init | ✅ Yes | `argc < 4` check in `main.c` prints "Number of parameter is less" and calls `exit(1)` | ✅ Implemented | `test_crashupload_arg_parsing.py` :: `test_no_args_exits_with_1`, `test_one_arg_exits_with_1`, `test_two_args_exits_with_1` |
| TC-009 | Dump type selection (minidump / coredump) | Config & Init | ✅ Yes | `argv[2]=="0"` → `DUMP_TYPE_MINIDUMP`; `"1"` → `DUMP_TYPE_COREDUMP` in `config_init_load()` | ✅ Implemented | `test_config_and_path.py` :: `test_coredump_mode_ignores_minidump_files`, `test_minidump_mode_ignores_coredump_files` |
| TC-010 | TLS v1.2 curl flag | Upload | ❌ No | Shell passes `--tlsv1.2` on CLI curl invocation; C `upload.c` uses libcurl `CURLOPT_SSLVERSION` — different implementation path | — | — |
| TC-011 | First instance acquires process lock | Lock Mechanism | ✅ Yes | `acquire_process_lock_or_exit()` in `lock_manager.c` uses `flock(LOCK_EX\|LOCK_NB)` to acquire lock file | ✅ Implemented | `test_lock_lifecycle.py` :: `test_first_instance_acquires_minidump_lock`, `test_first_instance_acquires_coredump_lock` |
| TC-012 | Second instance exits immediately (lock held) | Lock Mechanism | ✅ Yes | Second `flock(LOCK_NB)` call fails → `ERR_LOCK_HELD` → binary prints "already working" and exits | ✅ Implemented | `test_lock_and_exit.py` :: `test_multiple_instance_prevention_minidump`, `test_multiple_instance_prevention_coredump` |
| TC-013 | Wait-for-lock mode blocks until holder exits | Lock Mechanism | ✅ Yes | `argv[4]=="wait_for_lock"` → `acquire_process_lock_or_wait()` loops on blocking `flock()` until previous holder exits | ✅ Implemented | `test_lock_and_wait.py` :: `test_wait_for_lock_minidump`, `test_wait_for_lock_coredump` |
| TC-014 | Lock file removed on clean exit | Lock Mechanism | ✅ Yes | `lock_release()` calls `flock(LOCK_UN)`, closes fd, and `unlink()`s lock file at `cleanup:` label in `main.c` | ✅ Implemented | `test_lock_lifecycle.py` :: `test_lock_removed_on_clean_exit_minidump`, `test_lock_removed_on_clean_exit_coredump` |
| TC-015 | SIGTERM handler removes lock file | Lock Mechanism | ✅ Yes | `handle_signal()` in `main.c` calls `unlink(MINIDUMP_LOCK_FILE)` or `unlink(COREDUMP_LOCK_FILE)` based on `lock_dir_prefix` | ✅ Implemented | `test_signal_lock_cleanup.py` :: `test_sigterm_removes_minidump_lock`, `test_sigterm_removes_coredump_lock` |
| TC-016 | SIGKILL — lock file persists (uncatchable) | Lock Mechanism | ⚠️ Partial | SIGKILL cannot be caught; C handles SIGTERM/SIGINT only. A test can verify lock file remains after `kill -9`, confirming expected uncatchable-signal behavior | ✅ Implemented | `test_lock_lifecycle.py` :: `test_sigkill_lock_file_persists_minidump`, `test_sigkill_lock_file_persists_coredump` |
| TC-017 | Detect minidumps at `/opt/minidumps` (broadband) | Dump Detection | ✅ Yes | `directory_has_pattern(config->minidump_path, ".dmp")` in `prerequisites.c` scans for `.dmp` files | ✅ Implemented | `test_unsupported_devicetypes.py` :: `test_broadband_minidump_detection_in_core_path` |
| TC-018 | Detect minidumps at `/opt/minidumps` (extender) | Dump Detection | ✅ Yes | Same `directory_has_pattern()` call with `DEVICE_TYPE_EXTENDER` paths set by `config_init_load()` | ✅ Implemented | `test_unsupported_devicetypes.py` :: `test_extender_minidump_detection_in_core_path` |
| TC-019 | Detect coredumps at `/opt/coredumps` | Dump Detection | ✅ Yes | `directory_has_pattern(config->core_path, "_core")` in `prerequisites.c` | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_coredump_detection_normal_path` |
| TC-020 | Detect minidump `.dmp` file at secure path | Dump Detection | ✅ Yes | `directory_has_pattern("/opt/secure/minidumps", ".dmp")` returns 1 when `.dmp` file is present | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_minidump_detection_secure_path` |
| TC-021 | Detect coredump `_core` file at secure path | Dump Detection | ✅ Yes | `directory_has_pattern("/opt/secure/corefiles", "_core")` returns 1 when `_core` file is present | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_coredump_detection_secure_path` |
| TC-022 | No dump files found → `exit(0)` | Dump Detection | ✅ Yes | `directory_has_pattern()` returns 0 → `NO_DUMPS_FOUND=5` → `prerequisites_wait()` fails → `goto cleanup` → `exit(0)` | ✅ Implemented | `test_no_dumps_exit.py` :: `test_empty_minidump_dir_exits_with_0`, `test_empty_corefiles_dir_exits_with_0`, `test_wrong_extension_file_exits_with_0`, `test_nonexistent_dump_dir_exits_with_0`; `test_crashupload_failure_return.py` :: `test_prerequisites_no_dumps_exits_with_0` |
| TC-023 | MAC address read and normalised | Device Info | ✅ Yes | `GetEstbMac()` in `platform.c` reads from `MAC_FILE` (`/tmp/.macAddress`); `NormalizeMac()` strips `:` and uppercases | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_mac_address_read_and_normalised` |
| TC-024 | MAC address retrieved from hardware when file empty | Device Info | ✅ Yes | `GetEstbMac()` falls back to hardware interface query when `/tmp/.macAddress` is empty or missing | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_mac_fallback_when_file_missing_or_empty` |
| TC-025 | Model number retrieved from device | Device Info | ⚠️ Partial | `getModelNum()` in `platform.c` uses `common_device_api` internally; differs from shell `getDeviceDetails.sh` invocation but functionally equivalent | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_model_number_retrieved` |
| TC-026 | Model number fallback path | Device Info | ⚠️ Partial | `getModelNum()` C fallback logic exists; maps to a different code path than shell fallback | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_model_number_retrieved` |
| TC-027 | Model number from `getDeviceDetails.sh` | Device Info | ❌ No | Shell-specific: calls `/lib/rdk/getDeviceDetails.sh`; C uses direct `common_device_api` library call — no shell script invocation | — | — |
| TC-028 | SHA1 firmware hash retrieval | Device Info | ⚠️ Partial | `getSHA1()` in `platform.c` reads firmware hash via C API; shell calls `getSHA1` command — same result, different mechanism | ✅ Implemented | `test_config_checks_and_baseline.py` :: `test_sha1_firmware_hash_from_version_txt` |
| TC-029 | Partner ID via `getpartnerid.sh` | Device Info | ❌ No | Shell-specific: invokes `getpartnerid.sh`; C reads partner ID directly via `rf_hal_property_get()` — no script invocation | — | — |
| TC-030 | Partner ID from account management file | Device Info | ❌ No | Shell `grep`s account file for partner ID; no equivalent file-grep logic in C implementation | — | — |
| TC-031 | Wait for network connectivity before upload | Network / Prerequisites | ⚠️ Partial | `prerequisites_wait()` in `prerequisites.c` polls for network readiness; mechanism differs from shell flag-file polling (`/tmp/wifi_ready`, etc.) | 🔲 Not Yet | — |
| TC-032 | Network becomes available → processing proceeds | Network / Prerequisites | ⚠️ Partial | C `prerequisites_wait()` checks network state internally; no dependency on shell-specific flag files | 🔲 Not Yet | — |
| TC-033 | Network timeout → abort | Network / Prerequisites | ⚠️ Partial | C implementation has a configurable retry/timeout loop; failure returns error code, triggering `goto cleanup` | 🔲 Not Yet | — |
| TC-034 | Broadband network via `network_commn_status` | Network / Prerequisites | ❌ No | `network_commn_status` is a pure shell function; no direct equivalent in C implementation | — | — |
| TC-035 | Defer upload when uptime < 480 s | Upload Deferral | ✅ Yes | `defer_upload_if_needed()` in `prerequisites.c` reads `UPTIME_FILE` and sleeps for `DEVICE_TYPE_MEDIACLIENT` when uptime < 480 s | ✅ Implemented | `test_upload_deferral.py` :: `test_deferred_when_uptime_below_threshold` |
| TC-036 | No deferral when uptime ≥ 480 s | Upload Deferral | ✅ Yes | `defer_upload_if_needed()` skips sleep when uptime ≥ 480 s; L2_TEST build uses `/opt/uptime` for controlled values | ✅ Implemented | `test_upload_deferral.py` :: `test_no_deferral_when_uptime_above_threshold` |
| TC-037 | Reboot flag present → skip upload, exit(0) | Upload Deferral | ✅ Yes | `filePresentCheck("/tmp/set_crash_reboot_flag")` returns true inside `defer_upload_if_needed()` → `ret=0` → `goto cleanup` → `exit(0)` | ✅ Implemented | `test_reboot_and_log_scenario.py` :: `test_reboot_flag_present_skips_upload_exits_0` |
| TC-038 | RFC opt-out flag set → skip upload | Telemetry Opt-Out | ✅ Yes | `get_opt_out_status()` in `config_manager.c` queries RFC value; returns opt-out when flag is set | ✅ Implemented | `test_t2_optout.py` :: `test_rfc_optout_set_mediaclient_exits_0` |
| TC-039 | Opt-out file present → skip upload | Telemetry Opt-Out | ✅ Yes | `get_opt_out_status()` additionally checks for presence of opt-out override file on filesystem | ✅ Implemented | `test_t2_optout.py` :: `test_optout_file_absent_upload_not_blocked` |
| TC-040 | Opt-out check only for `MEDIACLIENT` device type | Telemetry Opt-Out | ✅ Yes | `get_opt_out_status()` check is gated on `DEVICE_TYPE_MEDIACLIENT`; other device types bypass this check | ✅ Implemented | `test_t2_optout.py` :: `test_optout_check_bypassed_for_nonmediaclient` |
| TC-041 | On-startup cleanup removes oldest dump files | Cleanup | ✅ Yes | `cleanup_batch()` in `cleanup_batch.c` mtime-sorts files; removes oldest beyond limit; uses `ON_STARTUP_DUMPS_CLEANED_UP_BASE` flag | ✅ Implemented | `test_cleanup_batch.py` :: `test_startup_cleanup_deletes_non_dump_files` |
| TC-042 | Old dump files deleted to enforce limit | Cleanup | ✅ Yes | Files older than newest `MAX_CORE_FILES=4` are deleted during cleanup pass | ✅ Implemented | `test_cleanup_batch.py` :: `test_stale_archive_files_older_than_2_days_deleted` |
| TC-043 | First-run cleanup flag file created | Cleanup | ✅ Yes | `ON_STARTUP_DUMPS_CLEANED_UP_BASE` flag file is created after first-run cleanup completes | ✅ Implemented | `test_cleanup_batch.py` :: `test_first_run_flag_created` |
| TC-044 | Subsequent runs skip first-run cleanup pass | Cleanup | ✅ Yes | Flag file presence detected → `cleanup_batch()` skips first-run cleanup path on re-entry | ✅ Implemented | `test_cleanup_batch.py` :: `test_subsequent_run_skips_startup_cleanup` |
| TC-045 | `MAX_CORE_FILES=4` limit enforced | Cleanup | ✅ Yes | Only the 4 newest files are retained; all older files are deleted by `cleanup_batch()` | ✅ Implemented | `test_cleanup_batch.py` :: `test_max_core_files_limit_enforced` |
| TC-046 | Empty dump directory handled gracefully | Cleanup | ✅ Yes | `cleanup_batch()` handles `opendir()` returning NULL or empty directory without error | ✅ Implemented | `test_cleanup_batch.py` :: `test_empty_dir_handled_gracefully` |
| TC-047 | Upload-on-startup mode (minidump-on-bootup) | Cleanup | ⚠️ Partial | Upload-on-startup flow exists in `main.c` via `minidump-on-bootup-upload.service`; exact behaviour may differ from shell on-startup path | 🔲 Not Yet | — |
| TC-048 | Upload count ≤ 10 → ALLOW_UPLOAD | Rate Limiting | ✅ Yes | `is_upload_limit_reached()` in `ratelimit.c` counts timestamp file lines; ≤ 10 entries → returns `ALLOW_UPLOAD` | ✅ Implemented | `test_ratelimit_allow.py` :: `test_upload_allowed_when_count_at_or_below_limit` |
| TC-049 | Upload count > 10 within window → STOP_UPLOAD | Rate Limiting | ✅ Yes | > 10 lines within `RECOVERY_DELAY_SECONDS` window → `is_upload_limit_reached()` returns `STOP_UPLOAD` | ✅ Implemented | `test_ratelimit.py` :: `test_upload_blocked_when_count_exceeds_10` |
| TC-050 | Rate limiting applied to minidump path only | Rate Limiting | ✅ Yes | `ratelimit_check_unified()` called in `main.c` only for `DUMP_TYPE_MINIDUMP` branch; coredump path skips rate limiting | ✅ Implemented | `test_ratelimit_allow.py` :: `test_coredump_not_rate_limited_by_minidump_counter` |
| TC-051 | Recovery time not yet reached → uploads still blocked | Rate Limiting | ✅ Yes | `is_recovery_time_reached()` reads deny-till timestamp from `/tmp/.deny_dump_uploads_till`; still inside window → blocked | ✅ Implemented | `test_ratelimit.py` :: `test_upload_blocked_when_deny_file_active` |
| TC-052 | Recovery time reached → uploads unblocked | Rate Limiting | ✅ Yes | `is_recovery_time_reached()` returns `true` after window expires → uploads resume normally | 🔲 Not Yet | — |
| TC-053 | Timestamp written to rate limit log after upload | Rate Limiting | ✅ Yes | `set_time()` in `ratelimit.c` appends current timestamp entry to rate limit log file | 🔲 Not Yet | — |
| TC-054 | Rate limit counter resets after recovery period | Rate Limiting | ✅ Yes | Timestamps older than `RECOVERY_DELAY_SECONDS` are not counted; counter effectively resets after recovery period | 🔲 Not Yet | — |
| TC-055 | Timestamp written in truncated integer format | Rate Limiting | ✅ Yes | `set_time()` writes truncated (integer) timestamp — fractional seconds stripped before writing | 🔲 Not Yet | — |
| TC-056 | Timestamp suppressed for non-production builds | Rate Limiting | ❌ No | Shell silences timestamp writes when `BUILD_TYPE` is non-prod; C `ratelimit.c` always writes timestamp regardless of build type | — | — |
| TC-057 | Filename sanitisation preserves container delimiter | Dump Processing | ✅ Yes | `sanitize_filename_preserve_container()` in `scanner.c` preserves the `<#=#>` delimiter and container name suffix intact | ✅ Implemented | `test_scanner_behaviour.py` :: `test_container_delimiter_preserved_in_sanitization` |
| TC-058 | Special characters in filename replaced with `_` | Dump Processing | ✅ Yes | Non-alphanumeric chars (excluding `-`, `.`, `_`) are replaced with `_` by `sanitize_filename_preserve_container()` | ✅ Implemented | `test_scanner_behaviour.py` :: `test_forbidden_chars_dropped_from_filename` |
| TC-059 | Container name preserved after sanitisation | Dump Processing | ✅ Yes | Text after `<#=#>` delimiter is kept verbatim through the sanitisation pass | ✅ Implemented | `test_scanner_behaviour.py` :: `test_container_name_preserved_with_forbidden_chars` |
| TC-060 | Skip existing `.tgz` archive files | Dump Processing | ✅ Yes | Dump iteration loop in `main.c` skips files whose extension matches `.tgz` to avoid re-processing already-archived dumps | ✅ Implemented | `test_dump_processing.py` :: `test_existing_tgz_not_re_archived` |
| TC-061 | Archive filename includes MAC + timestamp + pname + version | Dump Processing | ✅ Yes | Output archive named `<mac>_<timestamp>_<pname>_<version>.tgz`; assembled in `main.c` / `archive.c` | 🔲 Not Yet | — |
| TC-062 | Archive filename truncated at 135 characters | Dump Processing | ✅ Yes | `trim_process_name_in_path()` in `main.c` enforces 135-character filename limit for archive names | 🔲 Not Yet | — |
| TC-063 | `mpeos-main` process name mapped correctly | Dump Processing | ✅ Yes | `mpeos-main` recognised and mapped to its standardised archive name during dump naming in `main.c` | 🔲 Not Yet | — |
| TC-064 | Dump filename components parsed correctly | Dump Processing | ✅ Yes | `extract_pname()` and `extract_appname()` in `scanner.c` parse process name and application name from dump filename | ✅ Implemented | `test_scanner_behaviour.py` :: `test_dump_filename_components_parsed_correctly` |
| TC-065 | Archive created with dump file and associated logs | Archive Creation | ✅ Yes | `archive_create_smart()` in `archive.c` produces a `.tgz` containing the dump file and all mapped log files | 🔲 Not Yet | — |
| TC-066 | Archive contains all required files | Archive Creation | ✅ Yes | `archive_create_smart()` verifies each required file is added; returns error if mandatory file missing | 🔲 Not Yet | — |
| TC-067 | Broadband-specific log archive behaviour | Archive Creation | ⚠️ Partial | Broadband archive logic exists in `archive.c` but the set of included logs differs from the shell implementation | 🔲 Not Yet | — |
| TC-068 | `/tmp` free-space check before archiving | Archive Creation | ❌ No | Shell checks `/tmp` free space before creating archive; C `archive_create_smart()` performs no disk-space pre-check | — | — |
| TC-069 | Archive retry when `/tmp` disk is full | Archive Creation | ❌ No | Shell retries archive creation using a fallback `copy_log_files_tmp_dir` path; C has no equivalent retry mechanism | — | — |
| TC-070 | Temporary directory cleanup after archive | Archive Creation | ❌ No | Shell-specific temp directory copy-and-cleanup pattern (`copy_log_files_tmp_dir`); not present in C | — | — |
| TC-071 | Zero-size dump file skipped | Dump Processing | ✅ Yes | `stat()`-based size check in `scanner.c` / `archive.c` detects and skips zero-byte dump files | ✅ Implemented | `test_dump_processing.py` :: `test_zero_size_dump_handled_gracefully` |
| TC-072 | Process crash telemetry event sent | Crash Telemetry | ✅ Yes | `t2_event_s(T2_EVENT_PROCESS_CRASH, ...)` called in `scanner.c` when a process crash dump is processed | 🔲 Not Yet | — |
| TC-073 | Container crash telemetry event sent | Crash Telemetry | ✅ Yes | `t2_event_s(T2_EVENT_CONTAINER_CRASH, ...)` called in `scanner.c` when a container crash dump is detected | 🔲 Not Yet | — |
| TC-074 | Telemetry on tarball-retry (isTgz) detection | Crash Telemetry | ❌ No | Shell-specific: `isTgz` checks if re-upload of a previous tarball is happening and emits telemetry; no equivalent in C | — | — |
| TC-075 | Log files mapped for crashed process | Log File Mapping | ✅ Yes | `lookup_log_files_for_proc()` in `scanner.c` parses `LOGMAPPER_FILE_PATH` to find log files associated with the crashed process | 🔲 Not Yet | — |
| TC-076 | Log file lines capped at 500 (production build) | Log File Mapping | ❌ No | Shell truncates log files to 500 lines for prod `BUILD_TYPE`; C adds entire log file to archive without line-count limits | — | — |
| TC-077 | Log file lines capped at 5000 (non-production build) | Log File Mapping | ❌ No | Shell truncates log files to 5000 lines for non-prod builds; C has no build-type-based line-count limit | — | — |
| TC-078 | Missing log file handled gracefully | Log File Mapping | ✅ Yes | `scanner.c` checks file existence (`filePresentCheck()`) before adding to archive; missing log file is skipped with a warning log | 🔲 Not Yet | — |
| TC-079 | `crashed_url.txt` generated with upload URL | Log File Mapping | ✅ Yes | `crashed_url.txt` written with the S3 upload URL in `scanner.c` / `archive.c` before archive is finalised | 🔲 Not Yet | — |
| TC-080 | All associated log files added to archive | Log File Mapping | ✅ Yes | `archive_add_file()` called for each log file returned by `lookup_log_files_for_proc()`; all mapped logs included | 🔲 Not Yet | — |
| TC-081 | Upload succeeds on first attempt | Upload | ✅ Yes | `upload_file()` in `upload.c` returns `UPLOAD_SUCCESS` on first successful libcurl transfer | 🔲 Not Yet | — |
| TC-082 | Upload retried up to 3 times on failure | Upload | ✅ Yes | `MAX_RETRIES=3` in `upload.c`; failed libcurl call triggers `sleep(RETRY_DELAY_SECONDS=5)` and retry loop | 🔲 Not Yet | — |
| TC-083 | Upload permanently fails after 3 retries → error logged | Upload | ✅ Yes | After 3 consecutive failures `upload_file()` logs error and returns failure code to caller | 🔲 Not Yet | — |
| TC-084 | Fallback to alternative upload path | Upload | ⚠️ Partial | C fallback upload path is not fully defined; shell falls back to an alternative upload script — C design is TBD | 🔲 Not Yet | — |
| TC-085 | Single instance lock prevents duplicate execution | Lock Mechanism | ✅ Yes | `acquire_process_lock_or_exit()` prevents a second concurrent instance — identical mechanism to TC-012 | ✅ Implemented | `test_lock_and_exit.py` :: `test_multiple_instance_prevention_minidump`, `test_multiple_instance_prevention_coredump` |

---

## Coverage Statistics

| Metric | Count |
|--------|-------|
| Total TCs in `uploadDumps_TestCases.md` | 85 |
| ✅ Applicable to C implementation | 60 |
| ⚠️ Partially applicable | 10 |
| ❌ Not applicable (shell-only) | 15 |
| **Applicable TCs with L2 tests** | **46** |
| **Applicable TCs without L2 tests** | **24** |

### Applicable TCs — Coverage Breakdown by Category

| Category | Total TCs | ✅ Yes | ⚠️ Partial | ❌ No | Implemented |
|----------|-----------|--------|------------|-------|-------------|
| Config & Init | 9 | 8 | 0 | 1 | 6 (TC-004, TC-005, TC-006, TC-007, TC-008, TC-009) |
| Lock Mechanism | 7 | 6 | 1 | 0 | 7 (TC-011, TC-012, TC-013, TC-014, TC-015, TC-016, TC-085) |
| Dump Detection | 6 | 6 | 0 | 0 | 6 (TC-017, TC-018, TC-019, TC-020, TC-021, TC-022) |
| Device Info | 8 | 2 | 3 | 3 | 5 (TC-023, TC-024, TC-025, TC-026, TC-028) |
| Network / Prerequisites | 4 | 0 | 3 | 1 | 0 |
| Upload Deferral | 3 | 3 | 0 | 0 | 3 (TC-035, TC-036, TC-037) |
| Telemetry Opt-Out | 3 | 3 | 0 | 0 | 3 (TC-038, TC-039, TC-040) |
| Cleanup | 7 | 6 | 1 | 0 | 6 (TC-041, TC-042, TC-043, TC-044, TC-045, TC-046) |
| Rate Limiting | 9 | 8 | 0 | 1 | 4 (TC-048, TC-049, TC-050, TC-051) |
| Dump Processing & Naming | 8 | 8 | 0 | 0 | 6 (TC-057, TC-058, TC-059, TC-060, TC-064, TC-071) |
| Archive Creation | 6 | 2 | 1 | 3 | 0 |
| Crash Telemetry | 4 | 2 | 0 | 2 | 0 |
| Log File Mapping | 6 | 4 | 0 | 2 | 0 |
| Upload | 4 | 3 | 1 | 0 | 0 |
| **Total** | **85** | **60** | **10** | **15** | **46** |

---

## Extra L2 Tests (No Matching TC in `uploadDumps_TestCases.md`)

These tests were added to cover C-specific behaviour not captured in the original shell-oriented TCs.
TC-IDs prefixed with **`C-TC-`** denote C-implementation-specific test cases.

| TC-ID | Test File :: Function | Description |
|-------|-----------------------|-------------|
| C-TC-001 | `test_crashupload_failure_return.py` :: `test_system_initialize_failure_exits_with_1` | Verifies `system_initialize()` failure (unwritable `/opt/logs`) causes `exit(1)` |
| C-TC-002 | `test_reboot_and_log_scenario.py` :: `test_binary_produces_log_output` | Verifies binary always emits log output to stdout (logger init / exit) regardless of dump presence |

---

## Not-Applicable TCs — Summary

| TC-IDs | Reason |
|--------|--------|
| TC-001, TC-002, TC-003 | Shell `source` of `.properties` / `.sh` files; C uses internal `rf_hal_property_get()` API |
| TC-010 | Shell passes `--tlsv1.2` on CLI curl; C uses libcurl `CURLOPT_SSLVERSION` |
| TC-027 | Shell invokes `getDeviceDetails.sh`; C uses `common_device_api` library call |
| TC-029, TC-030 | Shell invokes `getpartnerid.sh` / greps account file; C uses `rf_hal_property_get()` |
| TC-034 | `network_commn_status` is a pure shell function; no C equivalent |
| TC-056 | Shell suppresses rate-limit timestamps for non-prod `BUILD_TYPE`; C always writes timestamps |
| TC-068, TC-069, TC-070 | Shell `/tmp` disk-space check + `copy_log_files_tmp_dir` retry; not implemented in C |
| TC-074 | Shell `isTgz` tarball-retry detection telemetry; no C equivalent |
| TC-076, TC-077 | Shell per-build-type log line-count caps (500 / 5000); C copies full log files |

---

## C Source ↔ TC Mapping Reference

| C Source File | Key Functions | Related TCs |
|---------------|---------------|-------------|
| `config/config_manager.c` | `config_init_load()`, `get_opt_out_status()` | TC-004–009, TC-038–040 |
| `init/system_init.c` | `system_initialize()` | TC-004 (init failure path) |
| `platform/platform.c` | `GetEstbMac()`, `NormalizeMac()`, `getModelNum()`, `getSHA1()` | TC-023–028 |
| `utils/prerequisites.c` | `prerequisites_wait()`, `directory_has_pattern()`, `defer_upload_if_needed()` | TC-017–022, TC-031–037 |
| `lock/lock_manager.c` | `acquire_process_lock_or_exit()`, `acquire_process_lock_or_wait()`, `lock_release()` | TC-011–016, TC-085 |
| `ratelimit/ratelimit.c` | `is_upload_limit_reached()`, `is_recovery_time_reached()`, `set_time()` | TC-048–055 |
| `scanner/scanner.c` | `sanitize_filename_preserve_container()`, `extract_pname()`, `lookup_log_files_for_proc()` | TC-057–059, TC-064, TC-071–073, TC-075, TC-078–080 |
| `archive/archive.c` | `archive_create_smart()`, `archive_add_file()` | TC-060–067, TC-071, TC-079–080 |
| `upload/upload.c` | `upload_file()` | TC-081–083 |
| `cleanup/cleanup_batch.c` | `cleanup_batch()` | TC-041–047 |
| `main.c` | Signal handler, dump loop, `trim_process_name_in_path()` | TC-008–009, TC-015–016, TC-060–063 |
