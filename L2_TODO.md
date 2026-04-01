# L2 Test TODO — CrashUpload C Implementation

Tracks which applicable TCs still need L2 functional tests.

**Reference:** `L2_TESTS.md` for full TC table and coverage statistics.

---

## ✅ Applicable + Implemented — 65 TCs

| TC-ID | Test Case Name |
|-------|----------------|
| TC-004 | Broadband device type path initialisation |
| TC-005 | Extender device type path initialisation |
| TC-006 | Secure mode path selection |
| TC-007 | Normal (non-secure) mode path selection |
| TC-008 | Insufficient arguments → exit(1) |
| TC-009 | Dump type selection (minidump / coredump) |
| TC-011 | First instance acquires process lock |
| TC-012 | Second instance exits immediately (lock held) |
| TC-013 | Wait-for-lock mode blocks until holder exits |
| TC-014 | Lock file removed on clean exit |
| TC-015 | SIGTERM handler removes lock file |
| TC-016 | SIGKILL — lock file persists (uncatchable) |
| TC-017 | Detect minidumps at `/opt/minidumps` (broadband) |
| TC-018 | Detect minidumps at `/opt/minidumps` (extender) |
| TC-019 | Detect coredumps at `/opt/coredumps` |
| TC-020 | Detect minidump `.dmp` file at secure path |
| TC-021 | Detect coredump `_core` file at secure path |
| TC-022 | No dump files found → exit(0) |
| TC-023 | MAC address read and normalised |
| TC-024 | MAC address retrieved from hardware when file empty |
| TC-025 | Model number retrieved from device |
| TC-026 | Model number fallback path |
| TC-028 | SHA1 firmware hash retrieval |
| TC-035 | Defer upload when uptime < 480 s |
| TC-036 | No deferral when uptime ≥ 480 s |
| TC-037 | Reboot flag present → skip upload, exit(0) |
| TC-038 | RFC opt-out flag set → skip upload |
| TC-039 | Opt-out file present → skip upload |
| TC-040 | Opt-out check only for `MEDIACLIENT` device type |
| TC-041 | On-startup cleanup removes oldest dump files |
| TC-042 | Old dump files deleted to enforce limit |
| TC-043 | First-run cleanup flag file created |
| TC-044 | Subsequent runs skip first-run cleanup pass |
| TC-045 | `MAX_CORE_FILES=4` limit enforced |
| TC-046 | Empty dump directory handled gracefully |
| TC-047 | Upload-on-startup mode — `/opt/.upload_on_startup` removed on coredump run |
| TC-048 | Upload count ≤ 10 → ALLOW_UPLOAD |
| TC-049 | Upload count > 10 within window → STOP_UPLOAD |
| TC-050 | Rate limiting applied to minidump path only |
| TC-051 | Recovery time not yet reached → uploads still blocked |
| TC-052 | Recovery time expired → uploads unblocked |
| TC-054 | Rate-limit counter reset after recovery period |
| TC-057 | Filename sanitisation preserves container delimiter |
| TC-058 | Special characters in filename replaced with `_` |
| TC-059 | Container name preserved after sanitisation |
| TC-060 | Skip existing `.tgz` archive files |
| TC-061 | Archive filename includes MAC + timestamp + pname + version |
| TC-062 | Archive filename truncated at 135 characters |
| TC-063 | `mpeos-main` process name mapped correctly |
| TC-064 | Dump filename components parsed correctly |
| TC-065 | Archive created with dump file and associated logs |
| TC-066 | Archive contains all required files |
| TC-067 | Broadband-specific log archive behaviour |
| TC-071 | Zero-size dump file skipped |
| TC-072 | Process crash telemetry event sent |
| TC-073 | Container crash telemetry event sent |
| TC-075 | Log files mapped for crashed process |
| TC-078 | Missing log file handled gracefully |
| TC-079 | `crashed_url.txt` generated with upload URL |
| TC-080 | All associated log files added to archive |
| TC-053 | Rate-limit check passes when no deny file present (is_recovery_time_reached) | Rate Limiting |
| TC-055 | set_time() writes timestamps in integer format (no fractional seconds) | Rate Limiting |
| TC-081 | Upload succeeds on first attempt | Upload |
| TC-082 | Upload retried up to 3 times on failure | Upload |
| TC-083 | Upload permanently fails after 3 retries → error logged | Upload |
| TC-085 | Single instance lock prevents duplicate execution |

---

## 🔲 Applicable + Not Implemented — 0 TCs

*(All applicable TCs now have L2 test coverage.)*

---

## ❌ Not Applicable — 19 TCs

These TCs cover shell-specific behaviour or unimplemented C stubs with no equivalent in the C implementation.
See `L2_TESTS.md` "Not-Applicable TCs — Summary" for the reason each was excluded.

### Config & Init — 3

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-001 | Source `device.properties` on startup | Shell `source` sets global vars; C uses `rf_hal_property_get()` API internally |
| TC-002 | Source `include.properties` on startup | Shell global variable setup; C uses compile-time / runtime config API |
| TC-003 | Source `t2Shared_api.sh` T2 library | Shell sources T2 helper script; C links T2 library directly |

### Network / Prerequisites — 4

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-031 | Wait for network connectivity before upload | Network-wait loop is an unimplemented TODO stub in `prerequisites_wait()` |
| TC-032 | Network becomes available → processing proceeds | Depends on same unimplemented network-wait loop as TC-031 |
| TC-033 | Network timeout → abort | Depends on same unimplemented network-wait loop; no timeout path exists |
| TC-034 | Broadband network via `network_commn_status` | Pure shell function; no direct equivalent in C |

### Device Info — 3

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-027 | Model number from `getDeviceDetails.sh` | Shell-specific; C uses `common_device_api` library call directly |
| TC-029 | Partner ID via `getpartnerid.sh` | Shell-specific; C reads partner ID via `rf_hal_property_get()` |
| TC-030 | Partner ID from account management file | Shell `grep`s account file; no equivalent file-grep logic in C |

### Rate Limiting — 1

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-056 | Timestamp suppressed for non-production builds | Shell silences timestamp writes for non-prod; C `ratelimit.c` always writes regardless of build type |

### Upload — 2

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-010 | TLS v1.2 curl flag | Shell passes `--tlsv1.2` on CLI curl; C uses libcurl `CURLOPT_SSLVERSION` |
| TC-084 | Fallback to alternative upload path | Fallback path is `TODO: SUPPORT NOT AVAILABLE` stub in `upload.c`; feature not implemented |

### Archive Creation — 3

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-068 | `/tmp` free-space check before archiving | Shell pre-checks `/tmp` disk space; C `archive_create_smart()` has no disk-space check |
| TC-069 | Archive retry when `/tmp` disk is full | Shell retries via `copy_log_files_tmp_dir` fallback; C has no retry mechanism |
| TC-070 | Temporary directory cleanup after archive | Shell-specific temp directory copy-and-cleanup pattern; not present in C |

### Crash Telemetry — 1

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-074 | Telemetry on tarball-retry (`isTgz`) detection | Shell-specific `isTgz` re-upload detection; no equivalent in C |

### Log File Mapping — 2

| TC-ID | Test Case Name | Reason |
|-------|----------------|--------|
| TC-076 | Log file lines capped at 500 (production build) | Shell truncates to 500 lines for prod; C archives entire log without line-count limits |
| TC-077 | Log file lines capped at 5000 (non-production build) | Shell truncates to 5000 lines for non-prod; C has no build-type-based line-count limit |

---

## Summary

| Status | Count |
|--------|-------|
| Total TCs in `uploadDumps_TestCases.md` | 85 |
| ❌ Not Applicable | 19 |
| ✅ Applicable — total | 66 |
| &nbsp;&nbsp;&nbsp;✅ Implemented | 66 |
| &nbsp;&nbsp;&nbsp;🔲 Pending | 0 |
