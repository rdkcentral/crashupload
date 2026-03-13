# L2 Test TODO — CrashUpload C Implementation

Tracks which applicable TCs still need L2 functional tests.

**Reference:** `L2_TESTS.md` for full TC table and coverage statistics.

---

## ✅ Applicable + Implemented — 46 TCs

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
| TC-048 | Upload count ≤ 10 → ALLOW_UPLOAD |
| TC-049 | Upload count > 10 within window → STOP_UPLOAD |
| TC-050 | Rate limiting applied to minidump path only |
| TC-051 | Recovery time not yet reached → uploads still blocked |
| TC-057 | Filename sanitisation preserves container delimiter |
| TC-058 | Special characters in filename replaced with `_` |
| TC-059 | Container name preserved after sanitisation |
| TC-060 | Skip existing `.tgz` archive files |
| TC-064 | Dump filename components parsed correctly |
| TC-071 | Zero-size dump file skipped |
| TC-085 | Single instance lock prevents duplicate execution |

---

## 🔲 Applicable + Not Implemented — 24 TCs

### Not Upload Related — 20

| TC-ID | Test Case Name | Category |
|-------|----------------|----------|
| TC-031 | Wait for network connectivity before upload | Network / Prerequisites |
| TC-032 | Network becomes available → processing proceeds | Network / Prerequisites |
| TC-033 | Network timeout → abort | Network / Prerequisites |
| TC-047 | Upload-on-startup mode (minidump-on-bootup) | Cleanup |
| TC-052 | Recovery time reached → uploads unblocked | Rate Limiting |
| TC-053 | Timestamp written to rate limit log after upload | Rate Limiting |
| TC-054 | Rate limit counter resets after recovery period | Rate Limiting |
| TC-055 | Timestamp written in truncated integer format | Rate Limiting |
| TC-061 | Archive filename includes MAC + timestamp + pname + version | Dump Processing |
| TC-062 | Archive filename truncated at 135 characters | Dump Processing |
| TC-063 | `mpeos-main` process name mapped correctly | Dump Processing |
| TC-065 | Archive created with dump file and associated logs | Archive Creation |
| TC-066 | Archive contains all required files | Archive Creation |
| TC-067 | Broadband-specific log archive behaviour | Archive Creation |
| TC-072 | Process crash telemetry event sent | Crash Telemetry |
| TC-073 | Container crash telemetry event sent | Crash Telemetry |
| TC-075 | Log files mapped for crashed process | Log File Mapping |
| TC-078 | Missing log file handled gracefully | Log File Mapping |
| TC-079 | `crashed_url.txt` generated with upload URL | Log File Mapping |
| TC-080 | All associated log files added to archive | Log File Mapping |

### Upload Related — 4

| TC-ID | Test Case Name | Category |
|-------|----------------|----------|
| TC-081 | Upload succeeds on first attempt | Upload |
| TC-082 | Upload retried up to 3 times on failure | Upload |
| TC-083 | Upload permanently fails after 3 retries → error logged | Upload |
| TC-084 | Fallback to alternative upload path | Upload |
