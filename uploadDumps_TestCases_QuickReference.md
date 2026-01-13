# Test Cases Quick Reference - Prioritized by Functionality Impact

## HIGH Priority (25 Test Cases)

| TC# | Test Case Name |
|-----|----------------|
| TC-001 | Configuration Files Loading - All Files Present |
| TC-004 | Device Type Detection - Broadband Device |
| TC-005 | Device Type Detection - Extender Device |
| TC-008 | Dump Flag Selection - Coredump Mode |
| TC-009 | Dump Flag Selection - Minidump Mode |
| TC-011 | Lock Creation - First Instance |
| TC-012 | Lock Creation - Second Instance Without Wait |
| TC-014 | Lock Removal - Normal Exit |
| TC-015 | Lock Removal - SIGTERM Signal |
| TC-016 | Lock Removal - SIGKILL/SIGTERM Signal |
| TC-017 | Dump File Detection - Broadband Device with Dumps |
| TC-018 | Dump File Detection - Broadband Device without Dumps |
| TC-019 | Dump File Detection - Extender Device with Dumps |
| TC-020 | Dump File Detection - Video Device with Minidumps |
| TC-021 | Dump File Detection - Video Device with Coredumps |
| TC-022 | Dump File Detection - No Dumps Available |
| TC-023 | MAC Address Validation - Valid MAC |
| TC-065 | Archive Creation - Coredump Mode |
| TC-066 | Archive Creation - Minidump Mode Video Device |
| TC-067 | Archive Creation - Minidump Mode Broadband Device |
| TC-081 | S3 Upload - First Attempt Success |
| TC-082 | S3 Upload - Retry Logic |
| TC-083 | S3 Upload - All Retries Failed |
| TC-084 | Verify Fall back path |
| TC-085 | Verify Only single instance should run |

---

## MEDIUM Priority (38 Test Cases)

| TC# | Test Case Name |
|-----|----------------|
| TC-006 | Upload Flag - Secure Mode |
| TC-007 | Upload Flag - Normal Mode |
| TC-010 | TLS Configuration - Yocto Device |
| TC-025 | Model Number Retrieval - Broadband Device |
| TC-026 | Model Number Retrieval - Extender Device |
| TC-027 | Model Number Retrieval - Video Device |
| TC-028 | SHA1 Build ID Retrieval |
| TC-031 | Network Check - Video Device Boot Sequence |
| TC-032 | Network Check - Route Not Available |
| TC-033 | Network Check - System Time Not Received |
| TC-034 | Network Check - Broadband Device |
| TC-035 | Upload Defer - Video Device Early Boot |
| TC-036 | Upload Defer - Video Device After Boot |
| TC-037 | Upload Defer - Crash During Defer Period |
| TC-038 | Telemetry Opt-Out Check - Enabled and Opted Out |
| TC-039 | Telemetry Opt-Out Check - Not Opted Out |
| TC-041 | Cleanup - Old Files Removal |
| TC-043 | Cleanup - Startup Cleanup First Run |
| TC-044 | Cleanup - Startup Cleanup Subsequent Runs |
| TC-045 | Cleanup - Maximum Core Files Limit |
| TC-048 | Upload Limit Check - Under Limit |
| TC-049 | Upload Limit Check - Limit Reached |
| TC-050 | Upload Limit Check - Coredump Exemption |
| TC-051 | Recovery Time Check - Before Recovery |
| TC-052 | Recovery Time Check - After Recovery |
| TC-053 | Recovery Time Check - No Recovery File |
| TC-055 | Timestamp File Management - Truncation |
| TC-057 | File Sanitization - Special Characters Removed |
| TC-058 | File Sanitization - Container Delimiter Preserved |
| TC-060 | Tarball Detection - Skip Already Archived |
| TC-061 | Dump File Naming - Standard Format |
| TC-062 | Dump File Naming - Long Filename Truncation |
| TC-063 | Dump File Naming - Already Processed |
| TC-064 | Coredump Naming - mpeos-main Exception |
| TC-068 | Archive Creation - Compression Failure Retry |
| TC-070 | Archive Creation - /tmp Space Check |
| TC-072 | Crash Telemetry - Standard Process Crash |
| TC-073 | Crash Telemetry - Container Crash |
| TC-074 | Crash Telemetry - Tarball Retry Detection |
| TC-075 | Log File Mapping - Process to Log Files |
| TC-076 | Log File Addition - Production Build |
| TC-077 | Log File Addition - Non-Production Build |

---

## LOW Priority (21 Test Cases)

| TC# | Test Case Name |
|-----|----------------|
| TC-002 | Configuration Files Loading - Missing device.properties |
| TC-003 | Configuration Files Loading - Missing include.properties |
| TC-013 | Lock Creation - Second Instance With Wait |
| TC-024 | MAC Address Validation - Empty MAC File |
| TC-029 | Partner ID Retrieval - Standard Device |
| TC-030 | Partner ID Retrieval - Extender Device |
| TC-040 | Telemetry Opt-Out Check - Non-MediaClient Device |
| TC-042 | Cleanup - Version File Removal |
| TC-046 | Cleanup - Empty Working Directory |
| TC-047 | Cleanup - Upload on Startup Mode |
| TC-054 | Recovery Time Check - Invalid File Content |
| TC-056 | Timestamp File Management - Non-Prod Build |
| TC-059 | File Sanitization - Empty Result |
| TC-069 | Archive Creation - Compression Failure Final |
| TC-071 | Zero Size Dump Detection |
| TC-078 | Log File Addition - Missing Log Files |
| TC-079 | Crashed URL File Addition - Video Device |
| TC-080 | Crashed URL File Addition - File Missing |

---

## Summary

- **Total Test Cases**: 84
- **HIGH Priority**: 25 (29.8%)
- **MEDIUM Priority**: 38 (45.2%)
- **LOW Priority**: 21 (25.0%)

**Note**: Prioritization is based on functionality impact, not implementation order or execution sequence.
