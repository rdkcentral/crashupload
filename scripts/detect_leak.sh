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
# detect_leak.sh - Run crashupload under libmemfnswrap.so
#
# Instruments the crashupload binary with LD_PRELOAD and records one report
# per short-lived case. These cases stay on the early-exit paths:
#   0) too few arguments            -> exit 1
#   1) empty minidump scan          -> exit 0
#   2) empty coredump scan          -> exit 0
#
# Upload, the inotify watcher, and long deferral sleeps are not exercised.
# On exit, libmemfnswrap.so writes /tmp/hp_<pid>_atexit.dat,
# /tmp/hpf_<pid>_atexit.dat, and /tmp/smaps_<pid>_atexit.txt. Those files
# are copied next to the text report. This script does not fail on the
# contents of the heap-walk files. Pass/fail is the process exit code.
#
# Usage:
#   sh scripts/detect_leak.sh
#   sh scripts/detect_leak.sh --help
#
# Environment variables:
#   MEMLEAK_INSTALL_DIR  - memleakutil prefix (default: /tmp/memleakutil-install)
#   CRASHUPLOAD_BIN      - crashupload binary (default: /usr/local/bin/crashupload,
#                          then c_sourcecode/src/crashupload)
#   LEAK_REPORT_DIR      - report directory (default: /tmp/crashupload-leak-reports)
#   LEAK_CASE_TIMEOUT    - seconds before a case is killed (default: 60)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

MEMLEAK_INSTALL_DIR="${MEMLEAK_INSTALL_DIR:-/tmp/memleakutil-install}"
LEAK_REPORT_DIR="${LEAK_REPORT_DIR:-/tmp/crashupload-leak-reports}"
LEAK_CASE_TIMEOUT="${LEAK_CASE_TIMEOUT:-60}"

if [ -z "${CRASHUPLOAD_BIN:-}" ]; then
    if [ -x /usr/local/bin/crashupload ]; then
        CRASHUPLOAD_BIN="/usr/local/bin/crashupload"
    elif [ -x "${PROJECT_ROOT}/c_sourcecode/src/crashupload" ]; then
        CRASHUPLOAD_BIN="${PROJECT_ROOT}/c_sourcecode/src/crashupload"
    else
        CRASHUPLOAD_BIN="/usr/local/bin/crashupload"
    fi
fi

print_help() {
    cat << 'EOF'
detect_leak.sh - Memory leak detection for crashupload

USAGE:
  sh scripts/detect_leak.sh
  sh scripts/detect_leak.sh --help

CASES:
  0) crashupload                         expect exit 1
  1) crashupload "" 0 secure             expect exit 0 (no minidumps)
  2) crashupload "" 1 secure             expect exit 0 (no coredumps)

ENVIRONMENT VARIABLES:
  MEMLEAK_INSTALL_DIR   Path to memleakutil installation
                        (default: /tmp/memleakutil-install)
  CRASHUPLOAD_BIN       Path to the crashupload binary
                        (default: /usr/local/bin/crashupload)
  LEAK_REPORT_DIR       Output directory for leak reports
                        (default: /tmp/crashupload-leak-reports)
  LEAK_CASE_TIMEOUT     Per-case timeout in seconds (default: 60)

NOTES:
  - Build memleakutil first: sh scripts/build_memleak.sh
  - Build crashupload first: ./cov_build.sh
  - Dump files matching .dmp or _core are moved aside for the run and restored
    on exit. Lock files /tmp/.uploadMinidumps and /tmp/.uploadCoredumps are removed.
  - RDK logger output may not appear on stdout. A missing log phrase does not
    fail a case. The exit code does.
  - In CI this script is advisory. detect_leak.yml reports a warning and does
    not fail the native build workflow.

EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    print_help
    exit 0
fi

if [ "$#" -gt 0 ]; then
    printf "%s\n" "ERROR: Unknown option: $1"
    print_help
    exit 1
fi

printf "%s\n" "================================================"
printf "%s\n" "  Crashupload Leak Detection Runner"
printf "%s\n\n" "================================================"

if [ ! -f "${MEMLEAK_INSTALL_DIR}/lib/libmemfnswrap.so" ]; then
    printf "%s\n\n" "ERROR: memleakutil not found at ${MEMLEAK_INSTALL_DIR}"
    printf "%s\n" "Please build memleakutil first:"
    echo "  sh scripts/build_memleak.sh"
    exit 1
fi

if [ ! -x "${CRASHUPLOAD_BIN}" ]; then
    printf "%s\n\n" "ERROR: crashupload binary not found at ${CRASHUPLOAD_BIN}"
    printf "%s\n" "Please build crashupload first:"
    echo "  ./cov_build.sh"
    exit 1
fi

mkdir -p "${LEAK_REPORT_DIR}"
printf "%s\n" "Clearing previous leak reports from ${LEAK_REPORT_DIR}..."
find "${LEAK_REPORT_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} \; 2>/dev/null || true
printf "%s\n\n" "Previous leak reports cleared"

STASH_DIR="$(mktemp -d /tmp/crashupload-leak-stash.XXXXXX)"
: > "${STASH_DIR}/manifest"

stash_matching() {
    dir="$1"
    pat="$2"
    mkdir -p "${dir}"
    for f in "${dir}"/*; do
        [ -f "${f}" ] || continue
        base=$(basename "${f}")
        # shellcheck disable=SC2254
        case "${base}" in
            ${pat})
                token=$(printf '%s' "${f}" | tr '/' '_')
                mv "${f}" "${STASH_DIR}/${token}"
                printf '%s|%s\n' "${STASH_DIR}/${token}" "${f}" >> "${STASH_DIR}/manifest"
                ;;
        esac
    done
}

restore_stashed() {
    if [ ! -f "${STASH_DIR}/manifest" ]; then
        return 0
    fi
    while IFS='|' read -r src dest; do
        [ -n "${src}" ] || continue
        [ -n "${dest}" ] || continue
        [ -f "${src}" ] || continue
        dest_dir=$(dirname "${dest}")
        mkdir -p "${dest_dir}"
        mv "${src}" "${dest}"
    done < "${STASH_DIR}/manifest"
}

cleanup_env() {
    restore_stashed
    rm -f /tmp/.uploadMinidumps /tmp/.uploadCoredumps
    rm -rf "${STASH_DIR}"
}
trap cleanup_env EXIT

prepare_scan_dirs() {
    mkdir -p \
        /opt/logs \
        /var/log \
        /opt/secure/minidumps \
        /opt/secure/corefiles \
        /opt/minidumps \
        /var/lib/systemd/coredump \
        /minidumps \
        /opt/corefiles
    touch /opt/logs/core_log.txt /opt/logs/core_log.txt.0
    if [ ! -e /var/log/messages ]; then
        touch /var/log/messages
    fi

    for dir in \
        /opt/secure/minidumps \
        /opt/secure/corefiles \
        /opt/minidumps \
        /var/lib/systemd/coredump \
        /minidumps \
        /opt/corefiles
    do
        stash_matching "${dir}" '*.dmp*'
        stash_matching "${dir}" '*_core*'
    done

    rm -f /tmp/.uploadMinidumps /tmp/.uploadCoredumps
}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_0="${LEAK_REPORT_DIR}/leak_report_0_args_${TIMESTAMP}.txt"
REPORT_1="${LEAK_REPORT_DIR}/leak_report_1_minidump_${TIMESTAMP}.txt"
REPORT_2="${LEAK_REPORT_DIR}/leak_report_2_coredump_${TIMESTAMP}.txt"

printf "%s\n" "Configuration:"
echo "  Memleakutil:        ${MEMLEAK_INSTALL_DIR}"
echo "  Crashupload Binary: ${CRASHUPLOAD_BIN}"
echo "  Report Directory:   ${LEAK_REPORT_DIR}"
echo "  Case Timeout:       ${LEAK_CASE_TIMEOUT}s"
echo "  Timestamp:          ${TIMESTAMP}"
printf "\n"

LEAK_LD_PRELOAD="${MEMLEAK_INSTALL_DIR}/lib/libmemfnswrap.so"
LEAK_LD_LIBRARY_PATH="${MEMLEAK_INSTALL_DIR}/lib:${LD_LIBRARY_PATH:-}"

append_known_logs() {
    report_file="$1"
    # core_log only. /var/log/messages is a system log and is not copied into the report.
    for log_file in /opt/logs/core_log.txt /opt/logs/core_log.txt.0; do
        if [ -f "${log_file}" ]; then
            printf '\n----- %s (tail) -----\n' "${log_file}" >> "${report_file}"
            tail -n 40 "${log_file}" >> "${report_file}" 2>/dev/null || true
        fi
    done
}

process_still_running() {
    pid="$1"
    if ! kill -0 "${pid}" 2>/dev/null; then
        return 1
    fi
    if [ -r "/proc/${pid}/stat" ]; then
        # comm can contain spaces, so the state is the token after the last ")".
        state=$(sed -n 's/.*)[[:space:]]\([A-Za-z]\)[[:space:]].*/\1/p' "/proc/${pid}/stat" 2>/dev/null || true)
        [ "${state}" = "Z" ] && return 1
        return 0
    fi
    state=$(ps -o state= -p "${pid}" 2>/dev/null | tr -d '[:space:]')
    case "${state}" in
        Z*) return 1 ;;
    esac
    return 0
}

copy_heap_artifacts() {
    pid="$1"
    for artifact in \
        "/tmp/hp_${pid}_atexit.dat" \
        "/tmp/hpf_${pid}_atexit.dat" \
        "/tmp/smaps_${pid}_atexit.txt"
    do
        if [ -f "${artifact}" ]; then
            cp -f "${artifact}" "${LEAK_REPORT_DIR}/"
            printf "%s\n" "Copied heap artifact ${artifact}"
        fi
    done
}

run_case() {
    case_id="$1"
    report_file="$2"
    expect_rc="$3"
    marker="$4"
    shift 4

    cat > "${report_file}" << EOF
================================================================================
Crashupload Memory Leak Detection Report
Generated: $(date -u)
================================================================================

Build Information:
  Memleakutil Library: ${MEMLEAK_INSTALL_DIR}/lib/libmemfnswrap.so
  Crashupload Binary:  ${CRASHUPLOAD_BIN}
  Detection Method:    LD_PRELOAD function interposition
  Case ID:             ${case_id}
  Expected Exit Code:  ${expect_rc}

Memory Functions Instrumented:
  - malloc(), free()
  - calloc(), realloc()
  - posix_memalign()

Execution Command:
  ${CRASHUPLOAD_BIN} $@

================================================================================
Execution Log
================================================================================

EOF

    printf "%s\n" "Running case ${case_id}: ${CRASHUPLOAD_BIN} $*"
    run_start=$(date +%s)
    set +e
    LD_PRELOAD="${LEAK_LD_PRELOAD}" LD_LIBRARY_PATH="${LEAK_LD_LIBRARY_PATH}" \
        "${CRASHUPLOAD_BIN}" "$@" >> "${report_file}" 2>&1 &
    pid=$!
    elapsed=0
    while process_still_running "${pid}"; do
        if [ "${elapsed}" -ge "${LEAK_CASE_TIMEOUT}" ]; then
            printf "%s\n" "Case ${case_id} exceeded ${LEAK_CASE_TIMEOUT}s; terminating pid ${pid}"
            kill "${pid}" 2>/dev/null || true
            sleep 1
            kill -9 "${pid}" 2>/dev/null || true
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    wait "${pid}"
    rc=$?
    set -e
    run_end=$(date +%s)
    run_duration=$((run_end - run_start))

    append_known_logs "${report_file}"
    copy_heap_artifacts "${pid}"

    cat >> "${report_file}" << EOF

================================================================================
Execution Summary
================================================================================

Exit Code:           ${rc}
Expected Exit Code:  ${expect_rc}
Execution Duration:  ${run_duration}s
Process PID:         ${pid}

Heap artifacts written by libmemfnswrap.so (when present):
  /tmp/hp_${pid}_atexit.dat
  /tmp/hpf_${pid}_atexit.dat
  /tmp/smaps_${pid}_atexit.txt

Copies are stored in ${LEAK_REPORT_DIR} when the library produced them.
This runner does not treat a non-empty heap walk as a failure. Allocations
still held by linked libraries at process exit can appear in that walk.

================================================================================
Report Generated: ${report_file}
================================================================================

EOF

    if [ "${rc}" -ne "${expect_rc}" ]; then
        printf "%s\n\n" "Case ${case_id} failed: exit ${rc}, expected ${expect_rc} (${run_duration}s, pid ${pid})"
        return 1
    fi

    if [ -n "${marker}" ] && grep -F "${marker}" "${report_file}" >/dev/null 2>&1; then
        printf "%s\n\n" "Case ${case_id} passed (exit ${rc}, marker found, ${run_duration}s, pid ${pid})"
    elif [ -n "${marker}" ]; then
        printf "%s\n\n" "Case ${case_id} passed on exit code ${rc}. Marker not in captured logs (${run_duration}s, pid ${pid})"
    else
        printf "%s\n\n" "Case ${case_id} passed (exit ${rc}, ${run_duration}s, pid ${pid})"
    fi
    return 0
}

printf "%s\n" "Preparing dump directories and log files..."
prepare_scan_dirs
printf "%s\n\n" "Scan directories ready"

printf "%s\n" "Starting crashupload leak test matrix..."
echo "  LD_PRELOAD: ${LEAK_LD_PRELOAD}"
printf "\n"

FAIL_COUNT=0

run_case "0-args" "${REPORT_0}" 1 "Number of parameter is less" || FAIL_COUNT=$((FAIL_COUNT + 1))
run_case "1-minidump" "${REPORT_1}" 0 "No dumps found, exiting" "" 0 secure || FAIL_COUNT=$((FAIL_COUNT + 1))
run_case "2-coredump" "${REPORT_2}" 0 "No dumps found, exiting" "" 1 secure || FAIL_COUNT=$((FAIL_COUNT + 1))

printf "%s\n" "Leak Detection Reports:"
echo "  0th case: ${REPORT_0}"
echo "  1st case: ${REPORT_1}"
echo "  2nd case: ${REPORT_2}"
printf "\n"

# Local runs print the text reports here. The workflow sets PRINT_REPORTS=0
# and prints them in its own step so the log has a single copy.
if [ "${PRINT_REPORTS:-1}" = "1" ]; then
    printf "%s\n" "--- Case 0 (arguments) full report ---"
    cat "${REPORT_0}" || true
    printf "\n"

    printf "%s\n" "--- Case 1 (minidump) full report ---"
    cat "${REPORT_1}" || true
    printf "\n"

    printf "%s\n" "--- Case 2 (coredump) full report ---"
    cat "${REPORT_2}" || true
    printf "\n"
fi

if [ "${FAIL_COUNT}" -eq 0 ]; then
    printf "%s\n" "================================================"
    printf "%s\n" "  + Leak detection test matrix SUCCESSFUL"
    printf "%s\n" "================================================"
    exit 0
fi

printf "%s\n" "================================================"
printf "%s\n" "  ! Leak detection test matrix completed with ${FAIL_COUNT} failing case(s)"
printf "%s\n" "================================================"
exit 1
