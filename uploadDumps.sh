#!/bin/busybox sh

# Load DEVICE_TYPE
if [ -f /etc/device.properties ]; then
    . /etc/device.properties
fi

if [ -z "$DEVICE_TYPE" ]; then
    DEVICE_TYPE="unknown"
fi

case "$DEVICE_TYPE" in
    mediaclient)
        LOG_DIR="/rdklogs/logs"
        ;;
    broadband|extender)
        LOG_DIR="/var/log"
        ;;
    *)
        LOG_DIR="/var/log"
        ;;
esac

CORE_LOG="${LOG_DIR}/core_log.txt"

Log() { 
    echo "`/bin/timestamp` [uploadDumps.sh] [PID:$$]: $*" >> $CORE_LOG 
}

UPLOAD_SCRIPT="/lib/rdk/uploadDumps.sh"
UPLOAD_BIN="/usr/bin/crashupload"

find_crashupload() {
    if [ -f "$UPLOAD_BIN" ]; then
        echo "$UPLOAD_BIN"
        return 0
    fi
    return 1
}

run_legacy() {
    if [ -x "$UPLOAD_SCRIPT" ]; then
        Log "Delegating to legacy uploader: $UPLOAD_SCRIPT"
        "$UPLOAD_SCRIPT" "$@"
        return $?
    fi
    Log "Error: legacy uploader not found at $UPLOAD_SCRIPT"
    exit 127
}

run_crashupload() {
    bin="$(find_crashupload || true)"
    if [ -n "$bin" ]; then
        Log "Delegating to crashupload binary: $bin"
        "$bin" "$@"
        return $?
    fi
    Log "crashupload binary not found; falling back to legacy uploader."
    run_legacy "$@"
}

case "$DEVICE_TYPE" in
    mediaclient)
        run_crashupload "$@"
        ;;
    broadband|extender)
        run_legacy "$@"
        ;;
    *)
        Log "Unknown DEVICE_TYPE='${DEVICE_TYPE}'; using legacy uploader."
        run_legacy "$@"
        ;;
esac

exit $?