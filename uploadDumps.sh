#!/bin/busybox sh

##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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
#Purpose : This script is to used to create and upload dump files
#Scope : RDK Devices
#Usage : Triggered by a path based systemd service
#This file is from crashupload repository
#Uploads coredumps to an ftp server if there are any

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
        if [ -f /tmp/.c_crashupload ]; then
            run_legacy "$@"
        else
            run_crashupload "$@"
        fi
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
