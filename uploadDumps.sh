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
LOGMAPPER_FILE="/etc/breakpad-logmapper.conf"
LOG_FILES="/tmp/minidump_log_files.txt"
if [ -f /lib/rdk/t2Shared_api.sh ]; then
    source /lib/rdk/t2Shared_api.sh
    IS_T2_ENABLED="true"
fi

if [ -f /etc/device.properties ];then
     . /etc/device.properties
else
     echo "Missing device configuration file: /etc/device.properties..!"
fi

if [ -f /etc/include.properties ];then
     . /etc/include.properties
else
     echo "Missing generic configuration file: /etc/include.properties..!"
fi

if [ -f $RDK_PATH/exec_curl_mtls.sh ]; then
     . $RDK_PATH/exec_curl_mtls.sh
fi

if [ -f /lib/rdk/uploadDumpsToS3.sh ]; then
     . /lib/rdk/uploadDumpsToS3.sh
fi

if [ -f /lib/rdk/getSecureDumpStatus.sh ];then
. /lib/rdk/getSecureDumpStatus.sh
fi

if [ -f /lib/rdk/uploadDumpsUtils.sh ];then
     . /lib/rdk/uploadDumpsUtils.sh
fi

UPLOAD_FLAG=$3
if [ -f /etc/os-release ]; then
        CORE_PATH=$CORE_PATH
fi

if [ "x$UPLOAD_FLAG" = "xsecure" ];then
        CORE_PATH="/opt/secure/corefiles"
        MINIDUMPS_PATH="/opt/secure/minidumps"
else
        CORE_PATH="/var/lib/systemd/coredump"
        MINIDUMPS_PATH="/opt/minidumps"
fi
# Log file setup
CORE_LOG="$LOG_PATH/core_log.txt"
if [[ ! -f $CORE_LOG ]]; then
    touch $CORE_LOG
    chmod a+w $CORE_LOG
fi

#Check for coredump and minidump files
if [ ! -e $MINIDUMPS_PATH/*.dmp* -a ! -e $CORE_PATH/*_core*.* ]; then exit 0; fi


if [ -f /lib/rdk/getpartnerid.sh ]; then
    source /lib/rdk/getpartnerid.sh
    partnerId="$(getPartnerId)"
fi

if [ -f $RDK_PATH/utils.sh ];then
     . $RDK_PATH/utils.sh
fi

if [ -f /lib/rdk/uploadDumpsUtilsDevice.sh ];then
     . /lib/rdk/uploadDumpsUtilsDevice.sh
fi

if [ "$DEVICE_TYPE" != "mediaclient" ] && [ -f $RDK_PATH/commonUtils.sh ]; then
     . $RDK_PATH/commonUtils.sh
fi

# Override Options for testing non PROD builds
 
if [ -f /opt/coredump.properties -a $BUILD_TYPE != "prod" ];then
     	. /opt/coredump.properties
fi

CURL_LOG_OPTION="%{remote_ip} %{remote_port}"



# export PATH and LD_LIBRARY_PATH for curl
export PATH=$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# causes a pipeline to produce a failure return code in case of errors
set -o pipefail

s3bucketurl="s3.amazonaws.com"
HTTP_CODE="/tmp/httpcode"
S3_FILENAME=""
CURL_UPLOAD_TIMEOUT=45
FOUR_EIGHTY_SECS=480
MAX_CORE_FILES=4
TMP_DIR_NAME=""
OUT_FILES=""

# Yocto conditionals
TLS=""
# force tls1.2 for yocto video devices and all braodband devices
if [ -f /etc/os-release ]; then
    TLS="--tlsv1.2"
fi

EnableOCSPStapling="/tmp/.EnableOCSPStapling"
EnableOCSP="/tmp/.EnableOCSPCA"

# Set the name of the log file using SHA1
setLogFile()
{
    fileName=$(basename $6)
    ## Do not perform log file processing if the core name is already processed
    echo "$fileName" | grep "_mac\|_dat\|_box\|_mod" 2> /dev/null 1> /dev/null
    if [ $? -eq 0 ]; then
       echo "$fileName"
       logMessage "Core name is already processed."
    else
       echo $1"_mac"$2"_dat"$3"_box"$4"_mod"$5"_"$fileName
    fi
}

# Usage: echo "debug information" | logStdout
# This function is needed because if we would try smth like "echo 'debug' >> $LOG"
# and we wouldn't have write access rights on $LOG, 'echo' wouldn't execute
logStdout()
{
    while read line; do
        logMessage "${line}"
    done
}

# Locking functions
# If you want to leave the script earlier than EOF, you should insert
# remove_lock $LOCK_DIR_PREFIX
# before you leave.
create_lock_or_exit()
{
    path="$1"
    while true; do
        if [[ -d "${path}.lock.d" ]]; then
            logMessage "Script is already working. ${path}.lock.d. Skip launch another instance..."
            exit 0
        fi
        mkdir "${path}.lock.d" || logMessage "Error creating ${path}.lock.d"
        break;
    done
}

# creates a lock or waits until it can be created
create_lock_or_wait()
{
    path="$1"
    while true; do
        if [[ -d "${path}.lock.d" ]]; then
            logMessage "Script is already working. ${path}.lock.d. Waiting to launch another instance..."
            sleep 2
            continue
        fi
        mkdir "${path}.lock.d" || logMessage "Error creating ${path}.lock.d"
        break;
    done
}

remove_lock()
{
    path="$1"
    if [ -d "${path}.lock.d" ]; then
        rmdir "${path}.lock.d" || logMessage "Error deleting ${path}.lock.d"
    fi
}

POTOMAC_USER=ccpstbscp
# Assign the input arguments
# CRASHTS was previously taken from first argument to the script, but we decided to just generate it here.
CRASHTS=$(date +%Y-%m-%d-%H-%M-%S)
DUMP_FLAG=$2

if [ "$DUMP_FLAG" == "1" ] ; then
    DUMP_NAME="coredump"
else
    DUMP_NAME="minidump"
fi

# 3rd argument is url to POTOMAC_SVR(see runXRE), so we can't use it for wait flag
WAIT_FOR_LOCK="$4"
TIMESTAMP_DEFAULT_VALUE="2000-01-01-00-00-00"
SHA1_DEFAULT_VALUE="0000000000000000000000000000000000000000"
MAC_DEFAULT_VALUE="000000000000"
MODEL_NUM_DEFAULT_VALUE="UNKNOWN"

logMessage()
{
    message="$1"
    echo "$(/bin/timestamp) [PID:$$]: $message" >> $CORE_LOG
}

tlsLog()
{
    echo "$(/bin/timestamp): $0: $*" >> $LOG_PATH/tlsError.log
}

sanitize()
{
   toClean="$1"
   # remove all except alphanumerics and some symbols
   # don't use stmh like ${toClean//[^\/a-zA-Z0-9 :+,]/} \
   # here since it doesn't work with slash (due to old busybox version, probably)
   clean=$(echo "$toClean"|sed -e 's/[^/a-zA-Z0-9 :+._,=-]//g')
   echo "$clean"
}


checkParameter()
{
    local paramName=\$"$1"
    local evaluatedValue=`eval "expr \"$paramName\" "`
    if [ -z $evaluatedValue ] ; then
        case "$1" in
        sha1)
            logMessage "SHA1 is empty. Setting default value."
            eval "$1=$SHA1_DEFAULT_VALUE"
            ;;
        modNum)
            logMessage "Model num is empty. Setting default value."
            eval "$1=$MODEL_NUM_DEFAULT_VALUE"
            ;;
        *TS)
            logMessage "Timestamp is empty. Setting default value."
            eval "$1=$TIMESTAMP_DEFAULT_VALUE"
            ;;
        esac
    fi
}

deleteAllButTheMostRecentFile()
{
    path=$1
    num_of_files=$(find "$path" -type f | wc -l)
    if [ "$num_of_files" -gt "$MAX_CORE_FILES" ]; then
        val=$((num_of_files - MAX_CORE_FILES))
        cd $path && ls -t1 | tail -n $val >> /tmp/dumps_to_delete.txt
        logMessage "Deleting dump files: $(cat /tmp/dumps_to_delete.txt)"
        while read line; do rm -rf $line; done < /tmp/dumps_to_delete.txt
        rm -rf /tmp/dumps_to_delete.txt
    fi
}

cleanup()
{
    if [ -z "$WORKING_DIR" ] || [ ! -d "$WORKING_DIR" ] || [ -z "$(ls -A $WORKING_DIR 2> /dev/null)" ]; then
        logMessage "WORKING_DIR is empty!!!"
        return
    fi

    logMessage "Cleanup ${DUMP_NAME} directory ${WORKING_DIR}"

    # find and delete files by wildcard '*_mac*_dat*' and older than 2 days
    find ${WORKING_DIR} -type f -name '*_mac*_dat*' -mtime +2 |
    while IFS= read -r file;
    do
        rm -f "$file"
        logMessage "Removed file: ${file}"
    done
    if [ ! -f /opt/.upload_on_startup ];then
        # delete version.txt
        rm -f ${WORKING_DIR}/version.txt

        # run only once on startup
        ON_STARTUP_DUMPS_CLEANED_UP="${ON_STARTUP_DUMPS_CLEANED_UP_BASE}"_"${DUMP_FLAG}"
        if [ ! -f "$ON_STARTUP_DUMPS_CLEANED_UP" ] ; then
            path="${WORKING_DIR}"

            # delete unfinished files from previous run
            deleted_files=$(find "$path" -type f -name "*_mac*_dat*" -print -exec rm -f {} \;)
            logMessage "Deleting unfinished files: ${deleted_files}"

            # delete non-dump files
            deleted_files=$(find "$path" -type f ! -name "${DUMPS_EXTN}" -print -exec rm -f {} \;)
            logMessage "Deleting non-dump files : ${deleted_files}"
            deleteAllButTheMostRecentFile "$path"

            touch "$ON_STARTUP_DUMPS_CLEANED_UP"
       fi
    else
       if [ "$DUMP_FLAG" == "1" ];then
            rm -rf /opt/.upload_on_startup
       fi
    fi
}

finalize()
{
    cleanup
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
}

sigkill_function()
{
    echo "Systemd Killing, Removing the script locks"
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
}

sigterm_function()
{
    echo "Systemd Terminating, Removing the script locks"
    [ -f "$crashLoopFlagFile" ] && rm -f "$crashLoopFlagFile"
    remove_lock $LOCK_DIR_PREFIX
    remove_lock "$TIMESTAMP_FILENAME"
}

trap 'sigkill_function' SIGKILL
trap 'sigterm_function' SIGTERM

if [ "$DUMP_FLAG" == "1" ] ; then
    logMessage "starting coredump processing"
    WORKING_DIR="$CORE_PATH"
    DUMPS_EXTN=*core.prog*.gz*
    TARBALLS=*.core.tgz
    #to limit this to only one instance at any time..
    LOCK_DIR_PREFIX="/tmp/.uploadCoredumps"
    CRASH_PORTAL_PATH="/opt/crashportal_uploads/coredumps/"
else
    logMessage "starting minidump processing"
    WORKING_DIR="$MINIDUMPS_PATH"
    DUMPS_EXTN=*.dmp*
    TARBALLS=*.dmp.tgz
    CRASH_PORTAL_PATH="/opt/crashportal_uploads/minidumps/"
    #to limit this to only one instance at any time..
    LOCK_DIR_PREFIX="/tmp/.uploadMinidumps"
    sleep 5
fi

if [ -z "$WORKING_DIR" ] || [ -z "$(ls -A $WORKING_DIR 2> /dev/null)" ];then
	logMessage "working dir is empty $WORKING_DIR"
	exit 0
fi

PORTAL_URL=$(tr181 -g Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl 2>&1)
REQUEST_TYPE=17

DENY_UPLOADS_FILE="/tmp/.deny_dump_uploads_till"
ON_STARTUP_DUMPS_CLEANED_UP_BASE="/tmp/.on_startup_dumps_cleaned_up"

encryptionEnable=false
if [ -f /etc/os-release ]; then
    encryptionEnable=`tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable 2>&1 > /dev/null`
fi

# append timestamp in seconds to $TIMESTAMP_FILENAME
# Uses globals: TIMESTAMP_FILENAME
logUploadTimestamp()
{
    if [ "$BUILD_TYPE" = "prod" ]; then
        date +%s >> "$TIMESTAMP_FILENAME"
        truncateTimeStampFile
    fi
}

# truncate $TIMESTAMP_FILENAME to 15 lines. We won't need more.
# Protected by create_lock_or_wait "$TIMESTAMP_FILENAME"
# Uses globals: TIMESTAMP_FILENAME
truncateTimeStampFile()
{
    # just in case there is no file yet
    touch "$TIMESTAMP_FILENAME" && chmod a+rw "$TIMESTAMP_FILENAME"

    tail -n 10 "$TIMESTAMP_FILENAME" > "${TIMESTAMP_FILENAME}_tmp"
    mv "${TIMESTAMP_FILENAME}_tmp" "$TIMESTAMP_FILENAME"
}

# Crash rate limit is reached if the 10th latest tarball was uploaded more then 10 minutes ago.
# Protected by create_lock_or_wait "$TIMESTAMP_FILENAME"
# Uses globals: TIMESTAMP_FILENAME
isUploadLimitReached()
{
    local limit_seconds=600
    touch "$TIMESTAMP_FILENAME" && chmod a+rw "$TIMESTAMP_FILENAME"

    local lines_count="$( wc -l < "$TIMESTAMP_FILENAME" )"
    if [ "$lines_count" -lt 10 ]; then
        # too few lines. Limit not reached. Return false.
        return 1
    fi

    local tenth_newest_crash_time=$( head -n1 "$TIMESTAMP_FILENAME" | awk '{print $1}' )
    local now=$( date "+%s" )

    if [ $(( now - tenth_newest_crash_time )) -lt $limit_seconds ]; then
        # limit reached. Return true.
        logMessage "Not uploading the dump. Too many dumps."
        return 0
    else
        return 1
    fi
}

# Set recovery time to Now + 10 minutes
# Uses globals: DENY_UPLOADS_FILE
setRecoveryTime()
{
    local current_time_sec="$( date +%s )"
    local dont_upload_for_sec=600
    echo $(( current_time_sec + dont_upload_for_sec )) > "$DENY_UPLOADS_FILE"
}

# true if upload denial time is unset or not reached
# Uses globals: DENY_UPLOADS_FILE
isRecoveryTimeReached()
{
    if [ ! -f "$DENY_UPLOADS_FILE" ]; then
      return 0
    fi

    local upload_denied_till="$( cat "$DENY_UPLOADS_FILE" )"

    # check if contents of the file are valid
    case $upload_denied_till in
        ''|*[!0-9]*) return 0 ;;
        *) true ;;
    esac

    local now="$( date +%s )"
    if [ "$now" -gt "$upload_denied_till" ]; then
        return 0
    fi

    return 1
}

# Removes unprocessed dumps that are waiting in the queue
# Uses globals: WORKING_DIR, DUMPS_EXTN
removePendingDumps()
{
      find "$WORKING_DIR" -name "$DUMPS_EXTN" -o -name "*.tgz" |
      while read file; do
          logMessage "Removing $file because upload limit has been reached or build is blacklisted or TelemetryOptOut is set"
          rm -f $file
      done
}
# Marks archive as crashlooped and uploads it to Crash Portal
# Arg 1: relative path for tgz to process
markAsCrashLoopedAndUpload()
{
    local tgz_name="$1"
    local new_tgz_name=$( echo $tgz_name | sed -e 's|.dmp.tgz$|.crashloop.dmp.tgz|g' )
    logMessage "Renaming $tgz_name to $new_tgz_name"
    mv $tgz_name $new_tgz_name
    coreUpload $new_tgz_name $PORTAL_URL $CRASH_PORTAL_PATH
}


# Note: This is not protected by the lock below.
TIMESTAMP_FILENAME="/tmp/.${DUMP_NAME}_upload_timestamps"

# Will wait if unable to create lock and 4th parameter is "wait_for_lock".
if [ "$WAIT_FOR_LOCK" = "wait_for_lock" ]; then
    create_lock_or_wait $LOCK_DIR_PREFIX
else
    create_lock_or_exit $LOCK_DIR_PREFIX
fi

#defer code upload for 8 mins of uptime to avoid CPU load during bootup(Only for Video devices)
if [ "$DEVICE_TYPE" = "hybrid" ] || [ "$DEVICE_TYPE" = "mediaclient" ]; then
    uptime_val=$(cut -d. -f1 /proc/uptime)
    if [ $uptime_val -lt $FOUR_EIGHTY_SECS ]; then
        sleep_time=$((FOUR_EIGHTY_SECS - uptime_val))
        logMessage "Deferring reboot for $sleep_time seconds"
		sleep $sleep_time
		if [ -f /tmp/set_crash_reboot_flag ];then
			logMessage "Process crashed exiting from the Deferring reboot"
			break
		fi
    fi
fi


# wait the internet connection once after boot
NETWORK_TESTED="/tmp/route_available"
NETWORK_TEST_ITERATIONS=18
NETWORK_TEST_DELAY=10
SYSTEM_TIME_TEST_ITERATIONS=10
SYSTEM_TIME_TEST_DELAY=1
SYSTEM_TIME_TESTED="/tmp/stt_received"
counter=1
NoNetwork=0
while [ $counter -le $NETWORK_TEST_ITERATIONS ]; do
    logMessage "Check Network status count $counter"
    if [ -f $NETWORK_TESTED ]; then
	logMessage "Route is Available break the loop"
        break
    else
        logMessage "Route is not available sleep for $NETWORK_TEST_DELAY"
        sleep $NETWORK_TEST_DELAY
        counter=$(( counter + 1 ))
    fi
done
if [ ! -f $NETWORK_TESTED ]; then
    logMessage "Route is NOT Available, tar dump and save it as MAX WAIT has been reached"
    NoNetwork=1
fi
logMessage "IP acquistion completed, Testing the system time is received"
if [ ! -f "$SYSTEM_TIME_TESTED" ]; then
    while [ $counter -le $SYSTEM_TIME_TEST_ITERATIONS ]; do
	if [ ! -f "$SYSTEM_TIME_TESTED" ]; then
            logMessage "Waiting for STT, iteration $counter"
            sleep $SYSTEM_TIME_TEST_DELAY
        else
            logMessage "Received $SYSTEM_TIME_TESTED flag"
            break
        fi

        if [ $counter = $SYSTEM_TIME_TEST_ITERATIONS ]; then
            logMessage "Continue without $SYSTEM_TIME_TESTED flag"
        fi

        counter=$(( counter + 1 ))
    done
else
    logMessage "Received $SYSTEM_TIME_TESTED flag"
fi


# Upon exit, remove locking
trap finalize EXIT


if [ ! -f /tmp/coredump_mutex_release ] && [ "$DUMP_FLAG" == "1" ]; then
     logMessage "Waiting for Coredump Completion"
     sleep 21
fi

is_box_rebooting()
{
	if [ -f /tmp/set_crash_reboot_flag ];then
	      logMessage "Skipping upload, Since Box is Rebooting now"
	      if [ "$IS_T2_ENABLED" == "true" ]; then
	              t2CountNotify "SYST_INFO_CoreUpldSkipped"
	      fi
	      logMessage "Upload will happen on next reboot"
	      exit 0
	fi
}
# Get the MAC address of the box
read -r MAC < /tmp/.macAddress
MAC="${MAC//:}"
logMessage "Mac address is $MAC"

count=$(find "$WORKING_DIR" -name "$DUMPS_EXTN" | wc -l)
if [ $count -eq 0 ]; then logMessage "No ${DUMP_NAME} for uploading exiting" ; exit 0; fi

cleanup
logMessage "Portal URL: $PORTAL_URL"

saveDump()
{
    if [ -z "$1"  ]; then
        logMessage "Saving dump with original name to retain container info"
        mv $MINIDUMPS_PATH/$S3_FILENAME $MINIDUMPS_PATH/$1
    fi

    count=$(find "$MINIDUMPS_PATH" -type f -name "*.dmp.tgz" | wc -l)
    while [ $count -gt 5 ]; do
         olddumps=$(ls -t $MINIDUMPS_PATH | tail -1)
         logMessage "Removing old dump $olddumps"
         rm -rf $MINIDUMPS_PATH/$olddumps
         count=$(ls $MINIDUMPS_PATH | wc -l)
     done
     logMessage "Total pending Minidumps : $count"
}

VERSION_FILE="version.txt"
boxType=$BOX_TYPE
modNum=$(getModel)

# Ensure modNum is not empty
checkParameter modNum

# Receiver binary is used to calculate SHA1 marker which is used to find debug file for the coredumps
sha1=`getSHA1 /version.txt`
# Ensure sha1 is not empty
checkParameter sha1

logMessage "buildID is $sha1"

if [ ! -d $WORKING_DIR ]; then exit 0; fi
cd $WORKING_DIR

shouldProcessFile()
{
    fName=$1
    # always upload minidumps
    if [ "$DUMP_FLAG" != "1" ]; then
        echo 'true'
        return
    # upload cores even for prod if it is not Receiver
    elif [[ -n "${fName##*Receiver*}" ]]; then
        echo 'true'
        return
    # upload cores not for prod
    elif [ "$BUILD_TYPE" != "prod" ]; then
        echo 'true'
        return
    else
    # it's prod coredump, not mpeos and not discovery
    logMessage "Not processing $fName"
        echo 'false'
        return
    fi
}

get_crashed_log_file()
{
    file="$1"
    pname=`echo ${file} | rev | cut -d"_" -f2- | rev`
    pname=${pname#"./"} #Remove ./ from the dump name
    appname=$(echo ${file} | cut -d "_" -f 2 | cut -d "-" -f 1)
    logMessage "Process crashed = $pname"
    log_files=$(awk -v proc="$pname" -F= '$1 ~ proc {print $2}' $LOGMAPPER_FILE)
    logMessage "Crashed process log file(s): $log_files"
    if [ ! -z "$appname" ];then
        logMessage "Appname, Process_Crashed = $appname, $pname"
    fi
    for i in $(echo $log_files | sed -n 1'p' | tr ',' '\n'); do
        echo "$LOG_PATH/$i" >> $LOG_FILES
    done
}

processCrashTelemtryInfo()
{
    logMessage "Processing the crash telemetry info"
    local file="$1"
    file=${file##"./"}
    local isTgz=0
    local isContainer=0
    local containerDelimiter="<#=#>"
    local backwarDelimiter="-"

    local ext=${file##*.}
    if [[ "$ext" = 'tgz' ]]; then
        logMessage "The File is already a tarball, this might be a retry or crash during shutdown"
        isTgz=1
        local file_temp=${file#*_mod*_}
        logMessage "Orginal Filename : $file"
        logMessage "Removing the meta information New Filename : $file_temp"
        logMessage "This could be a retry or crash from previous boot the appname can be truncated"
        t2CountNotify "SYS_INFO_TGZDUMP" "1"
        file=$file_temp
    fi

    if [ "${file#*$containerDelimiter}" != "$file" ]; then
        isContainer=1
        logMessage "From the file name crashed process is a container"
        firstBreak=${file%$containerDelimiter*}
        containerTime=${file##*$containerDelimiter}
        if [ "${firstBreak#*$containerDelimiter}" != "$firstBreak" ]; then
            #This is having appstatus info
            containerName=${firstBreak%$containerDelimiter*}
            containerStatus=${firstBreak#*$containerDelimiter}
        else
            #This is not having appstatus info mark it unknown
            containerName=$firstBreak
            containerStatus="unknown"
        fi
        file=$containerName$backwarDelimiter$containerTime

        local Appname=${containerName#*_}
        local ProcessName=${containerName%%_*}

        t2ValNotify "crashedContainerName_split" $containerName
        t2ValNotify "crashedContainerStatus_split" $containerStatus
        t2ValNotify "crashedContainerAppname_split" $Appname
        t2ValNotify "crashedContainerProcessName_split" $ProcessName
        t2CountNotify "SYS_INFO_CrashedContainer" "1"
        #as of now this is being logged in get_crashed_log_file but adding here as that is inconsistent
        logMessage "Container crash info Basic: $Appname, $ProcessName"
        logMessage "Container crash info Advance: $containerName, $containerStatus"
        logMessage "NEW Appname, Process_Crashed, Status = $Appname, $ProcessName, $containerStatus"
        logMessage "NEW Processname, App Name, AppState = $ProcessName, $Appname, $containerStatus"
        logMessage "ContainerName, ContainerStatus = $containerName, $containerStatus"
        t2ValNotify "NewProcessCrash_split" "$containerName, $containerStatus"
        
    fi
    # This is a temporary call; we need to get marker confirmation from the Triage Team.
    # We can clean this code later. Leaving it as is for now for backward compatibility.
    get_crashed_log_file $file
}

add_crashed_log_file()
{
    files="$@"

    line_count=5000
    if [ "$BUILD_TYPE" = "prod" ]; then
       line_count=500
    fi

    while read line
    do
        if [ ! -z "$line" -a -f "$line" ]; then
            logModTS=$(getLastModifiedTimeOfFile $line)
            checkParameter logModTS
            process_log=$(setLogFile $sha1 $MAC $logModTS $boxType $modNum $line)
            tail -n ${line_count} $line > $process_log
            logMessage "Adding File: $process_log to minidump tarball"
            files="$files $process_log"
        fi
    done < $LOG_FILES
    rm -rf $LOG_FILES
}

copy_log_files_tmp_dir()
{
    TmpDirectory="/tmp/$TMP_DIR_NAME"
    Logfiles="$@"
    result=0
    limit=70
    
    tmpDir="/tmp"

    # if directory exists, find out it's size
    if [ -d $tmpDir ]
     then
           usagePercentage=$(df -h '/tmp'| grep '\tmp' | awk '{print $5}')
           usagePercentage="${usagePercentage:0:1}"
     else
           logMessage "path $tmpDir not found!!!"
    fi
   #check if directory size is greater than limit
   if [ $usagePercentage -ge $limit ]; then
          logMessage "Skipping copying Logs to tmp dir due to limited Memory"
          OUT_FILES="$OUT_FILES $Logfiles"
    else
          logMessage "Copying Logs to tmp dir as Memory available. used size = $usagePercentage% limit = $limit%"
          mkdir $TmpDirectory 2> /dev/null
          cp $Logfiles $TmpDirectory 2> /dev/null
          logMessage "Logs Copied to $TmpDirectory Temporary"
    
          # Updating TmpDirectory files list to OUT_FILES as output for tar command
          for log in $TmpDirectory
          do
                OUT_FILES="$OUT_FILES $log"
          done
    fi
}

processDumps()
{
    # wait for app buffers are flushed
    type flushLogger &> /dev/null && flushLogger || sleep 2

    find -name "$DUMPS_EXTN" -type f | while read f;
    do
        #local f1=$(echo "$f" | sed -e 's/[^/a-zA-Z0-9 ._-]//g')
        #allow <#=#> to be there as part of container appstate changes
        local f1=$(echo "$f" | sed -e 's/<#=#>/PLACEHOLDER/g' -e 's/[^/a-zA-Z0-9 ._-]//g' -e 's/PLACEHOLDER/<#=#>/g')
        if [ -z "$f1" ]; then
            rm -f "$f"
            continue
        elif [ "$f1" != "$f" ]; then
            mv "$f" "$f1"
            f="$f1"
        fi
        if [ "$DUMP_FLAG" == "0" ]; then
            processCrashTelemtryInfo "$f"
        fi
        if [ -f "$f" ]; then
            # Checking whether is it a tarball so we should continue without further processing
	    #if [[ "$f" =~ '.+_mac.+_dat.+_box.+_mod.+' ]]; then
	    ext=${f##*.}
	    if [[ "$ext" = 'tgz' ]]; then
	        logMessage "Skip archiving $f as it is a tarball already."
	        continue
	    fi
	    #last modification date of a core dump, to ease refusing of already uploaded core dumps on a server side
            modDate=`getLastModifiedTimeOfFile $f`
            if [ -z "$CRASHTS" ]; then
                  CRASHTS=$modDate
                  # Ensure timestamp is not empty
                  checkParameter CRASHTS
            fi

            if [ "$DUMP_FLAG" == "1" ] ; then
                if echo $f | grep -q mpeos-main; then
                    #CRASHTS not reqd as minidump won't be uploaded for mpeos-main
                    dumpName=`setLogFile $sha1 $MAC $modDate $boxType $modNum $f`
                else
                    dumpName=`setLogFile $sha1 $MAC $CRASHTS $boxType $modNum $f`
                fi
		if [ "${#dumpName}" -ge "135" ]; then
		     #Removing the HEADER of the corefile due to ecryptfs limitation as file can't be open when it exceeds 140 characters.
	             dumpName="${dumpName#*_}"
		fi
                tgzFile=$dumpName".core.tgz"
            else
                dumpName=`setLogFile $sha1 $MAC $CRASHTS $boxType $modNum $f`
		if [ "${#dumpName}" -ge "135" ]; then
		     #Removing the HEADER of the corefile due to ecryptfs limitation as file can't be open when it exceeds 140 characters.
		     dumpName="${dumpName#*_}"
		fi
                tgzFile=$dumpName".tgz"
            fi
            
            #remove <#=#> characters from the dumpname to avoid processing issues.
            dumpName=$(echo "$dumpName" | sed -e 's/<#=#>/_/g')
            
            mv $f $dumpName
            cp "/"$VERSION_FILE .
            TMP_DIR_NAME=$dumpName

            logMessage "Size of the file: $(ls -l $dumpName)"
           if [ "$DUMP_FLAG" == "1" ] ; then
	        logfiles="$VERSION_FILE $CORE_LOG"
                if [ -f /tmp/set_crash_reboot_flag ];then
			logMessage "Compression without nice"
			tar -zcvf $tgzFile $dumpName $logfiles 2>&1 | logStdout
		else
		        logMessage "Compression with nice"
                        nice -n 19 tar -zcvf $tgzFile $dumpName $logfiles 2>&1 | logStdout
                fi
            else     
                    crashedUrlFile=$LOG_PATH/crashed_url.txt
                    logfiles="$VERSION_FILE $CORE_LOG $crashedUrlFile"
                    add_crashed_log_file $logfiles
                    nice -n 19 tar -zcvf $tgzFile $dumpName $logfiles 2>&1 | logStdout
             fi
	       if [ $? -eq 0 ]; then
                    logMessage "Success Compressing the files, $tgzFile $dumpName $VERSION_FILE $CORE_LOG "
                else
                    # If the tar creation failed then will create new tar after copying logs files to /tmp
                    OUT_FILES="$dumpName"
                    copy_log_files_tmp_dir $logfiles
	            nice -n 19 tar -zcvf $tgzFile $OUT_FILES 2>&1 | logStdout
                    if [ $? -eq 0 ]; then
                       logMessage "Success Compressing the files, $tgzFile $OUT_FILES"
                    else
                       logMessage "Compression Failed ."
		    fi
                fi
            logMessage "Size of the compressed file: $(ls -l $tgzFile)"
	    
	    if [ ! -z "$TMP_DIR_NAME" ] && [ -d "/tmp/$TMP_DIR_NAME" ]; then
	       rm -rf /tmp/$TMP_DIR_NAME
	       logMessage "Temporary Directory Deleted:/tmp/$TMP_DIR_NAME"
            fi
            rm $dumpName

            if [ "$DUMP_FLAG" == "0" ]; then
                process_logs=`find $WORKING_DIR \( -iname "*.log*" -o -iname "*.txt*" \) -type f -print -exec rm -f {} \;`
                logMessage "Removing ${process_logs}"
            fi
        fi
    done

    is_box_rebooting
    find -name "$TARBALLS" -type f | while read f;
    do
        if [ -f $f ]; then
            # On reaching the crash rate limit we stop processing further crashes for 10 minutes
            # (until a so-called "recovery time"). Any crashes occurring before the recovery time get
            # discarded and set the recovery time to 10 minutes from now, i.e. shift it.
            # If a crash occurs after the recovery time, we resume normal minidump uploads.
            # This also uploads specially-crafted archive that tells Crash Portal about hitting the limit.
            if isRecoveryTimeReached; then
                rm -f "$DENY_UPLOADS_FILE"
            else
                logMessage "Shifting the recovery time forward."
                setRecoveryTime
                removePendingDumps
                exit
            fi
            if [ "$DUMP_NAME" = "minidump" ] ; then
	        if isUploadLimitReached; then   
                    logMessage "Upload rate limit has been reached."
                    markAsCrashLoopedAndUpload $f
                    logMessage "Setting recovery time"
                    setRecoveryTime
                    removePendingDumps
                    exit
		fi
            else
                logMessage "Coredump File `echo $f`"
            fi
            S3_FILENAME=`echo ${f##*/}`
            count=1
            
            # check the network
            if [ "$DUMP_NAME" = "minidump" -a $NoNetwork -eq 1 ]; then
                logMessage "Network is not available skipping upload"
                saveDump
                return
            fi
            #check for PrivacyModes Control
            if [ "$DEVICE_TYPE" = "mediaclient" ]; then
                privacyMode=$(getPrivacyControlMode logMessage)
                if [ "$privacyMode" = "DO_NOT_SHARE" ]; then
                    logMessage "Privacy Mode is $privacyMode. Stop Uploading the data to the cloud"
                    #removing the .tgz files from dumps folder
                    removePendingDumps
                    return
                fi
            fi
            # upload to S3 amazon first
            ORGINAL_FILENAME="$(echo $S3_FILENAME)"
            S3_FILENAME=$(echo "$S3_FILENAME" | sed -e 's/<#=#>/_/g')
            
            if [ "$ORGINAL_FILENAME" = "$S3_FILENAME" ];then
                ORGINAL_FILENAME=""
            else
                mv $ORGINAL_FILENAME $S3_FILENAME
            fi
            
            logMessage "[$0]: $count: $DUMP_NAME S3 Upload "
	    if [ -f /lib/rdk/uploadDumpsToS3.sh ]; then
                echo "$WORKING_DIR $partnerId $DUMP_NAME $DEVICE_TYPE $VERSION_FILE $encryptionEnable $EnableOCSPStapling $EnableOCSP $TLS $BUILD_TYPE $modNum ${CURL_LOG_OPTION}" > /tmp/uploadtos3params
                uploadToS3 "`echo $S3_FILENAME`" 
                status=$?
		rm /tmp/uploadtos3params
	    else
                # A secure upload logic is required to upload the crash dumps to the cloud database server.
	   	# The upload script can take in parameters such as Device model, upload options related to security and the dump file to be uploaded
       		# The return value from the upload logic can be checked to determine a successful coredump upload to server.
	   	# Retries can be triggered at regular intervals if needed, in case the upload fails at the initial try.
       		echo "A secure core/minidump upload logic can be implemented here to upload the crash dumps to cloud database."
		echo "Parameters such as device type, secure upload options and the file to be uploaded can be passed to the upload function/script."
	    fi
            while [ $count -le 3 ]
            do
                # S3 amazon fail over recovery
		count=$(( count +1))
                if [ $status -ne 0 ];then
                     logMessage "[$0]: Execution Status: $status, S3 Amazon Upload of $DUMP_NAME Failed"
                     logMessage "[$0]: $count: (Retry), $DUMP_NAME S3 Upload"
                     sleep 2
		     if [ -f /lib/rdk/uploadDumpsToS3.sh ]; then
                         echo "$WORKING_DIR $partnerId $DUMP_NAME $DEVICE_TYPE $VERSION_FILE $encryptionEnable $EnableOCSPStapling $EnableOCSP $TLS $BUILD_TYPE $modNum ${CURL_LOG_OPTION}" > /tmp/uploadtos3params
                         uploadToS3 "`echo $S3_FILENAME`"
                         status=$?
			 rm /tmp/uploadtos3params
		     else
       			 # A secure upload logic is required to upload the crash dumps to the cloud database server.
	   		 # The upload script can take in parameters such as Device model, upload options related to security and the dump file to be uploaded
       			 # The return value from the upload logic can be checked to determine a successful coredump upload to server.
	   		 # Retries can be triggered at regular intervals if needed, in case the upload fails at the initial try.
       		         echo "A secure core/minidump upload logic can be implemented here to upload the crash dumps to cloud database."
		  	 echo "Parameters such as device type, secure upload options and the file to be uploaded can be passed to the upload function/script."
		     fi
                else
                     logMessage "[$0]: $DUMP_NAME uploadToS3 SUCESS: status: $status"
		     if [ "$DUMP_NAME" == "minidump" ] && [ "$IS_T2_ENABLED" == "true" ]; then
			     t2CountNotify "SYST_INFO_minidumpUpld"
		     fi
                     break
                fi
            done
            if [ $status -ne 0 ];then
                  logMessage "[$0]: S3 Amazon Upload of $DUMP_NAME Failed..!"
                  if [  "$DUMP_NAME" == "minidump" ]; then
                      logMessage "Check and save the dump $S3_FILENAME"
                      saveDump "$ORGINAL_FILENAME"
                  else
                      logMessage "Removing file $S3_FILENAME"
                      rm -f $S3_FILENAME
                  fi
                  exit 1
            else
                  echo "[$0]: Execution Status: $status, S3 Amazon Upload of $DUMP_NAME Success"
            fi
            ORGINAL_FILENAME=""
            logMessage "Removing file $S3_FILENAME"
            rm -f $S3_FILENAME
            logUploadTimestamp
        fi
    done
}

for j in 1 2 3; do
     dump_files=$(find . -name "$DUMPS_EXTN" | head -n1)
     if [ -z "$dump_files" ]; then
            break
     fi
        processDumps
done

finalize

