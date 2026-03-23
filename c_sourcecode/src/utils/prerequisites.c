/**
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * @file prerequisites.c
 * SKELETON: Implementation needed
 */
#include "prerequisites.h"
#include "cleanup_batch.h"
#include "errors.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "logger.h"

#define FOUR_EIGHTY_SECS 480   // 8 minutes (same as script)

void defer_upload_if_needed(device_type_t device_type)
{
    int ret = -1;

    if (device_type == DEVICE_TYPE_MEDIACLIENT)
    {
        /* Read uptime from /proc/uptime */
        FILE *fp = fopen("/proc/uptime", "r");
        if (!fp)
        {
            CRASHUPLOAD_ERROR("Failed to read /proc/uptime\n");
            return;
        }

        double uptime_seconds = 0.0;
        ret = fscanf(fp, "%lf", &uptime_seconds);
        fclose(fp);
        if (ret != 1)
        {
            CRASHUPLOAD_ERROR("Failed to parse /proc/uptime");
        }

        int uptime_val = (int)uptime_seconds;

        if (uptime_val < FOUR_EIGHTY_SECS)
        {

            int sleep_time = FOUR_EIGHTY_SECS - uptime_val;

            CRASHUPLOAD_INFO("Deferring Upload for %d seconds\n", sleep_time);
            sleep(sleep_time);
            CRASHUPLOAD_INFO("Deferring Upload for %d seconds completed\n", sleep_time);

            if (0 == (filePresentCheck("/tmp/set_crash_reboot_flag")))
            {
                CRASHUPLOAD_INFO("Process crashed, exiting from the deferring reboot");
                exit(0); // same as break (stop further execution)
            }
        }
    }
}

/**
 * Returns:
 *   1 -> Found at least one matching file
 *   0 -> No matching files
 *  -1 -> Error (directory missing, etc.)
 */
int directory_has_pattern(const char *dir, const char *pattern)
{
    DIR *dp = opendir(dir);
    if (!dp)
    {
        CRASHUPLOAD_INFO("%s dir not open\n", dir);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL)
    {
        // skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (strstr(entry->d_name, pattern) != NULL)
        {
            closedir(dp);
            return 1; // found match
        }
    }

    closedir(dp);
    return 0; // no match
}

int prerequisites_wait(config_t *config, int timeout_sec)
{
    int dump_file_found = 0;
    char dump_extn[16] = {0};
    /* TODO: Check network + time sync together */
    if (NULL == config)
    {
        CRASHUPLOAD_ERROR("Invalid parameter or NULL parameter\n");
        return -1;
    }
    CRASHUPLOAD_INFO("Inside prerequisites_wait: device type=%u\n", config->device_type);
    if ((config->device_type == DEVICE_TYPE_BROADBAND) || (config->device_type == DEVICE_TYPE_EXTENDER))
    {
        dump_file_found = directory_has_pattern(config->core_path, ".dmp");
    }
    else
    {
        if (config->dump_type == DUMP_TYPE_MINIDUMP)
        {
            dump_file_found = directory_has_pattern(config->minidump_path, ".dmp");
            strcpy(dump_extn, "*.dmp*");
        }
        else if (config->dump_type == DUMP_TYPE_COREDUMP)
        {
            dump_file_found = directory_has_pattern(config->core_path, "_core");
            strcpy(dump_extn, "*core.prog*.gz*");
        }
        else
        {
            CRASHUPLOAD_ERROR("Invalid Dump Type\n");
        }
    }
    if (1 != dump_file_found)
    {
        CRASHUPLOAD_INFO("dump file or core file not found. Exiting\n");
        return NO_DUMPS_FOUND;
    }
    if ((config->device_type == DEVICE_TYPE_MEDIACLIENT) && (config->opt_out == true))
    {
        CRASHUPLOAD_INFO("Coreupload is disabled as TelemetryOptOut is set\n");
        CRASHUPLOAD_INFO("Cleaning dump with extension:%s:%s\n", config->working_dir_path, dump_extn);
        remove_pending_dumps(config->working_dir_path, dump_extn);
        return 1;
    }
    defer_upload_if_needed(config->device_type);
    // TODO: Below mutex_release file create by core dump generation script.So using same
    if ((config->dump_type == DUMP_TYPE_COREDUMP) && (0 != (filePresentCheck(" /tmp/coredump_mutex_release"))))
    {
        CRASHUPLOAD_INFO("Waiting for Coredump Completion\n");
        sleep(21); // TODO: How this number arive??
    }
    return PREREQUISITES_SUCCESS;
}
