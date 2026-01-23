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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "systemutils.h"
#include "telemetryinterface.h"
#include "logger.h"

/**
 * FULL IMPLEMENTATION
 * Get system uptime with fallback from sysinfo() to /proc/uptime
 */
int system_get_uptime(uint64_t *uptime_seconds)
{
    if (!uptime_seconds)
    {
        return -1;
    }

    /* Try sysinfo() first (preferred method) */
    struct sysinfo info;
    if (sysinfo(&info) == 0)
    {
        *uptime_seconds = (uint64_t)info.uptime;
        return 0;
    }

    /* Fallback to /proc/uptime */
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp)
    {
        return -1;
    }

    double uptime_double;
    if (fscanf(fp, "%lf", &uptime_double) != 1)
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    *uptime_seconds = (uint64_t)uptime_double;
    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Check if process is running using /proc scan (no ps command)
 */
int system_check_process(const char *name, bool *is_running)
{
    if (!name || !is_running)
    {
        return -1;
    }

    *is_running = false;

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir)
    {
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL)
    {
        /* Check if directory name is numeric (PID) */
        if (entry->d_type == DT_DIR)
        {
            char *endptr;
            long pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && pid > 0)
            {
                /* Read process name from /proc/[pid]/comm */
                char comm_path[256];
                snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);

                FILE *fp = fopen(comm_path, "r");
                if (fp)
                {
                    char proc_name[256];
                    if (fgets(proc_name, sizeof(proc_name), fp))
                    {
                        /* Remove trailing newline */
                        char *newline = strchr(proc_name, '\n');
                        if (newline)
                            *newline = '\0';

                        if (strcmp(proc_name, name) == 0)
                        {
                            *is_running = true;
                            fclose(fp);
                            closedir(proc_dir);
                            return 0;
                        }
                    }
                    fclose(fp);
                }
            }
        }
    }

    closedir(proc_dir);
    return 0;
}

/**
 * SKELETON
 * Execute system reboot
 */
bool is_box_rebooting(bool t2_enabled)
{
    bool ret = false;
    /* SKELETON - Using system() call for now */
    if (0 == filePresentCheck("/tmp/set_crash_reboot_flag"))
    {
        CRASHUPLOAD_INFO("Skipping upload, Since Box is Rebooting now\n");
        if (t2_enabled)
        {
            t2CountNotify("SYST_INFO_CoreUpldSkipped", 1);
        }
        CRASHUPLOAD_INFO("Upload will happen on next reboot\n");
        ret = true;
    }
    return ret;
}
