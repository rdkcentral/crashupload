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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include "ratelimit.h"
#include "../utils/logger.h"

int set_time(const char *deny_file, int type)
{
    FILE *fp;
    time_t now;
    long deny_until;

    if (!deny_file)
        return -1;

    now = time(NULL);
    if (now == (time_t)-1)
        return -1;
    if (type == RECOVERY_TIME)
    {
        CRASHUPLOAD_INFO("Set Recovery Time inside file:%s\n", deny_file);
        deny_until = (long)now + RECOVERY_DELAY_SEC;
    }
    else
    {
        deny_until = (long)now;
    }

    fp = fopen(deny_file, "w");
    if (!fp)
        return -1;

    if (fprintf(fp, "%ld", deny_until) < 0)
    {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int is_upload_limit_reached(const char *file)
{
    FILE *fp = NULL;
    char buf[80] = {0};
    char first_line_data[80] = {0};
    int ret = ALLOW_UPLOAD;
    char *endptr;
    long first_crash_time;
    time_t now;
    int line_cnt = 0;

    fp = fopen(file, "r");
    if (fp != NULL)
    {
        while (fgets(buf, sizeof(buf), fp))
        {
            line_cnt++;
            if (line_cnt == 1)
            {
                strncpy(first_line_data, buf, sizeof(first_line_data) - 1);
                first_line_data[sizeof(first_line_data) - 1] = '\0';
            }
        }
    }
    else
    {
        CRASHUPLOAD_INFO("File for rate limit check not present:%s\n", file);
        return ret;
    }
    /* Validate numeric content */
    for (size_t i = 0; buf[i] != '\0' && buf[i] != '\n'; i++)
    {
        if (!isdigit((unsigned char)buf[i]))
            return ALLOW_UPLOAD;
    }

    first_crash_time = strtol(buf, &endptr, 10);
    if (endptr == buf)
        return ALLOW_UPLOAD;

    now = time(NULL);
    if (now == (time_t)-1)
        return ALLOW_UPLOAD;

    if (line_cnt <= 10)
    {
        CRASHUPLOAD_INFO("is_upload_limit_reached() not reached.%d\n", line_cnt);
    }
    else
    {
        if ((now - first_crash_time) < RECOVERY_DELAY_SEC)
        {
            CRASHUPLOAD_INFO("Not uploading the dump. Too many dumps.\n");
            ret = STOP_UPLOAD;
        }
        else
        {
            CRASHUPLOAD_INFO("is_upload_limit_reached() not reached proceed for upload\n");
            unlink(file);
        }
    }
    return ret;
}

int is_recovery_time_reached(const char *deny_file)
{
    struct stat st;
    FILE *fp;
    char buf[32];
    char *endptr;
    long deny_until;
    time_t now;

    if (!deny_file)
        return ALLOW_UPLOAD; /* allow upload */

    /* If deny file does not exist ?~F~R allow */
    if (stat(deny_file, &st) != 0)
        return ALLOW_UPLOAD;

    fp = fopen(deny_file, "r");
    if (!fp)
        return ALLOW_UPLOAD;

    if (!fgets(buf, sizeof(buf), fp))
    {
        fclose(fp);
        return ALLOW_UPLOAD;
    }
    fclose(fp);

    /* Validate numeric content */
    for (size_t i = 0; buf[i] != '\0' && buf[i] != '\n'; i++)
    {
        if (!isdigit((unsigned char)buf[i]))
            return ALLOW_UPLOAD;
    }

    deny_until = strtol(buf, &endptr, 10);
    if (endptr == buf)
        return ALLOW_UPLOAD;

    now = time(NULL);
    if (now == (time_t)-1)
        return ALLOW_UPLOAD;

    /* Recovery time reached */
    if (now > deny_until)
        return ALLOW_UPLOAD;

    /* Still in deny window */
    return STOP_UPLOAD;
}

int ratelimit_check_unified(dump_type_t dump_type)
{
    int status = -1;
    status = is_recovery_time_reached(DENY_UPLOADS_FILE);
    if (status != ALLOW_UPLOAD)
    {
        CRASHUPLOAD_INFO("Shifting the recovery time forward.\n");
        set_time(DENY_UPLOADS_FILE, CURRENT_TIME);
        return RATELIMIT_BLOCK;
    }
    if (dump_type == DUMP_TYPE_MINIDUMP)
    {
        status = is_upload_limit_reached("/tmp/.minidump_upload_timestamps");
        if (status != ALLOW_UPLOAD)
        {
            CRASHUPLOAD_INFO("Upload rate limit has been reached.\n");
            // TODO: markAsCrashLoopedAndUpload $f
            CRASHUPLOAD_INFO("Setting recovery time\n");
            set_time(DENY_UPLOADS_FILE, CURRENT_TIME);
            status = RATELIMIT_BLOCK;
        }
    }
    else
    {
        status = ALLOW_UPLOAD;
    }
    return status;
}
