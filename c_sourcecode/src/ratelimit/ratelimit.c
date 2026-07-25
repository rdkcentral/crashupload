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
#include <limits.h>
#include "ratelimit.h"
#include "logger.h"

int set_time(const char *deny_file, int type)
{
    FILE *fp;
    time_t now;
    long deny_until;
    const char *mode;

    if (!deny_file)
        return -1;

    /* Validate path to prevent traversal attacks */
    if (strstr(deny_file, "..") != NULL || deny_file[0] != '/')
    {
        CRASHUPLOAD_ERROR("Invalid file path (potential path traversal): %s\n", deny_file);
        return -1;
    }

    now = time(NULL);
    if (now == (time_t)-1)
        return -1;

    /* Determine file mode and timestamp value based on type */
    if (type == RECOVERY_TIME)
    {
        CRASHUPLOAD_INFO("Set Recovery Time inside file:%s\n", deny_file);
        /* Check for integer overflow */
        if (now > (LONG_MAX - RECOVERY_DELAY_SEC))
        {
            CRASHUPLOAD_ERROR("Integer overflow prevented in recovery time calculation\n");
            deny_until = LONG_MAX;
        }
        else
        {
            deny_until = (long)now + RECOVERY_DELAY_SEC;
        }
        mode = "w";  /* Overwrite for deny file */
    }
    else
    {
        deny_until = (long)now;
        /* Check if this is the timestamp file (should append) or deny file (should overwrite) */
        mode = (strncmp(deny_file, DENY_UPLOADS_FILE, strlen(DENY_UPLOADS_FILE)) == 0) ? "w" : "a";
    }

    fp = fopen(deny_file, mode);
    if (!fp)
        return -1;

    if (fprintf(fp, "%ld\n", deny_until) < 0)
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

    if (!file)
        return ALLOW_UPLOAD;

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
        fclose(fp);
    }
    else
    {
        CRASHUPLOAD_INFO("File for rate limit check not present\n");
        return ret;
    }

    /* Validate numeric content of FIRST line */
    for (size_t i = 0; first_line_data[i] != '\0' && first_line_data[i] != '\n' && i < sizeof(first_line_data); i++)
    {
        if (!isdigit((unsigned char)first_line_data[i]))
        {
            CRASHUPLOAD_WARN("Invalid timestamp format in first line\n");
            return ALLOW_UPLOAD;
        }
    }

    errno = 0;
    first_crash_time = strtol(first_line_data, &endptr, 10);
    if (endptr == first_line_data)
    {
        CRASHUPLOAD_WARN("Failed to parse first timestamp\n");
        return ALLOW_UPLOAD;
    }

    /* Check for overflow */
    if (errno == ERANGE || first_crash_time < 0)
    {
        CRASHUPLOAD_WARN("Timestamp overflow or invalid value detected\n");
        return ALLOW_UPLOAD;
    }

    now = time(NULL);
    if (now == (time_t)-1)
        return ALLOW_UPLOAD;

    if (line_cnt <= 10)
    {
        CRASHUPLOAD_INFO("is_upload_limit_reached() not reached. Count: %d\n", line_cnt);
    }
    else
    {
        if ((now - first_crash_time) < RECOVERY_DELAY_SEC)
        {
            CRASHUPLOAD_INFO("Not uploading the dump. Too many dumps within %d seconds.\n", RECOVERY_DELAY_SEC);
            ret = STOP_UPLOAD;
        }
        else
        {
            CRASHUPLOAD_INFO("is_upload_limit_reached() time window expired, proceed for upload\n");
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

    /* If deny file does not exist, allow */
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

    /* Validate numeric content with bounds check */
    for (size_t i = 0; buf[i] != '\0' && buf[i] != '\n' && i < sizeof(buf); i++)
    {
        if (!isdigit((unsigned char)buf[i]))
            return ALLOW_UPLOAD;
    }

    errno = 0;
    deny_until = strtol(buf, &endptr, 10);
    if (endptr == buf)
        return ALLOW_UPLOAD;

    /* Check for overflow or invalid values */
    if (errno == ERANGE || deny_until < 0)
    {
        CRASHUPLOAD_WARN("Deny file contains invalid timestamp, allowing upload\n");
        return ALLOW_UPLOAD;
    }

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
        set_time(DENY_UPLOADS_FILE, RECOVERY_TIME);  /* Set future time */
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
            set_time(DENY_UPLOADS_FILE, RECOVERY_TIME);  /* Set future time */
            status = RATELIMIT_BLOCK;
        }
    }
    else
    {
        status = ALLOW_UPLOAD;
    }
    return status;
}
