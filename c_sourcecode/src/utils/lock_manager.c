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
 * @file lock_manager.c
 * SKELETON: Implementation needed
 */
#include "lock_manager.h"
#include "telemetryinterface.h"
#include <stdbool.h>
#include "logger.h"

int acquire_process_lock_or_exit(const char *lock_path, bool t2_enabled)
{
    // char script_lock_path_dir[32] = {0};
    // snprintf(script_lock_path_dir, sizeof(script_lock_path_dir), "%s.lock.d", lock_path);
    int fd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
    {
        CRASHUPLOAD_ERROR("open error\n");
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
    {
        CRASHUPLOAD_INFO("Another execution is already working. %s. Skip launch another instance...\n", lock_path);
        if (t2_enabled == true)
        {
            t2CountNotify("SYST_WARN_NoMinidump", 1);
        }
        exit(0);
    }

    return fd; // Keep FD open until end
}

int acquire_process_lock_or_wait(const char *lock_path, int wait_time)
{
    // char script_lock_path_dir[32] = {0};
    // struct stat st;

    // snprintf(script_lock_path_dir, sizeof(script_lock_path_dir), "%s.lock.d", lock_path);
    // printf("acquire_process_lock_or_wait file=%s and dir lock file=%s\n", lock_path, script_lock_path_dir);
    int fd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
    {
        CRASHUPLOAD_ERROR("open error\n");
        return -1;
    }

    while ((flock(fd, LOCK_EX) < 0))
    {
        CRASHUPLOAD_INFO("Waiting for lock...\n");
        sleep(wait_time);
    }

    return fd;
}

void release_process_lock(int lock_fd)
{
    if (lock_fd >= 0)
    {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    else
    {
        CRASHUPLOAD_ERROR("Invalid file descripter try to close:%d\n", lock_fd);
    }
}

int lock_acquire(const char *lock_file, int timeout_sec, bool t2_enabled)
{
    int ret = -1;

    if (lock_file != NULL)
    {
        if (timeout_sec > 0)
        {
            ret = acquire_process_lock_or_wait(lock_file, timeout_sec);
        }
        else
        {
            ret = acquire_process_lock_or_exit(lock_file, t2_enabled);
        }
    }
    else
    {
        CRASHUPLOAD_ERROR("Invalid argument\n");
    }
    return ret;
}

void lock_release(int fd, const char *lock_file)
{
    release_process_lock(fd);
    unlink(lock_file);
}
