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
 * @file lock_manager.h
 * @brief Process lock manager
 * SKELETON: Interface definition
 */
#ifndef LOCK_MANAGER_H
#define LOCK_MANAGER_H

#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * @brief Acquire process lock
 * @param lock_file Path to lock file
 * @param timeout_sec Timeout in seconds
 * @return File descriptor on success, -1 on failure
 */
int lock_acquire(const char *lock_file, int timeout_sec, bool t2_enabled);

/**
 * @brief Release process lock
 * @param fd File descriptor from lock_acquire
 */
void lock_release(int fd, const char *file);

#endif
