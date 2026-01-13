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

#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool is_box_rebooting(bool t2_enabled);
/**
 * Get system uptime in seconds
 * Uses sysinfo() with fallback to /proc/uptime
 * @param uptime_seconds Pointer to store uptime
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with fallback mechanism
 */
int system_get_uptime(uint64_t *uptime_seconds);

/**
 * Get device model number
 * @param model Buffer to store model
 * @param len Buffer length
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with indefinite caching and multiple fallbacks
 */
int system_get_model(char *model, size_t len);

/**
 * Check if a process is running by name
 * @param name Process name to search for
 * @param is_running Pointer to store result (true if running)
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION using /proc scan (no ps command)
 */
int system_check_process(const char *name, bool *is_running);

/**
 * Execute system reboot
 * @return 0 on success, -1 on error
 * 
 * SKELETON - calls system() for now
 */
int system_reboot(void);

#endif /* SYSTEM_UTILS_H */
