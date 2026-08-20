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
 * @file platform.h
 * @brief Platform abstraction module
 * SKELETON: Interface definition
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include "../../common/types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "file_utils.h"
#include "common_device_api.h"

#define MAC_FILE "/tmp/.macAddress"
#define MAC_ADDRESS_LEN 17
#define TMP_CPU_INFO_FILE "/tmp/cpu_info"
#define CPU_INFO_FILE "/proc/cpuinfo"

#define IF_INFO_FILE            "/tmp/if_info"
#define SYSEVENT_TIMEOUT_SEC    900
#define SYSEVENT_POLL_SEC       5

/** @brief Initialize platform configuration
 * @param config Application configuration
 * @param platform Platform configuration (output)
 * @return ERR_SUCCESS on success
 */
int platform_initialize(const config_t *config, platform_config_t *platform);

/**
 * @brief Detect CPU core type from /tmp/cpu_info or /proc/cpuinfo.
 * @return "ARM", "ATOM", or "" (unknown). Result is cached in /tmp/cpu_info.
 */
const char *get_core_type(void);

/**
 * @brief Get the WAN interface name via sysevent polling (up to 900s).
 * Falls back to ATOM_INTERFACE/ARM_INTERFACE from device.properties on timeout.
 * @return interface name string (e.g. "erouter0"), or "unknown".
 */
const char *get_interface_value(void);

#endif
