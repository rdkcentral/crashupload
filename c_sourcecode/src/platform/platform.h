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

#include "types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "file_utils.h"
#include "common_device_api.h"

#define MAC_FILE "/tmp/.macAddress"
#define MAC_ADDRESS_LEN 17

/**
 * @brief Initialize platform configuration
 * @param config Application configuration
 * @param platform Platform configuration (output)
 * @return ERR_SUCCESS on success
 */
int platform_initialize(const config_t *config, platform_config_t *platform);

#endif
