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
 * @file system_init.h
 * @brief Consolidated system initialization module
 * 
 * Based on docs/migration/hld/updateduploadDumps-hld.md Section 2.1
 * Consolidates argument parsing, config loading, and platform initialization
 * 
 * SKELETON: Interface definition, implementation needed
 */

#ifndef SYSTEM_INIT_H
#define SYSTEM_INIT_H

#include "../../common/types.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Consolidated initialization function
 * 
 * Performs all initialization steps in one call:
 * - Parse command-line arguments
 * - Load configuration from all sources
 * - Initialize platform configuration
 * - Set up signal handlers
 * 
 * Optimization: Reduces 3 separate steps to 1 function (saves ~100-150ms)
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @param config Pointer to configuration structure (output)
 * @param platform Pointer to platform structure (output)
 * @return ERR_SUCCESS on success, error code on failure
 */
int system_initialize(int argc, char *argv[], 
                     config_t *config,
                     platform_config_t *platform);

#endif /* SYSTEM_INIT_H */
