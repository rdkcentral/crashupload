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
 * @file config_manager.h
 * @brief Configuration management module
 * SKELETON: Interface definition
 */
#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "../../common/types.h"

bool get_opt_out_status(void);
/**
 * @brief Load configuration from multiple sources
 * @param config Configuration structure to populate
 * @return ERR_SUCCESS on success
 */
int config_init_load(config_t *config, int argc, char *argv[]);

bool get_privacy_control_mode(config_t *config);

void config_cleanup(config_t *config);
#endif
