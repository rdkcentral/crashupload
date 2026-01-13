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
 * @file prerequisites.h
 * @brief Combined prerequisites checker
 * SKELETON: Interface definition
 */
#ifndef PREREQUISITES_H
#define PREREQUISITES_H

#include "../../common/types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"

/**
 * @brief Wait for network and time sync
 * @param timeout_sec Timeout in seconds
 * @return ERR_SUCCESS when ready
 */
int prerequisites_wait(config_t *config, int timeout_sec);

#endif
