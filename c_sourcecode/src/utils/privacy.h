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
 * @file privacy.h
 * @brief Unified privacy checker
 * SKELETON: Interface definition
 */
#ifndef PRIVACY_H
#define PRIVACY_H

#include "../../common/types.h"
#include <stdbool.h>

/**
 * @brief Check if uploads are blocked by privacy settings
 * @param config Configuration
 * @return true if blocked
 */
bool privacy_uploads_blocked(const config_t *config);

#endif
