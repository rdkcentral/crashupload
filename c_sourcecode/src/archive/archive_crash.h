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
 * @file archive_smart.h
 * @brief Smart archive creator with fallback
 * SKELETON: Interface definition
 */
#ifndef ARCHIVE_SMART_H
#define ARCHIVE_SMART_H

#include "types.h"
#include <archive.h>
#include <archive_entry.h>
#include <sys/resource.h>
/**
 * @brief Create archive with smart compression
 * @param dump Dump file to archive
 * @param platform Platform configuration
 * @param archive Archive info (output)
 * @return ERR_SUCCESS on success
 */
int archive_create_smart(const dump_file_t *dump, const config_t *config,
                         const platform_config_t *platform,
                         archive_info_t *archive, char *new_dump_name);

void set_low_priority(void);
int add_crashed_process_log_file(const config_t *config, const platform_config_t *platform,
                                 char *filename, char *process_log_file, size_t size);

#endif
