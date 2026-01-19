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
 * @file scanner.h
 * @brief Dump file scanner module
 * SKELETON: Interface definition
 */
#ifndef SCANNER_H
#define SCANNER_H

#include "../../common/types.h"
#include <ctype.h>
/**
 * @brief Find and sort dump files
 * @param config Configuration
 * @param dumps Array of dumps (output, caller must free)
 * @param count Number of dumps found (output)
 * @return ERR_SUCCESS on success
 */
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count, const char *dump_extn_pattern);

int process_file_entry(char *fullpath, char *dump_type, const config_t *config);
char *extract_pname(const char *filepath);
#endif
