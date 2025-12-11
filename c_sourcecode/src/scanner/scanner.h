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
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count);

int process_file_entry(char *fullpath, char *dump_type);
#endif
