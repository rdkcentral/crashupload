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
