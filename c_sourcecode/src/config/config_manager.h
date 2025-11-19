/**
 * @file config_manager.h
 * @brief Configuration management module
 * SKELETON: Interface definition
 */
#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "../../common/types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"

/**
 * @brief Load configuration from multiple sources
 * @param config Configuration structure to populate
 * @return ERR_SUCCESS on success
 */
int config_init_load(config_t *config);

/**
 * @brief Get configuration value by key
 * @param key Configuration key
 * @param value Buffer for value (output)
 * @param len Buffer length
 * @return ERR_SUCCESS on success
 */
int config_get(const char *key, char *value, size_t len);

#endif
