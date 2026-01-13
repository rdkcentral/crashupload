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

#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include <stdbool.h>

#define MAX_CONFIG_VALUE 256
#define MAX_CONFIG_PATH 1024

/**
 * Configuration structure
 */
typedef struct {
    char device_properties_path[MAX_CONFIG_PATH];
    char include_properties_path[MAX_CONFIG_PATH];
    char core_path[MAX_CONFIG_PATH];
    char minidump_path[MAX_CONFIG_PATH];
    bool t2_enabled;
    bool initialized;
} config_t;

/**
 * Initialize configuration from multiple sources
 * Priority: Environment variables > device.properties > include.properties
 * @param config Pointer to config structure
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION - Multi-source configuration loading
 */
int config_init(config_t *config);

/**
 * Get configuration value by key
 * @param config Pointer to config structure
 * @param key Configuration key
 * @param value Buffer to store value
 * @param len Buffer length
 * @return 0 on success, -1 on error
 * 
 * SKELETON - Structure ready, implementation pending
 */
int config_get_value(const config_t *config, const char *key, char *value, size_t len);

/**
 * Load properties from file
 * @param filepath Path to properties file
 * @param key Key to search for
 * @param value Buffer to store value
 * @param len Buffer length
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION
 */
int config_load_properties(const char *filepath, const char *key, char *value, size_t len);

/**
 * Clean up configuration resources
 * @param config Pointer to config structure
 * 
 * FULL IMPLEMENTATION
 */
void config_cleanup(config_t *config);

#endif /* CONFIG_H */
