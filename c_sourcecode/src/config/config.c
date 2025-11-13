/* FULL IMPLEMENTATION (config_init) + SKELETON (config_get_value) */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * FULL IMPLEMENTATION
 * Load properties from file - searches for key=value pairs
 */
int config_load_properties(const char *filepath, const char *key, char *value, size_t len) {
    if (!filepath || !key || !value || len < 1) {
        return -1;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        return -1;
    }

    char line[512];
    size_t key_len = strlen(key);

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* Check if line starts with key= */
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            char *val = line + key_len + 1;
            
            /* Remove trailing newline and whitespace */
            char *newline = strchr(val, '\n');
            if (newline) *newline = '\0';
            
            char *cr = strchr(val, '\r');
            if (cr) *cr = '\0';

            strncpy(value, val, len - 1);
            value[len - 1] = '\0';
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

/**
 * FULL IMPLEMENTATION
 * Initialize configuration from multiple sources
 * Priority: Environment variables > device.properties > include.properties
 */
int config_init(config_t *config) {
    if (!config) {
        return -1;
    }

    memset(config, 0, sizeof(config_t));

    /* Determine device type and set paths accordingly */
    const char *device_props_paths[] = {
        "/etc/device.properties",
        "/opt/device.properties",
        "/nvram/device.properties",
        NULL
    };

    /* Try to find device.properties */
    for (int i = 0; device_props_paths[i] != NULL; i++) {
        if (access(device_props_paths[i], R_OK) == 0) {
            strncpy(config->device_properties_path, device_props_paths[i], 
                    MAX_CONFIG_PATH - 1);
            break;
        }
    }

    /* Try to find include.properties */
    const char *include_props_paths[] = {
        "/etc/include.properties",
        "/opt/include.properties",
        NULL
    };

    for (int i = 0; include_props_paths[i] != NULL; i++) {
        if (access(include_props_paths[i], R_OK) == 0) {
            strncpy(config->include_properties_path, include_props_paths[i],
                    MAX_CONFIG_PATH - 1);
            break;
        }
    }

    /* Load CORE_PATH - try env var first, then device.properties */
    const char *core_path_env = getenv("CORE_PATH");
    if (core_path_env) {
        strncpy(config->core_path, core_path_env, MAX_CONFIG_PATH - 1);
    } else if (config->device_properties_path[0] != '\0') {
        char temp[MAX_CONFIG_VALUE];
        if (config_load_properties(config->device_properties_path, "CORE_PATH", 
                                   temp, sizeof(temp)) == 0) {
            strncpy(config->core_path, temp, MAX_CONFIG_PATH - 1);
        } else {
            /* Did not get exact implementation, added hardcoded value */
            strncpy(config->core_path, "/opt/core", MAX_CONFIG_PATH - 1);
        }
    } else {
        /* Did not get exact implementation, added hardcoded value */
        strncpy(config->core_path, "/opt/core", MAX_CONFIG_PATH - 1);
    }

    /* Load MINIDUMP_PATH */
    const char *minidump_path_env = getenv("MINIDUMP_PATH");
    if (minidump_path_env) {
        strncpy(config->minidump_path, minidump_path_env, MAX_CONFIG_PATH - 1);
    } else if (config->device_properties_path[0] != '\0') {
        char temp[MAX_CONFIG_VALUE];
        if (config_load_properties(config->device_properties_path, "MINIDUMP_PATH",
                                   temp, sizeof(temp)) == 0) {
            strncpy(config->minidump_path, temp, MAX_CONFIG_PATH - 1);
        } else {
            /* Did not get exact implementation, added hardcoded value */
            strncpy(config->minidump_path, "/opt/minidumps", MAX_CONFIG_PATH - 1);
        }
    } else {
        /* Did not get exact implementation, added hardcoded value */
        strncpy(config->minidump_path, "/opt/minidumps", MAX_CONFIG_PATH - 1);
    }

    /* Check for T2 telemetry support */
    if (access("/usr/bin/t2ValNotify", X_OK) == 0 ||
        access("/lib/rdk/t2ValNotify.sh", X_OK) == 0) {
        config->t2_enabled = true;
    } else {
        config->t2_enabled = false;
    }

    config->initialized = true;
    return 0;
}

/**
 * SKELETON
 * Get configuration value by key
 */
int config_get_value(const config_t *config, const char *key, char *value, size_t len) {
    if (!config || !config->initialized || !key || !value || len < 1) {
        return -1;
    }

    /* SKELETON - Try environment variable first */
    const char *env_val = getenv(key);
    if (env_val) {
        strncpy(value, env_val, len - 1);
        value[len - 1] = '\0';
        return 0;
    }

    /* SKELETON - Try device.properties */
    if (config->device_properties_path[0] != '\0') {
        if (config_load_properties(config->device_properties_path, key, value, len) == 0) {
            return 0;
        }
    }

    /* SKELETON - Try include.properties */
    if (config->include_properties_path[0] != '\0') {
        if (config_load_properties(config->include_properties_path, key, value, len) == 0) {
            return 0;
        }
    }

    return -1;
}

/**
 * FULL IMPLEMENTATION
 * Clean up configuration resources
 */
void config_cleanup(config_t *config) {
    if (config) {
        memset(config, 0, sizeof(config_t));
    }
}
