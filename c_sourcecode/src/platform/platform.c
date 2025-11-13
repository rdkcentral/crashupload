/* FULL IMPLEMENTATION (platform_init) + SKELETON (prerequisite/privacy checks) */

#include "platform.h"
#include "network_utils.h"
#include "file_utils.h"
#include "system_utils.h"
#include <stdio.h>
#include <string.h>

/**
 * FULL IMPLEMENTATION
 * Consolidated platform initialization (optimization: 3 separate calls → 1)
 * Gets MAC, IP, model, firmware SHA1 using caching for efficiency
 */
int platform_init(platform_config_t *platform) {
    if (!platform) {
        return -1;
    }

    memset(platform, 0, sizeof(platform_config_t));

    /* Get MAC address with 60s caching */
    if (network_get_mac_address("erouter0", platform->mac_address, 
                                MAX_MAC_LEN, true) != 0) {
        /* Fallback to eth0 */
        if (network_get_mac_address("eth0", platform->mac_address,
                                   MAX_MAC_LEN, true) != 0) {
            return -1;
        }
    }

    /* Get IP address */
    if (network_get_ip_address("erouter0", platform->ip_address,
                              MAX_IP_LEN) != 0) {
        /* Fallback to eth0 */
        if (network_get_ip_address("eth0", platform->ip_address,
                                  MAX_IP_LEN) != 0) {
            strncpy(platform->ip_address, "0.0.0.0", MAX_IP_LEN - 1);
        }
    }

    /* Get model with indefinite caching */
    if (system_get_model(platform->model, MAX_MODEL_LEN) != 0) {
        strncpy(platform->model, "UNKNOWN", MAX_MODEL_LEN - 1);
    }

    /* Get firmware SHA1 (mtime-based caching via file_utils) */
    const char *firmware_paths[] = {
        "/version.txt",
        "/etc/version.txt",
        "/opt/version.txt",
        NULL
    };

    for (int i = 0; firmware_paths[i] != NULL; i++) {
        if (file_get_sha1(firmware_paths[i], platform->firmware_sha1,
                         MAX_SHA1_LEN) == 0) {
            break;
        }
    }

    /* If no firmware file found, use placeholder */
    if (platform->firmware_sha1[0] == '\0') {
        /* Did not get exact implementation, added hardcoded value */
        strncpy(platform->firmware_sha1, "0000000000000000000000000000000000000000",
                MAX_SHA1_LEN - 1);
    }

    /* Determine platform type based on model */
    if (strstr(platform->model, "TG") || strstr(platform->model, "DPC")) {
        platform->type = PLATFORM_BROADBAND;
    } else if (strstr(platform->model, "XG") || strstr(platform->model, "XID")) {
        platform->type = PLATFORM_VIDEO;
    } else if (strstr(platform->model, "XH") || strstr(platform->model, "XLE")) {
        platform->type = PLATFORM_EXTENDER;
    } else if (strstr(platform->model, "XA") || strstr(platform->model, "MC")) {
        platform->type = PLATFORM_MEDIACLIENT;
    } else {
        platform->type = PLATFORM_UNKNOWN;
    }

    platform->initialized = true;
    return 0;
}

/**
 * SKELETON
 * Check prerequisites (network connectivity + time sync combined)
 */
int platform_check_prerequisites(const platform_config_t *platform) {
    if (!platform || !platform->initialized) {
        return -1;
    }

    /* SKELETON - Combined prerequisite check for optimization */
    /* TODO: Implement network connectivity check */
    /* TODO: Implement time synchronization check */
    /* Did not get function implementation, added mock function */
    
    /* For now, assume prerequisites are met if we have valid IP */
    if (strcmp(platform->ip_address, "0.0.0.0") == 0 ||
        platform->ip_address[0] == '\0') {
        return -1;
    }

    return 0;
}

/**
 * SKELETON  
 * Check privacy settings (opt-out + privacy mode unified)
 */
int platform_check_privacy(const platform_config_t *platform, bool *enabled) {
    if (!platform || !platform->initialized || !enabled) {
        return -1;
    }

    /* SKELETON - Unified privacy check for optimization */
    /* TODO: Check opt-out status from RFC settings */
    /* TODO: Check privacy mode flag */
    /* Did not get function implementation, added mock function */
    
    /* For now, assume privacy is not enabled (uploads allowed) */
    *enabled = false;
    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Get platform type as string
 */
const char* platform_get_type_string(platform_type_t type) {
    switch (type) {
        case PLATFORM_BROADBAND:
            return "broadband";
        case PLATFORM_VIDEO:
            return "video";
        case PLATFORM_EXTENDER:
            return "extender";
        case PLATFORM_MEDIACLIENT:
            return "mediaclient";
        default:
            return "unknown";
    }
}

/**
 * FULL IMPLEMENTATION
 * Clean up platform resources
 */
void platform_cleanup(platform_config_t *platform) {
    if (platform) {
        memset(platform, 0, sizeof(platform_config_t));
    }
}
