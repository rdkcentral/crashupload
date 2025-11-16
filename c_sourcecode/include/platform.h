#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdbool.h>

#define MAX_MAC_LEN 18
#define MAX_IP_LEN 16
#define MAX_MODEL_LEN 64
#define MAX_SHA1_LEN 41

/**
 * Platform types supported
 */
typedef enum {
    PLATFORM_BROADBAND,
    PLATFORM_VIDEO,
    PLATFORM_EXTENDER,
    PLATFORM_MEDIACLIENT,
    PLATFORM_UNKNOWN
} platform_type_t;

/**
 * Platform configuration structure
 */
typedef struct {
    char mac_address[MAX_MAC_LEN];
    char ip_address[MAX_IP_LEN];
    char model[MAX_MODEL_LEN];
    char firmware_sha1[MAX_SHA1_LEN];
    platform_type_t type;
    bool initialized;
} platform_config_t;

/**
 * Initialize platform configuration (consolidated initialization)
 * Gets MAC, IP, model, firmware SHA1 in optimized manner
 * Uses caching: MAC (60s), Model (indefinite), SHA1 (mtime-based)
 * @param platform Pointer to platform config structure
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION - Consolidated initialization optimization
 */
int platform_init(platform_config_t *platform);

/**
 * Check prerequisites (network connectivity + time sync)
 * Combined check for optimization
 * @param platform Pointer to platform config structure
 * @return 0 if prerequisites met, -1 otherwise
 * 
 * SKELETON - Structure ready, implementation pending
 */
int platform_check_prerequisites(const platform_config_t *platform);

/**
 * Check privacy settings (opt-out + privacy mode unified)
 * @param platform Pointer to platform config structure
 * @param enabled Pointer to store result (true if privacy disabled/opted-out)
 * @return 0 on success, -1 on error
 * 
 * SKELETON - Structure ready, implementation pending
 */
int platform_check_privacy(const platform_config_t *platform, bool *enabled);

/**
 * Get platform type string
 * @param type Platform type enum
 * @return Platform type string
 * 
 * FULL IMPLEMENTATION
 */
const char* platform_get_type_string(platform_type_t type);

/**
 * Clean up platform resources
 * @param platform Pointer to platform config structure
 * 
 * FULL IMPLEMENTATION
 */
void platform_cleanup(platform_config_t *platform);

#endif /* PLATFORM_H */
