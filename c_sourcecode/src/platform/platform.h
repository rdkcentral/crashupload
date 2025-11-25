/**
 * @file platform.h
 * @brief Platform abstraction module
 * SKELETON: Interface definition
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include "../../common/types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "file_utils.h"
#include "common_device_api.h"

#define MAC_FILE           "/tmp/.macAddress"
#define MAC_ADDRESS_LEN 17

/**
 * @brief Initialize platform configuration
 * @param config Application configuration
 * @param platform Platform configuration (output)
 * @return ERR_SUCCESS on success
 */
int platform_initialize(const config_t *config, platform_config_t *platform);

#endif
