/**
 * @file privacy.h
 * @brief Unified privacy checker
 * SKELETON: Interface definition
 */
#ifndef PRIVACY_H
#define PRIVACY_H

#include "../../common/types.h"
#include <stdbool.h>

/**
 * @brief Check if uploads are blocked by privacy settings
 * @param config Configuration
 * @return true if blocked
 */
bool privacy_uploads_blocked(const config_t *config);

#endif
