/**
 * @file prerequisites.h
 * @brief Combined prerequisites checker
 * SKELETON: Interface definition
 */
#ifndef PREREQUISITES_H
#define PREREQUISITES_H

#include "../../common/types.h"
#include "rdk_fwdl_utils.h"
#include "system_utils.h"

/**
 * @brief Wait for network and time sync
 * @param timeout_sec Timeout in seconds
 * @return ERR_SUCCESS when ready
 */
int prerequisites_wait(config_t *config, int timeout_sec);

#endif
