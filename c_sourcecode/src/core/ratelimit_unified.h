/**
 * @file ratelimit_unified.h
 * @brief Unified rate limiting module
 * SKELETON: Interface definition
 */
#ifndef RATELIMIT_UNIFIED_H
#define RATELIMIT_UNIFIED_H

#include "../../common/types.h"

/**
 * @brief Check unified rate limit (recovery + 10/10min)
 * @param dump Dump file to check
 * @return ratelimit_decision_t
 */
ratelimit_decision_t ratelimit_check_unified(const dump_file_t *dump);

/**
 * @brief Record upload attempt
 * @param success Whether upload succeeded
 */
void ratelimit_record_upload(bool success);

#endif
