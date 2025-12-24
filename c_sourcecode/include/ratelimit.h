#ifndef RATELIMIT_H
#define RATELIMIT_H

#include "../common/types.h"
#define RATELIMIT_BLOCK 0
/**
 * Check if upload is allowed (unified: recovery mode + 10/10min limit)
 * @return 0 if allowed, -1 if rate limited
 */
int ratelimit_check(void);

int ratelimit_check_unified(dump_type_t dump);

/**
 * Record successful upload
 * @return 0 on success, -1 on error
 */
int ratelimit_record_upload(void);

/**
 * Reset rate limiter state
 * @return 0 on success, -1 on error
 */
int ratelimit_reset(void);

/**
 * Get current upload count in time window
 * @return Upload count
 */
int ratelimit_get_count(void);

/**
 * Check if in recovery mode
 * @return 1 if in recovery mode, 0 otherwise
 */
int ratelimit_is_recovery_mode(void);

#endif /* RATELIMIT_H */
