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

#ifndef RATELIMIT_H
#define RATELIMIT_H

#include "../common/types.h"
#define RATELIMIT_BLOCK 0
//#define RECOVERY_DELAY_SEC 600 //TODO: Un-comment this and remove below
#define RECOVERY_DELAY_SEC 30
#define DENY_UPLOADS_FILE "/tmp/.deny_dump_uploads_till"
#define ALLOW_UPLOAD 1
#define STOP_UPLOAD 0
#define RECOVERY_TIME 1
#define CURRENT_TIME 2
/**
 * Check if upload is allowed (unified: recovery mode + 10/10min limit)
 * @return 0 if allowed, -1 if rate limited
 */
int ratelimit_check(void);

int ratelimit_check_unified(dump_type_t dump);
int set_time(const char *deny_file, int type);

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
