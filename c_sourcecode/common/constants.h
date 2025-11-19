/**
 * @file constants.h
 * @brief Constants and macros for crashupload C implementation
 * 
 * Based on docs/migration/requirements/uploadDumps-requirements.md
 * Following optimized design specifications
 */

#ifndef CRASHUPLOAD_CONSTANTS_H
#define CRASHUPLOAD_CONSTANTS_H

/* Application constants */
#define APP_NAME "crashupload"
#define APP_VERSION "2.0.0"

/* Path constants */
#define MAX_PATH_LEN 512
#define MAX_FILENAME_LEN 256
#define ECRYPTFS_MAX_FILENAME 135

/* Upload constants */
#define DEFAULT_UPLOAD_TIMEOUT 45
#define MAX_RETRIES_MINIDUMP 5
#define MAX_RETRIES_COREDUMP 3
#define RETRY_DELAY_MINIDUMP 3
#define RETRY_DELAY_COREDUMP 10

/* Rate limiting constants */
#define RATE_LIMIT_MAX_UPLOADS 10
#define RATE_LIMIT_WINDOW_SEC 600  /* 10 minutes */
#define CRASHLOOP_MAX_UPLOADS 5
#define CRASHLOOP_WINDOW_SEC 60    /* 1 minute */
#define RECOVERY_BLOCK_FILE "/tmp/.crashupload_recovery"
#define RATELIMIT_STATE_FILE "/tmp/.crashupload_ratelimit"

/* Processing constants */
#define MAX_DUMPS_PER_RUN 100
#define FILE_AGE_CLEANUP_DAYS 2

/* Lock constants */
#define LOCK_FILE "/var/run/crashupload.lock"
#define LOCK_TIMEOUT_SEC 300

/* Configuration file paths */
#define DEVICE_PROPERTIES "/etc/device.properties"
#define INCLUDE_PROPERTIES "/etc/include.properties"

/* Logging constants */
#define LOG_BUFFER_SIZE 512

/* Network constants */
#define PREREQUISITE_TIMEOUT_SEC 120
#define NETWORK_CHECK_INTERVAL_SEC 5

#endif /* CRASHUPLOAD_CONSTANTS_H */
