/**
 * @file errors.h
 * @brief Error codes for crashupload C implementation
 * 
 * Based on docs/migration/lld/updateduploadDumps-lld.md
 * Consistent error code scheme across all modules
 */

#ifndef CRASHUPLOAD_ERRORS_H
#define CRASHUPLOAD_ERRORS_H

/* Success */
#define CONFIG_SUCCESS 0
#define SYSTEM_INIT_SUCCESS 0
#define PLATFORM_INIT_SUCCESS 0
#define PREREQUISITES_SUCCESS 0
#define LOCK_ACQUIRE_SUCCESS 0
#define NO_DUMPS_FOUND 5

/* General errors (1-19) */
#define ERR_GENERAL_FAILURE 1
#define ERR_INVALID_ARGUMENT 2
#define ERR_OUT_OF_MEMORY 3
#define ERR_NOT_IMPLEMENTED 4

/* Configuration errors (20-39) */
#define ERR_CONFIG_LOAD_FAILED 20
#define ERR_CONFIG_INVALID 21
#define ERR_CONFIG_MISSING_REQUIRED 22

/* Platform errors (40-59) */
#define ERR_PLATFORM_INIT_FAILED 40
#define ERR_PLATFORM_UNSUPPORTED 41
#define ERR_PLATFORM_MAC_FAILED 42
#define ERR_PLATFORM_MODEL_FAILED 43

/* Scanner errors (60-79) */
#define ERR_SCANNER_NO_DUMPS 60
#define ERR_SCANNER_PATH_INVALID 61
#define ERR_SCANNER_READ_FAILED 62

/* Archive errors (80-99) */
#define ERR_ARCHIVE_CREATE_FAILED 80
#define ERR_ARCHIVE_COMPRESS_FAILED 81
#define ERR_ARCHIVE_FALLBACK_FAILED 82

/* Upload errors (100-119) */
#define ERR_UPLOAD_FAILED 100
#define ERR_UPLOAD_NETWORK 101
#define ERR_UPLOAD_TIMEOUT 102
#define ERR_UPLOAD_SERVER_ERROR 103

/* Rate limit errors (120-139) */
#define ERR_RATELIMIT_EXCEEDED 120
#define ERR_RATELIMIT_RECOVERY_MODE 121
#define ERR_RATELIMIT_STATE_FAILED 122

/* Lock errors (140-159) */
#define ERR_LOCK_FAILED 140
#define ERR_LOCK_TIMEOUT 141
#define ERR_LOCK_ALREADY_HELD 142

/* Privacy/prerequisite errors (160-179) */
#define ERR_PRIVACY_BLOCKED 160
#define ERR_PREREQUISITE_TIMEOUT 161
#define ERR_NETWORK_NOT_READY 162
#define ERR_TIME_NOT_SYNCED 163

#endif /* CRASHUPLOAD_ERRORS_H */
