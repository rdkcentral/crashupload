/**
 * @file types.h
 * @brief Common type definitions for crashupload C implementation
 * 
 * Based on docs/migration/hld/updateduploadDumps-hld.md
 * Following optimized architecture with consolidated modules
 */

#ifndef CRASHUPLOAD_TYPES_H
#define CRASHUPLOAD_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rdk_fwdl_utils.h"
#include "system_utils.h"

#define DENY_UPLOADS_FILE "/tmp/.deny_dump_uploads_till"
#define ON_STARTUP_DUMPS_CLEANED_UP_BASE "/tmp/.on_startup_dumps_cleaned_up"
#define EnableOCSPStapling "/tmp/.EnableOCSPStapling"
#define EnableOCSP "/tmp/.EnableOCSPCA"
#define MAX_CORE_FILES 4
#define LOGMAPPER_FILE_PATH "/etc/breakpad-logmapper.conf"
#define LOG_FILES_PATH "/tmp/minidump_log_files.txt"

/* Device types */
typedef enum {
    DEVICE_TYPE_BROADBAND,
    DEVICE_TYPE_VIDEO,
    DEVICE_TYPE_EXTENDER,
    DEVICE_TYPE_MEDIACLIENT,
    DEVICE_TYPE_UNKNOWN
} device_type_t;

/* Dump file types */
typedef enum {
    DUMP_TYPE_MINIDUMP,
    DUMP_TYPE_COREDUMP,
    DUMP_TYPE_UNKNOWN
} dump_type_t;

typedef enum {
    UPLOAD_MODE_NORMAL,
    UPLOAD_MODE_SECURE
} upload_mode_t;

typedef enum {
    LOCK_MODE_EXIT,
    LOCK_MODE_WAIT
} lock_mode_t;

// Upload result types
/*
typedef enum {
    UPLOAD_SUCCESS,
    UPLOAD_FAILURE_RETRY,
    UPLOAD_FAILURE_REMOVE,
    UPLOAD_FAILURE_SAVE
} upload_result_t;
*/

typedef enum {
    BUILD_TYPE_PROD,
    BUILD_TYPE_DEV,
    BUILD_TYPE_UNKNOWN
} build_type_t;

/* Rate limit decision */
typedef enum {
    RATELIMIT_ALLOW,
    RATELIMIT_BLOCK_RECOVERY,
    RATELIMIT_BLOCK_LIMIT
} ratelimit_decision_t;

/* Configuration structure (consolidated from HLD) */
typedef struct {
    device_type_t device_type;
    dump_type_t dump_type;
    lock_mode_t lock_mode;
    upload_mode_t upload_mode;
    build_type_t build_type;
    char upload_url[512];
    char dump_path[64];
    char core_path[64];
    char minidump_path[64];
    char archive_path[64];
    char working_dir_path[64];
    char core_log_file[64];
    char log_file[64];
    char log_mapper_file[64];
    char box_type[64];
    char log_path[16];
    char build_type_val[8];
    bool t2_enabled;
    bool privacy_mode;
    bool opt_out;
    int max_dumps_per_run;
    int upload_timeout;
} config_t;

/* Platform configuration structure */
typedef struct {
    char mac_address[18];
    char ip_address[16];
    char model[64];
    char device_id[128];
    char firmware_version[64];
    char platform_sha1[41];
} platform_config_t;

/* Dump file metadata */
/*typedef struct {
    char filepath[512];
    char basename[256];
    dump_type_t type;
    time_t mtime;
    off_t size;
} dump_file_t;*/

typedef struct {
    char path[512];
    char mtime_date[64];
    time_t mtime;
    off_t size;
    int is_minidump;  /* 1 for .dmp, 0 for .core */
} dump_file_t;

/* Archive info structure */
typedef struct {
    char archive_path[512];
    char archive_name[512];
    bool created_in_tmp;
} archive_info_t;

#endif /* CRASHUPLOAD_TYPES_H */
