#ifndef UPLOAD_H
#define UPLOAD_H

#include "../common/types.h"
#include "../common/constants.h"
#include "../common/errors.h"
#include "file_utils.h"

#define S3_SIGNEDURL_FILE "/tmp/signed_url_"

typedef enum {
    UPLOAD_TYPE_COREDUMP,
    UPLOAD_TYPE_MINIDUMP,
    UPLOAD_TYPE_LOG
} upload_type_t;

int upload_process(archive_info_t *archive, const config_t *config, const platform_config_t *platform);
/**
 * Upload file with TLS 1.2 and type-aware retry logic
 * @param filepath Path to file to upload
 * @param url Upload URL
 * @param type Type of upload (affects retry strategy)
 * @return 0 on success, -1 on error
 */
//int upload_file(const char *filepath, const char *url, upload_type_t type);
int upload_file(const char *filepath, const char *url, const char *dump_name, const char *crash_fw_version, const char *build_type, const char *model, const char *md5sum, device_type_t device_type);
/**
 * Upload coredump file
 * @param filepath Path to coredump file
 * @param url Upload URL
 * @return 0 on success, -1 on error
 */
int upload_coredump(const char *filepath, const char *url);

/**
 * Upload minidump file
 * @param filepath Path to minidump file
 * @param url Upload URL
 * @return 0 on success, -1 on error
 */
int upload_minidump(const char *filepath, const char *url);

/**
 * Upload multiple files in batch
 * @param filepaths Array of file paths
 * @param urls Array of URLs
 * @param count Number of files
 * @return 0 if all successful, -1 if any failed
 */
int upload_batch(const char **filepaths, const char **urls, int count);

#endif /* UPLOAD_H */
