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
int upload_file(const char *filepath, const char *url, const char *dump_name, const char *crash_fw_version, const char *build_type, const char *model, const char *md5sum, device_type_t device_type, bool t2_enabled);

#endif /* UPLOAD_H */
