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

#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

int is_regular_file(const char *path);
bool check_process_dmp_file(const char *file);
int extract_tail(const char *src,
                        const char *dst,
                        int max_lines);
int file_get_mtime_formatted(const char *path, char *mtime, size_t len);
int trim_process_name_in_path(const char *full_path,
                              const char *process_name, int max_pname_trim,
                              char *out,
                              size_t out_len);
int get_crash_timestamp_utc(char *out, size_t outsz);
int compute_s3_md5_base64(const char *filepath,
                          char *out_b64_md5,
                          size_t out_len);
size_t GetCrashFirmwareVersion( const char *versionFile, char *pFWVersion, size_t szBufSize );
bool tls_log(int curl_code, const char *device_type, const char *fqdn);
/*
 * Safely join dir + name into dest (size PATH_MAX).
 * Returns 0 on success, -1 on error (overflow).
 *
 * Example:
 *   dir="/tmp/dumps", name="app_core_123.dmp" -> "/tmp/dumps/app_core_123.dmp"
 */
int join_path(char *dest, size_t dest_size, const char *dir, const char *name);
/**
 * Calculate SHA1 hash of a file using streaming (8KB chunks for low memory)
 * @param path File path
 * @param hash Buffer to store SHA1 hash (minimum 41 bytes for hex string)
 * @param len Buffer length
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with 8KB streaming optimization
 */
int file_get_sha1(const char *path, char *hash, size_t len);

/**
 * Get file modification time formatted as YYYY-MM-DD-HH-MM-SS
 * @param path File path
 * @param mtime Buffer to store formatted time
 * @param len Buffer length (minimum 20 bytes)
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION
 */
int file_get_mtime_formatted(const char *path, char *mtime, size_t len);

/**
 * Get file size in bytes
 * @param path File path
 * @param size Pointer to store file size
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION
 */
int file_get_size(const char *path, uint64_t *size);

/**
 * @brief Wait for file size to stabilize (indicating write completion)
 *
 * Monitors file size by polling at regular intervals. Returns when file size
 * remains unchanged for a specified number of consecutive checks.
 *
 * @param filepath Path to the file to monitor
 * @param check_interval_sec Seconds to wait between size checks (e.g., 1 or 2)
 * @param stability_checks Number of consecutive stable checks required (e.g., 2 or 3)
 * @param max_iterations Maximum total time to wait before timeout (e.g., 30)
 * @return 0 on success (file stable), -1 on error/timeout
 */
int wait_for_file_size_stable(const char *filepath, int check_interval_sec, int stability_checks, int max_iterations);

#endif /* FILE_UTILS_H */
