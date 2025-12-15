#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


int file_get_mtime_formatted(const char *path, char *mtime, size_t len);
int trim_process_name_in_path(const char *full_path,
                              const char *process_name, int max_pname_trim
                              char *out,
                              size_t out_len);
int get_crash_timestamp_utc(char *out, size_t outsz);
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
 * Check if file exists
 * @param path File path
 * @return true if file exists, false otherwise
 * 
 * FULL IMPLEMENTATION
 */
bool file_exists(const char *path);

/**
 * Get file size in bytes
 * @param path File path
 * @param size Pointer to store file size
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION
 */
int file_get_size(const char *path, uint64_t *size);

#endif /* FILE_UTILS_H */
