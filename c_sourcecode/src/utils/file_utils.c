/* FULL IMPLEMENTATION - File utilities with SHA1 streaming optimization */

#include "file_utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/sha.h>

#define SHA1_CHUNK_SIZE 8192  /* 8KB streaming for low memory optimization */

/**
 * FULL IMPLEMENTATION
 * Calculate SHA1 with 8KB streaming to minimize memory usage
 */
int file_get_sha1(const char *path, char *hash, size_t len) {
    if (!path || !hash || len < 41) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    unsigned char buffer[SHA1_CHUNK_SIZE];
    size_t bytes_read;

    /* Stream file in 8KB chunks to minimize memory usage */
    while ((bytes_read = fread(buffer, 1, SHA1_CHUNK_SIZE, fp)) > 0) {
        SHA1_Update(&ctx, buffer, bytes_read);
    }

    fclose(fp);

    unsigned char sha1_digest[SHA_DIGEST_LENGTH];
    SHA1_Final(sha1_digest, &ctx);

    /* Convert binary hash to hex string */
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(hash + (i * 2), len - (i * 2), "%02x", sha1_digest[i]);
    }
    hash[40] = '\0';

    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Get file modification time in YYYY-MM-DD-HH-MM-SS format
 */
int file_get_mtime_formatted(const char *path, char *mtime, size_t len) {
    if (!path || !mtime || len < 20) {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        return -1;
    }

    struct tm *tm_info = localtime(&st.st_mtime);
    if (!tm_info) {
        return -1;
    }

    strftime(mtime, len, "%Y-%m-%d-%H-%M-%S", tm_info);
    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Check if file exists
 */
bool file_exists(const char *path) {
    if (!path) {
        return false;
    }

    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/**
 * FULL IMPLEMENTATION
 * Get file size in bytes
 */
int file_get_size(const char *path, uint64_t *size) {
    if (!path || !size) {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        return -1;
    }

    *size = (uint64_t)st.st_size;
    return 0;
}
