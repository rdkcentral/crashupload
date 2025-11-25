/* FULL IMPLEMENTATION - File utilities with SHA1 streaming optimization */

#include "file_utils.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define SHA1_CHUNK_SIZE 8192

/**
 * Calculate SHA1 checksum of a file.
 * Works for BOTH OpenSSL < 3.0 and OpenSSL >= 3.0.
 */
int file_get_sha1(const char *path, char *hash, size_t len)
{
    if (!path || !hash || len < 41)
        return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    unsigned char buffer[SHA1_CHUNK_SIZE];
    size_t bytes_read;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* ================================================================
       OPENSSL 1.1.x AND OLDER (uses SHA1_Init / SHA1_Update / SHA1_Final)
       ================================================================ */
    SHA_CTX ctx;
    SHA1_Init(&ctx);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        SHA1_Update(&ctx, buffer, bytes_read);
    }

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, &ctx);

#else
    /* ================================================================
       OPENSSL 3.x (uses EVP API)
       ================================================================ */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
#endif

    fclose(fp);

    /* Convert binary digest to hex string */
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(hash + (i * 2), len - (i * 2), "%02x", digest[i]);
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
