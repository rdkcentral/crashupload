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
#define TIMESTAMP_DEFAULT_VALUE "2000-01-01-00-00-00"
/*
 * Safely join dir + name into dest (size PATH_MAX).
 * Returns 0 on success, -1 on error (overflow).
 *
 * Example:
 *   dir="/tmp/dumps", name="app_core_123.dmp" -> "/tmp/dumps/app_core_123.dmp"
 */
int join_path(char *dest, size_t dest_size, const char *dir, const char *name)
{
    if (!dest || !dir || !name) return -1;
    size_t dlen = strlen(dir);
    if (dlen == 0) {
        if (strlen(name) >= dest_size) return -1;
        if (snprintf(dest, dest_size, "%s", name) >= dest_size) return -1;
        return 0;
    }
    if (dir[dlen - 1] == '/') {
        if (snprintf(dest, dest_size, "%s%s", dir, name) >= dest_size) return -1;
    } else {
        if (snprintf(dest, dest_size, "%s/%s", dir, name) >= dest_size) return -1;
    }
    return 0;
}

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
/*
 * Generates a UTC timestamp equivalent to:
 *     date -u +%Y-%m-%d-%H-%M-%S
 *
 * Output format length = 19 chars + null -> buffer must be >= 20 bytes.
 */
int get_crash_timestamp_utc(char *out, size_t outsz)
{
    if (!out || outsz < 20) {
        return -1;  // Invalid buffer
    }

    struct timespec ts;
    
    // systemd-compatible: use CLOCK_REALTIME for wall time
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
	strcpy(out,TIMESTAMP_DEFAULT_VALUE);
        return -1;
    }

    struct tm tm_utc;

    // Convert to UTC (equivalent to "date -u")
    if (gmtime_r(&ts.tv_sec, &tm_utc) == NULL) {
	strcpy(out,TIMESTAMP_DEFAULT_VALUE);
        return -1;
    }

    // Format: %Y-%m-%d-%H-%M-%S
    if (strftime(out, outsz, "%Y-%m-%d-%H-%M-%S", &tm_utc) == 0) {
	strcpy(out,TIMESTAMP_DEFAULT_VALUE);
        return -1;
    }

    return 0;
}

/* --------------------------------------------------------- */
/* Extract last N lines from file (low-memory implementation)*/
/* --------------------------------------------------------- */
/*
 * Example:
 *   extract_tail("app.log", "app_tail.log", 500);
 */
int extract_tail(const char *src,
                        const char *dst,
                        int max_lines)
{
    FILE *in = NULL;
    FILE *out = NULL;
    char **ring = NULL;
    int count = 0;
    int idx = 0;
    int i;
    int start;
    char buf[80] = {0};

    if (!src || !dst || max_lines <= 0)
        return -1;

    in = fopen(src, "r");
    if (!in)
        return -1;

    out = fopen(dst, "w");
    if (!out)
        goto cleanup;

    ring = calloc((size_t)max_lines, sizeof(char *));
    if (!ring)
        goto cleanup;

    //printf("Read start===========>\n");
    /* Read file line by line */
    while (fgets(buf, sizeof(buf), in)) {
        free(ring[idx]);
        ring[idx] = strdup(buf);
        if (!ring[idx])
            goto cleanup;

        //printf("idx=%d and %s\n", idx, ring[idx]);
        idx = (idx + 1) % max_lines;
        //printf("idx=%d and %s\n", idx, ring[idx]);
        if (count < max_lines)
            count++;
    }


    printf("Read End===========>\n");
    start = (count < max_lines) ? 0 : idx;
    /* Write lines in correct order */
    for (i = 0; i < count; i++) {
        int pos = (start + i) % max_lines;
        if (ring[pos])
            fputs(ring[pos], out);
    }
    //printf("Write to another file  End===========>\n");

cleanup:
    if (ring) {
        for (i = 0; i < max_lines; i++)
            free(ring[i]);
        free(ring);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    return 0;
}


int trim_process_name_in_path(const char *full_path,
                              const char *process_name, int max_pname_trim,
                              char *out,
                              size_t out_len)
{
    //size_t path_len;
    size_t pname_len;
    char trimmed_pname[64];
    const char *src;
    char *dst;

    if (!full_path || !process_name || !out || out_len == 0)
        return -1;

    //path_len = strlen(full_path);

    pname_len = strlen(process_name);
    if (pname_len == 0)
        return -1;

    /* Create trimmed process name (first max_pname_trim chars) */
    if (pname_len > max_pname_trim)
        pname_len = max_pname_trim;

    memcpy(trimmed_pname, process_name, pname_len);
    trimmed_pname[pname_len] = '\0';

    src = full_path;
    dst = out;

    /* Replace all occurrences of process_name */
    while (*src != '\0') {
        if (strncmp(src, process_name, strlen(process_name)) == 0) {
            /* Copy trimmed process name */
            if ((size_t)(dst - out) + pname_len >= out_len)
                return -1;

            memcpy(dst, trimmed_pname, pname_len);
            dst += pname_len;
            src += strlen(process_name);
        } else {
            if ((size_t)(dst - out) + 1 >= out_len)
                return -1;

            *dst++ = *src++;
        }
    }

    *dst = '\0';
    return 0;
}

/* Returns 1 if path refers to a regular file, 0 otherwise */
int is_regular_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}
bool check_process_dmp_file(const char *file)
{
    bool ret = false;
    char *mac = "_mac";
    char *dat = "_dat";
    char *box = "_box";
    char *mod = "_mod";

    if (file != NULL) {
        if (strstr(file, mac) || strstr(file, dat) || strstr(file, box) || strstr(file, mod)) {
	    ret = true;
	}
    }
    return ret;
}
