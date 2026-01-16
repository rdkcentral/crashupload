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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "file_utils.h"
#include "common_device_api.h"
#include "rdkv_cdl_log_wrapper.h"

#define SHA1_CHUNK_SIZE 8192
#define TIMESTAMP_DEFAULT_VALUE "2000-01-01-00-00-00"

bool tls_log(int curl_code, const char *device_type, const char *fqdn)
{
    if (!device_type || !fqdn) {
        return false;
    }
    if (0 != (strcmp(device_type, "broadband")	)) {
    if((curl_code == 35) || (curl_code == 51) || (curl_code == 53) || (curl_code == 54) || (curl_code == 58) || (curl_code == 59) || (curl_code == 60)
            || (curl_code == 64) || (curl_code == 66) || (curl_code == 77) || (curl_code == 80) || (curl_code == 82) || (curl_code == 83)
            || (curl_code == 90) || (curl_code == 91)) {
        TLSLOG(TLS_LOG_ERR, "CERTERR, DumpUL, %d, %s", curl_code, fqdn);
    }
    }
    return true;
}

/* function GetFirmwareVersion - gets the firmware version of the device.

        Usage: size_t GetFirmwareVersion <char *pFWVersion> <size_t szBufSize>

            pFWVersion - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 1.

            RETURN - number of characters copied to the output buffer.
*/
size_t GetCrashFirmwareVersion( const char *versionFile, char *pFWVersion, size_t szBufSize )
{
    FILE *fp;
    size_t i = 0;
    char *pTmp;
    char buf[150];

    if( pFWVersion != NULL && versionFile != NULL)
    {
        *pFWVersion = 0;
        if( (fp = fopen( versionFile, "r" )) != NULL )
        {
            pTmp = NULL;
            while( fgets( buf, sizeof(buf), fp ) != NULL )
            {
                if( (pTmp = strstr( buf, "imagename:" )) != NULL )
                {
                    while( *pTmp++ != ':' )
                    {
                        ;
                    }
                    break;
                }
            }
            fclose( fp );
            if( pTmp )
            {
                i = snprintf( pFWVersion, szBufSize, "%s", pTmp );
                i = stripinvalidchar( pFWVersion, i );
            }
        }
    }
    else
    {
        printf( "GetFirmwareVersion: Error, input argument NULL\n" );
    }
    return i;
}

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


int compute_s3_md5_base64(const char *filepath,
                          char *out_b64_md5,
                          size_t out_len)
{
    FILE *fp = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *b64 = NULL;
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;

    unsigned char md5_bin[EVP_MAX_MD_SIZE];
    unsigned int md5_len = 0;
    unsigned char io_buf[4096];
    size_t nread;
    int rc = -1;

    if (!filepath || !out_b64_md5 || out_len < 32)
        return -1;

    fp = fopen(filepath, "rb");
    if (!fp)
        goto cleanup;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        goto cleanup;

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1)
        goto cleanup;

    while ((nread = fread(io_buf, 1, sizeof(io_buf), fp)) > 0) {
        if (EVP_DigestUpdate(mdctx, io_buf, nread) != 1)
            goto cleanup;
    }

    if (ferror(fp))
        goto cleanup;

    if (EVP_DigestFinal_ex(mdctx, md5_bin, &md5_len) != 1)
        goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem)
        goto cleanup;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    if (BIO_write(b64, md5_bin, md5_len) <= 0)
        goto cleanup;

    if (BIO_flush(b64) != 1)
        goto cleanup;

    BIO_get_mem_ptr(mem, &bptr);
    if (!bptr || bptr->length == 0)
        goto cleanup;

    if (bptr->length + 1 > out_len)
        goto cleanup;

    memcpy(out_b64_md5, bptr->data, bptr->length);
    out_b64_md5[bptr->length] = '\0';

    rc = 0;

cleanup:
    if (fp)
        fclose(fp);
    if (mdctx)
        EVP_MD_CTX_free(mdctx);
    if (b64)
        BIO_free_all(b64);

    return rc;
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
    int ret = -1;

    if (!src || !dst || max_lines <= 0)
        return ret;

    in = fopen(src, "r");
    if (!in)
        return ret;

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
    ret = 0;
    //printf("Write to another file  End===========>\n");

cleanup:
    if (ring) {
        for (i = 0; i < max_lines; i++) {
	    if (ring[i] != NULL) {
                free(ring[i]);
	    }
	}
        free(ring);
    }
    if (in) fclose(in);
    if (out) fclose(out);
    return ret;
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

/**
 * @brief Wait for file to be fully written using blocking flock
 * @param filepath Path to the file
 * @return 0 on success, -1 on error
 */
int wait_for_file_ready(const char *filepath) {
    if (!filepath) {
        printf("wait_for_file_ready: filepath is NULL\n");
        return -1;
    }

    printf("Waiting for file to be fully written: %s\n", filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        printf("Cannot open file: %s (errno: %d - %s)\n", filepath, errno, strerror(errno));
        return -1;
    }

    /* BLOCKING flock - waits until writer releases exclusive lock
     * LOCK_SH = shared lock (multiple readers allowed)
     * Without LOCK_NB flag, this will BLOCK until lock is available
     */
    printf("Attempting to acquire shared lock (will block if file is being written): %s\n", filepath);

    if (flock(fd, LOCK_SH) == -1) {
        printf("Failed to acquire lock: %s (errno: %d - %s)\n", filepath, errno, strerror(errno));
        close(fd);
        return -1;
    }

    printf("Successfully acquired lock - file is ready: %s\n", filepath);

    /* Release lock and close */
    flock(fd, LOCK_UN);
    close(fd);

    return 0;
}
