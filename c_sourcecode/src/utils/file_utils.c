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
#include <archive.h>
#include <archive_entry.h>
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "file_utils.h"
#include "common_device_api.h"
#include "rdkv_cdl_log_wrapper.h"
#include "logger.h"

// For unit testing: allow static functions to be visible
#ifdef L2_TEST
#define STATIC_TESTABLE
#else
#define STATIC_TESTABLE static
#endif

#define SHA1_CHUNK_SIZE 8192
#define TIMESTAMP_DEFAULT_VALUE "2000-01-01-00-00-00"

bool tls_log(int curl_code, const char *device_type, const char *fqdn)
{
    if (!device_type || !fqdn)
    {
        return false;
    }
    if (0 != (strcmp(device_type, "broadband")))
    {
        if ((curl_code == 35) || (curl_code == 51) || (curl_code == 53) || (curl_code == 54) || (curl_code == 58) || (curl_code == 59) || (curl_code == 60) || (curl_code == 64) || (curl_code == 66) || (curl_code == 77) || (curl_code == 80) || (curl_code == 82) || (curl_code == 83) || (curl_code == 90) || (curl_code == 91))
        {
            TLSLOG(TLS_LOG_ERR, "CERTERR, DumpUL, %d, %s", curl_code, fqdn);
        }
    }
    return true;
}

/**
 * @brief Check if a file is a tarball based on extension
 * @param filepath Path to the file
 * @return true if file ends with .tgz or .tar.gz
 */
STATIC_TESTABLE bool is_tarball(const char *filepath)
{
    if (!filepath)
        return false;
    
    size_t len = strlen(filepath);
    if (len < 4)
        return false;
    
    // Check for .tgz
    if (len >= 4 && strcmp(filepath + len - 4, ".tgz") == 0)
        return true;
    
    // Check for .tar.gz
    if (len >= 7 && strcmp(filepath + len - 7, ".tar.gz") == 0)
        return true;
    
    return false;
}

/**
 * @brief Parse imagename from version.txt content
 * @param content The content of version.txt
 * @param output Buffer to store parsed imagename
 * @param output_size Size of output buffer
 * @return Number of characters written to output, or 0 on failure
 */
STATIC_TESTABLE size_t parse_imagename_from_content(const char *content, char *output, size_t output_size)
{
    if (!content || !output || output_size == 0)
        return 0;
    
    const char *line_start = content;
    const char *line_end;
    char line_buf[256];
    
    // Search through lines for "imagename:"
    while (*line_start)
    {
        // Find end of line
        line_end = strchr(line_start, '\n');
        if (!line_end)
            line_end = line_start + strlen(line_start);
        
        // Copy line to buffer
        size_t line_len = line_end - line_start;
        if (line_len >= sizeof(line_buf))
            line_len = sizeof(line_buf) - 1;
        
        memcpy(line_buf, line_start, line_len);
        line_buf[line_len] = '\0';
        
        // Check if this line contains "imagename:"
        char *imagename_ptr = strstr(line_buf, "imagename:");
        if (imagename_ptr)
        {
            // Skip past "imagename:"
            imagename_ptr += strlen("imagename:");
            
            // Skip any whitespace
            while (*imagename_ptr == ' ' || *imagename_ptr == '\t')
                imagename_ptr++;
            
            // Copy to output and strip invalid chars
            size_t result_len = snprintf(output, output_size, "%s", imagename_ptr);
            return stripinvalidchar(output, result_len);
        }
        
        // Move to next line
        if (*line_end == '\n')
            line_start = line_end + 1;
        else
            break;
    }
    
    return 0;
}

/**
 * @brief Extract version.txt from tarball in-memory and parse imagename
 * @param tarball_path Path to the .tgz file
 * @param output Buffer to store the firmware version
 * @param output_size Size of output buffer
 * @return Number of characters written, or 0 on failure
 */
STATIC_TESTABLE size_t extract_version_from_tarball(const char *tarball_path, char *output, size_t output_size)
{
    struct archive *a = NULL;
    struct archive_entry *entry = NULL;
    char *file_content = NULL;
    size_t result = 0;
    int r;
    
    if (!tarball_path || !output || output_size == 0)
        return 0;
    
    CRASHUPLOAD_INFO("Attempting to extract version.txt from tarball: %s\n", tarball_path);
    
    // Create archive reader
    a = archive_read_new();
    if (!a)
    {
        CRASHUPLOAD_ERROR("Failed to create archive reader\n");
        return 0;
    }
    
    // Support gzip and tar formats
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    
    // Open the tarball
    r = archive_read_open_filename(a, tarball_path, 10240);
    if (r != ARCHIVE_OK)
    {
        CRASHUPLOAD_ERROR("Failed to open tarball %s: %s\n", tarball_path, archive_error_string(a));
        archive_read_free(a);
        return 0;
    }
    
    // Iterate through archive entries to find version.txt
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK)
    {
        const char *entry_name = archive_entry_pathname(entry);
        
        if (!entry_name)
        {
            archive_read_data_skip(a);
            continue;
        }
        
        CRASHUPLOAD_INFO("Found entry in tarball: %s\n", entry_name);
        
        // Check if this is version.txt (may have path prefix)
        if (strcmp(entry_name, "version.txt") == 0 || 
            strstr(entry_name, "/version.txt") != NULL ||
            strcmp(entry_name, "./version.txt") == 0)
        {
            size_t file_size = archive_entry_size(entry);
            
            CRASHUPLOAD_INFO("Found version.txt in tarball, size: %zu bytes\n", file_size);
            
            // Sanity check: version.txt should be reasonably small
            if (file_size == 0)
            {
                CRASHUPLOAD_WARN("version.txt has unusual size: %zu bytes, skipping\n", file_size);
                archive_read_data_skip(a);
                continue;
            }
            
            // Allocate buffer for file content
            file_content = (char *)malloc(file_size + 1);
            if (!file_content)
            {
                CRASHUPLOAD_ERROR("Failed to allocate memory for version.txt content\n");
                break;
            }
            
            // Read file content into memory
            ssize_t bytes_read = archive_read_data(a, file_content, file_size);
            if (bytes_read < 0)
            {
                CRASHUPLOAD_ERROR("Failed to read version.txt from tarball: %s\n", archive_error_string(a));
                free(file_content);
                file_content = NULL;
                break;
            }
            
            file_content[bytes_read] = '\0';
            
            CRASHUPLOAD_INFO("Successfully extracted version.txt (%zd bytes)\n", bytes_read);
            
            // Parse imagename from the content
            result = parse_imagename_from_content(file_content, output, output_size);
            
            if (result > 0)
            {
                CRASHUPLOAD_INFO("Extracted firmware version from tarball: %s\n", output);
            }
            else
            {
                CRASHUPLOAD_WARN("Could not parse imagename from version.txt in tarball\n");
            }
            
            free(file_content);
            break;
        }
        
        // Skip other entries
        archive_read_data_skip(a);
    }
    
    // Cleanup
    archive_read_free(a);
    
    return result;
}

/**
 * @brief Read version from a regular file
 * @param filepath Path to version.txt
 * @param output Buffer to store the firmware version
 * @param output_size Size of output buffer
 * @return Number of characters written, or 0 on failure
 */
STATIC_TESTABLE size_t read_version_from_file(const char *filepath, char *output, size_t output_size)
{
    FILE *fp;
    size_t result = 0;
    char *pTmp;
    char buf[150];
    
    if (!filepath || !output || output_size == 0)
        return 0;
    
    *output = '\0';
    
    fp = fopen(filepath, "r");
    if (!fp)
    {
        CRASHUPLOAD_WARN("Failed to open version file: %s\n", filepath);
        return 0;
    }
    
    pTmp = NULL;
    while (fgets(buf, sizeof(buf), fp) != NULL)
    {
        if ((pTmp = strstr(buf, "imagename:")) != NULL)
        {
            while (*pTmp++ != ':')
            {
                ;
            }
            break;
        }
    }
    fclose(fp);
    
    if (pTmp)
    {
        result = snprintf(output, output_size, "%s", pTmp);
        result = stripinvalidchar(output, result);
    }
    
    return result;
}

/* function GetCrashFirmwareVersion - gets the firmware version of the device.
        
        This function intelligently determines the firmware version by:
        1. Checking if the source is a tarball (.tgz)
        2. If YES: Extracting version.txt from the tarball in-memory (for dumps from previous boots)
        3. If NO or extraction fails: Reading from /version.txt (current boot)

        Usage: size_t GetCrashFirmwareVersion <char *source> <char *pFWVersion> <size_t szBufSize>

            source - Can be either:
                     - A tarball path (e.g., "/minidumps/mac...dat...tgz") 
                     - A regular file path (e.g., "/version.txt")

            pFWVersion - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 2.

            RETURN - number of characters copied to the output buffer.
*/
size_t GetCrashFirmwareVersion(const char *source, char *pFWVersion, size_t szBufSize)
{
    size_t result = 0;
    
    if (!pFWVersion || !source)
    {
        CRASHUPLOAD_WARN("GetCrashFirmwareVersion: Error, input argument NULL\n");
        return 0;
    }
    
    *pFWVersion = '\0';
    
    // Check if source is a tarball
    if (is_tarball(source))
    {
        CRASHUPLOAD_INFO("Source is a tarball, attempting to extract version.txt\n");
        
        // Try to extract version.txt from tarball
        result = extract_version_from_tarball(source, pFWVersion, szBufSize);
        
        if (result > 0)
        {
            CRASHUPLOAD_INFO("Successfully extracted firmware version from tarball: %s\n", pFWVersion);
            return result;
        }
        
        // Extraction failed, fall back to current version
        CRASHUPLOAD_WARN("Failed to extract version from tarball, falling back to /version.txt\n");
    }
    
    // Either not a tarball, or extraction failed - use current boot's version.txt
    CRASHUPLOAD_INFO("Reading firmware version from /version.txt\n");
    result = read_version_from_file("/version.txt", pFWVersion, szBufSize);
    
    if (result > 0)
    {
        CRASHUPLOAD_INFO("Using current firmware version: %s\n", pFWVersion);
    }
    else
    {
        CRASHUPLOAD_ERROR("Failed to read firmware version from /version.txt\n");
    }
    
    return result;
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
    if (!dest || !dir || !name)
        return -1;
    size_t dlen = strlen(dir);
    if (dlen == 0)
    {
        if (strlen(name) >= dest_size)
            return -1;
        if (snprintf(dest, dest_size, "%s", name) >= dest_size)
            return -1;
        return 0;
    }
    if (dir[dlen - 1] == '/')
    {
        if (snprintf(dest, dest_size, "%s%s", dir, name) >= dest_size)
            return -1;
    }
    else
    {
        if (snprintf(dest, dest_size, "%s/%s", dir, name) >= dest_size)
            return -1;
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

    while ((nread = fread(io_buf, 1, sizeof(io_buf), fp)) > 0)
    {
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

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        SHA1_Update(&ctx, buffer, bytes_read);
    }

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, &ctx);

#else
    /* ================================================================
       OPENSSL 3.x (uses EVP API)
       ================================================================ */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1)
        {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
#endif

    fclose(fp);

    /* Convert binary digest to hex string */
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        snprintf(hash + (i * 2), len - (i * 2), "%02x", digest[i]);
    }
    hash[40] = '\0';

    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Get file modification time in YYYY-MM-DD-HH-MM-SS format
 */
int file_get_mtime_formatted(const char *path, char *mtime, size_t len)
{
    if (!path || !mtime || len < 20)
    {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) < 0)
    {
        return -1;
    }

    struct tm *tm_info = localtime(&st.st_mtime);
    if (!tm_info)
    {
        return -1;
    }

    strftime(mtime, len, "%Y-%m-%d-%H-%M-%S", tm_info);
    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Get file size in bytes
 */
int file_get_size(const char *path, uint64_t *size)
{
    if (!path || !size)
    {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) < 0)
    {
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
    if (!out || outsz < 20)
    {
        return -1; // Invalid buffer
    }

    struct timespec ts;

    // systemd-compatible: use CLOCK_REALTIME for wall time
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        strcpy(out, TIMESTAMP_DEFAULT_VALUE);
        return -1;
    }

    struct tm tm_utc;

    // Convert to UTC (equivalent to "date -u")
    if (gmtime_r(&ts.tv_sec, &tm_utc) == NULL)
    {
        strcpy(out, TIMESTAMP_DEFAULT_VALUE);
        return -1;
    }

    // Format: %Y-%m-%d-%H-%M-%S
    if (strftime(out, outsz, "%Y-%m-%d-%H-%M-%S", &tm_utc) == 0)
    {
        strcpy(out, TIMESTAMP_DEFAULT_VALUE);
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

    // printf("Read start===========>\n");
    /* Read file line by line */
    while (fgets(buf, sizeof(buf), in))
    {
        free(ring[idx]);
        ring[idx] = strdup(buf);
        if (!ring[idx])
            goto cleanup;

        // printf("idx=%d and %s\n", idx, ring[idx]);
        idx = (idx + 1) % max_lines;
        // printf("idx=%d and %s\n", idx, ring[idx]);
        if (count < max_lines)
            count++;
    }
    start = (count < max_lines) ? 0 : idx;
    /* Write lines in correct order */
    for (i = 0; i < count; i++)
    {
        int pos = (start + i) % max_lines;
        if (ring[pos])
            fputs(ring[pos], out);
    }
    ret = 0;
    // printf("Write to another file  End===========>\n");

cleanup:
    if (ring)
    {
        for (i = 0; i < max_lines; i++)
        {
            if (ring[i] != NULL)
            {
                free(ring[i]);
            }
        }
        free(ring);
    }
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    return ret;
}

int trim_process_name_in_path(const char *full_path,
                              const char *process_name, int max_pname_trim,
                              char *out,
                              size_t out_len)
{
    // size_t path_len;
    size_t pname_len;
    char trimmed_pname[64];
    const char *src;
    char *dst;

    if (!full_path || !process_name || !out || out_len == 0)
        return -1;

    // path_len = strlen(full_path);

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
    while (*src != '\0')
    {
        if (strncmp(src, process_name, strlen(process_name)) == 0)
        {
            /* Copy trimmed process name */
            if ((size_t)(dst - out) + pname_len >= out_len)
                return -1;

            memcpy(dst, trimmed_pname, pname_len);
            dst += pname_len;
            src += strlen(process_name);
        }
        else
        {
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
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode);
}
bool check_process_dmp_file(const char *file)
{
    bool ret = false;
    char *mac = "_mac";
    char *dat = "_dat";
    char *box = "_box";
    char *mod = "_mod";

    if (file != NULL)
    {
        if (strstr(file, mac) || strstr(file, dat) || strstr(file, box) || strstr(file, mod))
        {
            ret = true;
        }
    }
    return ret;
}

/**
 * @brief Wait for file size to stabilize (indicating write completion)
 *
 * Monitors file size changes to detect when writing is complete.
 * Checks file size at regular intervals and considers file ready when
 * size remains unchanged for consecutive checks.
 *
 * @param filepath Path to the file to monitor
 * @param check_interval_sec Seconds to wait between size checks
 * @param stability_checks Number of consecutive stable checks required
 * @param max_iterations Maximum number of iterations to check
 * @return 0 on success (file stable), -1 on error/timeout
 */
int wait_for_file_size_stable(const char *filepath, int check_interval_sec, int stability_checks, int max_iterations)
{
    if (!filepath || check_interval_sec <= 0 || stability_checks <= 0 || max_iterations <= 0)
    {
        CRASHUPLOAD_WARN("wait_for_file_size_stable: Invalid parameters\n");
        return -1;
    }

    struct stat st;
    off_t old_size = -1;
    int stable_count = 0;
    int iteration = 0;

    CRASHUPLOAD_INFO("Monitoring file size stability: %s\n", filepath);
    CRASHUPLOAD_INFO("Check interval: %ds, Required stable checks: %d, Max iterations: %d\n", check_interval_sec, stability_checks, max_iterations);

    while (iteration < max_iterations)
    {
        iteration++;

        /* Get current file size */
        if (stat(filepath, &st) != 0)
        {
            CRASHUPLOAD_WARN("Iteration %d/%d: Cannot stat file (may not exist yet): %s (errno: %d - %s)\n", iteration, max_iterations, filepath, errno, strerror(errno));
            /* File might not exist yet, sleep and retry */
            sleep(check_interval_sec);
            continue;
        }

        off_t current_size = st.st_size;

        /* First time getting valid size - just record it */
        if (old_size == -1)
        {
            old_size = current_size;
            CRASHUPLOAD_INFO("Iteration %d/%d: Initial file size: %lld bytes\n", iteration, max_iterations, (long long)current_size);
            sleep(check_interval_sec);
            continue;
        }

        /* Check if size changed */
        if (current_size != old_size)
        {
            /* Size changed - file is still being written */
            CRASHUPLOAD_INFO("Iteration %d/%d: File size changed: %lld -> %lld bytes (still writing...)\n", iteration, max_iterations, (long long)old_size, (long long)current_size);
            old_size = current_size;
            stable_count = 0; /* Reset stability counter */
            sleep(check_interval_sec);
        }
        else
        {
            /* Size unchanged - increment stability counter */
            stable_count++;
            CRASHUPLOAD_INFO("Iteration %d/%d: File size stable: %lld bytes (stable check %d/%d)\n", iteration, max_iterations, (long long)current_size, stable_count, stability_checks);

            /* Check if we have enough consecutive stable readings */
            if (stable_count >= stability_checks)
            {
                CRASHUPLOAD_INFO("File write completed (size stable for %d checks after %d iterations): %s\n", stability_checks, iteration, filepath);
                return 0; /* Success - file is ready */
            }

            sleep(check_interval_sec);
        }
    }

    /* Max iterations reached without stability */
    CRASHUPLOAD_INFO("Max iterations (%d) reached waiting for file stability: %s\n", max_iterations, filepath);
    CRASHUPLOAD_INFO("Final size: %lld bytes, stable count: %d/%d\n", (long long)old_size, stable_count, stability_checks);
    return -1;
}