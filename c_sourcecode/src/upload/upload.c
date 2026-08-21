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
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include "../rfcInterface/rfcinterface.h"
#include "../rbusInterface/rbus_interface.h"
#include "upload.h"
#ifndef GTEST_ENABLE
#include "common_device_api.h"
#include "system_utils.h"
#endif
#include "mtls_upload.h"
#include "upload_status.h"
#include "ratelimit.h"
#include <unistd.h>
#include "telemetryinterface.h"
#include "../utils/logger.h"

#define MAX_RETRIES 3
#define TIMEOUT_SECONDS 45
#define RETRY_DELAY_SECONDS 5
#define SIZE_POSTFIELD_BUF 2048

#ifdef RDKC
#define RDKC_PARTNER_ID_FILE "/opt/usr_config/partnerid.txt"
#endif

#if 0
/* FULL IMPLEMENTATION - Progress callback for upload monitoring */
static int upload_progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                                    curl_off_t ultotal, curl_off_t ulnow) {
    if (ultotal > 0) {
        double percent = (double)ulnow / (double)ultotal * 100.0;
        fprintf(stderr, "\rUpload progress: %.1f%%", percent);
        fflush(stderr);
    }
    return 0;
}
#endif

int get_crashupload_s3signed_url(char *url, size_t size_buf)
{
    int ret = -1;
    if (!url || size_buf <= 0 || size_buf >= 4096)
    {
        CRASHUPLOAD_ERROR("Error invalid parameter getting url\n");
        return ret;
    }
    ret = read_RFCProperty("S3SignedUrl", RFC_CRASHUPLOAD_S3URL, url, size_buf);
    if ((ret == READ_RFC_FAILURE) || (url[0] == '\0'))
    {
        CRASHUPLOAD_WARN("Read rfc failed For S3SignedUrl. Reading From device.properties file\n");
        ret = getDevicePropertyData("S3_AMAZON_SIGNING_URL", url, size_buf);
        if (ret == UTILS_SUCCESS)
        {
            CRASHUPLOAD_INFO("S3 Amazon Signing URL:%s\n", url);
        }
        else
        {
            CRASHUPLOAD_ERROR("Error to Get S3 Signing URL\n");
        }
    }
    return ret;
}

/* FULL IMPLEMENTATION - Type-aware upload with optimized retry logic */
int upload_file(const char *filepath, const char *url, const char *dump_name, const char *crash_fw_version, const char *build_type, const char *model, const char *md5sum, device_type_t device_type, bool t2_enabled)
{
    if (!filepath || !url || !dump_name || !crash_fw_version || !build_type || !model || !md5sum)
    {
        return -1;
    }
    char post_filed[SIZE_POSTFIELD_BUF] = {0};
    long http_code = 0;
    int curl_ret = 0;
    char *url_encode_data = NULL;
    size_t totlen = 0, remainlen, szPostFieldOut;
    MtlsAuth_t sec_out;
    int ret = -1;
    char out_url[1024] = {0};
    char s3_url_file[32] = {0};
    char fqdn[1024] = {0};

    memset(&sec_out, '\0', sizeof(sec_out));
    szPostFieldOut = sizeof(post_filed);

    CRASHUPLOAD_INFO("Before upload\n");
    CRASHUPLOAD_INFO("filepath=%s\n", filepath);
    CRASHUPLOAD_INFO("url=%s\n", url);
    CRASHUPLOAD_INFO("dump name=%s=>crash firmware=%s\n", dump_name, crash_fw_version);
    CRASHUPLOAD_INFO("build type=%s=>model=%s\n", build_type, model);
    CRASHUPLOAD_INFO("md5sum=%s\n", md5sum);

    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(filepath);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "filename=%s&", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "filename=%s&", filepath);
    }
    if (totlen >= szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(crash_fw_version);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "firmwareVersion=%s&", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "filename=%s&", crash_fw_version);
    }

    if (totlen >= szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(build_type);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "env=%s&", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "env=%s&", build_type);
    }

    if (totlen >= szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(model);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "model=%s&", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "model=%s&", model);
    }

    if (totlen >= szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(dump_name);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "type=%s&", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "type=%s&", dump_name);
    }

    if (totlen >= szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(md5sum);
    if (url_encode_data != NULL)
    {
        totlen += snprintf(post_filed + totlen, remainlen, "md5=%s", url_encode_data);
        free(url_encode_data);
        url_encode_data = NULL;
    }
    else
    {
        totlen += snprintf(post_filed + totlen, remainlen, "type=%s", md5sum);
    }
    if (totlen > szPostFieldOut)
    {
        CRASHUPLOAD_WARN("No space available for postfield data\n");
        return -1;
    }
    snprintf(s3_url_file, sizeof(s3_url_file), "%s%u", S3_SIGNEDURL_FILE, getpid());
    CRASHUPLOAD_INFO("S3 URL=%s\n", s3_url_file);
    for (int i = 1; i <= 3; i++)
    {
        if (totlen < szPostFieldOut)
        {
            CRASHUPLOAD_INFO("postfield data=%s\n", post_filed);
#if defined(L2_TEST)
            char s3_url_file_saved[sizeof(s3_url_file)];
            memcpy(s3_url_file_saved, s3_url_file, sizeof(s3_url_file));
#endif
            ret = performMetadataPostWithCertRotationEx(url, s3_url_file, post_filed, &sec_out, &http_code);
#if defined(L2_TEST)
            if (s3_url_file[0] == '\0')
                memcpy(s3_url_file, s3_url_file_saved, sizeof(s3_url_file));
#endif
            CRASHUPLOAD_INFO("After performMetadataPostWithCertRotationEx ret=%d=>http code=%lu\n", ret, http_code);
            __uploadutil_get_status(&http_code, &curl_ret);

            if (ret != 0 && curl_ret == 0 && (device_type == DEVICE_TYPE_BROADBAND || device_type == DEVICE_TYPE_EXTENDER))
            {
                curl_ret = ret;
            }
            CRASHUPLOAD_INFO("Curl Connected to FQDN: %s\n", url);
            CRASHUPLOAD_INFO("Curl return code :%d, HTTP SIGN URL Response:%lu\n", curl_ret, http_code);
            if (t2_enabled)
            {
                char upload_split_val[64];
                snprintf(upload_split_val, sizeof(upload_split_val), "%d, %ld", curl_ret, http_code);
                t2ValNotify("coreUpld_split", upload_split_val);
            }
#if defined(L2_TEST)
            /* TC-083 force-fail hook: if /tmp/cu_all_fail exists, treat every metadata attempt as a hard failure */
            if (access("/tmp/cu_all_fail", F_OK) == 0) {
                http_code = 500;
                curl_ret = -1;
            }
            /* TC-082 partial-fail hook: fail first N attempts then succeed. */
            FILE *_cu_fp = fopen("/tmp/cu_fail_n", "r+");
            if (_cu_fp) {
                    int _cu_n = 0;
                    if (fscanf(_cu_fp, "%d", &_cu_n) != 1)
                        _cu_n = 0;
                    rewind(_cu_fp);
                    fprintf(_cu_fp, "%d\n", (_cu_n > 0) ? _cu_n - 1 : 0);
                    fclose(_cu_fp);
                    if (_cu_n > 0) { http_code = 500; curl_ret = -1; }
            }
            if (http_code >= 200 && http_code < 300)
#else
            if (curl_ret ==0)
#endif
            {
                CRASHUPLOAD_INFO("Attempting TLS1.2 connection to Amazon S3\n");
                ret = extractS3PresignedUrl(s3_url_file, out_url, sizeof(out_url));
                CRASHUPLOAD_INFO("extractS3PresignedUrl ret=%d", ret); //out_url=%s\n", ret, out_url);
                if (ret == 0 && out_url[0] != '\0')
                {
                    ret = performS3PutUpload(out_url, filepath, &sec_out);
                    CRASHUPLOAD_INFO("performS3PutUpload return ret=%d\n", ret);
                    http_code = 0;
                    curl_ret = -1;
                    __uploadutil_get_status(&http_code, &curl_ret);
#if defined(L2_TEST)
                    if (ret != 0) curl_ret = ret;
#endif
                    CRASHUPLOAD_INFO("Curl return code: %d HTTP Response code: %ld\n", curl_ret, http_code);
                }
                else
                {
                    snprintf(fqdn, sizeof(fqdn), "%s", out_url);
                    curl_ret = -1;
                }
#if defined(GTEST_ENABLE)
                unlink(s3_url_file);
#else
                // unlink(s3_url_file);
#endif
            }
            else
            {
                snprintf(fqdn, sizeof(fqdn), "%s", url);
#if defined(L2_TEST)
                /* In L2 test mode, treat any non-2xx metadata response as a curl
                 * failure so the retry loop actually fires when the mock server
                 * returns an HTTP error code (libcurl itself returns 0 for a clean
                 * TCP response even when the HTTP status indicates failure). */
                if (curl_ret == 0)
                    curl_ret = -1;
#endif
            }
            if (curl_ret != 0)
            {
                CRASHUPLOAD_ERROR("Curl finished unsuccessfully! Error code: %d\n", curl_ret);
                if (device_type != DEVICE_TYPE_BROADBAND)
                {
                    tls_log(curl_ret, "mediaclient", fqdn);
                    char certerr_val[1024] = {0};
                    int prefix_len = snprintf(certerr_val, sizeof(certerr_val), "DumpUL, %d, ", curl_ret);
                    if (prefix_len > 0 && (size_t)prefix_len < sizeof(certerr_val))
                    {
                        size_t remaining = sizeof(certerr_val) - (size_t)prefix_len;
                        size_t fqdn_len = strlen(fqdn);
                        if (fqdn_len >= remaining)
                            fqdn_len = remaining - 1;
                        memcpy(certerr_val + prefix_len, fqdn, fqdn_len);
                        certerr_val[(size_t)prefix_len + fqdn_len] = '\0';
                    }
                    t2ValNotify("certerr_split", certerr_val);
                }
                else
                {
                    tls_log(curl_ret, "broadband", fqdn);
                }
                if (t2_enabled)
                {
                    t2CountNotify("SYS_ERROR_S3CoreUpload_Failed", 1);
                    if (curl_ret == 6)
                    {
                        t2CountNotify("SYST_INFO_CURL6", 1);
                    }
                    char marker[64];
                    snprintf(marker, sizeof(marker), "SYS_ERR_CoreUpload_Curl%d", curl_ret);
                    t2CountNotify(marker, 1);

                    char curl_err_str[16];
                    snprintf(curl_err_str, sizeof(curl_err_str), "%d", curl_ret);
                    t2ValNotify("CoredumpFail_split", curl_err_str);
                }
                CRASHUPLOAD_ERROR("Execution Status: %d, S3 Amazon Upload of %s Failed\n", curl_ret, filepath);
                CRASHUPLOAD_ERROR("%d: (Retry), minidump S3 Upload\n", i);
                sleep(2);
            }
            else
            {
                CRASHUPLOAD_INFO("Upload is successful with TLS1.2 for %s\n", filepath);
                if (t2_enabled)
                {
                    t2CountNotify("SYS_INFO_S3CoreUploaded", 1);
                }
                CRASHUPLOAD_INFO("Removing uploaded %s file\n", filepath);
                unlink(filepath);
                break;
            }
        }
        else
        {
            CRASHUPLOAD_ERROR("post field buffer corrupted. Total write bytes=%zu and total buf size=%zu\n", totlen, szPostFieldOut);
            CRASHUPLOAD_ERROR("postfield data=%s\n", post_filed); // TODO: Need to remove
            break;
        }
    }
    return curl_ret;
}

/* FULL IMPLEMENTATION - Batch upload multiple files */
int upload_process(archive_info_t *archive, const config_t *config, const platform_config_t *platform)
{
    if (!archive || !config || !platform)
    {
        return -1;
    }

    int status = -1;
    int ret = -1;
    char pPartnerId[16] = {0};
    char encryptionEnable[8] = {0};
    char portal_url[1024] = {0};
    char crashportalEndpointUrl[512] = {0};
    bool ocsp_stapling_enable = false;
    int request_type = 0;
    char md5sum[128] = {0};
    char dump_name[16] = {0};
    char crash_fw_version[128] = {0};
#ifdef RDKC
    {
        FILE *fp = fopen(RDKC_PARTNER_ID_FILE, "r");
        if (fp)
        {
            if (fgets(pPartnerId, sizeof(pPartnerId), fp))
            {
                size_t plen = strlen(pPartnerId);
                if (plen > 0 && pPartnerId[plen - 1] == '\n')
                    pPartnerId[plen - 1] = '\0';
            }
            fclose(fp);
        }
        ret = (pPartnerId[0] != '\0') ? 1 : 0;
    }
#else
    if (config->device_type == DEVICE_TYPE_EXTENDER)
    {
        /* Extender: partnerId sourced from account JSON, not from partner_id file */
        /* TODO: read PERSISTENT_PATH from device.properties if /opt/persistent is not universal */
        FILE *fp = fopen("/opt/persistent/account", "r");
        if (fp)
        {
            char line[512] = {0};
            while (fgets(line, sizeof(line), fp))
            {
                char *p = strstr(line, "\"partnerId\":\"");
                if (p)
                {
                    p += 13;
                    char *end = strchr(p, '"');
                    if (end)
                    {
                        size_t len = (size_t)(end - p);
                        if (len < sizeof(pPartnerId))
                        {
                            strncpy(pPartnerId, p, len);
                            pPartnerId[len] = '\0';
                        }
                    }
                    break;
                }
            }
            fclose(fp);
        }
        ret = (pPartnerId[0] != '\0') ? 1 : 0;
    }
    else
    {
        ret = GetPartnerId(pPartnerId, sizeof(pPartnerId));
    }
#endif
    if (ret == 0)
    {
        strcpy(pPartnerId, "comcast");
        CRASHUPLOAD_ERROR("GetPartnerId is failed. Assign default:%s\n", pPartnerId);
    }
    else
    {
        CRASHUPLOAD_INFO("GetPartnerId is Success:%s\n", pPartnerId);
    }
    if (config->device_type == DEVICE_TYPE_MEDIACLIENT)
    {
        // encryptionEnable=`tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable 2>&1 > /dev/null`
        ret = read_RFCProperty("EncryptCloudUpload", RFC_DMP_ENCRYPT_UPLOAD, encryptionEnable, sizeof(encryptionEnable));
        if ((ret == READ_RFC_FAILURE) || (encryptionEnable[0] == '\0'))
        {
            strcpy(encryptionEnable, "false"); // TODO: Need check what should be default value
            CRASHUPLOAD_WARN("Read rfc failed EncryptCloudUpload:%s\n", encryptionEnable);
        }
        else
        {
            CRASHUPLOAD_INFO("RFC_EncryptCloudUpload_Enable::%s\n", encryptionEnable);
        }
        ret = read_RFCProperty("CrashPortal", RFC_CRASH_PORTAL_URL, portal_url, sizeof(portal_url));
        if ((ret == READ_RFC_FAILURE) || (portal_url[0] == '\0'))
        {
            strcpy(portal_url, RDKE_PORTAL_DEFAULT_URL);
            CRASHUPLOAD_WARN("Read rfc failed CrashPortal:%s\n", portal_url);
        }
        else
        {
            CRASHUPLOAD_INFO("Read rfc Success CrashPortal:%s\n", portal_url);
        }
        request_type = 17;
        CRASHUPLOAD_INFO("request_type=%d\n", request_type);
        ret = read_RFCProperty("CrashPortalEndURL", RFC_CRASH_PORTAL_ENDPOINT_URL, crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
        if ((ret == READ_RFC_FAILURE) || (crashportalEndpointUrl[0] == '\0'))
        {
            CRASHUPLOAD_WARN("Read rfc failed crashportalEndpointUrl\n");
            // Get S3 sign url
            ret = get_crashupload_s3signed_url(crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
            if (ret < 0)
            {
                CRASHUPLOAD_ERROR("Unable to get the server url. So exit\n");
                return ret;
            }
        }
        else
        {
            CRASHUPLOAD_INFO("Read rfc Success crashportalEndpointUrl:\n Overriding the S3 Amazon Signing URL:%s\n", crashportalEndpointUrl);
        }
    }
    else if (config->device_type == DEVICE_TYPE_RDKC)
    {
        /* RDKC Camera upload flow:
         * Matches script uploadDumps.sh - encryptionEnable=false (no /etc/os-release)
         * S3 URL from device.properties S3_AMAZON_SIGNING_URL
         * Portal URL: crashportal.stb.r53.xcal.tv
         */
        strcpy(encryptionEnable, "false");
        strcpy(portal_url, RDKC_PORTAL_DEFAULT_URL);
        request_type = 17;
        CRASHUPLOAD_INFO("RDKC: request_type=%d portal=%s\n", request_type, portal_url);
        ret = get_crashupload_s3signed_url(crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
        if (ret < 0)
        {
            CRASHUPLOAD_ERROR("RDKC: Unable to get the S3 server url. So exit\n");
            return ret;
        }
        CRASHUPLOAD_INFO("RDKC: S3 signing URL=%s\n", crashportalEndpointUrl);
    }
    else if (config->device_type == DEVICE_TYPE_BROADBAND ||
             config->device_type == DEVICE_TYPE_EXTENDER)
    {
        /* Broadband: portal rdkbcrashportal.stb.r53.xcal.tv, request_type=18
         * Extender: same upload path; S3 URL sourced from device.properties via get_crashupload_s3signed_url */
        strcpy(portal_url, RDKB_PORTAL_DEFAULT_URL);
        request_type = 18;

        /* Init rbus once; used for M1 (encryptionEnable fallback) and M3 (S3 URL) */
        bool rbus_ok = rbus_init();

        if (config->device_type == DEVICE_TYPE_BROADBAND)
        {
            /* syscfg is primary; rbus is fallback when syscfg returns empty */
            if (crashupload_syscfg_get("encryptcloudupload", encryptionEnable, sizeof(encryptionEnable)))
            {
                size_t elen = strlen(encryptionEnable);
                if (elen > 0 && encryptionEnable[elen - 1] == '\n')
                    encryptionEnable[elen - 1] = '\0';
            }
            /*rbus fallback if syscfg returned empty */
            if (encryptionEnable[0] == '\0' && rbus_ok)
                rbus_get_string_param(RFC_DMP_ENCRYPT_UPLOAD, encryptionEnable, sizeof(encryptionEnable));

            if (encryptionEnable[0] == '\0')
            {
                strcpy(encryptionEnable, "false");
                CRASHUPLOAD_WARN("Broadband: encryptcloudupload empty, defaulting to false\n");
            }
            else
            {
                CRASHUPLOAD_INFO("Broadband: encryptionEnable=%s\n", encryptionEnable);
            }
        }
        else
        {
            /* Extender does not use syscfg for encryption flag */
            strcpy(encryptionEnable, "false");
        }

        CRASHUPLOAD_INFO("%s: request_type=%d portal=%s\n",
                         device_type_to_str(config->device_type), request_type, portal_url);

        /* M3: broadband primary S3 URL from Syndication.CrashPortal via rbus */
        if (config->device_type == DEVICE_TYPE_BROADBAND && rbus_ok)
            rbus_get_string_param(RDKB_SYNDICATION_CRASH_PORTAL,
                                  crashportalEndpointUrl, sizeof(crashportalEndpointUrl));

        /* Extender or broadband rbus miss: fall back to RFC/device.properties */
        if (crashportalEndpointUrl[0] == '\0')
        {
            /* D3: sky-uk partner uses EU signing URL from device.properties */
            if (config->device_type == DEVICE_TYPE_BROADBAND &&
                strncmp(pPartnerId, "sky-uk", 6) == 0)
            {
                ret = getDevicePropertyData("S3_AMAZON_SIGNING_URL_EU", crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
                if (ret != UTILS_SUCCESS)
                {
                    CRASHUPLOAD_WARN("Broadband sky-uk: failed to read S3_AMAZON_SIGNING_URL_EU\n");
                }
                if (crashportalEndpointUrl[0] != '\0')
                    CRASHUPLOAD_INFO("Broadband sky-uk: EU S3 URL=%s\n", crashportalEndpointUrl);
            }
        }
        if (crashportalEndpointUrl[0] == '\0')
        {
            ret = get_crashupload_s3signed_url(crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
            if (ret < 0)
            {
                CRASHUPLOAD_ERROR("%s: Unable to get S3 server url\n", device_type_to_str(config->device_type));
                if (rbus_ok) rbus_cleanup();
                return ret;
            }
        }
        CRASHUPLOAD_INFO("%s: S3 signing URL=%s\n",
                         device_type_to_str(config->device_type), crashportalEndpointUrl);
        if (rbus_ok)
            rbus_cleanup();
    }
    else
    {
        CRASHUPLOAD_ERROR("Unknown DEVICE_TYPE: %d\n", config->device_type);
        return -1;
    }
    if ((0 == (filePresentCheck(EnableOCSPStapling))) || (0 == (filePresentCheck(EnableOCSP))))
    {
        CRASHUPLOAD_INFO("ocsp_stapling_enable is enabled:%d\n", ocsp_stapling_enable);
        ocsp_stapling_enable = true;
    }
    if (0 == (strcmp(encryptionEnable, "true")))
    {
        compute_s3_md5_base64(archive->archive_name, md5sum, sizeof(md5sum));
    }
    if (config->dump_type == DUMP_TYPE_MINIDUMP)
    {
        strcpy(dump_name, "minidump");
    }
    else
    {
        strcpy(dump_name, "coredump");
    }
    
    // Extract firmware version from the archive itself (for dumps from previous boots)
    // or fallback to /version.txt (for current boot)
    GetCrashFirmwareVersion(archive->archive_name, crash_fw_version, sizeof(crash_fw_version));
    
    status = upload_file(archive->archive_name, crashportalEndpointUrl, dump_name, crash_fw_version, config->build_type_val, platform->model, md5sum, config->device_type, config->t2_enabled);
    if (0 == status)
    {
        CRASHUPLOAD_INFO("%s %s uploadToS3 SUCCESS: status=%d\n",
                         device_type_to_str(config->device_type),
                         config->dump_type == DUMP_TYPE_MINIDUMP ? "minidump" : "coredump",
                         status);
        if (config->dump_type == DUMP_TYPE_MINIDUMP && config->t2_enabled)
        {
            t2CountNotify("SYST_INFO_minidumpUpld", 1);
        }
        CRASHUPLOAD_INFO("Execution Status: %d, S3 Amazon Upload of Success\n", status);
        CRASHUPLOAD_INFO("Removing file %s\n", archive->archive_name);
        unlink(archive->archive_name);

        /* Record timestamp only for successful minidump uploads */
        if (config->dump_type == DUMP_TYPE_MINIDUMP)
        {
            set_time(MINIDUMP_UPLOAD_TIMESTAMPS_FILE, CURRENT_TIME);
        }
    }
    else
    {
        CRASHUPLOAD_ERROR("S3 Amazon Upload of %s Failed..!\n", config->dump_type == DUMP_TYPE_MINIDUMP ? "minidump" : "coredump");
        if (config->dump_type == DUMP_TYPE_MINIDUMP)
        {
            CRASHUPLOAD_ERROR("Check and save the dump %s\n", archive->archive_name);
            // TODO: save_dump();
        }
        else
        {
            CRASHUPLOAD_INFO("Removing file %s\n", archive->archive_name);
            unlink(archive->archive_name);
        }
    }
    return status;
}
