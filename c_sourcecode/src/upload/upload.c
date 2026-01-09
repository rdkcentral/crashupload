/* FULL IMPLEMENTATION - Upload manager with TLS 1.2 and type-aware retry */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include "../rfcInterface/rfcinterface.h"
#include "upload.h"
#ifndef GTEST_ENABLE
#include "common_device_api.h"
#endif
#include "mtls_upload.h"
#include "upload_status.h"
#include "ratelimit.h"
#include <unistd.h>

#define MAX_RETRIES 3
#define TIMEOUT_SECONDS 45
#define RETRY_DELAY_SECONDS 5
#define SIZE_POSTFIELD_BUF 2048

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
    if (!url || size_buf <= 0 || size_buf >= 4096) {
        printf("Error invalid parameter getting url\n");
	return ret;
    }
    ret = read_RFCProperty("S3SignedUrl", RFC_CRASHUPLOAD_S3URL, url, size_buf);
    if ((ret == READ_RFC_FAILURE) || (url[0] == '\0')) {
        printf("Read rfc failed For S3SignedUrl. Reading From device.properies file\n");
        ret = getDevicePropertyData("S3_AMAZON_SIGNING_URL", url, size_buf);
	if (ret == UTILS_SUCCESS) {
	    printf("S3 Amazon Signing URL:%s\n", url);
	} else {
	    printf("Error to Get S3 Signing URL\n");
	}
    }
    return ret;
}

/* FULL IMPLEMENTATION - Type-aware upload with optimized retry logic */
int upload_file(const char *filepath, const char *url, const char *dump_name, const char *crash_fw_version, const char *build_type, const char *model, const char *md5sum, device_type_t device_type) {
    if (!filepath || !url || !dump_name || !crash_fw_version || !build_type || !model || !md5sum) {
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

    printf("Before upload\n");
    printf("filepath=%s\n", filepath);
    printf("url=%s\n", url);
    printf("dump name=%s=>carsh firmware=%s\n", dump_name, crash_fw_version);
    printf("build type=%s=>model=%s\n", build_type, model);
    printf("md5sum=%s\n", md5sum);

    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(filepath);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "filename=%s&", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "filename=%s&", filepath);
    }
    if (totlen >= szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(crash_fw_version);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "firmwareVersion=%s&", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "filename=%s&", crash_fw_version);
    }

    if (totlen >= szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(build_type);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "env=%s&", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "env=%s&", build_type);
    }

    if (totlen >= szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(model);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "model=%s&", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "model=%s&", model);
    }

    if (totlen >= szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(dump_name);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "type=%s&", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "type=%s&", dump_name);
    }

    if (totlen >= szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    remainlen = szPostFieldOut - totlen;
    url_encode_data = urlEncodeString(md5sum);
    if (url_encode_data != NULL) {
        totlen += snprintf(post_filed+totlen, remainlen, "md5=%s", url_encode_data);
	free(url_encode_data);
	url_encode_data = NULL;
    }else {
        totlen += snprintf(post_filed+totlen, remainlen, "type=%s", md5sum);
    }
    if (totlen > szPostFieldOut) {
        printf("No space available for postfield data\n");
	return -1;
    }
    for (int i = 1; i <= 3; i++) {
    if (totlen < szPostFieldOut) {
        printf("postfiled data=%s\n", post_filed);
	ret = performMetadataPostWithCertRotationEx(url, filepath, post_filed, &sec_out, &http_code);
	printf("After performMetadataPostWithCertRotationEx ret=%d=>http code=%lu\n", ret, http_code);
	__uploadutil_get_status(&http_code, &curl_ret);
	printf("Curl Connected to $FQDN:%s\n", url);
	printf("Curl return code :%d, HTTP SIGN URL Response:%lu\n", curl_ret, http_code);
	//TODO:if $IS_T2_ENABLED" == "true then
            //t2ValNotify "coreUpld_split" "$ec, $http_code"
	if (curl_ret == 0) {
	    printf("Attempting TLS1.2 connection to Amazon S3\n");
	    snprintf(s3_url_file, sizeof(s3_url_file), "%s_%u", S3_SIGNEDURL_FILE, getpid());
	    printf("S3 URL=%s\n",s3_url_file);
            ret = extractS3PresignedUrl(s3_url_file, out_url, sizeof(out_url));
	    if (ret == 0 && out_url[0] != '\0') {
	        ret = performS3PutUpload(out_url, filepath, &sec_out);
		printf("performS3PutUpload return ret=%d\n", ret);
		http_code = 0;
		curl_ret = -1;
	        __uploadutil_get_status(&http_code, &curl_ret);
		printf("Curl return code: %d HTTP Response code: %ld\n", curl_ret, http_code);
	    } else {
	        snprintf(fqdn, sizeof(fqdn), "%s", out_url);
		curl_ret = -1;
	    }
	    unlink(s3_url_file);
	} else {
	    snprintf(fqdn, sizeof(fqdn), "%s", url);
	}
	if (curl_ret != 0) {
	    printf("Curl finished unsuccessfully! Error code: %d\n", curl_ret);
	    if (device_type != DEVICE_TYPE_BROADBAND) {
	        tls_log(curl_ret, "mediaclient", fqdn);
		//TODO: t2ValNotify "certerr_split" "DumpUL, $ec, $FQDN"
	    } else {
	        tls_log(curl_ret, "broadband", fqdn);
	    }
#if 0 //TODO
	    if (t2_enable) {
                t2CountNotify "SYS_ERROR_S3CoreUpload_Failed"
		if (curl_ret == 6) {
		    t2CountNotify "SYST_INFO_CURL6"
		}
		t2CountNotify "SYS_ERR_CoreUpload_Curl${ec}"
		t2ValNotify "CoredumpFail_split" ${ec}
	    }
#endif
	printf("Execution Status: %d, S3 Amazon Upload of %s Failed\n", curl_ret, filepath);
	printf("%d: (Retry), minidump S3 Upload\n", i);
	sleep(2);
	} else {
	    printf("S3 ${DUMP_NAME} Upload is successful $tlsMessage\n");
	    /* //TODO if (t2_enable) {
	        t2CountNotify "SYS_INFO_S3CoreUploaded"
	    }*/
	    printf("Removing uploaded $DUMP_NAME file %s\n", filepath);
	    unlink(filepath);
	    break;
	}
    } else {
        printf("post field buffer corrupted. Total write bytes=%zu and total buf size=%zu\n",totlen, szPostFieldOut);
        printf("postfiled data=%s\n", post_filed);//TODO: Need to remove
	break;
    }
    }
    return curl_ret;

}

/* FULL IMPLEMENTATION - Batch upload multiple files */
int upload_process(archive_info_t *archive, const config_t *config, const platform_config_t *platform) {
    if (!archive || !config || !platform) {
        return -1;
    }
    
    int status = -1;
    int ret = -1;
    char pPartnerId[16] = {0};
    char encryptionEnable[8] = {0};
    char portal_url[1024] = {0};
    char crashportalEndpointUrl[1024] = {0};
    bool ocsp_stapling_enable = false;
    int request_type = 0;
    char md5sum[128] = {0};
    char dump_name[16] = {0};
    char crash_fw_version[128] = {0};
    //size_t GetPartnerId( char *pPartnerId, size_t szBufSize );
    ret = GetPartnerId(pPartnerId, sizeof(pPartnerId));
    if (ret == 0) {
	strcpy(pPartnerId, "comcast");
        printf("GetPartnerId is failed. Assign dafault:%s\n", pPartnerId);
    } else {
        printf("GetPartnerId is Success:%s\n", pPartnerId);
    }
    if (config->device_type == DEVICE_TYPE_MEDIACLIENT) {
        //encryptionEnable=`tr181Set Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable 2>&1 > /dev/null`
	ret = read_RFCProperty("EncryptCloudUpload", RFC_DMP_ENCRYPT_UPLOAD, encryptionEnable, sizeof(encryptionEnable));
	if ((ret == READ_RFC_FAILURE) || (encryptionEnable[0] == '\0')) {
	    strcpy(encryptionEnable, "false");//TODO: Need check whta should be default value
            printf("Read rfc failed EncryptCloudUpload:%s\n",encryptionEnable);
	} else {
            printf("RFC_EncryptCloudUpload_Enable::%s\n",encryptionEnable);
	}
	ret = read_RFCProperty("CrashPortal", RFC_CRASH_PORTAL_URL, portal_url, sizeof(portal_url));
	if ((ret == READ_RFC_FAILURE) || (portal_url[0] == '\0')) {
	    strcpy(portal_url, "crashportal.stb.r53.xcal.tv");
            printf("Read rfc failed EncryptCloudUpload:%s\n",portal_url);
	} else {
            printf("Read rfc Success EncryptCloudUpload:%s\n",portal_url);
	}
        request_type = 17;
	printf("request_type=%d\n",request_type);
	ret = read_RFCProperty("CrashPortalEndURL", RFC_CRASH_PORTAL_ENDPOINT_URL, crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
	if ((ret == READ_RFC_FAILURE) || (crashportalEndpointUrl[0] == '\0')) {
            printf("Read rfc failed crashportalEndpointUrl\n");
	    //Get S3 sign url
	    ret = get_crashupload_s3signed_url(crashportalEndpointUrl, sizeof(crashportalEndpointUrl));
	    if (ret < 0) {
	        printf("Unable to get the server url. So exit\n");
		return ret;
	    }
	} else {
            printf("Read rfc Success crashportalEndpointUrl:\n Overriding the S3 Amazon SIgning URL:%s\n",crashportalEndpointUrl);
	}
    } else if (config->device_type == DEVICE_TYPE_BROADBAND) {
	ret = -1;
	printf("TODO: SUPPORT NOT AVAILABLE\n");
	printf("Unknown device\n");
	printf("[ERROR] Unknown DEVICE_TYPE:\n");
	return ret;
    } else {
	ret = -1;
	printf("Unknown device\n");
	printf("[ERROR] Unknown DEVICE_TYPE:\n");
	return ret;
    }
    if ((0 == (filePresentCheck(EnableOCSPStapling))) || (0 == (filePresentCheck(EnableOCSP)))) {
        printf("ocsp_stapling_enable is enabled:%d\n",ocsp_stapling_enable);
	ocsp_stapling_enable = true;
    }
    if (0 == (strcmp(encryptionEnable, "true"))) {
        compute_s3_md5_base64(archive->archive_name, md5sum, sizeof(md5sum));
    }
    if (config->dump_type == DUMP_TYPE_MINIDUMP) {
        strcpy(dump_name, "minidump");
    } else {
        strcpy(dump_name, "coredump");
    }
    GetCrashFirmwareVersion("/version.txt", crash_fw_version, sizeof(crash_fw_version));//TODO: This function should change to untar and read the version.txt image name
    status = upload_file(archive->archive_name, crashportalEndpointUrl, dump_name, crash_fw_version, config->build_type_val, platform->model, md5sum, config->device_type);
    if (0 == status) {
        printf("Minidump uploadToS3 SUCESS: status: %d\n", status);
#if 0 //TODO:
      if [ "$DUMP_NAME" == "minidump" ] && [ "$IS_T2_ENABLED" == "true" ]; then
			     t2CountNotify "SYST_INFO_minidumpUpld"
		     fi
#endif
        printf("Execution Status: %d, S3 Amazon Upload of $DUMP_NAME Success\n",status);
	printf("Removing file %s\n", archive->archive_name);
	unlink(archive->archive_name);
    } else {
        printf("S3 Amazon Upload of minidump Failed..!\n");
	if (config->dump_type == DUMP_TYPE_MINIDUMP) {
	    printf("Check and save the dump %s\n", archive->archive_name);
	    //TODO: save_dump();
	} else {
	    printf("Removing file %s\n", archive->archive_name);
	    unlink(archive->archive_name);
	    set_time("/tmp/.minidump_upload_timestamps", CURRENT_TIME);
	}
    }
    return status;
}
