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

#ifndef VIDEO_RFCINTERFACE_RFCINTERFACE_H_
#define VIDEO_RFCINTERFACE_RFCINTERFACE_H_


#include <stdbool.h>
// Guard the inclusion in such a way that this module could be easily combined as stub even on
// platforms without this api or an alternative interface such as rbus or ccspbus or xmidt
#if defined(RFC_API_ENABLED)
#ifndef GTEST_ENABLE
#include "rfcapi.h"
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RFC_VALUE_BUF_SIZE 512
#define READ_RFC_SUCCESS 1
#define READ_RFC_FAILURE -1
#define READ_RFC_NOTAPPLICABLE 0
#define WRITE_RFC_SUCCESS 1
#define WRITE_RFC_FAILURE -1
#define WRITE_RFC_NOTAPPLICABLE 0

#ifdef GTEST_ENABLE
/*Below code is use when GTEST is enable. Because During this
 * L1 Unit Test rfcapi.h header file not present */
typedef struct gtest_rfc
{
  char value[32];
  char name[32];
  int type;
  int status;
} RFC_ParamData_t;
typedef enum
{
  WDMP_FAILURE = 0,
  WDMP_SUCCESS,
  WDMP_ERR_DEFAULT_VALUE
} WDMP_STATUS;

#define WDMP_STRING 1
#define WDMP_UINT 3
#define WDMP_BOOLEAN 2
#endif

typedef enum
{
  RFC_STRING = 1,
  RFC_BOOL,
  RFC_UINT
} RFCVALDATATYPE;

#define RFC_DMP_ENCRYPT_UPLOAD "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.EncryptCloudUpload.Enable"
#define RFC_CRASH_PORTAL_URL "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.crashPortalSTBUrl"
#define RFC_CRASHUPLOAD_S3URL "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.CrashUpload.S3SigningUrl"
#define RFC_CRASH_PORTAL_ENDPOINT_URL "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.CrashportalEndpoint.URL"
#define RDKB_SYNDICATION_CRASH_PORTAL "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.CrashPortal"

#if defined(RFC_API_ENABLED)
#if defined(RDKC)
/**
 * @brief Read an RFC parameter (RDKC 2-param variant).
 * @param type   Caller-ID string (ignored on RDKC, accepted for API parity).
 * @param key    TR-181 parameter name.
 * @param data   Output buffer for the value.
 * @param datasize  Byte capacity of @p data.
 * @return READ_RFC_SUCCESS, READ_RFC_FAILURE, or READ_RFC_NOTAPPLICABLE.
 */
int read_RFCProperty(const char *type, const char *key, char *data, size_t datasize);
/**
 * @brief Write an RFC parameter — not supported on RDKC.
 * @return WRITE_RFC_NOTAPPLICABLE always.
 */
int write_RFCProperty(const char *type, const char *key, const char *data, RFCVALDATATYPE datatype);
#else
/**
 * @brief Read an RFC parameter (STB 3-param WDMP variant).
 * @param type   Caller-ID string passed to getRFCParameter.
 * @param key    TR-181 parameter name.
 * @param data   Output buffer for the value.
 * @param datasize  Byte capacity of @p data.
 * @return READ_RFC_SUCCESS, READ_RFC_FAILURE, or READ_RFC_NOTAPPLICABLE.
 */
int read_RFCProperty(char *type, const char *key, char *data, size_t datasize);
/**
 * @brief Write an RFC parameter via setRFCParameter.
 * @param type      Caller-ID string.
 * @param key       TR-181 parameter name.
 * @param data      New value as a null-terminated string.
 * @param datatype  RFC_STRING, RFC_BOOL, or RFC_UINT.
 * @return WRITE_RFC_SUCCESS or WRITE_RFC_FAILURE.
 */
int write_RFCProperty(char *type, const char *key, const char *data, RFCVALDATATYPE datatype);
#endif
#else
/**
 * @brief Read an RFC parameter — stub when RFC_API_ENABLED is not defined.
 * @return READ_RFC_NOTAPPLICABLE always.
 */
int read_RFCProperty(const char *type, const char *key, char *data, size_t datasize);
/**
 * @brief Write an RFC parameter — stub when RFC_API_ENABLED is not defined.
 * @return WRITE_RFC_NOTAPPLICABLE always.
 */
int write_RFCProperty(const char *type, const char *key, const char *data, RFCVALDATATYPE datatype);
#endif

#endif /* VIDEO_RFCINTERFACE_RFCINTERFACE_H_ */
