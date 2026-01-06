/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 * SPDX-License-Identifier: Apache-2.0
 */

#include "rfcinterface.h"

#ifndef GTEST_ENABLE
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#endif

#if defined(RFC_API_ENABLED)
/* Description: Reading rfc data
 * @param type : rfc type
 * @param key: rfc key
 * @param data : Store rfc value
 * @return int 1 READ_RFC_SUCCESS on success and READ_RFC_FAILURE -1 on failure
 * */
int read_RFCProperty(char* type, const char* key, char *out_value, size_t datasize) {
    RFC_ParamData_t param;
    int data_len;
    int ret = READ_RFC_FAILURE;

    if(key == NULL || out_value == NULL || datasize == 0 || type == NULL) {
        SWLOG_ERROR("read_RFCProperty() one or more input values are invalid\n");
        return ret;
    }
    //SWLOG_INFO("key=%s\n", key);
    WDMP_STATUS status = getRFCParameter(type, key, &param);
    if(status == WDMP_SUCCESS || status == WDMP_ERR_DEFAULT_VALUE) {
        data_len = strlen(param.value);
        if(data_len >= 2 && (param.value[0] == '"') && (param.value[data_len - 1] == '"')) {
            // remove quotes arround data
            snprintf( out_value, datasize, "%s", &param.value[1] );
            *(out_value + data_len - 2) = 0;
        }else {
            snprintf( out_value, datasize, "%s", param.value );
        }
        SWLOG_INFO("read_RFCProperty() name=%s,type=%d,value=%s,status=%d\n", param.name, param.type, param.value, status);
        ret = READ_RFC_SUCCESS;
    }else {
        SWLOG_ERROR("error:read_RFCProperty(): status= %d\n", status);
        *out_value = 0;
    }
    return ret;
}

/* Description: Writing rfc data
 * @param type : rfc type
 * @param key: rfc key
 * @param data : new rfc value
 * @param datatype: data type of value parameter
 * @return int 1 WRITE_RFC_SUCCESS on success and WRITE_RFC_FAILURE -1 on failure
 * */
int write_RFCProperty(char* type, const char* key, const char *value, RFCVALDATATYPE datatype) {
    WDMP_STATUS status = WDMP_FAILURE;
    int ret = WRITE_RFC_FAILURE;
    if (type == NULL || key == NULL || value == NULL) {
        SWLOG_ERROR("%s: Parameter is NULL\n", __FUNCTION__);
	return ret;
    }
    if (datatype == RFC_STRING) {
        status = setRFCParameter(type, key, value, WDMP_STRING);
    } else if(datatype == RFC_UINT) {
        status = setRFCParameter(type, key, value, WDMP_UINT);
    } else {
        status = setRFCParameter(type, key, value, WDMP_BOOLEAN);
    }
    if (status != WDMP_SUCCESS) {
        SWLOG_ERROR("%s: setRFCParameter failed. key=%s and status=%s\n", __FUNCTION__, key, getRFCErrorString(status));
    } else {
        SWLOG_INFO("%s: setRFCParameter Success\n", __FUNCTION__);
	ret = WRITE_RFC_SUCCESS;
    }
    return ret;
}
#else
/* Description: Below function should be implement Reading rfc data for RDK-M
 * @param type : rfc type
 * @param key: rfc key
 * @param data : Store rfc value
 * @return int 1 READ_RFC_SUCCESS on success and READ_RFC_FAILURE -1 on failure
 *             0 READ_RFC_NOTAPPLICABLE 
 * */
int read_RFCProperty(const char* type, const char* key, char *out_value, size_t datasize) {
    //TODO: Need to implement for RDK-M
    printf("%s: Not Applicabe For RDK-M. Need to implement\n", __FUNCTION__);
    return READ_RFC_NOTAPPLICABLE;
}
/* Description: Below function should be Writing rfc data For RDk-M
 * @param type : rfc type
 * @param key: rfc key
 * @param data : new rfc value
 * @param datatype: data type of value parameter
 * @return int 1 WRITE_RFC_SUCCESS on success and WRITE_RFC_FAILURE -1 on failure
 *             0 READ_RFC_NOTAPPLICABLE 
 * */
int write_RFCProperty(const char* type, const char* key, const char *value, RFCVALDATATYPE datatype) {
    //TODO: Need to implement for RDK-M
    printf("%s: Not Applicabe For RDK-M. Need to implement\n", __FUNCTION__);
    return WRITE_RFC_NOTAPPLICABLE;
}
#endif

