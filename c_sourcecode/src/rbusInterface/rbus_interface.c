/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rbus_interface.h"
#include "../utils/logger.h"

#ifdef SYSCFG_API_ENABLED
#include <syscfg/syscfg.h>
#endif

#ifdef SYSEVENT_API_ENABLED
#include "sysevent/sysevent.h"
#endif

#ifdef RBUS_API_ENABLED
#include "rbus/rbus.h"
static rbusHandle_t g_rbusHandle = NULL;
static bool g_rbusInitialized = false;

bool rbus_init(void)
{
    bool returnValue = false;
    if (g_rbusInitialized)
    {
        CRASHUPLOAD_INFO("RBUS already initialized\n");
        returnValue = true;
        return returnValue;
    }
    rbusError_t rc = rbus_open(&g_rbusHandle, "crashupload");
    if (rc != RBUS_ERROR_SUCCESS)
    {
        CRASHUPLOAD_ERROR("Failed to open RBUS connection: %d\n", rc);
        return returnValue;
    }

    g_rbusInitialized = true;
    CRASHUPLOAD_INFO("RBUS connection initialized\n");
    returnValue = true;
    return returnValue;
}

void rbus_cleanup(void)
{
    if (g_rbusInitialized && g_rbusHandle != NULL)
    {
        rbus_close(g_rbusHandle);
        g_rbusHandle = NULL;
        g_rbusInitialized = false;
        CRASHUPLOAD_INFO("RBUS connection closed\n");
    }
}

bool rbus_get_string_param(const char *param_name, char *value_buf, size_t buf_size)
{
    if (!param_name || !value_buf || buf_size == 0)
    {
        CRASHUPLOAD_ERROR("Invalid parameters\n");
        return false;
    }

    if (!g_rbusInitialized || g_rbusHandle == NULL)
    {
        CRASHUPLOAD_ERROR("RBUS not initialized, call rbus_init() first\n");
        return false;
    }

    rbusValue_t paramValue = NULL;
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    const char *stringValue = NULL;
    bool success = false;

    // Get parameter value using global handle
    rc = rbus_get(g_rbusHandle, param_name, &paramValue);
    if (rc == RBUS_ERROR_SUCCESS && paramValue != NULL)
    {
        stringValue = rbusValue_GetString(paramValue, NULL);
        if (stringValue != NULL && strlen(stringValue) > 0)
        {
            strncpy(value_buf, stringValue, buf_size - 1);
            value_buf[buf_size - 1] = '\0';
            CRASHUPLOAD_DEBUG("[%s:%d] %s=%s\n", __FUNCTION__, __LINE__, param_name, value_buf);
            success = true;
        }
        rbusValue_Release(paramValue);
    }
    else
    {
        CRASHUPLOAD_WARN("Failed to get %s: %d\n", param_name, rc);
    }

    return success;
}
#else
/* Stub implementations when RBUS_API_ENABLED is not defined */
bool rbus_init(void)
{
    CRASHUPLOAD_WARN("RBUS API not enabled, using stub implementation\n");
    return true;
}

void rbus_cleanup(void)
{
    /* No-op when RBUS not enabled */
}

bool rbus_get_string_param(const char *param_name, char *value_buf, size_t buf_size)
{
    if (value_buf && buf_size > 0)
    {
        strncpy(value_buf, "SHARE", buf_size - 1);
        value_buf[buf_size - 1] = '\0';
    }
    CRASHUPLOAD_WARN("RBUS API not enabled, using stub value for %s\n", param_name ? param_name : "NULL");
    return true;
}
#endif

bool crashupload_syscfg_get(const char *key, char *value_buf, size_t buf_size)
{
    if (!key || !value_buf || buf_size == 0)
    {
        CRASHUPLOAD_ERROR("syscfg_get wrapper: invalid parameters\n");
        return false;
    }

    value_buf[0] = '\0';

#ifdef SYSCFG_API_ENABLED
    if (syscfg_get(NULL, key, value_buf, (int)buf_size) == 0)
    {
        return true;
    }

    CRASHUPLOAD_WARN("syscfg_get wrapper: failed for key=%s\n", key);
    return false;
#else
    CRASHUPLOAD_DEBUG("syscfg_get wrapper: SYSCFG_API_ENABLED not set, key=%s\n", key);
    return false;
#endif
}

bool crashupload_syscfg_set(const char *key, const char *value)
{
    if (!key || !value)
    {
        CRASHUPLOAD_ERROR("syscfg_set wrapper: invalid parameters\n");
        return false;
    }

#ifdef SYSCFG_API_ENABLED
    if (syscfg_set(NULL, key, value) == 0)
    {
        return true;
    }

    CRASHUPLOAD_WARN("syscfg_set wrapper: failed for key=%s\n", key);
    return false;
#else
    CRASHUPLOAD_DEBUG("syscfg_set wrapper: SYSCFG_API_ENABLED not set, key=%s\n", key);
    return false;
#endif
}

bool crashupload_sysevent_get(const char *key, char *value_buf, size_t buf_size)
{
    if (!key || !value_buf || buf_size == 0)
    {
        CRASHUPLOAD_ERROR("sysevent_get wrapper: invalid parameters\n");
        return false;
    }

    value_buf[0] = '\0';

#ifdef SYSEVENT_API_ENABLED
    token_t token;
    int fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "crashupload", &token);
    if (fd < 0)
    {
        CRASHUPLOAD_WARN("sysevent_get wrapper: sysevent_open failed for key=%s\n", key);
        return false;
    }

    if (sysevent_get(fd, token, key, value_buf, (int)buf_size) != 0)
    {
        CRASHUPLOAD_WARN("sysevent_get wrapper: failed for key=%s\n", key);
        sysevent_close(fd, token);
        return false;
    }

    sysevent_close(fd, token);
    return true;
#else
    CRASHUPLOAD_DEBUG("sysevent_get wrapper: SYSEVENT_API_ENABLED not set, key=%s\n", key);
    return false;
#endif
}

bool crashupload_sysevent_set(const char *key, const char *value)
{
    if (!key || !value)
    {
        CRASHUPLOAD_ERROR("sysevent_set wrapper: invalid parameters\n");
        return false;
    }

#ifdef SYSEVENT_API_ENABLED
    token_t token;
    int fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "crashupload", &token);
    if (fd < 0)
    {
        CRASHUPLOAD_WARN("sysevent_set wrapper: sysevent_open failed for key=%s\n", key);
        return false;
    }

    if (sysevent_set(fd, token, key, value, 0) != 0)
    {
        CRASHUPLOAD_WARN("sysevent_set wrapper: failed for key=%s\n", key);
        sysevent_close(fd, token);
        return false;
    }

    sysevent_close(fd, token);
    return true;
#else
    CRASHUPLOAD_DEBUG("sysevent_set wrapper: SYSEVENT_API_ENABLED not set, key=%s\n", key);
    return false;
#endif
}
