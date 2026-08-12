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

/**
 * @file platform.c
 * SKELETON: Implementation needed
 */
#include "platform.h"
#include "../../common/errors.h"
#include "../utils/logger.h"
#include <fcntl.h>
#include <unistd.h>
#ifndef GTEST_ENABLE
#include "secure_wrapper.h"
#endif

/* function NormalizeMac - gets the eSTB MAC address of the device.

        Usage: size_t GetEstbMac <char *pEstbMac> <size_t szBufSize>

            pEstbMac - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 1.

            RETURN - number of characters copied to the output buffer.
*/
void NormalizeMac(char *mac, size_t size)
{
    if (mac == NULL || size == 0)
        return;

    size_t write_idx = 0;

    for (size_t read_idx = 0; mac[read_idx] != '\0' && read_idx < size; read_idx++)
    {
        char c = mac[read_idx];

        // Skip ':' characters
        if (c == ':')
            continue;

        // Convert lowercase alphabet to uppercase
        if (c >= 'a' && c <= 'z')
            c = c - ('a' - 'A'); // or use toupper(c)

        // Write character back, ensuring no overflow
        if (write_idx < size - 1)
        {
            mac[write_idx++] = c;
        }
    }

    // Null terminate
    mac[write_idx] = '\0';
}

/* function GetEstbMac - gets the eSTB MAC address of the device.

        Usage: size_t GetEstbMac <char *pEstbMac> <size_t szBufSize>

            pEstbMac - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 1.

            RETURN - number of characters copied to the output buffer.
*/
size_t GetEstbMac(char *pEstbMac, size_t szBufSize)
{
    FILE *fp;
    size_t i = 0;
    char estb_interface[8] = {0};
    int ret = -1;
    bool read_from_hwinterface = false; // default value
    if (pEstbMac != NULL)
    {
        *pEstbMac = 0;
        if ((fp = fopen(MAC_FILE, "r")) != NULL)
        {
            if (NULL != (fgets(pEstbMac, szBufSize, fp)))
            { // better be a valid string on first line
                i = stripinvalidchar(pEstbMac, szBufSize);
            }
            fclose(fp);
            i = stripinvalidchar(pEstbMac, szBufSize);
            CRASHUPLOAD_INFO("GetEstbMac: After reading ESTB_MAC_FILE value=%s\n", pEstbMac);
            /* Below condition if ESTB_MAC_FILE file having empty data and pEstbMac does not have 17 character
             * including total mac address with : separate */
            if (pEstbMac[0] == '\0' || pEstbMac[0] == '\n' || i != MAC_ADDRESS_LEN)
            {
                CRASHUPLOAD_INFO("GetEstbMac: ESTB_MAC_FILE file is empty read_from_hwinterface is set to true\n");
                read_from_hwinterface = true;
            }
        }
        else
        {
            read_from_hwinterface = true; // ESTB_MAC_FILE file does not present proceed for reading from interface
            CRASHUPLOAD_INFO("GetEstbMac: read_from_hwinterface is set to true\n");
        }
        if (read_from_hwinterface == true)
        {
            CRASHUPLOAD_INFO("GetEstbMac: Reading from hw interface\n");
            ret = getDevicePropertyData("ESTB_INTERFACE", estb_interface, sizeof(estb_interface));
            if (ret == UTILS_SUCCESS)
            {
                i = GetHwMacAddress(estb_interface, pEstbMac, szBufSize);
                if (i)
                {
                    CRASHUPLOAD_INFO("GetEstbMac: Hardware address=%s=\n", pEstbMac);
                }
                else
                {
                    /* When there is no hw address available */
                    *pEstbMac = 0;
                    CRASHUPLOAD_INFO("GetEstbMac: GetHwMacAddress return fail\n");
                }
            }
            else
            {
                *pEstbMac = 0;
                i = 0;
                CRASHUPLOAD_INFO("GetEstbMac: Interface is not part of /etc/device.properties missing\n");
            }
        }
    }
    else
    {
        CRASHUPLOAD_INFO("GetEstbMac: Error, input argument NULL\n");
    }
    return i;
}

int platform_initialize(const config_t *config, platform_config_t *platform)
{
    int ret = 0;

    memset(platform, 0, sizeof(platform_config_t));

    /* TODO: Get IP, device ID, SHA1 */
    ret = GetEstbMac(platform->mac_address, sizeof(platform->mac_address));
    if (ret)
    {
        NormalizeMac(platform->mac_address, sizeof(platform->mac_address));
        CRASHUPLOAD_INFO("Mac address is %s\n", platform->mac_address);
    }
    else
    {
        if (config && (config->device_type == DEVICE_TYPE_BROADBAND || config->device_type == DEVICE_TYPE_EXTENDER))
        {
            CRASHUPLOAD_ERROR("GetEstbMac is failed. Trying to get mac from wan interface\n");
            char wan_if[32] = {0};
            snprintf(wan_if, sizeof(wan_if), "%s", get_interface_value());
            if (wan_if[0] != '\0' && strcmp(wan_if, "unknown") != 0)
            {
                ret = GetHwMacAddress(wan_if, platform->mac_address, sizeof(platform->mac_address));
                if (ret)
                {
                    NormalizeMac(platform->mac_address, sizeof(platform->mac_address));
                    CRASHUPLOAD_INFO("Broadband MAC fallback via %s: %s\n", wan_if, platform->mac_address);
                }
            }
        }
        if (!ret)
        {
            CRASHUPLOAD_ERROR("Get mac is failed. Setting dafult value\n");
            strcpy(platform->mac_address, "000000000000");
        }
    }
    // TODO: For brodband and extender we have change the code
    ret = GetModelNum(platform->model, sizeof(platform->model));
    if (ret)
    {
        CRASHUPLOAD_INFO("Model Num=%s\n", platform->model);
    }
    else
    {
        CRASHUPLOAD_ERROR("GetModel is failed. Setting dafult value\n");
        strcpy(platform->model, "UNKNOWN");
    }
    ret = file_get_sha1("/version.txt", platform->platform_sha1, sizeof(platform->platform_sha1));
    if (ret == 0)
    {
        CRASHUPLOAD_INFO("file sha=%s\n", platform->platform_sha1);
    }
    else
    {
        CRASHUPLOAD_ERROR("file_get_sha1 error. Assign default value\n");
        strcpy(platform->platform_sha1, "000000000000000000000000000000000000000");
        CRASHUPLOAD_INFO("file sha=%s\n", platform->platform_sha1);
    }
    return PLATFORM_INIT_SUCCESS;
}

const char *get_core_type(void)
{
    static char core[8] = {0};
    if (core[0] != '\0')
        return core;

    FILE *fp = fopen(TMP_CPU_INFO_FILE, "r");
    if (fp)
    {
        if (fgets(core, sizeof(core), fp))
        {
            size_t len = strlen(core);
            if (len > 0 && core[len - 1] == '\n') core[len - 1] = '\0';
        }
        fclose(fp);
    }
    if (core[0] == '\0')
    {
        fp = fopen(CPU_INFO_FILE, "r");
        if (fp)
        {
            char line[128];
            while (fgets(line, sizeof(line), fp))
            {
                if (strstr(line, "aarch64") || strstr(line, "ARM")) { strcpy(core, "ARM");  break; }
                if (strstr(line, "Atom"))                            { strcpy(core, "ATOM"); break; }
            }
            fclose(fp);
        }
        /* cache result so subsequent calls skip /proc/cpuinfo parsing */
        if (core[0] != '\0')
        {
            int fd = open(TMP_CPU_INFO_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0)
            {
                fp = fdopen(fd, "w");
                if (fp) { fputs(core, fp); fclose(fp); }
                else close(fd);
            }
        }
    }
    CRASHUPLOAD_INFO("get_core_type: %s\n", core[0] ? core : "unknown");
    return core;
}

#define IF_INFO_FILE            "/tmp/if_info"
#define SYSEVENT_TIMEOUT_SEC    900
#define SYSEVENT_POLL_SEC       5

const char *get_interface_value(void)
{
    static char if_name[32] = {0};
#if defined(GTEST_ENABLE) || defined(L2_TEST)
    snprintf(if_name, sizeof(if_name), "%s", "erouter0");
    return if_name;
#else
    if (if_name[0] != '\0')
        return if_name;

    {
        FILE *fp = fopen(IF_INFO_FILE, "r");
        if (fp)
        {
            if (fgets(if_name, sizeof(if_name), fp))
            {
                size_t len = strlen(if_name);
                if (len > 0 && if_name[len - 1] == '\n')
                    if_name[len - 1] = '\0';
                if (if_name[0] != '\0')
                {
                    fclose(fp);
                    CRASHUPLOAD_INFO("get_interface_value: cache=%s\n", if_name);
                    return if_name;
                }
            }
            fclose(fp);
        }
    }

    /* Poll sysevent for current WAN interface; retry every 5s up to 900s (script parity) */
    int elapsed = 0;
    while (elapsed < SYSEVENT_TIMEOUT_SEC)
    {
        FILE *fp = v_secure_popen("r", "sysevent get current_wan_ifname");
        if (fp)
        {
            char buf[32] = {0};
            if (fgets(buf, sizeof(buf), fp))
            {
                size_t len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
                if (buf[0] != '\0')
                {
                    snprintf(if_name, sizeof(if_name), "%s", buf);
                    v_secure_pclose(fp);
                    CRASHUPLOAD_INFO("get_interface_value: sysevent=%s\n", if_name);
                    return if_name;
                }
            }
            v_secure_pclose(fp);
        }
        sleep(SYSEVENT_POLL_SEC);
        elapsed += SYSEVENT_POLL_SEC;
    }
    /* Fallback: derive interface from core type via device.properties */
    const char *core = get_core_type();
    int ret = -1;
    if (strcmp(core, "ATOM") == 0)
        ret = getDevicePropertyData("ATOM_INTERFACE", if_name, sizeof(if_name));
    else if (strcmp(core, "ARM") == 0)
        ret = getDevicePropertyData("ARM_INTERFACE", if_name, sizeof(if_name));
    else
        ret = -1;

    if (ret != 0 || if_name[0] == '\0')
        snprintf(if_name, sizeof(if_name), "%s", "unknown");

    if (if_name[0] != '\0' && strcmp(if_name, "unknown") != 0)
    {
        int fd = open(IF_INFO_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
        {
            FILE *fp = fdopen(fd, "w");
            if (fp) { fputs(if_name, fp); fclose(fp); }
            else close(fd);
        }
    }
    CRASHUPLOAD_INFO("get_interface_value: fallback core=%s if=%s\n", core, if_name);
    return if_name;
#endif
}
