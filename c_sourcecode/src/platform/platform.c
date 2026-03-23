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
#include "errors.h"
#include "logger.h"

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
        CRASHUPLOAD_ERROR("Get mac is failed. Setting dafult value\n");
        strcpy(platform->mac_address, "000000000000");
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
