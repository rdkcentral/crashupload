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
 * @file config_manager.c
 * SKELETON: Implementation needed
 */
#include "config_manager.h"
#include "../../common/errors.h"
#include "../utils/logger.h"
#include "../rfcInterface/rfcinterface.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define OPTOUT_FILE "/opt/tmtryoptout"

bool get_opt_out_status(void)
{
    bool optoutStatus = false;
    char currentVal[16] = "false";
    int ret = -1;
    char rfcStatus[32] = {0};
    ret = read_RFCProperty("rfcTelemetryOptout", RFC_TELEMETRY_OPTOUT, rfcStatus, sizeof(rfcStatus));
    if ((ret == READ_RFC_FAILURE) || (rfcStatus[0] == '\0'))
    {
        strcpy(rfcStatus, "false");
        CRASHUPLOAD_WARN("Read rfc failed rfcTelemetryOptout:%s and default value set:%s\n", RFC_TELEMETRY_OPTOUT, rfcStatus);
    }
    else
    {
        CRASHUPLOAD_INFO("Read rfc Success rfcTelemetryOptout:%s and value=:%s\n", RFC_TELEMETRY_OPTOUT, rfcStatus);
    }

    FILE *fp = fopen(OPTOUT_FILE, "r");
    if (fp)
    {
        if (fgets(currentVal, sizeof(currentVal), fp))
        {
            // remove newline if present
            currentVal[strcspn(currentVal, "\n")] = '\0';
        }
        fclose(fp);
    }

    // Compare & Set Status
    if (strcmp(rfcStatus, "true") == 0 && strcmp(currentVal, "true") == 0)
    {
        optoutStatus = true;
    }
    return optoutStatus;
}

int config_init_load(config_t *config, int argc, char *argv[])
{
    int ret = -1;
    char device_prop_data[64] = {0};
    char log_path[32] = {0};

    if (!config)
    {
        return -1;
    }

    memset(config, 0, sizeof(config_t));

    strcpy(config->log_file, "/tmp/minidump_log_files.txt");
    strcpy(config->log_mapper_file, "/etc/breakpad-logmapper.conf");

    ret = getIncludePropertyData("LOG_PATH", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS)
    {
        strncpy(config->log_path, device_prop_data, sizeof(config->log_path));
        config->log_path[sizeof(config->log_path) - 1] = '\0';
        CRASHUPLOAD_INFO("log path = %s\n", config->log_path);
    }
    else
    {
        strcpy(config->log_path, "/opt/logs");
        CRASHUPLOAD_WARN("Error to get log path. Set default path = %s\n", config->log_path);
    }
    strncpy(log_path, config->log_path, sizeof(log_path));
    CRASHUPLOAD_INFO("log path = %s\n", log_path);
    ret = getDevicePropertyData("BOX_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS)
    {
        CRASHUPLOAD_INFO("Box type = %s\n", device_prop_data);
        strncpy(config->box_type, device_prop_data, sizeof(config->box_type));
    }
    else
    {
        strcpy(config->box_type, "UNKNOWN");
    }
    ret = getDevicePropertyData("BUILD_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS)
    {
        CRASHUPLOAD_INFO("Build type = %s\n", device_prop_data);
        strncpy(config->build_type_val, device_prop_data, sizeof(config->build_type_val));
        config->build_type_val[sizeof(config->build_type_val) - 1] = '\0';
        if (0 == strncmp(device_prop_data, "prod", 4))
        {
            config->build_type = BUILD_TYPE_PROD;
        }
        else
        {
            config->build_type = BUILD_TYPE_DEV;
        }
    }
    else
    {
        config->build_type = BUILD_TYPE_UNKNOWN;
    }
    ret = getDevicePropertyData("DEVICE_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS)
    {
        CRASHUPLOAD_INFO("device type = %s\n", device_prop_data);
        if (0 == (strncmp(device_prop_data, "mediaclient", 11)) || (0 == (strncmp(device_prop_data, "hybrid", 11))))
        {
            config->device_type = DEVICE_TYPE_MEDIACLIENT;
            CRASHUPLOAD_INFO("device type=%d\n", config->device_type);
            snprintf(config->core_log_file, sizeof(config->core_log_file), "%s/%s", log_path, "core_log.txt");
            CRASHUPLOAD_INFO("core log=%s\n", config->core_log_file);
        }
        else if (0 == (strncmp(device_prop_data, "broadband", 9)))
        {
            config->device_type = DEVICE_TYPE_BROADBAND;
            snprintf(config->core_log_file, sizeof(config->core_log_file), "%s/%s", log_path, "core_log.txt");
            /* TODO: During brodband we have to implement
             * CORE_PATH="/minidumps"
               LOG_PATH="/rdklogs/logs"
               if [ ! -d $LOG_PATH ];then mkdir -p $LOG_PATH; fi
               if [ "$MULTI_CORE" = "yes" ] ;then
                       COMM_INTERFACE=`get_interface_value`
               else
                       COMM_INTERFACE=$INTERFACE
               fi
             */
        }
        else if (0 == (strncmp(device_prop_data, "extender", 8)))
        {
            config->device_type = DEVICE_TYPE_EXTENDER;
            strcpy(config->core_log_file, "/var/log/messages");
        }
        else
        {
            config->device_type = DEVICE_TYPE_UNKNOWN;
        }
    }
    else
    {
        CRASHUPLOAD_ERROR("%s: getDevicePropertyData() for device type fail\n", __FUNCTION__);
        return ERR_CONFIG_MISSING_REQUIRED;
    }
    if ((argc >= 4) && (0 == (strncmp(argv[3], "secure", 6))))
    {
        CRASHUPLOAD_INFO("Secure is enable\n");
        config->upload_mode = UPLOAD_MODE_SECURE;
        strcpy(config->core_path, "/opt/secure/corefiles");
        strcpy(config->minidump_path, "/opt/secure/minidumps");
    }
    else
    {
        CRASHUPLOAD_INFO("Secure is not enable\n");
        config->upload_mode = UPLOAD_MODE_NORMAL;
        strcpy(config->core_path, "/var/lib/systemd/coredump");
        strcpy(config->minidump_path, "/opt/minidumps");
    }
    if (argc >= 3)
    {
        if (0 == atoi(argv[2]))
        {
            CRASHUPLOAD_INFO("starting minidump processing\n");
            config->dump_type = DUMP_TYPE_MINIDUMP;
            if ((config->device_type == DEVICE_TYPE_BROADBAND) || (config->device_type == DEVICE_TYPE_EXTENDER))
            {
                strcpy(config->working_dir_path, "/minidumps");
                strcpy(config->minidump_path, "/minidumps");
            }
            else
            {
                strncpy(config->working_dir_path, config->minidump_path, sizeof(config->working_dir_path));
            }
        }
        else if (1 == atoi(argv[2]))
        {
            CRASHUPLOAD_INFO("starting coredump processing\n");
            config->dump_type = DUMP_TYPE_COREDUMP;
            strncpy(config->working_dir_path, config->core_path, sizeof(config->working_dir_path));
        }
        else
        {
            CRASHUPLOAD_INFO("Setting Unknown\n");
            config->dump_type = DUMP_TYPE_UNKNOWN;
        }
    }

    if (0 == (filePresentCheck("/lib/rdk/t2Shared_api.sh")))
    {
        config->t2_enabled = true;
    }
    else
    {
        config->t2_enabled = false;
    }

    config->opt_out = false;
    config->opt_out = get_opt_out_status();
    config->lock_mode = ((argc == 5) && (0 == (strncmp(argv[4], "wait_for_lock", 13)))) ? LOCK_MODE_WAIT : LOCK_MODE_EXIT;

    // Initialize privacy_mode with default value
    strncpy(config->privacy_mode, "SHARE", sizeof(config->privacy_mode) - 1);
    config->privacy_mode[sizeof(config->privacy_mode) - 1] = '\0';

    return CONFIG_SUCCESS;
}

/**
 * FULL IMPLEMENTATION
 * Clean up configuration resources
 */
void config_cleanup(config_t *config)
{
    if (config)
    {
        memset(config, 0, sizeof(config_t));
    }
}

/**
 * @brief Retrieve and apply privacy control mode from RFC configuration
 *
 * This function reads the privacy mode setting from the RFC (Remote Feature Control) system
 * and updates the configuration accordingly. Privacy mode controls whether crash dump data
 * should be uploaded to remote servers or kept locally for privacy reasons.
 *
 * Expected RFC Values:
 * - "DO_NOT_SHARE": Privacy mode enabled - crash dumps will NOT be uploaded
 * - "SHARE": Privacy mode disabled - crash dumps will be uploaded (default behavior)
 *
 * Behavior:
 * - If RFC read succeeds with valid value: Updates config->privacy_mode with RFC value
 * - If RFC read fails or returns empty: Keeps existing default value ("SHARE")
 * - If RFC returns unknown value: Keeps existing default value and logs warning
 *
 * The default value "SHARE" must be set in config_init_load() before calling this function.
 *
 * @param config Pointer to configuration structure to update
 *               Must not be NULL and privacy_mode must be pre-initialized
 *
 * @note This function is typically called after system initialization for mediaclient devices
 * @note The privacy mode is checked at two points: during archiving and before upload
 *
 * @see config_init_load() for default value initialization
 * @see RFC_PRIVACY_MODE constant for the RFC parameter key
 *
 */
void get_privacy_control_mode(config_t *config)
{
    if (!config)
    {
        CRASHUPLOAD_ERROR("config is NULL\n");
        return;
    }

    char rfcPrivacyMode[64] = {0};
    int ret = read_RFCProperty("rfcPrivacyMode", RFC_PRIVACY_MODE, rfcPrivacyMode, sizeof(rfcPrivacyMode));

    if ((ret == READ_RFC_FAILURE) || (rfcPrivacyMode[0] == '\0'))
    {
        CRASHUPLOAD_WARN("Read RFC failed for PrivacyMode, keeping default value: %s\n", config->privacy_mode);
    }
    else if (ret == READ_RFC_NOTAPPLICABLE)
    {
        CRASHUPLOAD_INFO("RFC PrivacyMode not applicable for this platform, keeping default: %s\n", config->privacy_mode);
    }
    else
    {
        CRASHUPLOAD_INFO("Read RFC Success for PrivacyMode, value: %s\n", rfcPrivacyMode);

        // Update privacy_mode with RFC value
        if (strcmp(rfcPrivacyMode, "DO_NOT_SHARE") == 0)
        {
            strncpy(config->privacy_mode, "DO_NOT_SHARE", sizeof(config->privacy_mode) - 1);
            config->privacy_mode[sizeof(config->privacy_mode) - 1] = '\0';
            CRASHUPLOAD_INFO("Privacy mode set to DO_NOT_SHARE - crash data will NOT be uploaded\n");
        }
        else if (strcmp(rfcPrivacyMode, "SHARE") == 0)
        {
            strncpy(config->privacy_mode, "SHARE", sizeof(config->privacy_mode) - 1);
            config->privacy_mode[sizeof(config->privacy_mode) - 1] = '\0';
            CRASHUPLOAD_INFO("Privacy mode set to SHARE - crash data will be uploaded\n");
        }
        else
        {
            // Unknown value, keep default
            CRASHUPLOAD_WARN("Unknown RFC PrivacyMode value: %s, keeping default: %s\n", rfcPrivacyMode, config->privacy_mode);
        }
    }
}