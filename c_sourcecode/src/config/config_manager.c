/**
 * @file config_manager.c
 * SKELETON: Implementation needed
 */
#include "config_manager.h"
#include "../../common/errors.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define RFC_TELEMETRY_OPTOUT "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.TelemetryOptOut.Enable"
#define OPTOUT_FILE "/opt/tmtryoptout"

bool get_opt_out_status(void)
{
    bool optoutStatus = false;
    char currentVal[16] = "false";

    //Read RFC Value
    //const char* rfcStatus = readRfcValue(RFC_TELEMETRY_OPTOUT);TODO: Bring rfcinterface code here
    const char* rfcStatus = "true";
    if (!rfcStatus) {
        rfcStatus = "false";
    }

    //Read Current Value from File
    FILE *fp = fopen(OPTOUT_FILE, "r");
    if (fp) {
        if (fgets(currentVal, sizeof(currentVal), fp)) {
            // remove newline if present
            currentVal[strcspn(currentVal, "\n")] = '\0';
        }
        fclose(fp);
    }

    //Compare & Set Status
    if (strcmp(rfcStatus, "true") == 0 && strcmp(currentVal, "true") == 0) {
        optoutStatus = true;
    }

    return optoutStatus;
}

int config_init_load(config_t *config) {
    int ret = -1;
    char device_prop_data[64] = {0};
    /* TODO: Load from env vars, device.properties, include.properties */
    if (!config) {
        return -1;
    }

    memset(config, 0, sizeof(config_t));

    strcpy(config->log_file, "/tmp/minidump_log_files.txt");
    strcpy(config->log_mapper_file, "/etc/breakpad-logmapper.conf");
    
    ret = getDevicePropertyData("DEVICE_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS) {
         printf("device type = %s\n", device_prop_data);
	 if (0 == (strncmp(device_prop_data, "mediaclient", 11))) {
	     config->device_type = DEVICE_TYPE_MEDIACLIENT;
	     printf("device type=%d\n",config->device_type);
	     strcpy(config->core_log_file, "/opt/logs/core_log.txt");
	     printf("core log=%s\n",config->core_log_file);
	 } else if (0 == (strncmp(device_prop_data, "broadband", 9))) {
	     config->device_type = DEVICE_TYPE_BROADBAND;
	     strcpy(config->core_log_file, "/rdklogs/logs/core_log.txt");
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
	 } else if (0 == (strncmp(device_prop_data, "extender", 8))) {
	     config->device_type = DEVICE_TYPE_EXTENDER;
	     strcpy(config->core_log_file, "/var/log/messages");
	 } else {
	     config->device_type = DEVICE_TYPE_UNKNOWN;
	 }
    } else {
         printf("%s: getDevicePropertyData() for device type fail\n", __FUNCTION__);
         return ERR_CONFIG_MISSING_REQUIRED;
    }

    //TODO: Need to find how to get upload_flag value
    int upload_flag = 1;
    if (upload_flag == 1) {
        strcpy(config->core_path, "/opt/secure/corefiles");
	strcpy(config->minidump_path, "/opt/secure/minidumps");
    } else {
        strcpy(config->core_path, "/var/lib/systemd/coredump");
	strcpy(config->minidump_path, "/opt/minidumps");
    }

    if (0 == (filePresentCheck("/lib/rdk/t2Shared_api.sh"))) {
        config->t2_enabled = true;
    } else {
        config->t2_enabled = false;
    }

    config->opt_out = false;
    config->opt_out = get_opt_out_status();

    return CONFIG_SUCCESS;
}

int config_get(const char *key, char *value, size_t len) {
    /* TODO: Implement config lookup */
    return ERR_NOT_IMPLEMENTED;
}

/**
 * FULL IMPLEMENTATION
 * Clean up configuration resources
 */
void config_cleanup(config_t *config) {
    if (config) {
        memset(config, 0, sizeof(config_t));
    }
}
