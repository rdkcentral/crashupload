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

int config_init_load(config_t *config, int argc, char *argv[]) {
    int ret = -1;
    char device_prop_data[64] = {0};
    char log_path[32] = {0};
    
    if (!config) {
        return -1;
    }

    memset(config, 0, sizeof(config_t));

    strcpy(config->log_file, "/tmp/minidump_log_files.txt");
    strcpy(config->log_mapper_file, "/etc/breakpad-logmapper.conf");
    
    ret = getIncludePropertyData("LOG_PATH", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS) {
        printf("log path = %s\n", log_path);
    } else {
	strcpy(log_path, "/opt/logs");
        printf("Error to get log path. Set default path = %s\n", log_path);
    }
    ret = getDevicePropertyData("BOX_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS) {
         printf("Box type = %s\n", device_prop_data);
	 strncpy(config->box_type, device_prop_data, sizeof(config->box_type));
    } else {
	 strcpy(config->box_type, "UNKNOWN");
    }
    ret = getDevicePropertyData("BUILD_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS) {
         printf("Build type = %s\n", device_prop_data);
	 if (0 == strncmp(device_prop_data, "prod", 4)) {
	     config->build_type = BUILD_TYPE_PROD;
	 } else {
	     config->build_type = BUILD_TYPE_DEV;
	 }
    } else {
	 config->build_type = BUILD_TYPE_UNKNOWN;
    }
    ret = getDevicePropertyData("DEVICE_TYPE", device_prop_data, sizeof(device_prop_data));
    if (ret == UTILS_SUCCESS) {
         printf("device type = %s\n", device_prop_data);
	 if (0 == (strncmp(device_prop_data, "mediaclient", 11))) {
	     config->device_type = DEVICE_TYPE_MEDIACLIENT;
	     printf("device type=%d\n",config->device_type);
	     snprintf(config->core_log_file, sizeof(config->core_log_file), "%s/%s", log_path, "core_log.txt");
	     printf("core log=%s\n",config->core_log_file);
	 } else if (0 == (strncmp(device_prop_data, "broadband", 9))) {
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
    if (argc == 3) {
        if(0 == atoi(argv[2])) {
	    printf("Setting Minidump\n");
	    config->dump_type = DUMP_TYPE_MINIDUMP;
	} else if (1 == atoi(argv[2])) {
	    printf("Setting Coredump\n");
	    config->dump_type = DUMP_TYPE_COREDUMP;
	} else {
	    printf("Setting Unknown\n");
	    config->dump_type = DUMP_TYPE_UNKNOWN;
	}
    }
    if ((argc == 4) && (0 == (strncmp(argv[3], "secure", 6)))) {
	printf("Secure is enable\n");
	config->upload_mode = UPLOAD_MODE_SECURE;
        strcpy(config->core_path, "/opt/secure/corefiles");
	strcpy(config->minidump_path, "/opt/secure/minidumps");
    } else {
	printf("Secure is not enable\n");
	config->upload_mode = UPLOAD_MODE_NORMAL;
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
    config->lock_mode = (0 == (strncmp(argv[4],"wait_for_lock", 13))) ? LOCK_MODE_WAIT : LOCK_MODE_EXIT;
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
