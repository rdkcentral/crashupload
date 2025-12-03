/**
 * @file prerequisites.c
 * SKELETON: Implementation needed
 */
#include "prerequisites.h"
#include "cleanup_batch.h"
#include "../../common/errors.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#define FOUR_EIGHTY_SECS 480   // 8 minutes (same as script)

void defer_upload_if_needed(device_type_t device_type)
{
    int ret = -1;
    
    if (device_type == DEVICE_TYPE_MEDIACLIENT)
    {
        /* Read uptime from /proc/uptime */
        FILE *fp = fopen("/proc/uptime", "r");
        if (!fp) {
            printf("Failed to read /proc/uptime\n");
            return;
        }

        double uptime_seconds = 0.0;
        ret = fscanf(fp, "%lf", &uptime_seconds);
        fclose(fp);
	if (ret != 1) {
            printf("Failed to parse /proc/uptime");
        }

        int uptime_val = (int)uptime_seconds;

        if (uptime_val < FOUR_EIGHTY_SECS) {

            int sleep_time = FOUR_EIGHTY_SECS - uptime_val;

            printf("Deferring Upload for %d seconds\n", sleep_time);
            sleep(sleep_time);
            printf("Deferring Upload for %d seconds completed\n", sleep_time);

            if (0 == (filePresentCheck("/tmp/set_crash_reboot_flag"))) {
                printf("Process crashed, exiting from the deferring reboot");
                exit(0);   // same as break (stop further execution)
            }
        }
    }
}

/**
 * Returns:
 *   1 -> Found at least one matching file
 *   0 -> No matching files
 *  -1 -> Error (directory missing, etc.)
 */
int directory_has_pattern(const char *dir, const char *pattern)
{
    DIR *dp = opendir(dir);
    if (!dp) {
	printf("%s dir not open\n", dir);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        // skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (strstr(entry->d_name, pattern) != NULL) {
            closedir(dp);
            return 1;  // found match
        }
    }

    closedir(dp);
    return 0;  // no match
}


int prerequisites_wait(config_t *config, int timeout_sec) {
    int dump_file_found = 0;
    char dump_extn[16] = {0};
    printf("Inside prerequisites_wait(): device type=%u, core dump file=%s, minidumpfile=%s\n", config->device_type, config->core_path, config->minidump_path);
    /* TODO: Check network + time sync together */
    if (NULL == config) {
        printf("Invalid parameter or NULL parameter\n");
	return -1;
    }
    if ((config->device_type == DEVICE_TYPE_BROADBAND) || (config->device_type == DEVICE_TYPE_EXTENDER)) {
        dump_file_found = directory_has_pattern(config->core_path,".dmp");
    } else {
	if (config->dump_type == DUMP_TYPE_MINIDUMP) {
            dump_file_found = directory_has_pattern(config->minidump_path,".dmp");
	    strcpy(dump_extn, "*.dmp*");
	} else if (config->dump_type == DUMP_TYPE_COREDUMP) {    
            dump_file_found = directory_has_pattern(config->core_path,"_core");
	    strcpy(dump_extn, "*core.prog*.gz*");
	} else {
	    printf("Invalid Dump Type\n");
	}
    }
    if (1 != dump_file_found) {
        printf("dump file or core file not found. So exit\n");
        return NO_DUMPS_FOUND;
    }
    if ((config->device_type == DEVICE_TYPE_MEDIACLIENT) && (config->opt_out == true)) {
        printf("Coreupload is disabled as TelemetryOptOut is set\n");
	printf("Cleaning dump with extension:%s:%s\n", config->working_dir_path,dump_extn);
	remove_pending_dumps(config->working_dir_path,dump_extn);
	return 1;
    }
    defer_upload_if_needed(config->device_type);
    //TODO: Below mutex_release file create by core dump generation script.So using same
    if ((config->dump_type == DUMP_TYPE_COREDUMP) && (0 != (filePresentCheck(" /tmp/coredump_mutex_release")))) {
        printf("Waiting for Coredump Completion\n");
	sleep(21);//TODO: How this number arive??
    }
    return PREREQUISITES_SUCCESS;
}
