/* FULL IMPLEMENTATION - System utilities with caching and fallbacks */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rdk_fwdl_utils.h"
#include "system_utils.h"
#include "systemutils.h"
#include "telemetryinterface.h"

/**
 * FULL IMPLEMENTATION
 * Get system uptime with fallback from sysinfo() to /proc/uptime
 */
int system_get_uptime(uint64_t *uptime_seconds) {
    if (!uptime_seconds) {
        return -1;
    }

    /* Try sysinfo() first (preferred method) */
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        *uptime_seconds = (uint64_t)info.uptime;
        return 0;
    }

    /* Fallback to /proc/uptime */
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) {
        return -1;
    }

    double uptime_double;
    if (fscanf(fp, "%lf", &uptime_double) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    *uptime_seconds = (uint64_t)uptime_double;
    return 0;
}

#if 0
/**
 * FULL IMPLEMENTATION
 * Get device model with indefinite caching and multiple fallbacks
 */
int system_get_model(char *model, size_t len) {
    if (!model || len < 1) {
        return -1;
    }

    /* Check cache first (indefinite TTL for optimization) */
    if (model_cached && cached_model[0] != '\0') {
        strncpy(model, cached_model, len - 1);
        model[len - 1] = '\0';
        return 0;
    }

    /* Try multiple device.properties locations */
    const char *device_props_paths[] = {
        "/etc/device.properties",
        "/opt/device.properties",
        "/nvram/device.properties",
        NULL
    };

    for (int i = 0; device_props_paths[i] != NULL; i++) {
        FILE *fp = fopen(device_props_paths[i], "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "MODEL_NUM=", 10) == 0) {
                    char *value = line + 10;
                    /* Remove trailing newline */
                    char *newline = strchr(value, '\n');
                    if (newline) *newline = '\0';
                    
                    strncpy(cached_model, value, sizeof(cached_model) - 1);
                    cached_model[sizeof(cached_model) - 1] = '\0';
                    model_cached = true;
                    
                    strncpy(model, cached_model, len - 1);
                    model[len - 1] = '\0';
                    fclose(fp);
                    return 0;
                }
            }
            fclose(fp);
        }
    }

    /* Fallback to version.txt */
    const char *version_paths[] = {
        "/version.txt",
        "/etc/version.txt",
        NULL
    };

    for (int i = 0; version_paths[i] != NULL; i++) {
        FILE *fp = fopen(version_paths[i], "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                /* Extract model from version string */
                char *newline = strchr(line, '\n');
                if (newline) *newline = '\0';
                
                strncpy(cached_model, line, sizeof(cached_model) - 1);
                cached_model[sizeof(cached_model) - 1] = '\0';
                model_cached = true;
                
                strncpy(model, cached_model, len - 1);
                model[len - 1] = '\0';
                fclose(fp);
                return 0;
            }
            fclose(fp);
        }
    }

    /* Did not get exact implementation, added hardcoded value */
    strncpy(model, "UNKNOWN", len - 1);
    model[len - 1] = '\0';
    return -1;
}
#endif

/**
 * FULL IMPLEMENTATION
 * Check if process is running using /proc scan (no ps command)
 */
int system_check_process(const char *name, bool *is_running) {
    if (!name || !is_running) {
        return -1;
    }

    *is_running = false;

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Check if directory name is numeric (PID) */
        if (entry->d_type == DT_DIR) {
            char *endptr;
            long pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && pid > 0) {
                /* Read process name from /proc/[pid]/comm */
                char comm_path[256];
                snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
                
                FILE *fp = fopen(comm_path, "r");
                if (fp) {
                    char proc_name[256];
                    if (fgets(proc_name, sizeof(proc_name), fp)) {
                        /* Remove trailing newline */
                        char *newline = strchr(proc_name, '\n');
                        if (newline) *newline = '\0';
                        
                        if (strcmp(proc_name, name) == 0) {
                            *is_running = true;
                            fclose(fp);
                            closedir(proc_dir);
                            return 0;
                        }
                    }
                    fclose(fp);
                }
            }
        }
    }

    closedir(proc_dir);
    return 0;
}

/**
 * SKELETON
 * Execute system reboot
 */
bool is_box_rebooting(bool t2_enabled) {
    bool ret = false;
    /* SKELETON - Using system() call for now */
    if (0 == filePresentCheck("/tmp/set_crash_reboot_flag")) {
        printf("Skipping upload, Since Box is Rebooting now\n");
        if (t2_enabled) {
            t2CountNotify("SYST_INFO_CoreUpldSkipped", 1);
        }
	    printf("Upload will happen on next reboot\n");
	    ret = true;
    }
    return ret;
}
