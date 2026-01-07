/**
 * @file system_init.c
 * @brief Consolidated system initialization implementation
 * 
 * Based on docs/migration/lld/updateduploadDumps-lld.md
 * SKELETON: Function body needs implementation
 */

#include "system_init.h"
#include "../../common/errors.h"
#include "../../common/constants.h"
#include "../config/config_manager.h"
#include "../platform/platform.h"
#include <stdio.h>
#include <string.h>

int system_initialize(int argc, char *argv[], 
                     config_t *config,
                     platform_config_t *platform) {
    /* TODO: Implement consolidated initialization:
     * 1. Parse command-line arguments
     * 2. Load configuration from environment variables (highest priority)
     * 3. Load configuration from device.properties
     * 4. Load configuration from include.properties
     * 5. Apply defaults for missing values
     * 6. Initialize platform configuration (MAC, model, SHA1, etc.)
     * 7. Set up signal handlers (SIGTERM, SIGINT)
     * 8. Validate configuration
     */
    if (argc < 0 || !argv || !config || !platform) {
        return -1;
    }
    config_init_load(config, argc, argv);
    printf("core_log file=%s\n", config->core_log_file);
    if (0 != (filePresentCheck(config->core_log_file))) {
        printf("%s File not present. Creating File\n", config->core_log_file);
        int fd = open(config->core_log_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            printf("open failed\n");
            return -1;
        }

        // Force mode regardless of umask
        if (chmod(config->core_log_file, 0666) != 0) {
            printf("chmod failed\n");
        }
        close(fd);
    }
    platform_initialize(config, platform);
    printf("Working dir=%s\n", config->working_dir_path);
    return SYSTEM_INIT_SUCCESS;
}
