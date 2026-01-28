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
#include "../utils/logger.h"
#include "../platform/platform.h"
#include "../t2Interface/telemetryinterface.h"
#include <stdio.h>
#include <string.h>

int system_initialize(int argc, char *argv[],
                      config_t *config,
                      platform_config_t *platform)
{
    if (argc < 0 || !argv || !config || !platform)
    {
        return -1;
    }

    /* Initialize telemetry */
    t2Init("crashupload");

    config_init_load(config, argc, argv);
    CRASHUPLOAD_INFO("core_log file=%s\n", config->core_log_file);
    if (0 != (filePresentCheck(config->core_log_file)))
    {
        CRASHUPLOAD_INFO("%s File not present. Creating File\n", config->core_log_file);
        int fd = open(config->core_log_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0)
        {
            CRASHUPLOAD_ERROR("open failed\n");
            return -1;
        }

        // Force mode regardless of umask
        if (chmod(config->core_log_file, 0666) != 0)
        {
            CRASHUPLOAD_ERROR("chmod failed\n");
        }
        close(fd);
    }
    platform_initialize(config, platform);
    CRASHUPLOAD_INFO("Working dir=%s\n", config->working_dir_path);
    return SYSTEM_INIT_SUCCESS;
}
