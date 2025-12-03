/**
 * @file cleanup_batch.c
 * SKELETON: Implementation needed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>
#include "cleanup_batch.h"
#include "../../common/errors.h"

int cleanup_batch_old_files(const config_t *config, int age_days) {
    /* TODO: Single directory scan to remove old files */
    return ERR_NOT_IMPLEMENTED;
}


void remove_pending_dumps(const char *working_dir,
                          const char *dumps_extn_pattern)
{
    char path[512];
    struct stat st;
    DIR *dir = opendir(working_dir);
    if (!dir) {
        printf("opendir Error.%s dir not presemt\n",working_dir);
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {

        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", working_dir, entry->d_name);

        if (stat(path, &st) < 0) {
            printf("stat Error\n");
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // Recursive call for directories
            remove_pending_dumps(path, dumps_extn_pattern);
        }
        else if (S_ISREG(st.st_mode)) {

            int match_extn = fnmatch(dumps_extn_pattern, entry->d_name, 0) == 0;
            int match_tgz  = fnmatch("*.tgz", entry->d_name, 0) == 0;

            if (match_extn || match_tgz) {
                printf("Removing %s because upload limit has been reached or build is blacklisted or TelemetryOptOut is set\n",path);

                if (unlink(path) == 0) {
                    // File deleted
                } else {
                    printf("unlink error\n");
                }
            }
        }
    }

    closedir(dir);
}

