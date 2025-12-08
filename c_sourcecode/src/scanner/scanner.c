/* FULL IMPLEMENTATION - Dump file scanner module */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "../../common/types.h"

#define MAX_DUMPS 100
#define PATH_MAX 4096

/*typedef struct {
    char path[PATH_MAX];
    time_t mtime;
    off_t size;
    int is_minidump;  // 1 for .dmp, 0 for .core
} dump_file_t;*/

static dump_file_t found_dumps[MAX_DUMPS];
static int dump_count = 0;

/* FULL IMPLEMENTATION - Check if file has dump extension */
static int is_dump_file(const char *filename) {
    size_t len = strlen(filename);
    
    /* Check for .dmp extension (minidump) */
    if (len > 4 && strcmp(filename + len - 4, ".dmp") == 0) {
        return 1;
    }
    
    /* Check for .core extension (coredump) */
    if (len > 5 && strcmp(filename + len - 5, ".core") == 0) {
        return 2;
    }
    
    /* Check for core.* pattern (systemd coredumps) */
    if (strncmp(filename, "core.", 5) == 0) {
        return 2;
    }
    
    return 0;
}

/* FULL IMPLEMENTATION - Scan directory for dump files */
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count) {
    if (!path || !dumps || !count) {
        return -1;
    }
    
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to open directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    dump_count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL && dump_count < MAX_DUMPS) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        int dump_type = is_dump_file(entry->d_name);
        if (dump_type == 0) {
            continue;
        }
        
        /* Build full path */
        char fullpath[256];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        
        /* Get file stats */
        struct stat st;
        if (stat(fullpath, &st) != 0) {
            continue;
        }
        
        /* Skip if not a regular file */
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        
        /* Add to array */
        strncpy(found_dumps[dump_count].path, fullpath, sizeof(found_dumps[dump_count].path));
        found_dumps[dump_count].path[512 - 1] = '\0';
        found_dumps[dump_count].mtime = st.st_mtime;
        found_dumps[dump_count].size = st.st_size;
        found_dumps[dump_count].is_minidump = (dump_type == 1);
	printf("Dump/Core file name=%s\n", found_dumps[dump_count].path);
        dump_count++;
    }
    
    closedir(dir);
    
    *dumps = found_dumps;
    *count = dump_count;
    
    return dump_count;
}

/* FULL IMPLEMENTATION - Get sorted dumps (oldest first for upload priority) */
int scanner_get_sorted_dumps(dump_file_t **dumps, int *count) {
    if (!dumps || !count) {
        return -1;
    }
    
    /* Simple bubble sort by modification time (oldest first) */
    for (int i = 0; i < dump_count - 1; i++) {
        for (int j = 0; j < dump_count - i - 1; j++) {
            if (found_dumps[j].mtime > found_dumps[j + 1].mtime) {
                dump_file_t temp = found_dumps[j];
                found_dumps[j] = found_dumps[j + 1];
                found_dumps[j + 1] = temp;
            }
        }
    }
    
    *dumps = found_dumps;
    *count = dump_count;
    return 0;
}

/* FULL IMPLEMENTATION - Clear scanner state */
void scanner_cleanup(void) {
    dump_count = 0;
    memset(found_dumps, 0, sizeof(found_dumps));
}
