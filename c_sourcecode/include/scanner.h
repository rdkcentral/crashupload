#ifndef SCANNER_H
#define SCANNER_H

#include <time.h>
#include <sys/types.h>

#define PATH_MAX 4096

typedef struct {
    char path[PATH_MAX];
    time_t mtime;
    off_t size;
    int is_minidump;
} dump_file_t;

/**
 * Scan directory for dump files (.dmp, .core)
 * @param path Directory to scan
 * @param dumps Output array of found dumps
 * @param count Output count of found dumps
 * @return Number of dumps found, or -1 on error
 */
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count);

/**
 * Get dumps sorted by modification time (oldest first)
 * @param dumps Output array of sorted dumps
 * @param count Output count of dumps
 * @return 0 on success, -1 on error
 */
int scanner_get_sorted_dumps(dump_file_t **dumps, int *count);

/**
 * Cleanup scanner state
 */
void scanner_cleanup(void);

#endif /* SCANNER_H */
