/**
 * @file cleanup_batch.h
 * @brief Batch cleanup operations
 * SKELETON: Interface definition
 */
#ifndef CLEANUP_BATCH_H
#define CLEANUP_BATCH_H

#include <limits.h>
#include <errno.h>
#include <time.h>
#include "../../common/types.h"

/* ---------- File list structure for sorting by mtime ---------- */

typedef struct {
    char *path;     /* malloc'd path string */
    time_t mtime;   /* last modification time */
} file_info_t;

typedef struct {
    file_info_t *arr;
    size_t size;
    size_t capacity;
} file_vector_t;


/**
 * @brief Cleanup old files in batch
 * @param config Configuration
 * @param age_days Files older than this are removed
 * @return ERR_SUCCESS on success
 */
int cleanup_batch(const char *working_dir,
                      const char *dumps_extn_pattern,
                      const char *on_startup_flag_base,
                      const char *dump_flag,
                      size_t max_core_files);

void remove_pending_dumps(const char *working_dir,
                          const char *dumps_extn_pattern);
#endif
