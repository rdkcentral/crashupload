/**
 * @file cleanup_batch.h
 * @brief Batch cleanup operations
 * SKELETON: Interface definition
 */
#ifndef CLEANUP_BATCH_H
#define CLEANUP_BATCH_H

#include "../../common/types.h"

/**
 * @brief Cleanup old files in batch
 * @param config Configuration
 * @param age_days Files older than this are removed
 * @return ERR_SUCCESS on success
 */
int cleanup_batch_old_files(const config_t *config, int age_days);

#endif
