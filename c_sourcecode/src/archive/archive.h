/**
 * @file archive_smart.h
 * @brief Smart archive creator with fallback
 * SKELETON: Interface definition
 */
#ifndef ARCHIVE_SMART_H
#define ARCHIVE_SMART_H

#include "../../common/types.h"
#include <archive.h>
#include <archive_entry.h>
#include <sys/resource.h>
/**
 * @brief Create archive with smart compression
 * @param dump Dump file to archive
 * @param platform Platform configuration
 * @param archive Archive info (output)
 * @return ERR_SUCCESS on success
 */
int archive_create_smart(const dump_file_t *dump, const config_t *config,
                         const platform_config_t *platform,
                         archive_info_t *archive, char *new_dump_name);

void set_low_priority(void);

#endif
