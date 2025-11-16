/**
 * @file upload_typeaware.h
 * @brief Type-aware upload handler
 * SKELETON: Interface definition
 */
#ifndef UPLOAD_TYPEAWARE_H
#define UPLOAD_TYPEAWARE_H

#include "../../common/types.h"

/**
 * @brief Upload file with type-aware retry logic
 * @param archive Archive to upload
 * @param dump Original dump file
 * @param config Configuration
 * @return upload_result_t
 */
upload_result_t upload_file_type_aware(const archive_info_t *archive,
                                        const dump_file_t *dump,
                                        const config_t *config);

#endif
