/**
 * @file upload_typeaware.c
 * SKELETON: Implementation needed
 */
#include "upload_typeaware.h"
#include "../../common/errors.h"
#include "../../common/constants.h"

upload_result_t upload_file_type_aware(const archive_info_t *archive,
                                        const dump_file_t *dump,
                                        const config_t *config) {
    /* TODO: Upload with type-specific retry (minidump: 5x3s, coredump: 3x10s) */
    return UPLOAD_FAILURE_RETRY;
}
