#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stddef.h>

/**
 * Create compressed archive with smart optimization
 * Tries direct compression first, falls back to /tmp if space issues
 * @param input Input file path
 * @param output Output archive path
 * @return 0 on success, -1 on error
 */
int archive_create(const char *input, const char *output);

/**
 * Generate archive filename with platform info
 * Format: SHA1_macMAC_datTIMESTAMP_modMODEL_basename.tgz
 * @param dump_path Original dump file path
 * @param mac MAC address
 * @param model Device model
 * @param sha1 Firmware SHA1
 * @param output Output buffer for filename
 * @param output_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int archive_generate_filename(const char *dump_path, const char *mac,
                              const char *model, const char *sha1,
                              char *output, size_t output_size);

#endif /* ARCHIVE_H */
