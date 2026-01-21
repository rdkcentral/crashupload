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
 * @file logger.h
 * @brief Logging utility
 * SKELETON: Interface definition
 */
#ifndef LOGGER_H
#define LOGGER_H

#if defined(RDK_LOGGER)
#include "rdk_debug.h"

#define CRASHUPLOAD_TRACE(format, ...)   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)
#define CRASHUPLOAD_DEBUG(format, ...)   RDK_LOG(RDK_LOG_DEBUG,  "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)
#define CRASHUPLOAD_INFO(format, ...)    RDK_LOG(RDK_LOG_INFO,   "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)
#define CRASHUPLOAD_WARN(format, ...)    RDK_LOG(RDK_LOG_WARN,   "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)
#define CRASHUPLOAD_ERROR(format, ...)   RDK_LOG(RDK_LOG_ERROR,  "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)
#define CRASHUPLOAD_FATAL(format, ...)   RDK_LOG(RDK_LOG_FATAL,  "LOG.RDK.CRASHUPLOAD", format, ##__VA_ARGS__)

#else
/* Fallback to custom logging */

#define CRASHUPLOAD_LOG_INFO (1)

void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...);

#define CRASHUPLOAD_TRACE(FORMAT...) crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)
#define CRASHUPLOAD_DEBUG(FORMAT...) crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)
#define CRASHUPLOAD_INFO(FORMAT...)  crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)
#define CRASHUPLOAD_WARN(FORMAT...)  crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)
#define CRASHUPLOAD_ERROR(FORMAT...) crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)
#define CRASHUPLOAD_FATAL(FORMAT...) crashupload_log(CRASHUPLOAD_LOG_INFO, __FILE__, __LINE__, FORMAT)

#endif /* RDK_LOGGER */

#define DEBUG_INI_NAME "/etc/debug.ini"

#if 0 /* TLS log macro definition */
#define TLS_LOG_FILE "/opt/logs/tlsError.log"
#define TLS_LOG_ERR  (1)
#define TLS_LOG_WARN (2)
#define TLS_LOG_INFO (3)
#define tls_debug_level (3)

#define TLSLOG(level, ...) do {  \
    FILE *fp_tls = fopen(TLS_LOG_FILE, "a"); \
    if ((fp_tls != NULL) && (level <= tls_debug_level)) { \
        if (level == TLS_LOG_ERR) { \
            fprintf(fp_tls,"ERROR: %s:%d:", __FILE__, __LINE__); \
        } else if (level == TLS_LOG_INFO) { \
            fprintf(fp_tls,"INFO: %s:%d:", __FILE__, __LINE__); \
        } else { \
            fprintf(fp_tls,"DBG: %s:%d:", __FILE__, __LINE__); \
        }\
        fprintf(fp_tls, __VA_ARGS__); \
        fprintf(fp_tls, "\n"); \
        fflush(fp_tls); \
        fclose(fp_tls); \
    } \
} while (0)
#endif

/**
 * @brief Initialize logging subsystem
 * 
 * When RDK_LOGGER defined: Initializes RDK Logger with /etc/debug.ini
 * When RDK_LOGGER not defined: No-op (returns success)
 * 
 * @return 0 on success, non-zero on failure
 */
int logger_init(void);

/**
 * @brief Cleanup logging subsystem
 * 
 * When RDK_LOGGER defined: Deinitializes RDK Logger
 * When RDK_LOGGER not defined: No-op
 */
void logger_exit(void);

/* 
 * Legacy API
 */
void logger_error(const char *fmt, ...);
void logger_warn(const char *fmt, ...);
void logger_info(const char *fmt, ...);

#endif /* LOGGER_H */
