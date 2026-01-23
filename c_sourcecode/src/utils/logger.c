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
 * @file logger.c
 * SKELETON: Implementation needed
 */
#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initialize RDK Logger subsystem
 * 
 * This function MUST be called at application startup (in main).
 * 
 * When RDK_LOGGER is defined:
 *   - Option 1: Calls rdk_logger_init() with /etc/debug.ini (file-based config)
 *   - Option 2: Calls rdk_logger_ext_init() with programmatic config (extended API)
 *   - Enables runtime log level control
 * 
 * When RDK_LOGGER is NOT defined:
 *   - Simply logs that fallback mode is active
 *   - No external dependencies
 */
int logger_init() {
#if defined(RDK_LOGGER)

#if defined(USE_EXTENDED_LOGGER_INIT)
    /* Extended initialization with programmatic configuration */
    rdk_logger_ext_config_t config = {
        .pModuleName = "LOG.RDK.CRASHUPLOAD",     /* Module name */
        .loglevel = RDK_LOG_INFO,                 /* Default log level */
        .output = RDKLOG_OUTPUT_CONSOLE,          /* Output to console (stdout/stderr) */
        .format = RDKLOG_FORMAT_WITH_TS,          /* Timestamped format */
        .pFilePolicy = NULL                       /* Not using file output, so NULL */
    };
    
    if (rdk_logger_ext_init(&config) != RDK_SUCCESS) {
        printf("CRASHUPLOAD: ERROR - Extended logger init failed\n");
        return 1; // Return non-zero on failure
    }
#else
    /* Standard initialization with debug.ini file */
    printf("RDK logger standard init with %s\n", DEBUG_INI_NAME);
    if (rdk_logger_init(DEBUG_INI_NAME) != RDK_SUCCESS) {
        printf("CRASHUPLOAD: ERROR - Logger init failed\n");
        return 1; // Return non-zero on failure
    }
#endif

#else
    printf("CRASHUPLOAD: Using fallback logger\n");
#endif
    return 0; // Return 0 on success
}

/**
 * @brief Cleanup RDK Logger subsystem
 * 
 * This function MUST be called before application exit.
 * 
 * When RDK_LOGGER is defined:
 *   - Calls rdk_logger_deinit() to cleanup resources
 * 
 * When RDK_LOGGER is NOT defined:
 *   - No-op
 */
void logger_exit() {
#if defined(RDK_LOGGER)
    rdk_logger_deinit();
    printf("CRASHUPLOAD: RDK Logger cleaned up\n");
#else
    printf("CRASHUPLOAD: Fallback logger cleanup (no-op)\n");
#endif
}

#if !defined(RDK_LOGGER)
/**
 * @brief Fallback logging function when RDK Logger not available
 * 
 * This function is used when RDK_LOGGER is NOT defined.
 * It provides basic printf-style logging with file/line information.
 * 
 * @param level Log level (currently all treated as INFO)
 * @param file Source filename (__FILE__)
 * @param line Line number (__LINE__)
 * @param msg Format string (printf-style)
 * @param ... Variable arguments for format string
 */

 void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...) {
    va_list arg;
    char *pTempChar = NULL;
    int messageLen;

    /* Buffer size calculation */
    va_start(arg, msg);
    messageLen = vsnprintf(NULL, 0, msg, arg);
    va_end(arg);

    if (messageLen > 0) {
        messageLen++; /* Add space for null terminator */
        pTempChar = (char *)malloc(messageLen);
        
        if (pTempChar) {
            /* Format the message */
            va_start(arg, msg);
            int ret = vsnprintf(pTempChar, messageLen, msg, arg);
            va_end(arg);
            
            if (ret >= 0) {
                /* Print with file/line context */
                printf("[CRASHUPLOAD] %s:%d: %s\n", file, line, pTempChar);
                fflush(stdout);
            } else {
                perror("vsnprintf failed in crashupload_log");
            }
            
            free(pTempChar);
        } else {
            fprintf(stderr, "[CRASHUPLOAD] ERROR: malloc failed in crashupload_log\n");
        }
    }
 }


#endif

void logger_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
#if defined(RDK_LOGGER)
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CRASHUPLOAD", "%s", buffer);
#else
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
#endif
    va_end(args);
}

void logger_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
#if defined(RDK_LOGGER)
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    RDK_LOG(RDK_LOG_WARN, "LOG.RDK.CRASHUPLOAD", "%s", buffer);
#else
    fprintf(stderr, "[WARN] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    fflush(stderr);
#endif
    va_end(args);
}

void logger_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
#if defined(RDK_LOGGER)
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CRASHUPLOAD", "%s", buffer);
#else
    printf("[INFO] ");
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
#endif
    va_end(args);
}
