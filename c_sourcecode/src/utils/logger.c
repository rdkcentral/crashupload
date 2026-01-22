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
 *   - Calls rdk_logger_init() with /etc/debug.ini
 *   - Enables runtime log level control
 * 
 * When RDK_LOGGER is NOT defined:
 *   - Simply logs that fallback mode is active
 *   - No external dependencies
 */
int logger_init() {
    printf("CRASHUPLOAD: Logger initialization starting...\n");
#if defined(RDK_LOGGER)
    printf("CRASHUPLOAD: RDK_LOGGER is DEFINED - using RDK Logger\n");
    printf("CRASHUPLOAD: Initializing RDK Logger with config: %s\n", DEBUG_INI_NAME);
    
    int ret = rdk_logger_init(DEBUG_INI_NAME);
    if (ret != 0) {
        fprintf(stderr, "CRASHUPLOAD: ERROR - rdk_logger_init() failed with return code: %d\n", ret);
        fprintf(stderr, "CRASHUPLOAD: Make sure %s exists and is properly configured\n", DEBUG_INI_NAME);
        fprintf(stderr, "CRASHUPLOAD: Example config:\n");
        fprintf(stderr, "  LOG.RDK.CRASHUPLOAD=INFO\n");
        fprintf(stderr, "  ENABLE_STDOUT=1\n");
        return 1; // Return non-zero on failure
    }
    
    printf("CRASHUPLOAD: RDK Logger initialized successfully\n");
    printf("CRASHUPLOAD: Testing RDK_LOG output...\n");
    
    // Test all log levels to verify they work
    RDK_LOG(RDK_LOG_FATAL, "LOG.RDK.CRASHUPLOAD", "TEST: FATAL level message\n");
    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CRASHUPLOAD", "TEST: ERROR level message\n");
    RDK_LOG(RDK_LOG_WARN, "LOG.RDK.CRASHUPLOAD", "TEST: WARN level message\n");
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CRASHUPLOAD", "TEST: INFO level message\n");
    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CRASHUPLOAD", "TEST: DEBUG level message\n");
    
    printf("CRASHUPLOAD: If you don't see RDK_LOG messages above, check:\n");
    printf("  1. /etc/debug.ini exists\n");
    printf("  2. LOG.RDK.CRASHUPLOAD=INFO (or DEBUG/TRACE1) is set\n");
    printf("  3. ENABLE_STDOUT=1 is set (for console output)\n");
    printf("  4. Log file location if ENABLE_LOGFILE=1\n");
#else
    printf("CRASHUPLOAD: RDK_LOGGER is NOT DEFINED - using fallback logger\n");
#endif
    printf("CRASHUPLOAD: Logger initialization complete\n");
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
    printf("CRASHUPLOAD: Logger cleanup\n");
#if defined(RDK_LOGGER)
    rdk_logger_deinit();
    printf("CRASHUPLOAD: RDK Logger cleaned up\n");
#else
    printf("CRASHUPLOAD: Fallback logger cleanup (no-op)\n");
#endif
    printf("CRASHUPLOAD: Logger cleanup complete\n");
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
