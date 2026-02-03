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
 * @file ratelimit_gmock.cpp
 * @brief Mock implementations for ratelimit test dependencies
 */

#include <cstdio>
#include <cstring>

// Mock logger functions for ratelimit tests
extern "C" {

int logger_init() {
    return 0;
}

void logger_exit() {
    // No-op
}

/**
 * Mock implementation of crashupload_log
 * 
 * This is the logging function used by crashupload components.
 * For unit tests, we provide a minimal mock that discards log messages.
 * 
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param msg Format string and variadic arguments
 */
void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...) {
    // Mock implementation - do nothing
    (void)level;
    (void)file;
    (void)line;
    (void)msg;
}

}
