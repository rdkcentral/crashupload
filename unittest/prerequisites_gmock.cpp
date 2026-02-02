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
 * @file prerequisites_gmock.cpp
 * @brief Mock implementations for prerequisites test dependencies
 */

#include <cstdio>
#include <cstring>
#include <cstdarg>

// Mock functions for prerequisites tests
extern "C" {

int logger_init() {
    return 0;
}

void logger_exit() {
    // No-op
}

/**
 * Mock implementation of crashupload_log
 */
void crashupload_log(unsigned int level, const char *file, int line, const char *msg, ...) {
    // Mock implementation - do nothing
    (void)level;
    (void)file;
    (void)line;
    (void)msg;
}

/**
 * Mock implementation of filePresentCheck
 * Returns 0 if file exists, 1 if not
 */
int filePresentCheck(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (fp) {
        fclose(fp);
        return 0;  // File exists
    }
    return 1;  // File does not exist
}

/**
 * Mock implementation of remove_pending_dumps
 */
void remove_pending_dumps(const char *dir, const char *pattern) {
    // Mock implementation - do nothing for tests
    (void)dir;
    (void)pattern;
}

}
