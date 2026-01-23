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
 * @file telemetryinterface.c
 * @brief Telemetry interface functions for T2 event logging
 *
 * This file provides wrapper functions for T2 telemetry event logging system.
 * Functions are conditionally compiled based on T2_EVENT_ENABLED flag.
 */

#include "telemetryinterface.h"
#include <stdio.h>
#include "../utils/logger.h"

#ifdef T2_EVENT_ENABLED
#include <telemetry_busmessage_sender.h>
#endif

/**
 * @brief Initializes the T2 telemetry system
 *
 * @param[in] component Component name for telemetry initialization
 *
 * @return void
 *
 * @note Requires T2_EVENT_ENABLED to be defined
 */
void t2Init(char *component)
{
#ifdef T2_EVENT_ENABLED
    t2_init(component);
#else
    CRASHUPLOAD_INFO("[NOT IMPLEMENTED] T2 Telemetry Initialized for component: %s\n", component);
#endif
}

/**
 * @brief Uninitializes the T2 telemetry system
 *
 * @return void
 *
 * @note Requires T2_EVENT_ENABLED to be defined
 */
void t2Uninit(void)
{
#ifdef T2_EVENT_ENABLED
    t2_uninit();
#else
    CRASHUPLOAD_INFO("[NOT IMPLEMENTED] T2 Telemetry Uninitialized\n");
#endif
}

/**
 * @brief Sends a telemetry count/numeric event to T2 system
 *
 * @param[in] marker Telemetry marker name/identifier
 * @param[in] val    Integer value to be logged
 *
 * @return void
 *
 * @note Requires T2_EVENT_ENABLED to be defined
 */
void t2CountNotify(char *marker, int val)
{
#ifdef T2_EVENT_ENABLED
    t2_event_d(marker, val);
#else
    CRASHUPLOAD_INFO("[NOT IMPLEMENTED] T2 Telemetry Count Event Sent: Marker=%s, Value=%d\n", marker, val);
#endif
}

/**
 * @brief Sends a telemetry string event to T2 system
 *
 * @param[in] marker Telemetry marker name/identifier
 * @param[in] val    String value to be logged
 *
 * @return void
 *
 * @note Requires T2_EVENT_ENABLED to be defined
 */
void t2ValNotify(char *marker, char *val)
{
#ifdef T2_EVENT_ENABLED
    t2_event_s(marker, val);
#else
    CRASHUPLOAD_INFO("[NOT IMPLEMENTED] T2 Telemetry String Event Sent: Marker=%s, Value=%s\n", marker, val);
#endif
}
