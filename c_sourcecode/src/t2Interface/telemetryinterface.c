/**
 * @file telemetryinterface.c
 * @brief Telemetry interface functions for T2 event logging
 *
 * This file provides wrapper functions for T2 telemetry event logging system.
 * Functions are conditionally compiled based on T2_EVENT_ENABLED flag.
 */

#include "telemetryinterface.h"

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
void t2Init(const char *component) {
#ifdef T2_EVENT_ENABLED
    t2_init(component);
#endif
}

/**
 * @brief Uninitializes the T2 telemetry system
 *
 * @return void
 *
 * @note Requires T2_EVENT_ENABLED to be defined
 */
void t2Uninit(void){
#ifdef T2_EVENT_ENABLED
    t2_uninit();
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
void t2CountNotify(char *marker, int val) {
#ifdef T2_EVENT_ENABLED
    t2_event_d(marker, val);
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
void t2ValNotify( char *marker, char *val )
{
#ifdef T2_EVENT_ENABLED
    t2_event_s(marker, val);
#endif
}
