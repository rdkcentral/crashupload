/**
 * @file telemetryinterface.c
 * @brief Telemetry interface functions for T2 event logging
 *
 * This file provides wrapper functions for T2 telemetry event logging system.
 * Functions are conditionally compiled based on T2_EVENT_ENABLED flag.
 */

#include "telemetryinterface.h"

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
