#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool is_box_rebooting(bool t2_enabled);
/**
 * Get system uptime in seconds
 * Uses sysinfo() with fallback to /proc/uptime
 * @param uptime_seconds Pointer to store uptime
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with fallback mechanism
 */
int system_get_uptime(uint64_t *uptime_seconds);

/**
 * Get device model number
 * @param model Buffer to store model
 * @param len Buffer length
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with indefinite caching and multiple fallbacks
 */
int system_get_model(char *model, size_t len);

/**
 * Check if a process is running by name
 * @param name Process name to search for
 * @param is_running Pointer to store result (true if running)
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION using /proc scan (no ps command)
 */
int system_check_process(const char *name, bool *is_running);

/**
 * Execute system reboot
 * @return 0 on success, -1 on error
 * 
 * SKELETON - calls system() for now
 */
int system_reboot(void);

#endif /* SYSTEM_UTILS_H */
