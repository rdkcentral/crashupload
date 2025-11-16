#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Get MAC address for a network interface
 * @param iface Interface name (e.g., "eth0", "erouter0")
 * @param mac Buffer to store MAC address
 * @param len Buffer length (minimum 18 for format with colons, 13 without)
 * @param colons true to include colons (AA:BB:CC:DD:EE:FF), false for AABBCCDDEEFF
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION with 60-second TTL caching for optimization
 */
int network_get_mac_address(const char *iface, char *mac, size_t len, bool colons);

/**
 * Get IP address for a network interface
 * @param iface Interface name (e.g., "eth0", "erouter0")
 * @param ip Buffer to store IP address
 * @param len Buffer length (minimum 16 for IPv4)
 * @return 0 on success, -1 on error
 * 
 * FULL IMPLEMENTATION
 */
int network_get_ip_address(const char *iface, char *ip, size_t len);

#endif /* NETWORK_UTILS_H */
