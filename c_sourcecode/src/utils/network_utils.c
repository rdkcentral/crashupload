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

#include "network_utils.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* MAC address cache with 60-second TTL for optimization */
static char cached_mac[18] = {0};
static char cached_iface[IFNAMSIZ] = {0};
static time_t cache_time = 0;
static const time_t CACHE_TTL = 60; /* 60 seconds as per optimization spec */

/**
 * FULL IMPLEMENTATION
 * Get MAC address with 60-second caching optimization
 * Uses ioctl() instead of system() calls for efficiency
 */
int network_get_mac_address(const char *iface, char *mac, size_t len, bool colons)
{
    if (!iface || !mac || len < (colons ? 18 : 13))
    {
        return -1;
    }

    time_t now = time(NULL);

    /* Check cache validity (60-second TTL) */
    if (cached_mac[0] != '\0' &&
        strcmp(cached_iface, iface) == 0 &&
        (now - cache_time) < CACHE_TTL)
    {
        /* Cache hit - return cached value */
        if (colons)
        {
            snprintf(mac, len, "%s", cached_mac);
        }
        else
        {
            /* Remove colons from cached MAC */
            int j = 0;
            for (int i = 0; cached_mac[i] != '\0' && j < (int)len - 1; i++)
            {
                if (cached_mac[i] != ':')
                {
                    mac[j++] = cached_mac[i];
                }
            }
            mac[j] = '\0';
        }
        return 0;
    }

    /* Cache miss - retrieve MAC address using ioctl */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(sock);
        return -1;
    }
    close(sock);

    unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    /* Store in cache with colons (canonical format) */
    snprintf(cached_mac, sizeof(cached_mac),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             hwaddr[0], hwaddr[1], hwaddr[2],
             hwaddr[3], hwaddr[4], hwaddr[5]);
    strncpy(cached_iface, iface, IFNAMSIZ - 1);
    cache_time = now;

    /* Return in requested format */
    if (colons)
    {
        snprintf(mac, len, "%s", cached_mac);
    }
    else
    {
        snprintf(mac, len, "%02X%02X%02X%02X%02X%02X",
                 hwaddr[0], hwaddr[1], hwaddr[2],
                 hwaddr[3], hwaddr[4], hwaddr[5]);
    }

    return 0;
}

/**
 * FULL IMPLEMENTATION
 * Get IP address using ioctl() for efficiency
 */
int network_get_ip_address(const char *iface, char *ip, size_t len)
{
    if (!iface || !ip || len < 16)
    {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        close(sock);
        return -1;
    }
    close(sock);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    const char *ip_str = inet_ntoa(addr->sin_addr);
    if (!ip_str)
    {
        return -1;
    }

    strncpy(ip, ip_str, len - 1);
    ip[len - 1] = '\0';

    return 0;
}
