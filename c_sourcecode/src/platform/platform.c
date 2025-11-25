/**
 * @file platform.c
 * SKELETON: Implementation needed
 */
#include "platform.h"
#include "../../common/errors.h"

/* function NormalizeMac - gets the eSTB MAC address of the device.

        Usage: size_t GetEstbMac <char *pEstbMac> <size_t szBufSize>

            pEstbMac - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 1.

            RETURN - number of characters copied to the output buffer.
*/
void NormalizeMac(char *mac, size_t size)
{
    if (mac == NULL || size == 0)
        return;

    size_t write_idx = 0;

    for (size_t read_idx = 0; mac[read_idx] != '\0' && read_idx < size; read_idx++)
    {
        char c = mac[read_idx];

        // Skip ':' characters
        if (c == ':')
            continue;

        // Convert lowercase alphabet to uppercase
        if (c >= 'a' && c <= 'z')
            c = c - ('a' - 'A');   // or use toupper(c)

        // Write character back, ensuring no overflow
        if (write_idx < size - 1) {
            mac[write_idx++] = c;
        }
    }

    // Null terminate
    mac[write_idx] = '\0';
}

/* function GetEstbMac - gets the eSTB MAC address of the device.

        Usage: size_t GetEstbMac <char *pEstbMac> <size_t szBufSize>

            pEstbMac - pointer to a char buffer to store the output string.

            szBufSize - the size of the character buffer in argument 1.

            RETURN - number of characters copied to the output buffer.
*/
size_t GetEstbMac( char *pEstbMac, size_t szBufSize )
{
    FILE *fp;
    size_t i = 0;
    char estb_interface[8] = {0};
    int ret = -1;
    bool read_from_hwinterface = false; // default value
    if( pEstbMac != NULL )
    {
        *pEstbMac = 0;
        if( (fp = fopen( MAC_FILE, "r" )) != NULL )
        {
            if (NULL != (fgets( pEstbMac, szBufSize, fp ))) {   // better be a valid string on first line
                i = stripinvalidchar( pEstbMac, szBufSize );
	    }
            fclose( fp );
            i = stripinvalidchar( pEstbMac, szBufSize );
            printf("GetEstbMac: After reading ESTB_MAC_FILE value=%s\n", pEstbMac);
            /* Below condition if ESTB_MAC_FILE file having empty data and pEstbMac does not have 17 character
            * including total mac address with : separate */
            if (pEstbMac[0] == '\0' || pEstbMac[0] == '\n' || i != MAC_ADDRESS_LEN)
            {
                printf("GetEstbMac: ESTB_MAC_FILE file is empty read_from_hwinterface is set to true\n");
                read_from_hwinterface = true;
            }
        }
        else
        {
            read_from_hwinterface = true;//ESTB_MAC_FILE file does not present proceed for reading from interface
            printf("GetEstbMac: read_from_hwinterface is set to true\n");
        }
        if (read_from_hwinterface == true)
        {
            printf("GetEstbMac: Reading from hw interface\n");
            ret = getDevicePropertyData("ESTB_INTERFACE", estb_interface, sizeof(estb_interface));
            if (ret == UTILS_SUCCESS)
            {
                i = GetHwMacAddress(estb_interface, pEstbMac, szBufSize);
                if(i)
                {
                    printf("GetEstbMac: Hardware address=%s=\n", pEstbMac);
                }
                else
                {
                    /* When there is no hw address available */
                    *pEstbMac = 0;
                    printf("GetEstbMac: GetHwMacAddress return fail\n");
                }
            }
            else
            {
                *pEstbMac = 0;
                i = 0;
		printf("GetEstbMac: Interface is not part of /etc/device.properties missing\n");
            }
        }
    }
    else
    {
        printf( "GetEstbMac: Error, input argument NULL\n" );
    }
    return i;
}

int platform_initialize(const config_t *config, platform_config_t *platform) {
    int ret = 0;

    memset(platform, 0, sizeof(platform_config_t));

    /* TODO: Get IP, device ID, SHA1 */
    ret = GetEstbMac(platform->mac_address, sizeof(platform->mac_address));
    if (ret) {
        NormalizeMac(platform->mac_address, sizeof(platform->mac_address));
	printf("Mac address is %s\n", platform->mac_address);
    }else {
        printf("Get mac is failed. Setting dafult value\n");
        strcpy(platform->mac_address,"000000000000");
    }
    //TODO: For brodband and extender we have change the code
    ret = GetModelNum( platform->model, sizeof(platform->model) );
    if (ret) {
        printf("Model Num=%s\n", platform->model);
    }else {
        printf("GetModel is failed. Setting dafult value\n");
        strcpy(platform->model,"UNKNOWN");
    }
    ret = file_get_sha1("/version.txt", platform->platform_sha1, sizeof(platform->platform_sha1));
    if (ret == 0) {
        printf("file sha=%s\n", platform->platform_sha1);
    } else {
        printf("file_get_sha1 error. Assign default value\n");
	strcpy(platform->platform_sha1,"000000000000000000000000000000000000000");
        printf("file sha=%s\n", platform->platform_sha1);
    }
    return PLATFORM_INIT_SUCCESS;
}
