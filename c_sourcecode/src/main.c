/* FULL IMPLEMENTATION - Main application with optimized 7-step flow */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "config.h"
#include "platform.h"
#include "scanner.h"
#include "archive.h"
#include "upload.h"
#include "ratelimit.h"

/* Did not get exact implementation, added hardcoded value */
#define UPLOAD_URL "https://crashupload.example.com/upload"

int main(int argc, char *argv[]) {
    printf("=== Crash Upload Utility (C Implementation) ===\n");
    printf("Optimized implementation based on updateduploadDumps-hld.md\n\n");

    /* Step 1: Consolidated Initialization (optimization: 3→2 calls) */
    printf("Step 1: Consolidated Initialization\n");
    
    config_t config;
    if (config_init(&config) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize configuration\n");
        return 1;
    }
    printf("  ✓ Configuration loaded\n");
    printf("    - CORE_PATH: %s\n", config.core_path);
    printf("    - MINIDUMP_PATH: %s\n", config.minidump_path);
    printf("    - T2 Telemetry: %s\n", config.t2_enabled ? "enabled" : "disabled");

    platform_config_t platform;
    if (platform_init(&platform) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize platform\n");
        config_cleanup(&config);
        return 1;
    }
    printf("  ✓ Platform initialized\n");
    printf("    - MAC: %s\n", platform.mac_address);
    printf("    - IP: %s\n", platform.ip_address);
    printf("    - Model: %s\n", platform.model);
    printf("    - Type: %s\n", platform_get_type_string(platform.type));
    printf("    - Firmware SHA1: %.10s...\n", platform.firmware_sha1);

    /* Step 2: Combined Prerequisites (optimization: network + time sync) */
    printf("\nStep 2: Combined Prerequisites Check\n");
    if (platform_check_prerequisites(&platform) != 0) {
        fprintf(stderr, "ERROR: Prerequisites not met\n");
        platform_cleanup(&platform);
        config_cleanup(&config);
        return 1;
    }
    printf("  ✓ Prerequisites met (SKELETON)\n");

    /* Step 3: Unified Privacy Check (optimization: opt-out + privacy mode) */
    printf("\nStep 3: Unified Privacy Check\n");
    bool privacy_enabled = false;
    if (platform_check_privacy(&platform, &privacy_enabled) == 0) {
        if (privacy_enabled) {
            printf("  ! Privacy mode enabled - uploads disabled\n");
            platform_cleanup(&platform);
            config_cleanup(&config);
            return 0;
        }
        printf("  ✓ Privacy check passed (SKELETON)\n");
    }

    /* Step 4: Scan for Dump Files (FULL IMPLEMENTATION) */
    printf("\nStep 4: Scan for Dump Files\n");
    dump_file_t *dumps = NULL;
    int dump_count = 0;
    
    if (scanner_find_dumps(config.core_path, &dumps, &dump_count) < 0) {
        fprintf(stderr, "ERROR: Failed to scan for dumps\n");
        platform_cleanup(&platform);
        config_cleanup(&config);
        return 1;
    }
    
    printf("  ✓ Found %d dump file(s) in %s\n", dump_count, config.core_path);
    
    if (dump_count == 0) {
        printf("  → No dumps to upload\n");
        scanner_cleanup();
        platform_cleanup(&platform);
        config_cleanup(&config);
        return 0;
    }
    
    /* Sort dumps oldest first */
    scanner_get_sorted_dumps(&dumps, &dump_count);
    
    for (int i = 0; i < dump_count; i++) {
        printf("    [%d] %s (%ld bytes, %s)\n", 
               i + 1, dumps[i].path, (long)dumps[i].size,
               dumps[i].is_minidump ? "minidump" : "coredump");
    }

    /* Step 5: Process Each Dump */
    int uploaded_count = 0;
    int failed_count = 0;
    
    for (int i = 0; i < dump_count; i++) {
        printf("\n=== Processing dump %d/%d ===\n", i + 1, dump_count);
        
        /* Step 5a: Unified Rate Limiting (optimization: recovery + 10/10min check) */
        printf("Step 5a: Rate Limit Check\n");
        if (ratelimit_check() != 0) {
            printf("  ! Rate limit exceeded, skipping remaining dumps\n");
            failed_count = dump_count - i;
            break;
        }
        printf("  ✓ Rate limit OK (%d/10 uploads in window)\n", ratelimit_get_count());
        
        /* Step 5b: Smart Compression (FULL IMPLEMENTATION) */
        printf("\nStep 5b: Smart Compression\n");
        char archive_name[PATH_MAX];
        if (archive_generate_filename(dumps[i].path, platform.mac_address,
                                     platform.model, platform.firmware_sha1,
                                     archive_name, sizeof(archive_name)) != 0) {
            fprintf(stderr, "ERROR: Failed to generate archive filename\n");
            failed_count++;
            continue;
        }
        
        char archive_path[PATH_MAX];
        snprintf(archive_path, sizeof(archive_path), "/tmp/%s", archive_name);
        
        if (archive_create(dumps[i].path, archive_path) != 0) {
            fprintf(stderr, "ERROR: Failed to create archive\n");
            failed_count++;
            continue;
        }
        printf("  ✓ Archive created: %s\n", archive_path);
        
        /* Step 5c: Type-Aware Upload (FULL IMPLEMENTATION) */
        printf("\nStep 5c: Type-Aware Upload\n");
        int upload_result;
        if (dumps[i].is_minidump) {
            upload_result = upload_minidump(archive_path, UPLOAD_URL);
        } else {
            upload_result = upload_coredump(archive_path, UPLOAD_URL);
        }
        
        if (upload_result == 0) {
            printf("  ✓ Upload successful\n");
            ratelimit_record_upload();
            uploaded_count++;
            
            /* Cleanup uploaded files */
            unlink(archive_path);
            unlink(dumps[i].path);
            printf("  ✓ Cleaned up dump and archive\n");
        } else {
            fprintf(stderr, "ERROR: Upload failed\n");
            unlink(archive_path);  /* Clean up archive even if upload failed */
            failed_count++;
        }
    }

    /* Step 6: Summary */
    printf("\n=== Upload Summary ===\n");
    printf("Total dumps found: %d\n", dump_count);
    printf("Successfully uploaded: %d\n", uploaded_count);
    printf("Failed: %d\n", failed_count);
    printf("Rate limit status: %d/10 uploads in window\n", ratelimit_get_count());
    if (ratelimit_is_recovery_mode()) {
        printf("WARNING: System in recovery mode (crashloop detected)\n");
    }

    scanner_cleanup();
    platform_cleanup(&platform);
    config_cleanup(&config);
    
    return (failed_count == 0) ? 0 : 1;
}
