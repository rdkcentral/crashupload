/**
 * @file main.c
 * @brief Main entry point for crashupload C implementation
 * 
 * Based on docs/migration/diagrams/flowcharts/optimizeduploadDumps-flowcharts.md
 * Implements optimized 7-step main flow with consolidated operations
 * 
 * SKELETON: Function bodies need implementation
 */

#include "../common/types.h"
#include "../common/constants.h"
#include "../common/errors.h"
#include "init/system_init.h"
#include "utils/prerequisites.h"
#include "utils/privacy.h"
#include "utils/lock_manager.h"
#include "scanner/scanner.h"
#include "core/archive_smart.h"
#include "core/upload_typeaware.h"
#include "core/ratelimit_unified.h"
#include "utils/cleanup_batch.h"
#include "utils/logger.h"
#include <signal.h>

static int lock_dir_prefix = 0;

void handle_signal(int no, siginfo_t* info, void* uc)
{
    printf("Raise SIGTERM signal.\nSystemd Terminating, Removing the script locks\n");
    if (lock_dir_prefix == 1) {
        unlink("/tmp/.uploadCoredumps");
	//dump file clean up is pending
    } else {
        unlink("/tmp/.uploadMinidumps");
	//dump file clean up is pending
    }
}
/**
 * @brief Main application entry point
 * 
 * Implements optimized 7-step flow:
 * 1. Consolidated initialization (parse + config + platform)
 * 2. Combined prerequisites check (network + time)
 * 3. Unified privacy check (opt-out + privacy mode)
 * 4. Lock acquisition
 * 5. Process dumps (scan, archive, upload, rate limit)
 * 6. Batch cleanup
 * 7. Shutdown
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char *argv[]) {
    config_t config;
    platform_config_t platform;
    int lock_fd = -1;
    int ret_sig = -1;
    int ret = EXIT_SUCCESS;
    char lock_file_path[32] = {0};
    char dump_extn_pattern[16] = {0};
    
    if (argc < 3) {
        printf("Number of parameter is less\n");
	exit(1);
    }
    if (1 == atoi(argv[2])) {
        lock_dir_prefix = 1;
	strcpy(lock_file_path, "/tmp/.uploadCoredumps");
    } else {
        lock_dir_prefix = 0;
	strcpy(lock_file_path, "/tmp/.uploadMinidumps");
    }
    struct sigaction rdkv_newaction;
    memset(&rdkv_newaction, '\0', sizeof(rdkv_newaction));
    rdkv_newaction.sa_sigaction = handle_signal;
    //rdkv_newaction.sa_flags = SA_ONSTACK | SA_SIGINFO; TODO: need to check why compile error
    rdkv_newaction.sa_flags = SA_SIGINFO;
    ret_sig = sigaction(SIGTERM, &rdkv_newaction, NULL);
    if (ret_sig == -1) {
        printf( "SIGTERM handler install fail\n");
    }else {
        printf( "SIGTERM handler install success\n");
    }
    /* Step 1: Consolidated Initialization */
    /* TODO: Implement consolidated initialization */
    if (system_initialize(argc, argv, &config, &platform) != SYSTEM_INIT_SUCCESS) {
        logger_error("System initialization failed:%d\n", lock_fd);
        return EXIT_FAILURE;
    }
    /* Step 2: Lock Acquisition */
    lock_fd = lock_acquire(lock_file_path, 5);
    if (lock_fd < LOCK_ACQUIRE_SUCCESS) {
        logger_error("Failed to acquire lock");
        return EXIT_FAILURE;
    }
    /* Step 2: Combined Prerequisites Check */
    /* TODO: Implement combined network + time check */
    if (prerequisites_wait(&config, PREREQUISITE_TIMEOUT_SEC) != PREREQUISITES_SUCCESS) {
        logger_error("Prerequisites check failed");
        lock_release(lock_fd);
        return EXIT_FAILURE;
    }
#if 0    
    /* Step 3: Unified Privacy Check */
    /* TODO: Implement unified privacy check */
    if (privacy_uploads_blocked(&config)) {
        logger_info("Uploads blocked by privacy settings");
        return EXIT_SUCCESS;  /* Not an error */
    }
#endif
    if (config.dump_type == DUMP_TYPE_MINIDUMP) {
            strcpy(dump_extn_pattern, "*.dmp*");
        } else if (config.dump_type == DUMP_TYPE_COREDUMP) {
            strcpy(dump_extn_pattern, "*core.prog*.gz*");
        } else {
            printf("Invalid Dump Type\n");
        }

    cleanup_batch(config.working_dir_path, dump_extn_pattern, ON_STARTUP_DUMPS_CLEANED_UP_BASE, argv[2], MAX_CORE_FILES);
    /* Step 5: Process Dumps */
    /* TODO: Implement dump processing loop */
    dump_file_t *dumps = NULL;
    int dump_count = 0;
    
    /* 5.1: Scan for dumps */
    if (scanner_find_dumps(config.working_dir_path, &dumps, &dump_count) <= 0) {
        logger_info("No dumps found or scan failed");
        goto cleanup;
    }
    printf("After scan dump found:%d\n", dump_count);
    /* 5.2: Process each dump */
    for (int i = 0; i < dump_count; i++) {
        printf("List of dump file=%s=======>\n", (dumps+i)->path);
	process_file_entry((dumps+i)->path, argv[2]);
        printf("List of dump file After process_file_entry=%s=======>\n", (dumps+i)->path);
    }
        /* Check unified rate limit */
#if 0    
        ratelimit_decision_t decision = ratelimit_check_unified(&dumps[i]);
        
        if (decision == RATELIMIT_BLOCK_RECOVERY) {
            logger_warn("Upload blocked: recovery mode active");
            break;
        }
        
        if (decision == RATELIMIT_BLOCK_LIMIT) {
            logger_warn("Upload blocked: rate limit exceeded");
            continue;
        }
        
        /* Create archive with smart compression */
        archive_info_t archive;
        if (archive_create_smart(&dumps[i], &platform, &archive) != ERR_SUCCESS) {
            logger_error("Archive creation failed for %s", dumps[i].filepath);
            continue;
        }
        
        /* Upload with type-aware handling */
        upload_result_t result = upload_file_type_aware(&archive, &dumps[i], &config);
        
        /* Handle result based on dump type */
        if (result == UPLOAD_SUCCESS || result == UPLOAD_FAILURE_REMOVE) {
            /* Remove original dump and archive */
            /* TODO: Implement file removal */
        } else if (result == UPLOAD_FAILURE_SAVE) {
            /* Save archive for later retry */
            /* TODO: Implement archive preservation */
        }
    }
    
    /* Step 6: Batch Cleanup */
    /* TODO: Implement batch cleanup of old files */
    cleanup_batch_old_files(&config, FILE_AGE_CLEANUP_DAYS);
    
#endif    
cleanup:
    /* Step 7: Shutdown */
    //if (dumps) {
    //    free(dumps);
    //}
    
    if (lock_fd >= 0) {
        lock_release(lock_fd);
    }
    return ret;
}
