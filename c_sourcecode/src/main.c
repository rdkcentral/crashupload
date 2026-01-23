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
#include "archive/archive_crash.h"
#include "utils/cleanup_batch.h"
#include "utils/logger.h"
#include <signal.h>
#include "file_utils.h"
#include "ratelimit.h"
#include "systemutils.h"
#include "upload.h"
#include "t2Interface/telemetryinterface.h"

int lock_dir_prefix = 0;

void handle_signal(int no, siginfo_t* info, void* uc)
{
    printf("Raise SIGTERM signal.\nSystemd Terminating, Removing the script locks\n");
    if (lock_dir_prefix == 1) {
        unlink(COREDUMP_LOCK_FILE);
	//dump file clean up is pending
    } else {
        unlink(MINIDUMP_LOCK_FILE);
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
#ifndef GTEST_ENABLE
int main(int argc, char *argv[]) {
#else
int main_test(int argc, char *argv[]) {
#endif
    /* Print build configuration */
    printf("========================================\n");
    printf("CRASHUPLOAD - Build Configuration\n");
    printf("========================================\n");
#if defined(RDK_LOGGER)
    printf("RDK_LOGGER: ENABLED\n");
#else
    printf("RDK_LOGGER: DISABLED (using fallback)\n");
#endif
    printf("========================================\n");
    
    /* Initialize the logger - continue even if RDK Logger init fails (will use fallback) */
    if (logger_init() != 0) {
        printf("WARNING: RDK Logger initialization failed, using fallback logger\n");
    }

    config_t config;
    platform_config_t platform;
    int lock_fd = -1;
    int ret_sig = -1;
    int ret = 0;
    char lock_file_path[32] = {0};
    char dump_extn_pattern[16] = {0};
    char mtime_date[64] = {0};
    int len = 0;
    char crashts[64] = {0};
    char new_dump_name[1024] = {0};
    char trim_dump_name[1024] = {0};
    char dump_file_name[512] = {0};
    char *tmp = NULL;
    bool is_process_dmp_file = false;
    archive_info_t *archive = NULL;
    char time_stamp_file_name[64] = {0};
    
    if (argc < 3) {
        CRASHUPLOAD_ERROR("Number of parameter is less\n");
        logger_exit();
#ifndef GTEST_ENABLE
	exit(1);
#else
	return 1;
#endif
    }
    if (1 == atoi(argv[2])) {
        lock_dir_prefix = 1;
	    strcpy(lock_file_path, COREDUMP_LOCK_FILE);
    } else {
        lock_dir_prefix = 0;
	    strcpy(lock_file_path, MINIDUMP_LOCK_FILE);
    }
    struct sigaction rdkv_newaction;
    memset(&rdkv_newaction, '\0', sizeof(rdkv_newaction));
    rdkv_newaction.sa_sigaction = handle_signal;
    //rdkv_newaction.sa_flags = SA_ONSTACK | SA_SIGINFO; TODO: need to check why compile error
    rdkv_newaction.sa_flags = SA_SIGINFO;
    ret_sig = sigaction(SIGTERM, &rdkv_newaction, NULL);
    if (ret_sig == -1) {
        CRASHUPLOAD_ERROR("SIGTERM handler install fail\n");
    }else {
        CRASHUPLOAD_INFO("SIGTERM handler install success\n");
    }
    /* Step 1: Consolidated Initialization */
    /* TODO: Implement consolidated initialization */
    if (system_initialize(argc, argv, &config, &platform) != SYSTEM_INIT_SUCCESS) {
        CRASHUPLOAD_ERROR("System initialization failed:%d\n", lock_fd);
        printf("Failed system_initialize\n");
        t2Uninit();
        logger_exit();
#ifndef GTEST_ENABLE
        exit(1);
#else
	return 1;
#endif
    }
    /* Step 2: Lock Acquisition */
    int lock_sec = (config.lock_mode == LOCK_MODE_WAIT) ? 5 : 0;
    lock_fd = lock_acquire(lock_file_path, lock_sec, config.t2_enabled);
    if (lock_fd < LOCK_ACQUIRE_SUCCESS) {
        CRASHUPLOAD_ERROR("Failed to acquire lock");
        printf("Failed to acquire lock\n");
        t2Uninit();
        logger_exit();
#ifndef GTEST_ENABLE
        exit(0);
#else
	return 0;
#endif
    }
    /* Step 2: Combined Prerequisites Check */
    /* TODO: Implement combined network + time check */
    if (prerequisites_wait(&config, PREREQUISITE_TIMEOUT_SEC) != PREREQUISITES_SUCCESS) {
        CRASHUPLOAD_ERROR("Prerequisites check failed");
        printf("Prerequisites check failed\n");
        //lock_release(lock_fd, lock_file_path);
        goto cleanup;
        //return EXIT_FAILURE;
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
	        strcpy(time_stamp_file_name, "/tmp/.minidump_upload_timestamps");
        } else if (config.dump_type == DUMP_TYPE_COREDUMP) {
            strcpy(dump_extn_pattern, "*core.prog*.gz*");
	        strcpy(time_stamp_file_name, "/tmp/.coredump_upload_timestamps");
        } else {
	        strcpy(time_stamp_file_name, "/tmp/.minidump_upload_timestamps");
            CRASHUPLOAD_ERROR("Invalid Dump Type\n");
        }

    cleanup_batch(config.working_dir_path, dump_extn_pattern, ON_STARTUP_DUMPS_CLEANED_UP_BASE, argv[2], MAX_CORE_FILES);
    
    /* Step 5: Process Dumps */
    /* TODO: Implement dump processing loop */
    dump_file_t *dumps = NULL;
    int dump_count = 0;
    if (0 != (chdir(config.working_dir_path))) {
        CRASHUPLOAD_ERROR("Error in change dir:%s\n",config.working_dir_path);
	    goto cleanup;
    } else {
        CRASHUPLOAD_INFO("Successfully change dir to %s\n", config.working_dir_path);
        printf("Successfully change dir to %s\n", config.working_dir_path);
    }

    /* 5.1: Scan for dumps */
    if (scanner_find_dumps(".", &dumps, &dump_count, dump_extn_pattern) <= 0) {
        CRASHUPLOAD_INFO("No dumps found or scan failed");
        goto cleanup;
    }
    printf("After scan dump found:%d\n", dump_count);
    archive = malloc(dump_count*sizeof(archive_info_t));
    if (archive == NULL) {
        CRASHUPLOAD_ERROR("Error to allocate memory for archive\n");
	    ret = 1;
	    goto cleanup;
    }

    memset(archive, '\0',dump_count * sizeof(archive));
    /* 5.2: Process each dump */
    for (int i = 0; i < dump_count; i++) {
        CRASHUPLOAD_INFO("** Processing dump: %s", (dumps+i)->path);
        printf("List of dump file=%s=======>\n", (dumps+i)->path);
	    process_file_entry((dumps+i)->path, argv[2], &config);
        printf("List of dump file After process_file_entry=%s=======>\n", (dumps+i)->path);
	    len = strlen((dumps+i)->path);
	    if (len > 4 && strcmp((dumps+i)->path + len - 4, ".tgz") == 0) {
            printf("Skip archiving %s as it is a tarball already.\n", (dumps+i)->path);
            snprintf((archive+i)->archive_name, sizeof((archive+i)->archive_name), "%s", (dumps+i)->path);
            printf("Skip archiving %s as it is a tarball already.\n", (archive+i)->archive_name);
            continue;
	    }
        if (0 == file_get_mtime_formatted((dumps+i)->path, mtime_date, sizeof(mtime_date))) {
	    printf("mtime ============> %s\n", mtime_date);
	    strncpy((dumps+i)->mtime_date, mtime_date, sizeof((dumps+i)->mtime_date));
	    (dumps+i)->mtime_date[sizeof((dumps+i)->mtime_date)-1] = '\0';
	    memset(mtime_date, '\0', sizeof(mtime_date));
	    printf("mtime of file:%s:is:%s\n",(dumps+i)->path, (dumps+i)->mtime_date);
	} else {
	    printf("file_get_mtime_formatted() return fail\n");
	}
	get_crash_timestamp_utc(crashts, sizeof(crashts));
	printf("crashts=%s\n", crashts);
	tmp = strrchr((dumps+i)->path, '/');
	if (tmp != NULL) {
	    snprintf(dump_file_name, sizeof(dump_file_name), "%s", tmp+1);
	} else {
	    snprintf(dump_file_name, sizeof(dump_file_name), "%s", (dumps+i)->path);
	}
	is_process_dmp_file = check_process_dmp_file(dump_file_name);
	if (is_process_dmp_file == false) {
            if (config.dump_type == DUMP_TYPE_COREDUMP) {
	        if (NULL != (strstr((dumps+i)->path,"mpeos-main"))) {
	            snprintf(new_dump_name, sizeof(new_dump_name), "%s_mac%s_dat%s_box%s_mod%s_%s", platform.platform_sha1, platform.mac_address,(dumps+i)->mtime_date, config.box_type, platform.model,dump_file_name);
		    printf("new dump name crated for mpeos-main=%s\n", new_dump_name);
	        } else {
	            snprintf(new_dump_name, sizeof(new_dump_name), "%s_mac%s_dat%s_box%s_mod%s_%s", platform.platform_sha1, platform.mac_address,crashts, config.box_type, platform.model,dump_file_name);
		    printf("new dump name crated for core dump=%s\n", new_dump_name);
	        }
	    } else {
	        snprintf(new_dump_name, sizeof(new_dump_name), "%s_mac%s_dat%s_box%s_mod%s_%s", platform.platform_sha1, platform.mac_address,crashts, config.box_type, platform.model,dump_file_name);
		printf("new dump name crated for mini dump=%s\n", new_dump_name);
	    }
	} else {
	    printf("Core name is already processed.%s\n", dump_file_name);
	    strncpy(new_dump_name, dump_file_name, sizeof(new_dump_name));
	    new_dump_name[sizeof(new_dump_name)-1] = '\0';
	    printf("Core name is already processed.%s\n", new_dump_name);
	}
	if (strlen(new_dump_name) >= 135) {
	    tmp = strchr(new_dump_name, '_');
	    if (tmp != NULL) {
	        snprintf(new_dump_name, sizeof(new_dump_name), "%s", tmp+1);
		printf("After stripping dump file=%s\n", new_dump_name);
	    }
	}
	if (strlen(new_dump_name) >= 135) {
	    printf("The file name is still greater than 135 charecters try trimming the processname to 20 chars from the filename\n");
	    printf("The Current File Name :%s\n", new_dump_name);
	    char *pname = extract_pname(new_dump_name);
            if (!pname) {
	        printf("process name not found to do trim\n");
	    } else {
	        printf("Change the process name process name length to 20 byte-%s\n", pname);
	        trim_process_name_in_path(new_dump_name,pname,20,trim_dump_name, sizeof(trim_dump_name));
	        printf("Changed File Name : %s\n", trim_dump_name);
		    strncpy(new_dump_name, trim_dump_name, sizeof(new_dump_name));
	    }
	}
	    printf("Processing for TAR:%s\n",new_dump_name);
        /* Create archive with smart compression */
        if (archive_create_smart(&dumps[i], &config, &platform, &archive[i], new_dump_name) != ARCHIVE_SUCCESS) {
            logger_error("Archive creation failed for %s", dumps[i].path);
            continue;
        }
    }
    if (true == is_box_rebooting(config.t2_enabled)) {
        printf("Box is rebooting, skip upload process\n");
	ret = 0;
        goto cleanup;
    }
        /* Check unified rate limit */
    if (RATELIMIT_BLOCK == ratelimit_check_unified(config.dump_type)) {
        printf("Rate Limit is blocked. Exit\n");
	remove_pending_dumps(config.working_dir_path, dump_extn_pattern);
	goto cleanup;
    }
    for (int i = 0; i < dump_count; i++) {
        if (strstr(archive[i].archive_name,"_core")) {
            printf("Coredump File :%s\n",archive[i].archive_name);
        }
	ret = upload_process(&archive[i], &config, &platform);
	printf("upload_process return ret=%d\n", ret);
	if (ret != 0) {
	    break;
	}
    }
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
    cleanup_batch(config.working_dir_path, dump_extn_pattern, ON_STARTUP_DUMPS_CLEANED_UP_BASE, argv[2], MAX_CORE_FILES);
    if (lock_fd >= 0) {
        lock_release(lock_fd, lock_file_path);
    }
    /* Uninitialize telemetry */
    t2Uninit();
    logger_exit();

#ifndef GTEST_ENABLE
    exit(ret);
#else
    return ret;
#endif
}
