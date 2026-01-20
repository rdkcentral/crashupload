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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <limits.h>
#include "archive_crash.h"
#include <fcntl.h>
#include "file_utils.h"
#include "telemetryinterface.h"

#define MIN_FREE_SPACE_MB 50
#define MAX_FILE_TO_TAR 7

/* --------------------------------------------------------- */
/* Utility: set very low CPU priority (like nice -19)        */
/* --------------------------------------------------------- */
void set_low_priority(void)
{
    /* Best effort: failure is not fatal */
    (void)setpriority(PRIO_PROCESS, 0, 19);
}

#if 0
/* FULL IMPLEMENTATION - Check available disk space */
static long get_free_space_mb(const char *path) {
    struct statvfs stat;
    
    if (statvfs(path, &stat) != 0) {
        return -1;
    }
    
    /* Calculate free space in MB */
    unsigned long free_bytes = stat.f_bsize * stat.f_bavail;
    return (long)(free_bytes / (1024 * 1024));
}

/* FULL IMPLEMENTATION - Get directory from path */
static void get_dirname(const char *path, char *dir, size_t dir_size) {
    strncpy(dir, path, dir_size - 1);
    dir[dir_size - 1] = '\0';
    
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(dir, ".");
    }
}
#endif
/* --------------------------------------------------------- */
/* Add one file to archive                                   */
/* --------------------------------------------------------- */
static int archive_add_file(struct archive *a,
                            const char *path)
{
    struct archive_entry *entry = NULL;
    int fd = -1;
    struct stat st;
    char buf[1024];
    ssize_t r;
    int ret_result = -1;

    if (!a || !path)
        return ret_result;

    if (stat(path, &st) != 0)
        return ret_result;

    entry = archive_entry_new();
    if (!entry)
        return ret_result;
    
    printf("archive_add_file: path=%s size=%ld mtime=%ld\n",
           path, (long)st.st_size, (long)st.st_mtime);

    archive_entry_set_pathname(entry, path);
    archive_entry_set_size(entry, st.st_size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0777);
    archive_entry_set_mtime(entry, st.st_mtime, 0);
    archive_entry_set_atime(entry, st.st_atime, 0);
    archive_entry_set_ctime(entry, st.st_ctime, 0);

    printf("archive_add_file: writing header for %s\n", path);
    if (archive_write_header(a, entry) != ARCHIVE_OK)
        goto error;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto error;

    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        if (archive_write_data(a, buf, (size_t)r) < 0)
            goto error;
    }
    printf("archive_add_file: completed writing %s\n", path);
    ret_result = 0;

error:
    if (fd >= 0) close(fd);
    archive_entry_free(entry);
    return ret_result;
}

/* --------------------------------------------------------- */
/* Create tar.gz archive                                     */
/* --------------------------------------------------------- */
/*
 * Parameters:
 *   tar_name: output tar.gz
 *   files[] : list of input files
 *   count   : number of files
 */
static int create_tarball(bool setlow_priority, const char *tar_name,
                          char **files,
                          size_t count)
{
    struct archive *a = NULL;
    size_t i;
    int ret_result = -1;

    if (!tar_name || !files || count == 0)
        return ret_result;

    if (setlow_priority == true) {
	printf("Setting Low Priority\n");
        set_low_priority();
    }

    a = archive_write_new();
    if (!a)
        return ret_result;

    archive_write_add_filter_gzip(a);
    archive_write_set_format_pax_restricted(a);

    if (archive_write_open_filename(a, tar_name) != ARCHIVE_OK) {
	
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        if (is_regular_file(files[i])) {
            ret_result = archive_add_file(a, files[i]);
        }
    }
    //ret_result = 0;

cleanup:
    archive_write_close(a);
    archive_write_free(a);
    return ret_result;
}

int add_crashed_process_log_file(const config_t *config, const platform_config_t *platform,
                         char *filename, char *process_log_file, size_t size) {
    int ret = -1;
    char *tmp = NULL;
    char *log_file = NULL;
    int no_of_line_cp = 500;
    char mtime_date[64] = {0};

    if (!config || !platform || !filename || !process_log_file || size <= 0) {
        printf("add_crashed_process_log_file() Invalid argument\n");
	return ret;
    }
    if (config->build_type != BUILD_TYPE_PROD) {
        no_of_line_cp = 5000;
    }
    tmp = strchr(filename, '\n');
    if (tmp) {
        *tmp = '\0';
    }
    if (0 == file_get_mtime_formatted(filename, mtime_date, sizeof(mtime_date))) {
        printf("mtime of file:%s is %s\n", filename, mtime_date);
    } else {
        printf("mtime of file:%s is error\n", filename);
    }
    log_file = strrchr(filename, '/');
    if (log_file) {
	snprintf(process_log_file, size, "%s/mac%s_dat%s_box%s_mod%s_%s", config->working_dir_path, platform->mac_address, mtime_date, config->box_type, platform->model,log_file+1);
    } else {
	snprintf(process_log_file, size, "%s/mac%s_dat%s_box%s_mod%s_%s", config->working_dir_path, platform->mac_address, mtime_date, config->box_type, platform->model,filename);
    }
    printf("File copy from:%s=>%s\n", filename, process_log_file);
    ret = extract_tail(filename, process_log_file, no_of_line_cp);
    return ret;
}

int archive_create_smart(const dump_file_t *dump, const config_t *config,
                         const platform_config_t *platform,
                         archive_info_t *archive, char *new_dump_name) {
    
    char *tmp = NULL;
    char *arch_files_list[MAX_FILE_TO_TAR];
    char target_file_name[256] = {0};
    int i;
    char crash_url_file[32] = {0};
    int no_of_files = 3;
    int tar_status = -1;
    char process_name_log[256] = {0};
    int cnt_process_log_file = 0;
    FILE *fp = NULL;
    char buf[80] = {0};

    if (!dump || !config || !platform || !archive || !new_dump_name) {
	printf("archive_create_smart Invalid Argument\n");
        return -1;
    }

    const char *pattern = "<#=#>";
    const size_t pattern_len = 5;  // Length of "<#=#>"
    printf("archive_create_smart() Before process dump name=%s\n", new_dump_name);
    // Sanitize dump name to replace "<#=#>" with "_"
    while((tmp = strstr(new_dump_name, pattern)) != NULL) {
        printf("  -> Found '<#=#>' at position %ld\n", (long)(tmp - new_dump_name));
        *tmp = '_';
        strcpy(tmp + 1, tmp + pattern_len);
        printf("  -> Replaced with '_', shifted string\n"); 
    }
    printf("archive_create_smart() After process dump name=%s\n", new_dump_name);
    
    //char tmp1[512] = {0};
    //snprintf(tmp1, sizeof(tmp1), "%s/%s", config->working_dir_path, new_dump_name);
    //strcpy(new_dump_name, tmp1);
    printf("Rename dump name file->%s->%s\n", dump->path, new_dump_name);
    if (rename(dump->path, new_dump_name) != 0) {
        if (errno == EEXIST || errno == EACCES) {
            (void)unlink(new_dump_name);
            if (rename(dump->path, new_dump_name) != 0) {
                printf("Failed to rename %s -> %s : %s", dump->path, new_dump_name, strerror(errno));
                return -1;
            }else {
                printf("Renamed After retry %s -> %s\n", dump->path, new_dump_name);
            }
        } else {
            printf("Failed to rename %s -> %s : %s\n", dump->path, new_dump_name, strerror(errno));
            return -1;
        }
    } else {
        printf("Renamed %s -> %s\n", dump->path, new_dump_name);
    }
    uint64_t size_dump_u64 = 0;
    if ( 0 == (file_get_size(new_dump_name, &size_dump_u64))) {
        printf("Size of the file:%llu\n", (unsigned long long)size_dump_u64);
    }

    if (config->t2_enabled && size_dump_u64 == 0) {
        t2CountNotify("SYST_ERR_MINIDPZEROSIZE", 1);
    }

    for (i = 0; i < MAX_FILE_TO_TAR; i++) {
        arch_files_list[i] = malloc(256);
    }
    if (config->dump_type == DUMP_TYPE_COREDUMP) {
        snprintf(target_file_name, sizeof(target_file_name), "%s.core.tgz", new_dump_name);
        snprintf(arch_files_list[0], 256, "%s", new_dump_name);
	snprintf(arch_files_list[1], 256, "%s", "/version.txt");
	snprintf(arch_files_list[2], 256, "%s", config->core_log_file);
	//snprintf(arch_files_list[3], 256, "%s", crash_url_file);
	printf("Before core dump tar list of file name:%s\n", target_file_name);
	printf("dump file=%s\n",arch_files_list[0]);
	printf("version file=%s\n", arch_files_list[1]);
	printf("core log file=%s\n", arch_files_list[2]);
	//printf("crash url file=%s\n", arch_files_list[3]);
       if(0 == (filePresentCheck("/tmp/set_crash_reboot_flag"))) {
           printf("Compression without nice\n");
           tar_status = create_tarball(false, target_file_name, arch_files_list, no_of_files);

       } else {
           printf("Compression with nice\n");
           tar_status = create_tarball(true, target_file_name, arch_files_list, no_of_files);
       }
   } else {
       printf("Inside minidump==============>\n");
       snprintf(target_file_name, sizeof(target_file_name), "%s.tgz", new_dump_name);
       if (config->device_type == DEVICE_TYPE_MEDIACLIENT) {
	   snprintf(arch_files_list[0], 256, "%s", new_dump_name);
	   snprintf(arch_files_list[1], 256, "%s", "/version.txt");
	   snprintf(arch_files_list[2], 256, "%s", config->core_log_file);
	   snprintf(crash_url_file, sizeof(crash_url_file),"%s/%s", config->log_path, "crashed_url.txt");
           if (0 == (filePresentCheck(crash_url_file))) { //TODO: Add logic if file has data
	       //files="$VERSION_FILE $CORE_LOG $crashedUrlFile"
               //add_crashed_log_file $files		    
               //nice -n 19 tar -zcvf $tgzFile $dumpName $files 2>&1 | logStdout
	       snprintf(arch_files_list[no_of_files], 256, "%s", crash_url_file);
	       printf("crash url file=%s\n", arch_files_list[no_of_files]);
	       no_of_files++;
	   }
	   fp = fopen(LOG_FILES_PATH, "r");
	   if (fp != NULL) {
		   while(fgets(buf, sizeof(buf), fp)) {
		       if (cnt_process_log_file == 3) {
			   printf("Reached Max number of process log file\n");//TODO: This is logic not present in script. Need review
		           break;
		       }
		       //TODO: More optimization required. Insted copy last 5000 line copy we can do byte copy. 
	               if (!add_crashed_process_log_file(config, platform, buf, process_name_log, sizeof(process_name_log))) {
		           snprintf(arch_files_list[no_of_files], 256, "%s", process_name_log);
                           printf("process log file=%s\n", arch_files_list[no_of_files]);
	                   no_of_files++;
			   cnt_process_log_file++;
	               } else {
			   printf("Error to add add_crashed_process_log_file():%s\n", buf);
	               }
		   }
		   unlink(LOG_FILES_PATH);
	   } else {
	          printf("Error in opening file:%s\n",LOG_FILES_PATH);
	   }
	   /*if (!add_crashed_process_log_file(config, platform, process_log, sizeof(process_log))) {
	   } else {
	   }
	   snprintf(process_log, sizeof(process_log), "mac%s_dat%s_box%s_mod%s_%s", platform->mac_address,dumps->mtime_date, config.box_type, platform.model,dump_file_name)
	   if (config->build_type == BUILD_TYPE_PROD) {
	       extract_tail(LOG_FILES_PATH,,500);
	   } else {
	       extract_tail(LOG_FILES_PATH,,5000);
	   }*/
	   printf("Before tar list of file name:%s\n", target_file_name);
	   printf("dump file=%s\n",arch_files_list[0]);
	   printf("version file=%s\n", arch_files_list[1]);
	   printf("core log file=%s\n", arch_files_list[2]);
	   tar_status = create_tarball(true, target_file_name, arch_files_list, no_of_files);
       }
   }
   if (!tar_status) {
       snprintf(archive->archive_name,sizeof(archive->archive_name),"%s", target_file_name);
       printf("Success Compressing the files,%s\n", archive->archive_name);
       printf("dump file=%s\n",arch_files_list[0]);
       printf("version file=%s\n", arch_files_list[1]);
       printf("core log file=%s\n", arch_files_list[2]);
   } else {
       printf("TAR creation failed try by coping to /tmp\n");
	    //TODO:Copy all the file to /tmp and try tar again. This is fall back
        if (config->t2_enabled) {
            t2ValNotify("SYST_WARN_CompFail", target_file_name);
        }
    }
   if (0 == (filePresentCheck(arch_files_list[0]))) {
       unlink(arch_files_list[0]);
   }
   while (cnt_process_log_file != 0 && cnt_process_log_file <= no_of_files) {
       if (0 == (filePresentCheck(arch_files_list[no_of_files - cnt_process_log_file]))) {
	  unlink(arch_files_list[no_of_files - cnt_process_log_file]);
       }
       cnt_process_log_file--;
   }
   for (i = 0; i < MAX_FILE_TO_TAR; i++) {
       free(arch_files_list[i]);
   }
   return tar_status;
}
#if 0
/* FULL IMPLEMENTATION - Smart compression with optimization:
 * Try direct compression first, fallback to /tmp if space issues */
int archive_create(const char *input, const char *output) {
    if (!input || !output) {
        return -1;
    }
    
    /* Check if input file exists */
    struct stat st;
    if (stat(input, &st) != 0) {
        fprintf(stderr, "Input file does not exist: %s\n", input);
        return -1;
    }
    
    char output_dir[PATH_MAX];
    get_dirname(output, output_dir, sizeof(output_dir));
    
    /* Optimization: Try direct compression first */
    long free_space = get_free_space_mb(output_dir);
    
    if (free_space >= MIN_FREE_SPACE_MB) {
        /* Sufficient space - compress directly to target */
        printf("Archive: Direct compression to %s\n", output);
        if (execute_tar(input, output) == 0) {
            return 0;
        }
        fprintf(stderr, "Direct compression failed, trying /tmp fallback\n");
    } else {
        printf("Archive: Insufficient space (%ld MB), using /tmp fallback\n", free_space);
    }
    
    /* Optimization: Fallback to /tmp if direct compression failed or no space */
    char tmp_output[PATH_MAX];
    snprintf(tmp_output, sizeof(tmp_output), "/tmp/dump_%d.tgz", getpid());
    
    long tmp_free = get_free_space_mb("/tmp");
    if (tmp_free < MIN_FREE_SPACE_MB) {
        fprintf(stderr, "Insufficient space in /tmp (%ld MB)\n", tmp_free);
        return -1;
    }
    
    printf("Archive: Compressing to /tmp, then moving to %s\n", output);
    if (execute_tar(input, tmp_output) != 0) {
        fprintf(stderr, "Compression to /tmp failed\n");
        return -1;
    }
    
    /* Move from /tmp to final destination */
    if (rename(tmp_output, output) != 0) {
        fprintf(stderr, "Failed to move archive: %s\n", strerror(errno));
        unlink(tmp_output);
        return -1;
    }
    
    return 0;
}

/* FULL IMPLEMENTATION - Generate archive filename with platform info */
int archive_generate_filename(const char *dump_path, const char *mac, 
                              const char *model, const char *sha1,
                              char *output, size_t output_size) {
    if (!dump_path || !mac || !model || !output) {
        return -1;
    }
    
    /* Extract base filename */
    const char *basename = strrchr(dump_path, '/');
    if (basename) {
        basename++;
    } else {
        basename = dump_path;
    }
    
    /* Get current timestamp */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H-%M-%S", tm);
    
    /* Format: SHA1_macMAC_datTIMESTAMP_boxTYPE_modMODEL_basename.tgz
     * Optimization: Limit length to avoid ecryptfs 135-char filename limit */
    char safe_mac[32];
    strncpy(safe_mac, mac, sizeof(safe_mac) - 1);
    safe_mac[sizeof(safe_mac) - 1] = '\0';
    
    /* Remove colons from MAC */
    char *p = safe_mac;
    char *q = safe_mac;
    while (*p) {
        if (*p != ':') {
            *q++ = *p;
        }
        p++;
    }
    *q = '\0';
    
    /* Build filename */
    snprintf(output, output_size, "%s_mac%s_dat%s_mod%s_%s.tgz",
             sha1 ? sha1 : "unknown",
             safe_mac,
             timestamp,
             model ? model : "unknown",
             basename);
    
    /* Truncate if too long (ecryptfs limit: 135 chars) */
    if (strlen(output) > 135) {
        output[135] = '\0';
        /* Ensure .tgz extension */
        strcpy(output + 131, ".tgz");
    }
    
    return 0;
}
#endif
