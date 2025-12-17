/* FULL IMPLEMENTATION - Archive creator with smart compression */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <limits.h>
#include "archive.h"
#include <fcntl.h>
#include "file_utils.h"

#define MIN_FREE_SPACE_MB 50

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

    archive_entry_set_pathname(entry, path);
    archive_entry_set_size(entry, st.st_size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0777);

    if (archive_write_header(a, entry) != ARCHIVE_OK)
        goto error;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto error;

    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        if (archive_write_data(a, buf, (size_t)r) < 0)
            goto error;
    }
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
int archive_create_smart(const dump_file_t *dump, const config_t *config,
                         const platform_config_t *platform,
                         archive_info_t *archive, char *new_dump_name) {
    
    char *tmp = NULL;
    char *arch_files_list[5];
    char target_file_name[256] = {0};
    int i;
    char crash_url_file[32] = {0};
    int no_of_files = 3;
    int tar_status = -1;

    if (!dump || !config || !platform || !archive || !new_dump_name) {
	printf("archive_create_smart Invalid Argument\n");
        return -1;
    }
    tmp = strstr(new_dump_name, "<#=#>");
    if (tmp != NULL) {
        printf("Remove <#=#> from the dump name:%s\n",new_dump_name);
	strcpy(tmp, tmp+5);
	strcpy(new_dump_name, tmp);
	new_dump_name[strlen(tmp)] = '\0';
    }
    printf("archive_create_smart() After process dump name=%s\n", new_dump_name);
    char tmp1[512] = {0};
    snprintf(tmp1, sizeof(tmp1), "%s/%s", "/opt/minidumps", new_dump_name);
    strcpy(new_dump_name, tmp1);
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
    size_t size_dump = 0;
    if ( 0 == (file_get_size(new_dump_name, &size_dump))) {
        printf("Size of the file:%lu\n", size_dump);
    }
    //TODO: Add below telemetry
    //if [ "$IS_T2_ENABLED" == "true" ] && [ ! -s "$dumpName" ]; then
	//            t2CountNotify "SYST_ERR_MINIDPZEROSIZE"
          //  fi
    for (i = 0; i < 5; i++) {
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
	       snprintf(arch_files_list[3], 256, "%s", crash_url_file);
	       printf("crash url file=%s\n", arch_files_list[3]);
	       no_of_files = 4;
	   }
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
   }
   for (i = 0; i < 5; i++) {
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
