/* FULL IMPLEMENTATION - Archive creator with smart compression */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <limits.h>

#define MIN_FREE_SPACE_MB 50

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

/* FULL IMPLEMENTATION - Execute tar command safely */
static int execute_tar(const char *input, const char *output) {
    /* Build tar command - using fork/exec instead of system() for security */
    pid_t pid = fork();
    
    if (pid == -1) {
        return -1;
    }
    
    if (pid == 0) {
        /* Child process */
        char *args[] = {
            "/bin/tar",
            "-czf",
            (char *)output,
            "-C",
            (char *)"/",  /* Change to root to use absolute path */
            (char *)input,
            NULL
        };
        
        execvp(args[0], args);
        _exit(1);  /* exec failed */
    }
    
    /* Parent process - wait for completion */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return -1;
    }
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    
    return -1;
}

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
