/* FULL IMPLEMENTATION - Dump file scanner module */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "../../common/types.h"
#include "file_utils.h"
#include "scanner.h"

#define MAX_DUMPS 100
#define PATH_MAX 512


static dump_file_t found_dumps[MAX_DUMPS];
static int dump_count = 0;
/* Container delimiter in filenames */
static const char containerDelimiter[] = "<#=#>";

/* Telemetry stubs - replace with real implementations */
static void t2ValNotify(const char *key, const char *val)
{
    (void)key; (void)val;
    /* integrate with real telemetry API */
}
static void t2CountNotify(const char *key, const char *val_or_null)
{
    (void)key; (void)val_or_null;
    /* integrate with real telemetry API */
}

/* Returns 1 if path refers to a regular file, 0 otherwise */
static int is_regular_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}
#if 0
/* Read a single line from file `path` into buffer (sz), trimming newline.
 * Returns 0 on success, -1 on error.
 */
int read_line_trim(const char *path, char *buf, size_t sz)
{
    if (!path || !buf || sz == 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)sz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    /* trim newline */
    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}
#endif
/* Write a single line to LOG_FILES_PATH (append). Return 0 on success */
static int append_logfile_entry(const char *entry)
{
    if (!entry) return -1;
    FILE *f = fopen(LOG_FILES_PATH, "a");
    if (!f) return -1;
    /* write with newline */
    if (fprintf(f, "%s\n", entry) < 0) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) return -1;
    return 0;
}


static int is_allowed_char(char c) {
    return ( (c >= '0' && c <= '9') ||
             (c >= 'A' && c <= 'Z') ||
             (c >= 'a' && c <= 'z') ||
             c=='/' || c==' ' || c=='.' || c=='_' || c=='-');
}

static char *sanitize_segment(const char *s) {
    size_t len = strlen(s);
    char *out = calloc(len + 1, 1);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (is_allowed_char(s[i])) {
            out[j++] = s[i];
        }
    }
    out[j] = '\0';
    return out;
}

/*
 * sanitize_filename:
 *   - Keeps directory separators ('/') intact.
 *   - Preserves the exact token "<#=#>" wherever present.
 *   - Removes characters other than:
 *       a-z A-Z 0-9 space . _ - and '/'
 *   - Returns newly allocated string (must be freed by caller).
 *
 * Example:
 *   input: "./app*wrong<#=#>st@te.dmp"
 *   steps:
 *     1) treat "<#=#>" as placeholder
 *     2) drop forbidden chars: "*", "@"
 *     3) restore placeholder
 *   output: "./appwrong<#=#>stte.dmp"
 *
 * Note: This mirrors the shell sed approach:
 *   sed -e 's/<#=#>/PLACEHOLDER/g' -e 's/[^/a-zA-Z0-9 ._-]//g' -e 's/PLACEHOLDER/<#=#>/g'
 *
 * Returns allocated char* on success, NULL on error.
 */
int sanitize_filename_preserve_container(const char *fname, char *out, size_t outsz)
{
    const char *DELIM = "<#=#>";
    size_t dlen = strlen(DELIM);

    if (!fname || !out || outsz == 0)
        return -1;

    out[0] = '\0';  // ensure output starts clean

    const char *p = fname;
    const char *match;
    //size_t fname_len = strlen(fname);

    while ((match = strstr(p, DELIM)) != NULL) {

        /* Extract segment BEFORE delimiter */
        size_t seg_len = (size_t)(match - p);

        char tmp[128];
        if (seg_len >= sizeof(tmp)) seg_len = sizeof(tmp)-1;

        memcpy(tmp, p, seg_len);
        tmp[seg_len] = '\0';

        char *clean = sanitize_segment(tmp);
        if (!clean) return -1;

        /* Append sanitized segment */
        size_t remain = outsz - strlen(out) - 1;
        strncat(out, clean, remain);
        free(clean);

        /* Append delimiter as-is */
        remain = outsz - strlen(out) - 1;
        strncat(out, DELIM, remain);

        /* Move past delimiter */
        p = match + dlen;
    }
        /* Remaining tail segment (after last delimiter) */
    if (*p) {
        char *clean = sanitize_segment(p);
        if (!clean) return -1;

        size_t remain = outsz - strlen(out) - 1;
        strncat(out, clean, remain);
        free(clean);
    }

    return 0;
}

static char *extract_pname(const char *filepath)
{
    if (!filepath) return NULL;
    /* Find last '/' to separate directory and basename */
    const char *slash = strrchr(filepath, '/');
    const char *basename = (slash ? slash + 1 : filepath);
    size_t dirlen = (slash ? (size_t)(slash - filepath) : 0);

    /* Find last '_' in basename */
    const char *last_unders = strrchr(basename, '_');

    size_t outlen = 0;
    if (!last_unders) {
        /* no underscore => use whole filepath but strip leading "./" */
        const char *start = filepath;
        if (strncmp(start, "./", 2) == 0) start += 2;
        outlen = strlen(start);
        char *out = malloc(outlen + 1);
        if (!out) return NULL;
        memcpy(out, start, outlen + 1);
        return out;
    }

    /* Build result: dir + '/' (if present) + basename up to last '_' (exclude underscore part) */
    size_t base_keep = (size_t)(last_unders - basename);
    outlen = dirlen + (dirlen ? 1 : 0) + base_keep;
    /* Allocate +1 for null */
    char *out = malloc(outlen + 1);
    if (!out) return NULL;
    size_t wi = 0;
    if (dirlen) {
        memcpy(out, filepath, dirlen);
        wi += dirlen;
        out[wi++] = '/';
    }
    memcpy(out + wi, basename, base_keep);
    wi += base_keep;
    out[wi] = '\0';

    /* Remove leading "./" if present */
    if (strncmp(out, "./", 2) == 0) {
        size_t newlen = strlen(out) - 2;
        memmove(out, out + 2, newlen + 1);
    }
    return out;
}

/*
 * extract_appname:
 *   Original shell:
 *     appname=$(echo ${file} | cut -d "_" -f 2 | cut -d "-" -f 1)
 *
 *   Logic:
 *     - take second underscore-delimited field
 *     - then take first '-' delimited token
 *
 *   Returns newly allocated string or NULL.
 *
 *   Example:
 *     file = "prefix_appname-1_proc_123.dmp" -> appname = "appname"
 */
static char *extract_appname(const char *filepath)
{
    if (!filepath) return NULL;
    /* Work on basename */
    const char *basename = strrchr(filepath, '/');
    basename = (basename ? basename + 1 : filepath);

    /* Find first '_' */
    const char *first_unders = strchr(basename, '_');
    if (!first_unders) return NULL;
    const char *second_unders = strchr(first_unders + 1, '_');
    /* The shell cuts field 2: that is the text between first and second underscore.
       But shell cut -f2 returns the second field even if there are more underscores; if second underscore missing,
       it will take up to end of string. So we take from first_unders+1 to second_unders-1 or to end. */
    const char *field_start = first_unders + 1;
    const char *field_end = second_unders ? second_unders : (basename + strlen(basename));

    size_t fieldlen = (size_t)(field_end - field_start);
    if (fieldlen == 0) return NULL;

    /* Now split by '-' and take first token */
    const char *dash = memchr(field_start, '-', fieldlen);
    size_t toklen = dash ? (size_t)(dash - field_start) : fieldlen;

    char *out = malloc(toklen + 1);
    if (!out) return NULL;
    memcpy(out, field_start, toklen);
    out[toklen] = '\0';
    return out;
}

/*
 * lookup_log_files_for_proc:
 *   Parse LOGMAPPER_FILE_PATH for lines "procPattern=log1,log2".
 *   If procPattern contains the pname as substring, we return the associated RHS string (caller must free).
 *
 *   This approximates awk -v proc="$pname" -F= '$1 ~ proc {print $2}'
 *
 *   Returns malloc'd string with comma-separated filenames on success (caller frees), NULL if none found.
 */
static char *lookup_log_files_for_proc(const char *pname)
{
    if (!pname) return NULL;
    FILE *f = fopen(LOGMAPPER_FILE_PATH, "r");
    if (!f) return NULL;

    char *result = NULL;
    char line[4096];
    printf("=============> pname=%s\n", pname);
    while (fgets(line, sizeof(line), f)) {
        /* trim newline */
        line[strcspn(line, "\r\n")] = '\0';
        /* skip empty lines */
        if (line[0] == '\0') continue;
        /* split on first '=' */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *lhs = line;
        char *rhs = eq + 1;
        /* if lhs contains pname as substring -> match */
        if (strstr(pname, lhs) != NULL) {
            /* copy rhs */
            result = strdup(rhs);
            break;
        }
    }
    fclose(f);
    return result;
}

/*
 * get_crashed_log_file:
 *   Given a sanitized filename (may include path or not), extract process name 'pname',
 *   extract appname, report telemetry, look up log files from LOGMAPPER_FILE_PATH and append
 *   full log paths to LOG_FILES_PATH.
 *
 *   This function mirrors the shell get_crashed_log_file() behavior.
 */
static int get_crashed_log_file(const char *file)
{
    if (!file) return -1;
    printf("In get_crashed_log_file file=%s========================>\n", file);
    /* Extract pname */
    char *pname = extract_pname(file);
    if (!pname) return -1;

    /* Remove leading "./" if present already handled in extract_pname */

    /* Extract appname */
    char *appname = extract_appname(file);

    printf("Process crashed = %s\n", pname);

    /* Telemetry if enabled (replace IS_T2_ENABLED check as needed) */
    const char *IS_T2_ENABLED = getenv("IS_T2_ENABLED"); /* env var control; modify as needed */
    if (IS_T2_ENABLED && strcmp(IS_T2_ENABLED, "true") == 0) {
        t2ValNotify("processCrash_split", pname);
        t2ValNotify("SYST_ERR_Process_Crash_accum", pname);
        t2CountNotify("SYST_ERR_ProcessCrash", NULL);
    }
    printf("Going to call lookup_log_files_for_proc() ===========================\n");
    /* Lookup log files (comma-separated) */
    char *logrhs = lookup_log_files_for_proc(pname);
    if (logrhs) {
        printf("Crashed process log file(s): %s\n", logrhs);

        /* Split comma-separated list and append LOG_PATH/<name> to LOG_FILES_PATH */
        char *saveptr = NULL;
        char *token = strtok_r(logrhs, ",", &saveptr);
        while (token) {
            /* Trim leading/trailing spaces */
            while (*token && isspace((unsigned char)*token)) token++;
            char *end = token + strlen(token);
            while (end > token && isspace((unsigned char)*(end - 1))) { end--; }
            char tmp = *end; *end = '\0';

            char logfull[PATH_MAX];
            if (join_path(logfull, sizeof(logfull), LOG_FILES_PATH, token) == 0) {
                if (append_logfile_entry(logfull) != 0) {
		    printf("Failed to append log entry: %s\n", logfull);
                }
            } else {
                printf("Path too long for log: %s/%s", LOG_FILES_PATH, token);
            }
            *end = tmp;
            token = strtok_r(NULL, ",", &saveptr);
        }
        free(logrhs);
    } else {
        printf("No log mapper entry found for process\n");
    }

    if (appname) {
        printf("Appname, Process_Crashed = %s, %s\n", appname, pname);
        free(appname);
    }

    free(pname);
    return 0;
}

/*
 * processCrashTelemetryInfo:
 *   Handle:
 *     - .tgz detection: set isTgz flag and strip metadata pattern _mod_*
 *     - container detection by "<#=#>" token: extract containerName, containerStatus, times
 *     - set telemetry values accordingly
 *     - finally call get_crashed_log_file() with normalized filename
 *
 *   Returns 0 on success.
 */
static int processCrashTelemetryInfo(const char *rawfile)
{
    if (!rawfile) return -1;

    /* Work on a local mutable copy */
    char file[PATH_MAX];
    if (strlen(rawfile) >= PATH_MAX) return -1;
    strncpy(file, rawfile, PATH_MAX);
    file[PATH_MAX - 1] = '\0';

    /* Remove leading "./" */
    if (strncmp(file, "./", 2) == 0) memmove(file, file + 2, strlen(file + 2) + 1);

    int isTgz = 0;
    int isContainer = 0;

     /* detect extension (text after last '.') */
    char *ext = strrchr(file, '.');
    if (ext && strcmp(ext, ".tgz") == 0) {
        isTgz = 1;
        printf("The File is already a tarball, this might be a retry or crash during shutdown:%d\n", isTgz);

        /* original shell: file_temp=${file#*_mod*_}
         * Remove everything up to and including the first occurrence of "_mod_" (if present).
         * Example: "abc_mod_foo.tgz" -> "foo.tgz"
         */
        char *pmod = strstr(file, "_mod");
        if (pmod) {
            char tmp[PATH_MAX];
            size_t remain_len = strlen(pmod + strlen("_mod"));
            if (remain_len >= PATH_MAX) return -1;
            memcpy(tmp, pmod + strlen("_mod"), remain_len + 1);
            pmod = NULL;
            pmod = strchr(tmp, '_');
            if (pmod != NULL) {
                strncpy(tmp, pmod+1, sizeof(tmp)-1);
		tmp[sizeof(tmp)-1] = '\0';
            }
            snprintf(file, PATH_MAX, "%s", tmp);
            printf("Removed the meta information from tgz filename\n");
            printf("tgz file name after remove meta info=%s\n", file);
            t2CountNotify("SYS_INFO_TGZDUMP", "1");
        }
    }
        /* Container detection: check if containerDelimiter appears in file */
    if (strstr(file, containerDelimiter) != NULL) {
        isContainer = 1;
        printf("From the file name crashed process is a container=%d\n", isContainer);

        /* Split on last containerDelimiter for time part (file##*$containerDelimiter) */
        //Satya:Commented====>char *lastDel = strrchr(file, containerDelimiter[0]); /* naive find - improved below
        /* Better approach: find last occurrence of containerDelimiter substring */
        char *pos = NULL;
        char *scan = file;
        while ((scan = strstr(scan, containerDelimiter)) != NULL) {
            pos = scan;
            scan = scan + 1;
        }
        if (!pos) {
            /* unexpected, fallback */
            pos = strstr(file, containerDelimiter);
            if (!pos) {
                /* proceed without container handling */
                goto call_get_crashed;
            }
        }
        /* firstBreak = substring before first delimiter occurrence (we used last pos above for time; find first) */
        char firstBreak[256];
        char containerTime[64];
        /* find first occurrence for containerTime extraction logic similar to shell */
        char *firstPos = strstr(file, containerDelimiter);
        if (!firstPos) goto call_get_crashed;
        /* Extract firstBreak (everything before firstPos) */
        size_t fb_len = (size_t)(firstPos - file);
        if (fb_len >= PATH_MAX) fb_len = PATH_MAX - 1;
        memcpy(firstBreak, file, fb_len);
        firstBreak[fb_len] = '\0';
        /* containerTime is everything after last delimiter */
        char *lastPos = NULL;
        scan = file;
        while ((scan = strstr(scan, containerDelimiter)) != NULL) {
            lastPos = scan;
            scan = scan + 1;
        }
        if (!lastPos) goto call_get_crashed;
        const char *timepart = lastPos + strlen(containerDelimiter);
        snprintf(containerTime, sizeof(containerTime), "%s", timepart);

	char containerName[256];
        char containerStatus[256];
        /* check if firstBreak contains another delimiter -> then has status info */
        if (strstr(firstBreak, containerDelimiter) != NULL) {
            /* containerName = firstBreak%delimiter*  (text before last delimiter inside firstBreak) */
            char *lastInside = NULL;
            char *sc2 = firstBreak;
            while ((sc2 = strstr(sc2, containerDelimiter)) != NULL) {
                lastInside = sc2;
                sc2 = sc2 + 1;
            }
            if (lastInside) {
                size_t cname_len = (size_t)(lastInside - firstBreak);
                if (cname_len >= sizeof(containerName)) cname_len = sizeof(containerName) - 1;
                memcpy(containerName, firstBreak, cname_len);
                containerName[cname_len] = '\0';
                snprintf(containerStatus, sizeof(containerStatus), "%s", lastInside + strlen(containerDelimiter));
            } else {
                snprintf(containerName, sizeof(containerName), "%s", firstBreak);
                snprintf(containerStatus, sizeof(containerStatus), "unknown");
            }
        } else {
            snprintf(containerName, sizeof(containerName), "%s", firstBreak);
            snprintf(containerStatus, sizeof(containerStatus), "unknown");
        }

        /* Construct file = containerName-backwardDelimiter-containerTime */
        char normalized[PATH_MAX];
        snprintf(normalized, sizeof(normalized), "%s-%s", containerName, containerTime);
        /* Now extract Appname and ProcessName from containerName */
        /* Appname = substring after first '_' */
        char *us = strchr(containerName, '_');
        char Appname[PATH_MAX];
        char ProcessName[PATH_MAX];
        if (us) {
            snprintf(Appname, sizeof(Appname), "%s", us + 1);
            size_t pnamelen = (size_t)(us - containerName);
            if (pnamelen >= sizeof(ProcessName)) pnamelen = sizeof(ProcessName) - 1;
            memcpy(ProcessName, containerName, pnamelen);
            ProcessName[pnamelen] = '\0';
        } else {
            snprintf(Appname, sizeof(Appname), "%s", containerName);
            snprintf(ProcessName, sizeof(ProcessName), "%s", containerName);
        }
        /* Telemetry notifications */
        t2ValNotify("crashedContainerName_split", containerName);
        t2ValNotify("crashedContainerStatus_split", containerStatus);
        t2ValNotify("crashedContainerAppname_split", Appname);
        t2ValNotify("crashedContainerProcessName_split", ProcessName);
        t2CountNotify("SYS_INFO_CrashedContainer", NULL);

        /* Logging similar to shell */
        printf("Container crash info Basic: %s, %s\n", Appname, ProcessName);
        printf("Container crash info Advance: %s, %s\n", containerName, containerStatus);
        printf("NEW Appname, Process_Crashed, Status = %s, %s, %s\n", Appname, ProcessName, containerStatus);
        printf("NEW Processname, App Name, AppState = %s, %s, %s\n", ProcessName, Appname, containerStatus);

        /* Add APP_ERROR_Crashed telemetry */
        char tmpbuf[PATH_MAX * 3];
        snprintf(tmpbuf, sizeof(tmpbuf), "%s,%s,%s", Appname, ProcessName, containerStatus);
        t2ValNotify("APP_ERROR_Crashed_split", tmpbuf);
        t2ValNotify("APP_ERROR_Crashed_accum", tmpbuf);

        printf("ContainerName = %s\n", containerName);
        t2ValNotify("APP_ERROR_CrashInfo", containerName);
        printf("ContainerStatus = %s\n", containerStatus);
        t2ValNotify("APP_ERROR_CrashInfo_status", containerStatus);

        /* switch normalized file into file variable */
        snprintf(file, sizeof(file), "%s", normalized);
    }

call_get_crashed:
    /* Finally call get_crashed_log_file() for the (possibly normalized) filename */
    get_crashed_log_file(file);
    return 0;
}


/*
 * process_file_entry:
 *   For each candidate file:
 *    - sanitize filename
 *    - if sanitized becomes empty -> unlink original file
 *    - if sanitized differs from original -> rename atomically
 *    - call processCrashTelemetryInfo() if DUMP_FLAG == "0"
 *
 *   Returns 0 on success, non-zero on error.
 */
int process_file_entry(char *fullpath, char *dump_type)
{
    int sanitize_ret = -1;
    char sanitized[256] = {0};
    if (!fullpath) return -1;

    /* Only process regular files */
    if (!is_regular_file(fullpath)) return 0;

    /* Determine filename relative / basename (we preserve path) */
    char dirname[PATH_MAX];
    char basename[PATH_MAX];
    char fullcopy[PATH_MAX];

    if (strlen(fullpath) >= PATH_MAX) return -1;
    strncpy(fullcopy, fullpath, PATH_MAX);
    fullcopy[PATH_MAX - 1] = '\0';

    printf("full path of the file=%s=>\n", fullpath);

    char *slash = strrchr(fullcopy, '/');
    if (slash) {
        size_t dlen = (size_t)(slash - fullcopy);
        if (dlen >= PATH_MAX) return -1;
        memcpy(dirname, fullcopy, dlen);
        dirname[dlen] = '\0';
        strncpy(basename, slash + 1, PATH_MAX);
        basename[PATH_MAX - 1] = '\0';
    } else {
        dirname[0] = '.';
        dirname[1] = '\0';
        strncpy(basename, fullcopy, PATH_MAX);
        basename[PATH_MAX - 1] = '\0';
    }
    printf("process_file_entry dir name=%s=>\nbasename=%s=>\n", dirname, basename);
    /* Sanitize basename while preserving containerDelimiter token */
    sanitize_ret = sanitize_filename_preserve_container(basename, sanitized, sizeof(sanitized));
    if ((sanitize_ret == 0) && (sanitized[0] == '\0')) {
        /* sanitized became empty (or error) => delete original file */
        if (unlink(fullpath) != 0) {
            printf("Failed to unlink (sanitized empty): %s : %s\n", fullpath, strerror(errno));
            return -1;
        }
        printf("Removed file with empty sanitized name: %s\n", fullpath);
        return 0;
    }
        /* If sanitized differs from original basename, rename */
    if (strcmp(sanitized, basename) != 0) {
        char newfull[PATH_MAX];
        if (join_path(newfull, sizeof(newfull), dirname, sanitized) != 0) {
            printf("Path too long after sanitization; skipping rename\n");
            return -1;
        }
        /* Use rename() for atomic move; if target exists, choose to overwrite */
        if (rename(fullpath, newfull) != 0) {
            /* If rename failed because target exists, try unlink target and rename again */
            if (errno == EEXIST || errno == EACCES) {
                (void)unlink(newfull);
                if (rename(fullpath, newfull) != 0) {
                    printf("Failed to rename %s -> %s : %s", fullpath, newfull, strerror(errno));
                    return -1;
                }else {
		    printf("Renamed After retry %s -> %s\n", fullpath, newfull);
	            strcpy(fullpath, newfull);
	            printf("After rename fullpath buffer updated=%s=\n",fullpath);
		}
            } else {
                printf("Failed to rename %s -> %s : %s\n", fullpath, newfull, strerror(errno));
                return -1;
            }
        } else {
            printf("Renamed %s -> %s\n", fullpath, newfull);
	    strcpy(fullpath, newfull);
	    printf("After rename fullpath buffer updated=%s=\n",fullpath);
        }
        /* set fullpath to newfull for subsequent processing */
        if (strlen(newfull) >= PATH_MAX) {
            return -1;
        }
        if (0 == (strcmp(dump_type, "0"))) {
            /* call processCrashTelemetryInfo with sanitized filename relative path */
            processCrashTelemetryInfo(newfull);
        } else {
            printf("processCrashTelemetryInfo is not allowed\n");
        }
    } else {
            if (0 == (strcmp(dump_type, "0"))) {
                /* sanitized == basename: no rename */
                processCrashTelemetryInfo(fullpath);
            } else {
                printf("processCrashTelemetryInfo is not allowed\n");
            }
    }

    return 0;
}


/* FULL IMPLEMENTATION - Check if file has dump extension */
static int is_dump_file(const char *filename) {
    size_t len = strlen(filename);
    
    /* Check for .dmp extension (minidump) */
    if (len > 4 && strcmp(filename + len - 4, ".dmp") == 0) {
        return 1;
    }
    
    /* Check for .core extension (coredump) */
    if (len > 5 && strcmp(filename + len - 5, ".core") == 0) {
        return 2;
    }
    
    /* Check for core.* pattern (systemd coredumps) */
    if (strncmp(filename, "core.", 5) == 0) {
        return 2;
    }

    if (len > 4 && strcmp(filename + len - 4, ".tgz") == 0) {
        return 3;
    }
    
    return 0;
}

/* FULL IMPLEMENTATION - Scan directory for dump files */
int scanner_find_dumps(const char *path, dump_file_t **dumps, int *count) {
    if (!path || !dumps || !count) {
        return -1;
    }
    
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to open directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    dump_count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL && dump_count < MAX_DUMPS) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        int dump_type = is_dump_file(entry->d_name);
        if (dump_type == 0) {
            continue;
        }
        
        /* Build full path */
        char fullpath[256];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        
        /* Get file stats */
        struct stat st;
        if (stat(fullpath, &st) != 0) {
            continue;
        }
        
        /* Skip if not a regular file */
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        
        /* Add to array */
        strncpy(found_dumps[dump_count].path, fullpath, sizeof(found_dumps[dump_count].path));
        found_dumps[dump_count].path[512 - 1] = '\0';
        found_dumps[dump_count].mtime = st.st_mtime;
        found_dumps[dump_count].size = st.st_size;
        found_dumps[dump_count].is_minidump = (dump_type == 1);
	printf("Dump/Core file name=%s\n", found_dumps[dump_count].path);
        dump_count++;
    }
    
    closedir(dir);
    
    *dumps = found_dumps;
    *count = dump_count;
    
    return dump_count;
}

/* FULL IMPLEMENTATION - Get sorted dumps (oldest first for upload priority) */
int scanner_get_sorted_dumps(dump_file_t **dumps, int *count) {
    if (!dumps || !count) {
        return -1;
    }
    
    /* Simple bubble sort by modification time (oldest first) */
    for (int i = 0; i < dump_count - 1; i++) {
        for (int j = 0; j < dump_count - i - 1; j++) {
            if (found_dumps[j].mtime > found_dumps[j + 1].mtime) {
                dump_file_t temp = found_dumps[j];
                found_dumps[j] = found_dumps[j + 1];
                found_dumps[j + 1] = temp;
            }
        }
    }
    
    *dumps = found_dumps;
    *count = dump_count;
    return 0;
}

/* FULL IMPLEMENTATION - Clear scanner state */
void scanner_cleanup(void) {
    dump_count = 0;
    memset(found_dumps, 0, sizeof(found_dumps));
}
