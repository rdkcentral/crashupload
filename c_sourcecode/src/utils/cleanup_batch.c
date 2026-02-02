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
 * @file cleanup_batch.c
 * SKELETON: Implementation needed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>
#include "cleanup_batch.h"
#include "../../common/errors.h"
#include "logger.h"

// For unit testing: allow static functions to be visible
#ifdef L2_TEST
#define STATIC_TESTABLE
#else
#define STATIC_TESTABLE static
#endif

#define PATH_MAX_LEN 512

/* Safe join: dest must be PATH_MAX_LEN bytes. Returns 0 on success, -1 on error. */
STATIC_TESTABLE int cb_join_path(char dest[PATH_MAX_LEN], const char *dir, const char *name)
{
    if (!dir || !name)
        return -1;
    size_t dlen = strlen(dir);
    if (dlen == 0)
    {
        if (strlen(name) >= PATH_MAX_LEN)
            return -1;
        snprintf(dest, PATH_MAX_LEN, "%s", name);
        return 0;
    }
    /* Ensure there's exactly one slash between */
    if (dir[dlen - 1] == '/')
    {
        if (snprintf(dest, PATH_MAX_LEN, "%s%s", dir, name) >= PATH_MAX_LEN)
            return -1;
    }
    else
    {
        if (snprintf(dest, PATH_MAX_LEN, "%s/%s", dir, name) >= PATH_MAX_LEN)
            return -1;
    }
    return 0;
}

/* Check if directory exists and non-empty */
STATIC_TESTABLE int dir_exists_and_nonempty(const char *path)
{
    DIR *d = opendir(path);
    if (!d)
        return 0; /* doesn't exist or cannot open */
    struct dirent *ent;
    int nonempty = 0;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
        {
            nonempty = 1;
            break;
        }
    }
    closedir(d);
    return nonempty;
}

/* Returns 1 if file exists and is regular file, 0 otherwise */
STATIC_TESTABLE int file_exists_regular(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
    {
        CRASHUPLOAD_WARN("path not exist %s\n", path);
        return 0;
    }
    return S_ISREG(st.st_mode);
}

STATIC_TESTABLE int file_vector_init(file_vector_t *v)
{
    if (!v)
        return -1;
    v->arr = NULL;
    v->size = 0;
    v->capacity = 0;
    return 0;
}

STATIC_TESTABLE void file_vector_free(file_vector_t *v)
{
    if (!v)
        return;
    for (size_t i = 0; i < v->size; ++i)
    {
        free(v->arr[i].path);
    }
    free(v->arr);
    v->arr = NULL;
    v->size = v->capacity = 0;
}

STATIC_TESTABLE int file_vector_push(file_vector_t *v, const char *path, time_t mtime)
{
    if (!v || !path)
        return -1;
    if (v->size == v->capacity)
    {
        size_t newcap = (v->capacity == 0) ? 64 : v->capacity * 2;
        file_info_t *tmp = realloc(v->arr, newcap * sizeof(file_info_t));
        if (!tmp)
            return -1;
        v->arr = tmp;
        v->capacity = newcap;
    }
    v->arr[v->size].path = strdup(path);
    if (!v->arr[v->size].path)
        return -1;
    v->arr[v->size].mtime = mtime;
    v->size++;
    return 0;
}

/* Sort comparator: newest first (desc by mtime), tie-break by path */
STATIC_TESTABLE int cmp_mtime_desc(const void *a, const void *b)
{
    const file_info_t *fa = a;
    const file_info_t *fb = b;
    if (fa->mtime > fb->mtime)
        return -1;
    if (fa->mtime < fb->mtime)
        return 1;
    return strcmp(fa->path, fb->path);
}
/*
 * Walk directory recursively and call callback for each regular file.
 * The callback signature: int cb(const char *filepath, const struct stat *st, void *user)
 * If cb returns non-zero, walk stops and value is returned.
 */
typedef int (*file_cb_t)(const char *, const struct stat *, void *);
int walk_dir_recursive(const char *dirpath, file_cb_t cb, void *user)
{
    DIR *d = opendir(dirpath);
    if (!d)
    {
        /* errno preserved for caller if needed */
        return -1;
    }

    struct dirent *ent;
    char full[PATH_MAX_LEN];
    int rc = 0;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        if (cb_join_path(full, dirpath, ent->d_name) != 0)
        {
            /* path too long; skip */
            continue;
        }

        struct stat st;
        if (lstat(full, &st) != 0)
        {
            /* skip entries we cannot stat */
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            rc = walk_dir_recursive(full, cb, user);
            if (rc != 0)
                break;
        }
        else if (S_ISREG(st.st_mode))
        {
            rc = cb(full, &st, user);
            if (rc != 0)
                break;
        }
        else
        {
            /* skip other types (symlinks, sockets, etc.) */
            continue;
        }
    }

    closedir(d);
    return rc;
}

/* ---------- Implementation: deleteAllButTheMostRecentFile(path) ---------- */
    /*int collect_cb(const char *filepath, const struct stat *st, void *user)
    {
        (void) user;
        if (file_vector_push(&files, filepath, st->st_mtime) != 0) {
            return -1; // stop 
        }
        return 0;
    }*/

/*
 * Delete all files in 'path' except the most recent 'max_keep' files.
 * Matches all regular files (no pattern). Returns 0 on success, -1 on error.
 */

int delete_all_but_most_recent(const char *path, size_t max_keep)
{
    if (!path)
        return -1;

    file_vector_t files;
    if (file_vector_init(&files) != 0)
        return -1;

    /* Callback to collect files */
    struct collect_ctx
    {
        file_vector_t *vec;
        int err;
    } ctx;
    ctx.vec = &files;
    ctx.err = 0;

    int collect_cb(const char *filepath, const struct stat *st, void *user)
    {
        (void)user;
        if (file_vector_push(&files, filepath, st->st_mtime) != 0)
        {
            return -1; // stop
        }
        return 0;
    }

    if (walk_dir_recursive(path, collect_cb, &ctx) != 0)
    {
        /* Either walk error or memory error; but continue to cleanup vector */
        /* If walk_dir_recursive returned -1 because couldn't open subdir, still proceed with what we have */
    }

    if (files.size <= max_keep)
    {
        /* nothing to delete */
        file_vector_free(&files);
        return 0;
    }
    /* sort files by mtime desc (newest first) */
    qsort(files.arr, files.size, sizeof(file_info_t), cmp_mtime_desc);

    size_t to_delete = files.size - max_keep;
    for (size_t i = 0; i < to_delete; ++i)
    {
        const char *p = files.arr[files.size - 1 - i].path; /* oldest entries at end */
        CRASHUPLOAD_INFO("Deleting old dump file: %s\n", p);
        if (unlink(p) != 0)
        {
            CRASHUPLOAD_WARN("Failed to unlink %s: %s\n", p, strerror(errno));
        }
    }

    file_vector_free(&files);
    return 0;
}

/* ---------- Helpers to delete files matching patterns / older than days ---------- */

/* Context for delete-by-pattern-and-time */
struct del_pattern_ctx
{
    const char *pattern;     /* fnmatch-style pattern (can be NULL) */
    int delete_if_not_match; /* if 1, delete files that do NOT match pattern */
    time_t older_than;       /* if >0, only delete if st->st_mtime < older_than */
    size_t deleted_count;
};

/* Callback used with walk_dir_recursive to delete matching files */
static int delete_match_cb(const char *filepath, const struct stat *st, void *user)
{
    struct del_pattern_ctx *ctx = (struct del_pattern_ctx *)user;
    const char *fname = strrchr(filepath, '/');
    fname = (fname ? fname + 1 : filepath);

    int match = 1; /* default match */
    if (ctx->pattern)
    {
        match = (fnmatch(ctx->pattern, fname, 0) == 0) ? 1 : 0;
    }

    if (ctx->delete_if_not_match)
        match = !match;

    if (ctx->older_than > 0 && st->st_mtime >= ctx->older_than)
    {
        /* not older */
        return 0;
    }

    if (match)
    {
        if (unlink(filepath) == 0)
        {
            ctx->deleted_count++;
            CRASHUPLOAD_INFO("Removed file: %s\n", filepath);
        }
        else
        {
            CRASHUPLOAD_WARN("Failed to remove file: %s : %s\n", filepath, strerror(errno));
        }
    }
    return 0;
}

/* Delete files that match pattern and older than 'days' (days > 0), recursive. */
static int delete_files_matching_pattern_older_than(const char *path, const char *pattern, int days)
{
    if (!path)
        return -1;
    time_t cutoff = 0;
    if (days > 0)
    {
        time_t now = time(NULL);
        cutoff = now - (time_t)days * 24 * 60 * 60;
    }

    struct del_pattern_ctx ctx;
    ctx.pattern = pattern;
    ctx.delete_if_not_match = 0;
    ctx.older_than = cutoff;
    ctx.deleted_count = 0;

    if (walk_dir_recursive(path, delete_match_cb, &ctx) != 0)
    {
        /* ignore - continue */
    }

    return 0;
}

/* Delete all files matching pattern (recursive). */
static int delete_files_matching_pattern(const char *path, const char *pattern)
{
    if (!path)
        return -1;
    struct del_pattern_ctx ctx;
    ctx.pattern = pattern;
    ctx.delete_if_not_match = 0;
    ctx.older_than = 0;
    ctx.deleted_count = 0;
    if (walk_dir_recursive(path, delete_match_cb, &ctx) != 0)
    {
        /* ignore */
    }
    return 0;
}

/* Delete all files that do NOT match the pattern (recursive). */
static int delete_files_not_matching_pattern(const char *path, const char *pattern)
{
    if (!path)
        return -1;
    struct del_pattern_ctx ctx;
    ctx.pattern = pattern;
    ctx.delete_if_not_match = 1;
    ctx.older_than = 0;
    ctx.deleted_count = 0;
    if (walk_dir_recursive(path, delete_match_cb, &ctx) != 0)
    {
        /* ignore */
    }
    return 0;
}

/*
 * cleanup_batch() arguments:
 *
 * working_dir: directory to cleanup (must not be NULL)
 * dumps_extn_pattern: fnmatch pattern for dump files e.g. "*.dmp" or "*.minidump"
 * on_startup_flag_base: path base for "on startup dumps cleaned up" file, e.g. "/tmp/onstart"
 * dump_flag: string representation, used for composing ON_STARTUP_DUMPS_CLEANED_UP filename
 * max_core_files: number of most recent files to keep
 */
int cleanup_batch(const char *working_dir,
                  const char *dumps_extn_pattern,
                  const char *on_startup_flag_base,
                  const char *dump_flag,
                  size_t max_core_files)
{
    if (!working_dir)
        return -1;

    /* Check existence & non-empty (similar to shell condition) */
    if (!dir_exists_and_nonempty(working_dir))
    {
        CRASHUPLOAD_INFO("WORKING_DIR is empty or missing\n");
        return 0; /* nothing to do */
    }

    CRASHUPLOAD_INFO("Cleanup %s directory\n", working_dir);
    /* 1) Find and delete files by wildcard '*_mac*_dat*' older than 2 days */
    delete_files_matching_pattern_older_than(working_dir, "*_mac*_dat*", 2);

    /* 2) If /opt/.upload_on_startup does not exist, run on-startup cleanup */
    if (!file_exists_regular("/opt/.upload_on_startup"))
    {
        CRASHUPLOAD_INFO("Inside start up cleanup delete version.txt\n");
        /* delete version.txt in working_dir (best-effort) */
        char version_path[PATH_MAX_LEN];
        if (cb_join_path(version_path, working_dir, "version.txt") == 0)
        {
            if (unlink(version_path) == 0)
            {
                CRASHUPLOAD_INFO("Deleted %s\n", version_path);
            }
            else
            {
                /* ignore if not present */
            }
        }
        /* Compose ON_STARTUP_DUMPS_CLEANED_UP path */
        char on_startup_flag[PATH_MAX_LEN];
        if (on_startup_flag_base && dump_flag)
        {
            snprintf(on_startup_flag, sizeof(on_startup_flag), "%s_%s", on_startup_flag_base, dump_flag);
        }
        else
        {
            on_startup_flag[0] = '\0';
        }
        CRASHUPLOAD_INFO("on startup flag=%s\n", on_startup_flag);
        int need_run_startup = 1;
        if (on_startup_flag[0] != '\0')
        {
            if (file_exists_regular(on_startup_flag))
                need_run_startup = 0;
        }
        CRASHUPLOAD_INFO("need_run_startup = %d\n", need_run_startup);
        if (need_run_startup)
        {
            CRASHUPLOAD_INFO("Inside run start up cleanup\n");
            /* delete unfinished files from previous run (matching "*_mac*_dat*") */
            delete_files_matching_pattern(working_dir, "*_mac*_dat*");

            /* delete non-dump files */
            if (dumps_extn_pattern && dumps_extn_pattern[0] != '\0')
            {
                delete_files_not_matching_pattern(working_dir, dumps_extn_pattern);
            }

            /* delete older dumps keeping most recent 'max_core_files' */
            delete_all_but_most_recent(working_dir, max_core_files);

            /* touch the flag file to indicate we've cleaned up on startup */
            if (on_startup_flag[0] != '\0')
            {
                FILE *fp = fopen(on_startup_flag, "w");
                if (fp)
                    fclose(fp);
            }
        }
    }
    else
    {
        CRASHUPLOAD_INFO("Inside not run start up cleanup\n");
        /* If upload_on_startup exists and dump_flag == "1", remove the file (mirror shell behaviour) */
        if (dump_flag && strcmp(dump_flag, "1") == 0)
        {
            unlink("/opt/.upload_on_startup");
        }
    }

    return 0;
}

void remove_pending_dumps(const char *working_dir,
                          const char *dumps_extn_pattern)
{
    char path[512];
    struct stat st;
    DIR *dir = opendir(working_dir);
    if (!dir)
    {
        CRASHUPLOAD_WARN("opendir Error: %s dir not present\n", working_dir);
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL)
    {

        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", working_dir, entry->d_name);

        if (stat(path, &st) < 0)
        {
            CRASHUPLOAD_WARN("stat Error: %s\n", path);
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            // Recursive call for directories
            remove_pending_dumps(path, dumps_extn_pattern);
        }
        else if (S_ISREG(st.st_mode))
        {

            int match_extn = fnmatch(dumps_extn_pattern, entry->d_name, 0) == 0;
            int match_tgz = fnmatch("*.tgz", entry->d_name, 0) == 0;

            if (match_extn || match_tgz)
            {
                CRASHUPLOAD_INFO("Removing %s because upload limit has been reached or build is blacklisted or TelemetryOptOut is set\n", path);

                if (unlink(path) == 0)
                {
                    // File deleted
                }
                else
                {
                    CRASHUPLOAD_WARN("unlink error\n");
                }
            }
        }
    }

    closedir(dir);
}
