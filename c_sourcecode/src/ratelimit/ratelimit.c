/* FULL IMPLEMENTATION - Rate limiter with unified recovery + 10/10min check */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include "ratelimit.h"

//#define RECOVERY_DELAY_SEC 600
#define RECOVERY_DELAY_SEC 30
#define DENY_UPLOADS_FILE "/tmp/.deny_dump_uploads_till"
#define ALLOW_UPLOAD 1
#define STOP_UPLOAD 0
#define RECOVERY_TIME 1
#define CURRENT_TIME 2

int set_time(const char *deny_file, int type)
{
    FILE *fp;
    time_t now;
    long deny_until;

    if (!deny_file)
        return -1;

    now = time(NULL);
    if (now == (time_t)-1)
        return -1;
    if (type == RECOVERY_TIME) {
	printf("Set Rcovery Time inside file:%s\n", deny_file);
        deny_until = (long)now + RECOVERY_DELAY_SEC;
    }

    fp = fopen(deny_file, "w");
    if (!fp)
        return -1;

    if (fprintf(fp, "%ld", deny_until) < 0) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int is_upload_limit_reached(const char *file)
{
    FILE *fp = NULL;
    char buf[80] = {0};
    char first_line_data[80] = {0};
    int ret = ALLOW_UPLOAD;
    char *endptr;
    long first_crash_time;
    time_t now;
    int line_cnt = 0;

    fp = fopen(file, "r");
    if (fp != NULL) {
        while(fgets(buf, sizeof(buf), fp)) {
	    line_cnt++;
	    if (line_cnt == 1) {
	        strncpy(first_line_data, buf, sizeof(first_line_data)-1);
		first_line_data[sizeof(first_line_data)-1] = '\0';
	    }
	}
    } else {
        printf("File for rate limit check not present:%s\n", file);
	return ret;
    }
    /* Validate numeric content */
    for (size_t i = 0; buf[i] != '\0' && buf[i] != '\n'; i++) {
        if (!isdigit((unsigned char)buf[i]))
            return ALLOW_UPLOAD;
    }

    first_crash_time = strtol(buf, &endptr, 10);
    if (endptr == buf)
        return ALLOW_UPLOAD;

    now = time(NULL);
    if (now == (time_t)-1)
        return ALLOW_UPLOAD;
    
    if (line_cnt <= 10) {
        printf("is_upload_limit_reached() not reached.%d\n", line_cnt);
    } else {
	if ((now - first_crash_time) < RECOVERY_DELAY_SEC) {
            printf("Not uploading the dump. Too many dumps.\n");
	    ret = STOP_UPLOAD;
	} else {
            printf("is_upload_limit_reached() not reached proceed for upload\n");
	    unlink(file);
	}
    }
    return ret;
}

int is_recovery_time_reached(const char *deny_file)
{
    struct stat st;
    FILE *fp;
    char buf[32];
    char *endptr;
    long deny_until;
    time_t now;

    if (!deny_file)
        return ALLOW_UPLOAD; /* allow upload */

    /* If deny file does not exist ?~F~R allow */
    if (stat(deny_file, &st) != 0)
        return ALLOW_UPLOAD;

    fp = fopen(deny_file, "r");
    if (!fp)
        return ALLOW_UPLOAD;

    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return ALLOW_UPLOAD;
    }
    fclose(fp);

    /* Validate numeric content */
    for (size_t i = 0; buf[i] != '\0' && buf[i] != '\n'; i++) {
        if (!isdigit((unsigned char)buf[i]))
            return ALLOW_UPLOAD;
    }

    deny_until = strtol(buf, &endptr, 10);
    if (endptr == buf)
        return ALLOW_UPLOAD;

    now = time(NULL);
    if (now == (time_t)-1)
        return ALLOW_UPLOAD;

    /* Recovery time reached */
    if (now > deny_until)
        return ALLOW_UPLOAD;

    /* Still in deny window */
    return STOP_UPLOAD;
}

int ratelimit_check_unified(dump_type_t dump_type)
{
    int status = -1;
    status = is_recovery_time_reached(DENY_UPLOADS_FILE);
    if (status != ALLOW_UPLOAD) {
        printf("Shifting the recovery time forward.\n");
	set_time(DENY_UPLOADS_FILE, CURRENT_TIME);
	return RATELIMIT_BLOCK;
    }
    if (dump_type == DUMP_TYPE_MINIDUMP) {
	status = is_upload_limit_reached("/tmp/.minidump_upload_timestamps");
        if (status != ALLOW_UPLOAD) {
	    printf("Upload rate limit has been reached.\n");
	    //TODO: markAsCrashLoopedAndUpload $f
	    printf("Setting recovery time\n");
	    set_time(DENY_UPLOADS_FILE, CURRENT_TIME);
	    status = RATELIMIT_BLOCK;
	}
    } else {
        status = ALLOW_UPLOAD;
    }
    return status;
}

#if 0
/* FULL IMPLEMENTATION - Load rate limit state from file */
static int load_state(void) {
    FILE *fp = fopen(RATE_LIMIT_FILE, "rb");
    if (!fp) {
        /* File doesn't exist - initialize fresh state */
        memset(&state, 0, sizeof(state));
        state_loaded = 1;
        return 0;
    }
    
    size_t read = fread(&state, sizeof(state), 1, fp);
    fclose(fp);
    
    if (read != 1) {
        /* Corrupted file - reset state */
        memset(&state, 0, sizeof(state));
    }
    
    state_loaded = 1;
    return 0;
}

/* FULL IMPLEMENTATION - Save rate limit state to file */
static int save_state(void) {
    FILE *fp = fopen(RATE_LIMIT_FILE, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to save rate limit state: %s\n", strerror(errno));
        return -1;
    }
    
    fwrite(&state, sizeof(state), 1, fp);
    fclose(fp);
    
    return 0;
}

/* FULL IMPLEMENTATION - Clean old timestamps outside time window */
static void clean_old_timestamps(void) {
    time_t now = time(NULL);
    int new_count = 0;
    time_t new_timestamps[MAX_UPLOADS];
    
    for (int i = 0; i < state.count; i++) {
        if ((now - state.timestamps[i]) < TIME_WINDOW_SECONDS) {
            new_timestamps[new_count++] = state.timestamps[i];
        }
    }
    
    state.count = new_count;
    memcpy(state.timestamps, new_timestamps, sizeof(time_t) * new_count);
}

/* FULL IMPLEMENTATION - Unified rate limit check (optimization: recovery + 10/10min combined) */
int ratelimit_check(void) {
    if (!state_loaded) {
        load_state();
    }
    
    time_t now = time(NULL);
    
    /* Optimization: Unified recovery mode check */
    if (state.recovery_mode) {
        /* In recovery mode - check if we should exit recovery */
        if (state.count == 0 || (now - state.timestamps[state.count - 1]) > TIME_WINDOW_SECONDS) {
            printf("RateLimit: Exiting recovery mode\n");
            state.recovery_mode = 0;
            save_state();
        } else {
            printf("RateLimit: Still in recovery mode, blocking upload\n");
            return -1;
        }
    }
    
    /* Optimization: Crashloop detection */
    if ((now - state.last_crashloop_check) < CRASHLOOP_WINDOW_SECONDS) {
        state.crashloop_count++;
        if (state.crashloop_count >= CRASHLOOP_THRESHOLD) {
            printf("RateLimit: Crashloop detected (%d uploads in %ld seconds), entering recovery mode\n",
                   state.crashloop_count, (long)(now - state.last_crashloop_check));
            state.recovery_mode = 1;
            state.crashloop_count = 0;
            save_state();
            return -1;
        }
    } else {
        /* Reset crashloop counter if window expired */
        state.crashloop_count = 1;
        state.last_crashloop_check = now;
    }
    
    /* Clean old timestamps */
    clean_old_timestamps();
    
    /* Optimization: 10/10min check */
    if (state.count >= MAX_UPLOADS) {
        time_t oldest = state.timestamps[0];
        time_t remaining = TIME_WINDOW_SECONDS - (now - oldest);
        
        printf("RateLimit: Upload limit reached (%d uploads in last 10 minutes)\n", MAX_UPLOADS);
        printf("RateLimit: Retry after %ld seconds\n", remaining);
        return -1;
    }
    
    return 0;
}

/* FULL IMPLEMENTATION - Record successful upload */
int ratelimit_record_upload(void) {
    if (!state_loaded) {
        load_state();
    }
    
    time_t now = time(NULL);
    
    /* Clean old timestamps first */
    clean_old_timestamps();
    
    if (state.count < MAX_UPLOADS) {
        state.timestamps[state.count++] = now;
        save_state();
        
        printf("RateLimit: Upload recorded (%d/%d in current window)\n", 
               state.count, MAX_UPLOADS);
        return 0;
    }
    
    return -1;
}

/* FULL IMPLEMENTATION - Reset rate limiter (for testing or manual recovery) */
int ratelimit_reset(void) {
    memset(&state, 0, sizeof(state));
    state_loaded = 1;
    save_state();
    
    printf("RateLimit: State reset\n");
    return 0;
}

/* FULL IMPLEMENTATION - Get current upload count */
int ratelimit_get_count(void) {
    if (!state_loaded) {
        load_state();
    }
    
    clean_old_timestamps();
    return state.count;
}

/* FULL IMPLEMENTATION - Check if in recovery mode */
int ratelimit_is_recovery_mode(void) {
    if (!state_loaded) {
        load_state();
    }
    
    return state.recovery_mode;
}
#endif
