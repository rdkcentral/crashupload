/* FULL IMPLEMENTATION - Rate limiter with unified recovery + 10/10min check */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#define RATE_LIMIT_FILE "/tmp/.crashupload_ratelimit"
#define MAX_UPLOADS 10
#define TIME_WINDOW_SECONDS (10 * 60)  /* 10 minutes */
#define CRASHLOOP_THRESHOLD 5
#define CRASHLOOP_WINDOW_SECONDS 60

typedef struct {
    time_t timestamps[MAX_UPLOADS];
    int count;
    int crashloop_count;
    time_t last_crashloop_check;
    int recovery_mode;
} ratelimit_state_t;

static ratelimit_state_t state = {0};
static int state_loaded = 0;

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
