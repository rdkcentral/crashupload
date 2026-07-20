# Runtime Execution Model

## Execution Modes
### Mode 1: Mediaclient preferred C path
- Fact: uploadDumps.sh selects crashupload binary if present.
- Fact: binary may fall back to legacy via script if exit code indicates failure and dispatcher chooses fallback.

### Mode 2: Broadband/extender legacy path
- Fact: uploadDumps.sh directly invokes runDumpUpload.sh for broadband/extender.
- Fact: upload.c currently marks broadband branch unsupported for C upload_process.

### Mode 3: Manual/diagnostic invocation
- Inference: crashupload can be executed directly with argument contract expected by main (argv[2] dump type flag; optional secure/wait_for_lock flags).
- Unknown: direct CLI contract stability across releases.

## Detailed C Binary Flow (Observed)
1. Preconditions and argument check
- argc must be >= 3.
- argv[2] determines dump type branch: 0 minidump, 1 coredump.

2. Locking and signal behavior
- lock file path set by dump type.
- SIGTERM handler removes lock file based on active mode.
- lock mode optional wait_for_lock causes blocking lock behavior.

3. Initialization
- t2 init, config load, platform init, core log creation.

4. Prerequisite gate
- dump presence check in expected directory.
- mediaclient deferral to 480 seconds uptime threshold.
- optional coredump completion wait logic tied to mutex flag file.

5. Privacy gate
- mediaclient reads RBUS privacy mode.
- DO_NOT_SHARE skips upload, but cleanup path still executes.

6. Startup cleanup and scan
- cleanup_batch runs before and after processing.
- scanner finds candidate files and ensures size stability.

7. Per-dump processing
- sanitize/rename/telemetry extraction.
- metadata naming with mac/date/box/model/process context.
- archive creation with selected sidecar files.

8. Rate limit and reboot checks
- skip upload if reboot flag present.
- global deny-window (`/tmp/.deny_dump_uploads_till`) is evaluated before dump-type specific checks and can block both minidump and coredump uploads while active.
- minidump upload-counter check (`/tmp/.minidump_upload_timestamps`) is only evaluated for minidump runs.
- when blocked, pending dumps in the active working directory can be removed.

9. Upload loop
- sequential upload per archive.
- break on first upload error.

10. Cleanup and termination
- cleanup batch rerun.
- release lock, uninit telemetry, exit with ret code.

## Concurrency and Process Model
- Fact: single-process, mostly sequential processing.
- Fact: no explicit multithreading in processing path.
- Fact: inter-process concurrency controlled by flock lock files.
- Inference: throughput scales by trigger frequency and batch size rather than parallel upload workers.

## State and File Semantics
### Locking
- /tmp/.uploadMinidumps
- /tmp/.uploadCoredumps

### Rate limit and deny windows
- /tmp/.minidump_upload_timestamps
- /tmp/.deny_dump_uploads_till
- policy note: deny-window is global cooldown; minidump timestamp file is minidump-only counter state.

### Startup/cleanup markers
- /tmp/.on_startup_dumps_cleaned_up_<flag>
- /opt/.upload_on_startup

### Reboot/flow flags
- /tmp/set_crash_reboot_flag
- /tmp/coredump_mutex_release (checked in prerequisites path)

## Failure Handling Semantics
- Fact: lock contention in non-wait mode exits quickly.
- Fact: scan failures/no dumps route to cleanup and often zero exit.
- Fact: upload failure breaks remaining upload loop.
- Fact: cleanup is best-effort and often non-fatal.
- Unknown: upstream service restart policies and retry cadence on non-zero exits.

## Execution Truth vs Expectations
- Fact: several comments indicate optimized 7-step conceptual flow, but implementation includes TODOs and mixed maturity.
- Inference: OpenSpec work should baseline on observed behavior rather than intended design commentary.
