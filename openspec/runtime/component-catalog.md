# Runtime Component Catalog and Binary Analysis

## Overview
This section catalogs meaningful runtime components and analyzes startup path, invoker, initialization, config loading, artifact handling, upload path, retry/failure handling, and cleanup.

## Component A: crashupload C binary
- Binary target: crashupload (c_sourcecode/src/Makefile.am)
- Entry point: main in c_sourcecode/src/main.c
- Intended invoker:
  - Fact: uploadDumps.sh delegates to /usr/bin/crashupload when available (mediaclient branch).
  - Inference: can also be invoked directly by service wrappers or operators.
- Startup path:
  1. logger_init
  2. signal handler install for SIGTERM
  3. system_initialize (t2 init + config + platform)
  4. lock acquisition per dump type
  5. prerequisite check
  6. scan/process/archive/upload loop
  7. cleanup, lock release, t2 uninit, logger_exit

### Initialization flow
- Fact: system_initialize creates core log file if missing and chmod 0666.
- Fact: config_init_load resolves device_type, build_type, dump_type, upload mode (secure/normal), paths, and T2 enablement.
- Fact: platform_initialize resolves mac/model/platform sha1 with fallback defaults.

### Configuration loading
- Fact: device/include property reads via getDevicePropertyData/getIncludePropertyData.
- Fact: RFC and RBUS used selectively in later stages (privacy and upload endpoint/encryption toggles).
- Inference: image-specific API implementations behind these symbols are critical runtime dependency.

### Crash discovery and staging
- Fact: working_dir_path selected from mode/device type.
- Fact: scanner_find_dumps scans one directory (no deep recursion), max 5 files per run, checks write-completion stability.
- Fact: process_file_entry sanitizes and may rename files before archive step.

### Packaging and metadata
- Fact: archive_create_smart renames dump to normalized name, gathers version/core_log and optional mapped process logs.
- Fact: coredump and minidump archives differ in naming and included members.
- Fact: tar.gz creation uses libarchive with optional lower priority.

### Upload execution
- Fact: upload_process supports mediaclient path; broadband/extender branch currently returns unsupported in upload.c.
- Fact: upload_file performs metadata POST to get pre-signed URL and then S3 PUT.
- Fact: per-file upload loop in main breaks on first failure.

### Retry, failure, cleanup
- Fact: upload_file has bounded retry loop (3 attempts in current code).
- Fact: successful upload removes local archive and for minidump appends timestamp file for rate limit accounting.
- Fact: cleanup_batch executes at startup and cleanup label; lock is always released on cleanup path if acquired.

## Component B: uploadDumps.sh orchestration script
- Entry point: /lib/rdk/uploadDumps.sh
- Intended invoker:
  - systemd service/timer/path units
  - optional inotify watcher command execution
- Operational model: lightweight dispatcher with fallback logic.
- Core behavior:
  - Fact: for mediaclient, attempts crashupload binary unless /tmp/.legacy_crashuploader exists.
  - Fact: on binary critical/non-zero failures, falls back to runDumpUpload.sh.
  - Fact: for broadband/extender, directly runs legacy path.

## Component C: runDumpUpload.sh legacy flow
- Entry point: /lib/rdk/runDumpUpload.sh
- Intended invoker: uploadDumps.sh fallback or direct legacy deployment.
- Operational model: monolithic shell workflow sourcing multiple helper scripts.
- Behavior highlights:
  - loads device/include properties and many platform scripts.
  - sets core/minidump paths by device type and secure mode.
  - checks for dump presence before deeper processing.
- Unknown: full effective runtime depends on sourced scripts not fully analyzed here.

## Component D: inotify-minidump-watcher
- Binary: src/inotify-minidump-watcher.c built by src/Makefile
- Intended invoker: service or manual process configured to monitor a directory.
- Operational model: persistent watcher using inotify IN_CREATE.
- Startup path: directory_watcher(directory, command, args, patterns)
- Trigger action:
  - on matching file creation, executes shell command and arguments.
- Inference: this component is a trigger helper, not the uploader itself.

## Component E: systemd units and triggers
### coredump-upload.path + coredump-upload.service
- Path unit watches /minidumps PathChanged.
- Service executes uploadDumps.sh with arguments.
- Inference: despite service naming coredump-upload, observed path trigger references /minidumps and should be manually validated in target image.

### minidump-on-bootup-upload.timer + service
- Timer triggers after boot delay (OnBootSec=5min).
- Service executes uploadDumps.sh.
- Inference: used to drain boot-time crashes after network/device initialization period.

## Component F: Linked integration libraries
From c_sourcecode/src/Makefile.am:
- libcurl, openssl, zlib, pthread, archive, uploadutil
- rfcapi, rbus, telemetry_msgsender/t2utils, dwnlutil/fwutils/secure_wrapper/parsejson

Inference:
- Crashupload behavior depends substantially on external RDK libraries and build flags (RFC_API_ENABLED, RBUS_API_ENABLED, T2_EVENT_ENABLED).

## Component-by-Component Evidence Tags
- Fact: main runtime control in c_sourcecode/src/main.c
- Fact: build composition in c_sourcecode/src/Makefile.am and c_sourcecode/configure.ac
- Fact: orchestration/fallback in uploadDumps.sh
- Fact: legacy path in runDumpUpload.sh
- Fact: trigger options in coredump-upload.path, minidump-on-bootup-upload.timer, and inotify-minidump-watcher.c

## OpenSpec Baseline Conclusions
- Inference: meaningful architectural unit for future changes is not only the C binary; it is trigger + dispatcher + C/legacy dual path + external integrations.
- Assumption: some production images may bypass certain components; deployment profile should be treated as variable and captured per-platform in future OpenSpec change specs.
