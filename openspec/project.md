# Crashupload Baseline Architecture Dossier

## Scope and Intent
This document is the canonical OpenSpec baseline for the current crashupload repository as-is. It captures runtime behavior for a brownfield embedded Linux/RDK crash collection and upload system, with code-truth priority over naming and README claims.

Classification used throughout:
- Fact: directly verified in repository source/build/service artifacts.
- Inference: strongly implied by verified control flow or deployment wiring.
- Assumption: reasonable but not directly verified in this repository snapshot.
- Unknown: requires manual validation on target device/image/runtime.

## System Purpose
- Fact: The repository implements device-side crash artifact discovery, packaging, and upload logic across shell and C paths (uploadDumps.sh, runDumpUpload.sh, c_sourcecode/src/main.c, upload.c).
- Fact: System supports minidump and coredump handling with device-type branching (mediaclient, broadband, extender) in configuration logic (config_manager.c).
- Inference: The platform is in migration: C binary path is primary for mediaclient where available; shell legacy remains active and is still primary for some device types.

## High-Level Architectural Overview
The runtime is not a single daemon. It is an event/timer/script orchestrated one-shot execution model.

Core layers:
1. Trigger layer
- systemd path/timer/services and optional inotify watcher trigger uploadDumps.sh.
2. Orchestration layer
- uploadDumps.sh chooses crashupload binary or legacy runDumpUpload.sh path depending on device type and fallback conditions.
3. Processing layer
- C binary performs initialization, locking, prerequisite gating, scanning, naming/sanitization, archive creation, upload, and cleanup.
4. Integration layer
- Device properties/include properties, RFC, RBUS privacy control, telemetry (T2), partner/model APIs, upload utility/TLS helpers.

Supporting documentation:
- Runtime component catalog: openspec/runtime/component-catalog.md
- Runtime behavior and lifecycle: openspec/runtime/execution-model.md
- Crash pipeline deep dive: openspec/pipeline/crash-processing-pipeline.md
- Subsystem responsibilities: openspec/subsystems/subsystem-analysis.md
- External/client integration model: openspec/integrations/client-integration-model.md
- Operational/deployment model: openspec/runtime/operational-deployment-model.md
- Visual diagrams: openspec/diagrams/architecture-diagrams.md
- Gaps and validation checklist: openspec/gaps/known-unknowns-and-validation.md
- Change readiness matrix: openspec/gaps/change-readiness-matrix.md

## Runtime Models
### 1) Triggered one-shot upload execution
- Fact: coredump-upload.service invokes /lib/rdk/uploadDumps.sh with dump flag argument 0.
- Fact: minidump-on-bootup-upload.timer starts minidump-on-bootup-upload.service after boot delay; service invokes uploadDumps.sh.
- Fact: Legacy inotify-minidump-watcher binary can watch a directory and execute upload script on IN_CREATE matches.
- Inference: Primary runtime mode is event/timer triggered batches, not continuously running upload daemon logic in the C path.

### 2) Orchestrated dual-path runtime (C and shell)
- Fact: uploadDumps.sh delegates to /usr/bin/crashupload if present for mediaclient; falls back to legacy runDumpUpload.sh on failure or for non-mediaclient paths.
- Fact: broadband/extender branches in uploadDumps.sh currently force legacy path.
- Inference: Production may be mixed-fleet with both paths active depending on image/device characteristics.

### 3) Batch crash processing runtime
- Fact: C main loop scans working directory for candidate dumps, processes up to scanner MAX_DUMPS (5), archives each, then uploads sequentially.
- Fact: One lock per dump type (/tmp/.uploadMinidumps or /tmp/.uploadCoredumps) enforces single-instance semantics.

## Process Relationships
- systemd units/timers/path -> uploadDumps.sh
- uploadDumps.sh -> crashupload binary OR runDumpUpload.sh legacy shell flow
- crashupload binary -> internal modules (config/platform/prerequisites/scanner/archive/upload/ratelimit/cleanup)
- crashupload binary -> external APIs/libraries (RFC/RBUS/T2/common_device_api/uploadutil/libarchive/libcurl)

## Crash Intake vs Processing vs Upload Model
### Intake
- Fact: Intake is file-system based discovery in configured working directories; no direct producer IPC API in C code.
- Fact: Discovery patterns vary by mode/device type (for example *.dmp*, *core.prog*.gz*).

### Processing
- Fact: Candidate file names are sanitized; telemetry extraction parses process/container cues from names; optional mapped process logs are added.
- Fact: Artifact naming embeds platform SHA1, MAC, timestamp, box type, model, and original file name (with length trimming logic).

### Upload
- Fact: Upload path for mediaclient is two-phase: metadata POST to get S3 signed URL, then S3 PUT upload.
- Fact: Upload flow records telemetry markers, supports limited retries, and removes uploaded artifacts on success.
- Fact: Minidump success appends timestamp marker file for rate limiting.

## IPC / Trigger / Integration Architecture Summary
- Fact: Trigger model is systemd path/timer/service and optional inotify command execution.
- Fact: Privacy mode is read from RBUS parameter Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode for mediaclient path.
- Fact: Configuration and endpoint resolution uses device properties/include properties, RFC reads, and fallback defaults.
- Fact: Observability uses logging plus T2 counters/values; TLS failures can emit specialized logs.
- Unknown: Exact production wiring between coredump generators and trigger units across all RDK variants.

## Persistent State, Spool, Queue, Temp, Retry
- Fact: Persistent-ish state files in /tmp include lock files, deny window file, minidump upload timestamps, startup cleanup flags.
- Fact: Working directories are used as local spool/staging; archives are created in place and then uploaded.
- Fact: On some failures/rate-limit conditions, pending dumps can be removed by cleanup routines.
- Inference: Queue semantics are file-system queue with periodic/event batch drain, not transactional durable queue.

## Baseline Quality Notes for OpenSpec Adoption
- Fact: Source contains explicit TODO/SKELETON markers in several modules despite active behavior; implementation maturity differs by module/device path.
- Inference: OpenSpec changes should explicitly scope by device type and runtime path (C vs legacy shell) to avoid accidental regressions.
- Recommendation: Use this baseline as "as-built/as-run" foundation; avoid relying on README performance/feature claims without runtime validation.

## Primary Evidence Files
- c_sourcecode/src/main.c
- c_sourcecode/src/config/config_manager.c
- c_sourcecode/src/init/system_init.c
- c_sourcecode/src/platform/platform.c
- c_sourcecode/src/utils/prerequisites.c
- c_sourcecode/src/scanner/scanner.c
- c_sourcecode/src/archive/archive.c
- c_sourcecode/src/upload/upload.c
- c_sourcecode/src/ratelimit/ratelimit.c
- c_sourcecode/src/utils/cleanup_batch.c
- c_sourcecode/src/utils/lock_manager.c
- c_sourcecode/src/rfcInterface/rfcinterface.c
- c_sourcecode/src/rbusInterface/rbus_interface.c
- c_sourcecode/src/t2Interface/telemetryinterface.c
- coredump-upload.service
- coredump-upload.path
- minidump-on-bootup-upload.service
- minidump-on-bootup-upload.timer
- uploadDumps.sh
- runDumpUpload.sh
- src/inotify-minidump-watcher.c
- c_sourcecode/src/Makefile.am
- c_sourcecode/configure.ac
