# Operational and Deployment Model

## Service Startup and Triggering
- Fact: minidump-on-bootup-upload.timer starts a one-shot upload service 5 minutes after boot.
- Fact: coredump-upload.path watches a dump path and triggers coredump-upload.service.
- Fact: services execute uploadDumps.sh, not crashupload directly.

## One-shot vs Persistent Behavior
- crashupload binary: one-shot batch processor.
- uploadDumps.sh and runDumpUpload.sh: one-shot per trigger.
- inotify-minidump-watcher: persistent if deployed as long-running watcher.

## Event/Timer/Trigger Model
- Timer-driven boot catch-up.
- Path/inotify event-driven intake.
- Manual execution as fallback/ops option.

## Concurrency Model
- Single process per invocation.
- Intra-process sequential loop over detected dumps.
- Inter-process serialization via flock-based lock files.

## Filesystem Dependencies
### Input directories
- /opt/minidumps
- /minidumps
- /var/lib/systemd/coredump
- /opt/secure/minidumps
- /opt/secure/corefiles

### Logging and metadata files
- core_log.txt location derived from device type/log path.
- /version.txt consumed for firmware metadata.
- /etc/breakpad-logmapper.conf used for mapping process to log files.

### Runtime state files
- locks, deny windows, upload timestamp ledgers, startup cleanup flags, reboot flags.

## Temp and Persistence Characteristics
- Fact: major state files are in /tmp and therefore non-persistent across reboot.
- Inference: reboot naturally resets some throttling/lock state while stored artifacts may persist in non-/tmp directories.

## Network Dependencies
- Outbound HTTPS/TLS path for metadata and S3 upload.
- endpoint/url discovery depends on RFC/property availability.
- Unknown: proxy, certificate chain, DNS behavior per deployment environment.

## Security-Sensitive Boundaries
- Artifact contents may include crash dumps, URLs, and copied logs.
- Device identity information is embedded in artifact naming/metadata.
- Privacy gating exists but scoped by branch/device conditions.
- Unknown: complete data retention and regulatory controls beyond component boundaries.

## Observability and Operability
- Logging via crashupload logger wrappers and core logs.
- telemetry events/counters emitted conditionally.
- L2 test harness indicates extensive behavioral scenarios covered for C path.

## Deployment Observations for Brownfield Migration
- Fact: mixed shell/C coexistence remains in repository.
- Inference: deployment is likely phased by device type and image maturity.
- Recommendation: OpenSpec changes should declare target path (C-only, legacy-only, or dual-path) and expected service wiring explicitly.
