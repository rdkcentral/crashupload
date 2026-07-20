# Client and Integration Model

## External Interaction Surfaces

## 1) CLI / command interfaces
### uploadDumps.sh
- Primary external entry for services and helper watchers.
- Accepts positional arguments passed through to selected runtime path.

### crashupload binary
- Fact: current main expects positional flags where argv[2] determines dump mode (0 minidump, 1 coredump) and optional argv[3]=secure, argv[4]=wait_for_lock.
- Inference: practical CLI contract is script-oriented rather than end-user friendly options.

### inotify-minidump-watcher
- Usage includes directory, command, args, and file patterns.
- Executes configured command when matching file is created.

## 2) System integration points
- systemd units and timer/path triggers.
- Filesystem directories as crash intake source and local spool.
- Marker/flag files in /tmp and /opt governing policy and control flow.

## 3) Library/API integrations
- Property/config: getDevicePropertyData, getIncludePropertyData, GetPartnerId, GetModelNum, etc.
- Policy/config APIs: RFC parameter read/write, RBUS privacy parameter reads.
- Telemetry: T2 events for counters and split values.
- Upload/security: uploadutil and TLS/curl stack.

## Request Lifecycle: Trigger to Completion
1. Trigger source invokes uploadDumps.sh.
2. Dispatcher selects C or legacy path.
3. Runtime initializes config/platform and lock.
4. Runtime verifies eligibility (dumps present, deferral/privacy/reboot/rate-limit rules).
5. Runtime discovers and normalizes artifacts.
6. Runtime archives payload with metadata/log context.
7. Runtime performs upload workflow.
8. Runtime records outcome markers and cleanup.
9. Runtime exits with status consumed by invoker policy.

## Intended Caller Workflows
### Systemd boot workflow
- Timer fires after boot window, invoking minidump processing path via uploadDumps.sh.

### Filesystem event workflow
- Path/inotify detects dump creation, invokes upload script.

### Manual operator workflow
- invoke script or binary for diagnostics/retry scenarios.

## Configuration and Environment Dependencies
- Files:
  - /etc/device.properties
  - /etc/include.properties
  - /etc/breakpad-logmapper.conf
- Runtime dirs:
  - /opt/minidumps, /minidumps, /var/lib/systemd/coredump, /opt/secure/*
- Runtime flags/markers:
  - /tmp/.uploadMinidumps, /tmp/.uploadCoredumps
  - /tmp/.minidump_upload_timestamps, /tmp/.deny_dump_uploads_till
  - /tmp/set_crash_reboot_flag
  - /opt/.upload_on_startup

## Rate-Limit State Semantics
- /tmp/.deny_dump_uploads_till: global cooldown gate; if active, upload processing is blocked regardless of dump type.
- /tmp/.minidump_upload_timestamps: minidump-only rolling counter used to trigger cooldown when upload volume exceeds threshold.

## Device-Side vs External Integration Boundaries
- Device-side only:
  - file scanning, archive composition, local policy gates, cleanup.
- Externally integrated:
  - RFC/RBUS data sources, telemetry backplane, crash portal endpoint/signed URL service, S3 upload endpoint.

## Integration Risks for OpenSpec Planning
- Fact: behavior differs strongly by device type and runtime branch.
- Fact: some integration paths are stubs or unsupported in specific branches (for example broadband in upload.c).
- Inference: future changes should specify per-device/path applicability and rollback strategy.
