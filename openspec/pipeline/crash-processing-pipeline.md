# Crash Processing Architecture

## End-to-End Pipeline

## Stage 0: Crash producers (outside this repo)
- Fact: this repository consumes files from directories such as /opt/minidumps, /minidumps, /var/lib/systemd/coredump, /opt/secure/*.
- Inference: crash producers include kernel/systemd coredump handlers and breakpad/minidump producers.
- Unknown: exact producer process tree and ordering on each RDK profile.

## Stage 1: Intake trigger
- Fact: systemd timer/path/service and optional inotify watcher trigger upload orchestration script.
- Fact: intake is filesystem event/time driven, not explicit queue RPC.

## Stage 2: Dispatch and runtime selection
- Fact: uploadDumps.sh selects C binary or legacy path by device type and fallback state.
- Inference: dispatch script is compatibility seam and should be treated as architectural control point.

## Stage 3: Preconditions and eligibility
- Fact: lock acquisition enforces one concurrent worker per dump type.
- Fact: prerequisite check verifies dump presence and may defer mediaclient uploads to uptime threshold.
- Fact: privacy mode DO_NOT_SHARE blocks upload path in mediaclient branch.

## Stage 4: Artifact discovery and normalization
- Fact: scanner inspects working directory and classifies files by extension/pattern.
- Fact: write-stability check reduces partial-file processing risk.
- Fact: filename sanitization preserves container delimiter token and strips disallowed characters.
- Fact: telemetry extraction parses process/container cues from filename conventions.

## Stage 5: Metadata enrichment and packaging
- Fact: renamed artifact names include platform SHA1, MAC, date stamp, box type, model, and original tail name.
- Fact: version metadata sourced from /version.txt or extracted from tarball version.txt in utility logic.
- Fact: archive_create_smart composes tar.gz with dump + version + core log + optional mapped process logs + optional crashed_url file.

## Stage 6: Upload transport
- Fact: mediaclient upload path performs metadata POST (for signed URL) then S3 PUT upload.
- Fact: endpoint and encryption toggles can come from RFC, with fallback to device properties/defaults.
- Fact: OCSP enable flags are file-based toggles (/tmp/.EnableOCSPStapling or /tmp/.EnableOCSPCA).

## Stage 7: Retry/backoff/failure semantics
- Fact: upload_file has bounded retry attempts and fixed sleep between failures.
- Fact: minidump uploads update timestamp ledger on success.
- Fact: rate-limit block can purge pending dumps matching dump/archive patterns.
- Inference: current behavior favors preventing runaway upload loops over guaranteed eventual delivery.

## Stage 8: Post-upload cleanup/retention
- Fact: successful upload removes local archive.
- Fact: startup and end cleanup remove stale files, enforce max retained recent files, and clear non-dump residue based on policy.
- Fact: DO_NOT_SHARE mode triggers cleanup of pending dumps in configured path.

## Ownership Boundaries
### Crash producers
- Outside repository (systemd-coredump, app crash handlers, breakpad pathways).

### Collection logic
- scanner, prerequisites, lock manager, cleanup batch, platform/config initialization.

### Local staging/spool
- Working directories and generated .tgz archives; /tmp marker files as state controls.

### Transport/upload
- upload module and external upload utility/TLS helpers.

### Server/API integration
- RFC-configured metadata endpoint and signed URL flow to S3 upload target.

## Security and Privacy Sensitive Data Handling
- Fact: payload and metadata include device identifiers (MAC/model/platform hash), firmware info, process names, and potentially logs.
- Fact: privacy control mode can disable uploads for mediaclient.
- Inference: archives may contain sensitive operational data; retention and transport controls are security-critical.
- Unknown: at-rest encryption guarantees for local spool files and policy enforcement outside this component.

## Facts vs Inferences Summary
- Fact: file-based crash pipeline with batch processing and explicit cleanup markers.
- Fact: S3 pre-signed URL based upload flow with telemetry and retry.
- Inference: durability is best-effort file queue rather than strict exactly-once processing.
- Assumption: network outages are expected and partially handled by repeated triggering + retained files.
- Unknown: end-to-end idempotency at server side.
