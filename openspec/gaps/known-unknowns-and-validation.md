# Known Gaps, Unknowns, and Validation Checklist

## Purpose
Track uncertainty and manual validation needs before using this baseline for design-impacting OpenSpec changes.

Related planning artifact:
- openspec/gaps/change-readiness-matrix.md

## A) High-confidence Facts with Potential Risk
1. Mixed runtime paths remain active
- Fact: C and legacy shell paths coexist with dispatcher fallback.
- Risk: behavior diverges by device type and deployment.

2. Upload implementation asymmetry by device type
- Fact: upload.c currently handles mediaclient path; broadband branch in C upload_process returns unsupported.
- Risk: assumptions of feature parity across SKUs may be incorrect.

3. Trigger naming/path mismatch potential
- Fact: coredump-upload.path watches /minidumps.
- Risk: unit naming may not reflect actual watched path semantics.

## B) Strong Inferences to Validate
1. Trigger reliability and retries
- Inference: repeated service/timer/path activations provide eventual retry.
- Validate: systemd restart/retry policies and trigger frequency in target image.

2. End-to-end data retention expectations
- Inference: file-system queue behavior is best-effort, not durable transactional queue.
- Validate: retention requirements and loss tolerance under power/network faults.

3. Privacy coverage completeness
- Inference: privacy gate mainly enforced in mediaclient C path.
- Validate: equivalent controls in legacy and non-mediaclient flows.

## C) Explicit Assumptions
1. External RDK APIs are available and stable
- Assumption: getDevicePropertyData, RFC, RBUS, telemetry APIs resolve correctly at runtime.

2. Security and certificate handling are managed by linked libraries and system config
- Assumption: trust chain and mTLS/cert rotation are correctly provisioned in target image.

3. Crash producer locations match configured paths
- Assumption: producers reliably deposit artifacts in paths selected by current config logic.

## D) Unknowns Requiring Manual Validation
1. Full legacy pipeline behavior from sourced scripts
- Unknown: runDumpUpload.sh depends on multiple sourced scripts not fully analyzed in this baseline.

2. Producer-to-trigger wiring across all RDK variants
- Unknown: exact mechanism from crash event to service/path trigger differs by image.

3. Operational SLAs and server-side idempotency
- Unknown: how remote backend deduplicates or handles partial retries.

4. Sensitive data governance
- Unknown: data retention, encryption at rest, and privacy policy scope outside this component.

## E) Suggested Validation Checklist for Next OpenSpec Change
1. Runtime path inventory per target device type
- Confirm whether C path, legacy path, or both are active.

2. Trigger matrix validation
- Verify enabled units and actual watched paths on device.

3. Endpoint and credential resolution test
- Validate RFC/property precedence and fallback behavior.

4. Privacy-mode test matrix
- Validate DO_NOT_SHARE behavior across all active runtime paths.

5. Failure-mode drills
- Network outage, metadata endpoint failure, S3 failure, reboot race, lock contention.

6. Retention and cleanup audit
- Confirm expected deletion policy for pending/failed/successful artifacts.

7. Telemetry contract validation
- Confirm marker names, routing, and observability dashboards.

## F) Prioritized Modernization Opportunities (from baseline)
1. Unify C and legacy behavior per device type to reduce divergence.
2. Make network/time prerequisite logic explicit and complete (currently partial/TODO).
3. Add explicit durable spool semantics if reliability requirements demand it.
4. Normalize trigger naming/wiring documentation with actual runtime paths.
5. Add machine-readable architecture contract in OpenSpec for path-by-device behavior.
