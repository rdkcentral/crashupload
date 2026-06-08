# Subsystem Responsibility Analysis

## Subsystem Map
1. Trigger and orchestration subsystem
  - systemd units, timer/path, optional inotify watcher, uploadDumps.sh dispatcher.

2. Initialization and config subsystem
  - system_init, config_manager, platform.

3. Intake and qualification subsystem
  - prerequisites, lock_manager, scanner.

4. Packaging subsystem
  - archive, file utilities, log mapping in scanner.

5. Transport subsystem
  - upload module with endpoint discovery, metadata POST, S3 PUT.

6. Policy subsystem
  - ratelimit, privacy mode check, reboot flag behavior.

7. Operations and observability subsystem
  - logger and telemetry interface wrappers.

## Subsystem A: Trigger and orchestration
- Facts:
  - systemd timer and path units invoke uploadDumps.sh.
  - uploadDumps.sh chooses C vs legacy runtime branch and fallback.
- Inferences:
  - This layer is the primary operational policy switch for migration strategy.
- Unknowns:
  - exact service installation/enabling matrix per platform SKU.

## Subsystem B: Initialization and config
- Facts:
  - config_manager derives mode from argv and device properties.
  - platform subsystem builds identifier set (mac/model/sha1) with fallbacks.
- Risks:
  - mixed defaults and TODOs can hide platform-specific behavior gaps.

## Subsystem C: Intake and qualification
- Facts:
  - lock files ensure single active worker per dump type.
  - prerequisites include dump-presence check and optional deferred upload.
  - scanner enforces max file count and file-size stability gate.
- Inference:
  - stability gate mitigates racing with producer write completion.

## Subsystem D: Packaging
- Facts:
  - archive_create_smart creates tar.gz and can include mapped process logs.
  - filename normalization logic handles long names and container delimiter cleanup.
- Unknown:
  - full fidelity vs legacy script for all edge-case filename conventions.

## Subsystem E: Transport
- Facts:
  - endpoint resolution path includes RFC and device property fallback.
  - upload is two-step (metadata then object upload) with telemetry markers.
- Inference:
  - control plane and data plane are split, enabling signed URL workflows.

## Subsystem F: Policy (rate limit/privacy/reboot)
- Facts:
  - deny-window and upload timestamp files in /tmp govern upload throttling.
  - reboot flag can skip upload to avoid conflict during reboot transitions.
  - privacy DO_NOT_SHARE bypasses upload for mediaclient path.
- Assumption:
  - product-level privacy compliance also depends on paths outside this component.

## Subsystem G: Observability
- Facts:
  - component emits logs and T2 counters/values.
  - telemetry calls are feature-flag/build-flag dependent wrappers.
- Unknown:
  - production log routing and marker governance ownership.

## Cross-Cutting Concerns
- Device type branching significantly changes behavior.
- Build flags (RFC_API_ENABLED, RBUS_API_ENABLED, T2_EVENT_ENABLED, L2_TEST) alter effective runtime semantics.
- Legacy and C implementations coexist and must be jointly reasoned during change planning.
