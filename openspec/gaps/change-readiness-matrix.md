# Change Readiness Matrix

## Purpose
Map likely future OpenSpec proposals to impacted runtime paths, subsystem blast radius, and risk tiers so teams can scope brownfield changes safely.

Risk tier definitions:
- Critical: likely to impact crash loss, privacy compliance, or fleet stability if changed incorrectly.
- High: broad runtime impact across multiple subsystems or device branches.
- Medium: meaningful behavioral impact but bounded by feature/device scope.
- Low: localized impact with limited cross-subsystem coupling.

## Matrix
| Proposal Theme | Candidate OpenSpec Change | Primary Impacted Runtime Paths | Key Impacted Components | Risk Tier | Why This Tier | Minimum Validation Gate |
|---|---|---|---|---|---|---|
| Runtime path convergence | Migrate broadband/extender from legacy shell to C upload path | uploadDumps.sh dispatcher, crashupload upload_process, service triggers | uploadDumps.sh, runDumpUpload.sh, c_sourcecode/src/upload/upload.c, config_manager.c | Critical | Alters active execution path for whole device classes and changes failure semantics | Device-type A/B execution validation, upload success/failure parity, rollback toggle |
| Dispatcher policy hardening | Replace implicit fallback policy with explicit, configurable decision matrix | uploadDumps.sh, service call contracts | uploadDumps.sh, service units, error/exit contracts | High | Fallback policy is current safety net; mis-change can black-hole uploads | Failure injection for binary errors and unavailable dependencies, fallback observability checks |
| Trigger wiring correction | Align unit naming, watched paths, and trigger intent | coredump-upload.path/service, timer units | coredump-upload.path, coredump-upload.service, minidump-on-bootup-upload.timer/service | High | Trigger miswiring can prevent intake entirely or create noisy retrigger loops | On-device unit enablement audit plus synthetic crash trigger tests |
| Prerequisite completion | Implement full network/time readiness behavior in C path | prerequisites gate before scan/upload | c_sourcecode/src/utils/prerequisites.c, main.c | High | Gate currently partial; adding checks can unintentionally block all uploads | Offline/slow-network/time-sync test matrix with bounded timeout behavior |
| Privacy consistency | Enforce equivalent DO_NOT_SHARE behavior across C and legacy paths | dispatcher + both runtimes | config_manager.c, rbus_interface.c, uploadDumps.sh, runDumpUpload.sh | Critical | Privacy controls are compliance-sensitive and currently branch-dependent | Cross-path privacy-mode tests with artifact retention/deletion verification |
| Queue durability | Add durable spool/state outside /tmp for retry continuity | state management and cleanup | ratelimit.c, cleanup_batch.c, main.c, service scheduling | High | Changes persistence model, recovery behavior, and storage pressure profile | Power-cycle/reboot fault injection and duplicate-upload/idempotency checks |
| Retry/backoff modernization | Add adaptive backoff and error-class retry policy | upload transport loop | upload.c, telemetry markers, dispatcher retry interaction | Medium | Bounded to transport but affects latency and success rates | Endpoint fault-injection tests and retry telemetry conformance |
| Archive content policy | Standardize archive members and log inclusion limits | packaging and privacy surface | archive.c, scanner.c, file_utils.c, log mapper behavior | High | Alters payload shape and potentially sensitive data exposure | Payload contract diffing and privacy data minimization review |
| Filename/metadata contract | Normalize naming schema and long-name handling rules | scanner -> archive naming chain | scanner.c, main.c, archive.c, file_utils.c | Medium | Affects backend parsing and dedupe assumptions | Backward-compat parsing tests against existing backend expectations |
| Cleanup and retention policy | Rework startup/end cleanup behavior and pending-dump purge rules | cleanup phases and rate-limit side effects | cleanup_batch.c, ratelimit.c, main.c | High | Cleanup can delete artifacts before successful upload if misconfigured | Retention regression tests for success/failure/rate-limit/privacy branches |
| Observability unification | Rationalize log + telemetry markers across paths | C and legacy observability | telemetryinterface.c, logger.c, uploadDumps.sh/runDumpUpload.sh markers | Medium | Low direct functional risk but high operational diagnosis impact | Marker inventory conformance and dashboard compatibility checks |
| Endpoint/config resolution | Unify RFC/property precedence and fallback defaults | upload endpoint resolution and config load | upload.c, rfcinterface.c, config_manager.c | High | Misordered precedence can route traffic incorrectly or fail uploads | Config precedence test matrix with malformed/empty RFC/property scenarios |
| Security hardening | Tighten TLS/cert/OCSP behavior and endpoint validation | transport and cert handling | upload.c, file_utils.c (tls_log), uploadutil integration | High | Security changes can silently break connectivity across fleet | Certificate rotation and TLS failure-mode drill with controlled cert errors |
| Concurrency model evolution | Move from single-worker lock model to parallel workers or queue workers | locking, scanning, upload loop | lock_manager.c, main.c, scanner.c, cleanup_batch.c | Critical | Race and duplicate processing risk rises sharply with concurrency | Concurrency stress tests for duplicate upload, lock correctness, and cleanup races |
| API surface cleanup | Replace positional args with explicit CLI contract for crashupload | invocation and integration contracts | main.c, uploadDumps.sh, service ExecStart lines, tests | Medium | Mostly integration contract risk, manageable with wrappers | Backward-compat wrapper tests and service/script invocation migration checks |

## Change Readiness by Area
| Area | Current Readiness | Notes |
|---|---|---|
| Trigger/orchestration changes | Medium | Good visibility, but mixed path deployment increases regression risk |
| C pipeline internals | Medium | Core flow is traceable; some TODO/SKELETON areas remain |
| Legacy pipeline modifications | Low | Significant behavior spread across sourced scripts not fully baseline-mapped |
| Cross-path parity initiatives | Low | High validation burden due to divergent behaviors by device type |
| Observability-only changes | High | Lower runtime blast radius if marker compatibility is preserved |

## Suggested Ownership Cut for Future OpenSpec Proposals
- Platform/Service owner: trigger units, deployment wiring, dispatcher policy.
- Crash pipeline owner: scan/package/upload/cleanup behavior.
- Privacy/security owner: privacy-mode enforcement, payload policy, TLS/cert controls.
- SRE/operations owner: telemetry contracts, runbook updates, failure-mode acceptance.

## Recommended Proposal Template Additions
For each future OpenSpec change, include:
1. Target runtime paths: C, legacy, or both.
2. Device-type applicability matrix.
3. Trigger and invocation contracts affected.
4. Data handling and privacy impact statement.
5. Fault-injection validation plan and rollback lever.
6. Telemetry and operational acceptance criteria.
