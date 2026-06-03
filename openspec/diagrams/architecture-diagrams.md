# Architecture Diagrams

## 1) System Context and Layering
```mermaid
flowchart TB
  classDef trigger fill:#e8f1ff,stroke:#3b6ea8,color:#123;
  classDef orchestration fill:#eaf8ef,stroke:#2e7d4f,color:#123;
  classDef runtime fill:#fff4e6,stroke:#9a6c1f,color:#123;
  classDef integration fill:#f3ecff,stroke:#6d4aa0,color:#123;
  classDef external fill:#fdeeee,stroke:#a64545,color:#123;

  subgraph L1[Trigger Layer]
    T1[systemd timer/path/service]
    T2[inotify-minidump-watcher]
  end

  subgraph L2[Orchestration Layer]
    O1[uploadDumps.sh dispatcher]
    O2[runDumpUpload.sh legacy path]
  end

  subgraph L3[Runtime Layer]
    R1[crashupload main]
    R2[scanner + prerequisites + lock]
    R3[archive packaging]
    R4[upload transport]
    R5[cleanup + ratelimit]
  end

  subgraph L4[Integration Layer]
    I1[device/include properties]
    I2[RFC + RBUS]
    I3[T2 telemetry]
    I4[uploadutil/libcurl/libarchive]
  end

  subgraph L5[External Services]
    E1[Crash metadata endpoint]
    E2[Pre-signed S3 upload endpoint]
  end

  T1 --> O1
  T2 --> O1
  O1 -->|mediaclient preferred| R1
  O1 -->|fallback or non-C path| O2

  R1 --> R2 --> R3 --> R4 --> R5
  R1 -.config.-> I1
  R1 -.policy.-> I2
  R4 -.telemetry.-> I3
  R4 -.tls/upload.-> I4
  R4 --> E1 --> E2

  class T1,T2 trigger
  class O1,O2 orchestration
  class R1,R2,R3,R4,R5 runtime
  class I1,I2,I3,I4 integration
  class E1,E2 external
```

## 2) Crash Upload Sequence (C Path)
```mermaid
sequenceDiagram
  autonumber
  participant Sys as systemd/path/timer
  participant Disp as uploadDumps.sh
  participant Bin as crashupload
  participant Scn as scanner/archive
  participant Up as upload module
  participant Cfg as RFC/RBUS/properties
  participant Svc as metadata+S3 services

  Sys->>Disp: trigger upload flow
  Disp->>Disp: choose runtime path
  Disp->>Bin: exec crashupload args
  Bin->>Cfg: load config/platform/privacy/endpoint hints
  Bin->>Bin: acquire lock + prerequisite checks
  Bin->>Scn: discover and normalize dumps
  Scn-->>Bin: archive candidates
  loop each archive
    Bin->>Up: upload_process(archive)
    Up->>Cfg: read RFC endpoint/encryption toggles
    Up->>Svc: metadata POST for signed URL
    Svc-->>Up: signed URL response
    Up->>Svc: S3 PUT archive
    Svc-->>Up: upload status
    Up-->>Bin: success/failure
  end
  Bin->>Bin: rate-limit timestamp, cleanup, unlock
  Bin-->>Disp: exit code
```

## 3) Crash Processing Flowchart
```mermaid
flowchart TD
  classDef gate fill:#fef6e7,stroke:#b7791f,color:#222;
  classDef action fill:#edf7ff,stroke:#2b6cb0,color:#222;
  classDef endstate fill:#e9f8ef,stroke:#2f855a,color:#222;
  classDef fail fill:#fde8e8,stroke:#c53030,color:#222;

  A[Start invocation] --> B[Load config and platform]
  B --> C{Acquire lock?}
  C -- no --> X1[Exit early]:::endstate
  C -- yes --> D{Prerequisites pass?}
  D -- no --> X2[Cleanup and exit]:::endstate
  D -- yes --> E{Privacy DO_NOT_SHARE?}
  E -- yes --> X3[Skip upload, cleanup]:::endstate
  E -- no --> F[Scan and sanitize dump files]
  F --> G[Create archives and enrich metadata]
  G --> H{Reboot flag or rate-limit block?}
  H -- yes --> X4[Skip or purge pending, cleanup]:::endstate
  H -- no --> I[Sequential upload loop]
  I --> J{Upload success?}
  J -- no --> Y1[Break loop on failure]:::fail
  J -- yes --> K[Remove uploaded archive and mark success]
  Y1 --> L[Final cleanup + unlock]
  K --> L
  L --> M[Exit]

  class A,B,F,G,I,K,L,M action
  class C,D,E,H,J gate
```

## 4) Process Communication and State Files
```mermaid
flowchart LR
  classDef proc fill:#eaf3ff,stroke:#2c5282,color:#123;
  classDef state fill:#fff6db,stroke:#a16b00,color:#123;
  classDef data fill:#e9f7ef,stroke:#2f855a,color:#123;

  P1[systemd/inotify]:::proc --> P2[uploadDumps.sh]:::proc
  P2 -->|exec| P3[crashupload]:::proc
  P2 -->|fallback| P4[runDumpUpload.sh]:::proc

  S1[/tmp/.uploadMinidumps]:::state -. lock .-> P3
  S2[/tmp/.uploadCoredumps]:::state -. lock .-> P3
  S3[/tmp/.deny_dump_uploads_till]:::state -. policy .-> P3
  S4[/tmp/.minidump_upload_timestamps]:::state -. policy .-> P3
  S5[/tmp/set_crash_reboot_flag]:::state -. control .-> P3
  S6[/tmp/.on_startup_dumps_cleaned_up_*]:::state -. cleanup state .-> P3

  D1[/opt/minidumps or /minidumps]:::data --> P3
  D2[/var/lib/systemd/coredump]:::data --> P3
  D3[/opt/secure/*]:::data --> P3
```

## 5) Service/Runtime Lifecycle
```mermaid
stateDiagram-v2
  [*] --> Idle
  Idle --> Triggered: systemd timer/path or inotify event
  Triggered --> Dispatching: uploadDumps.sh runtime selection
  Dispatching --> CPath: crashupload selected
  Dispatching --> LegacyPath: runDumpUpload.sh selected

  CPath --> Init
  Init --> Locked
  Locked --> Qualified: prerequisites + privacy + reboot + ratelimit
  Qualified --> Processing: scan -> package -> upload
  Processing --> Cleanup
  Cleanup --> Exit

  LegacyPath --> Exit
  Exit --> Idle
```

## 6) Upload Execution Decision Flow
```mermaid
flowchart TD
  A[archive ready] --> B[resolve endpoint + flags]
  B --> C[metadata POST for signed URL]
  C --> D{metadata ok?}
  D -- no --> R[retry budget check]
  D -- yes --> E[S3 PUT upload]
  E --> F{upload ok?}
  F -- no --> R
  F -- yes --> G[emit success telemetry]
  G --> H[delete local archive]
  H --> I[for minidump append timestamp]

  R --> J{retries left?}
  J -- yes --> C
  J -- no --> K[emit failure telemetry]
```
