# crashupload (`src/`)

This directory is the source for the **crashupload** binary. It is built by autotools from `c_sourcecode/` (`SUBDIRS = src watcher`).

## What it does

`crashupload` is the C replacement path for dump packaging and upload. The entry point is `main.c`, which initializes logging/config/platform, waits for prerequisites, takes the process lock, scans for dumps, archives, uploads, rate-limits, and cleans up.

## Modules

| Path | Role |
|------|------|
| `main.c` | Process entry and main flow |
| `init/` | Consolidated system initialization |
| `config/` | Runtime configuration load |
| `platform/` | Device/platform specifics |
| `scanner/` | Dump file discovery |
| `archive/` | Archive creation |
| `upload/` | Upload to crash portal |
| `ratelimit/` | Upload rate limiting |
| `rfcInterface/` | RFC parameter access |
| `rbusInterface/` | RBUS init/uninit |
| `t2Interface/` | Telemetry markers |
| `utils/` | Logger, locks, files, prerequisites, batch cleanup |

Headers used across modules also live in `../common/` and `../include/`.

## Build

Do not run a standalone Makefile in this folder. Build from the parent tree:

```bash
cd ..
autoreconf -i
./configure
make
```

The binary is `src/crashupload` (installed as `/usr/bin/crashupload`).

## Tests

L1 coverage for these sources is under `../../unittest/` (`*_gtest` binaries). Run from the crashupload repo root:

```bash
./run_ut.sh
```
