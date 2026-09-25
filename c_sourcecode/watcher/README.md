# inotify-minidump-watcher (`watcher/`)

Standalone helper binary that watches a directory with inotify (`IN_CREATE`) and runs a command when a created filename matches one or more glob patterns (typically `*.dmp`).

It is **not** the uploader. On a match it executes the configured command (historically `/lib/rdk/uploadDumps.sh`). If `COMMAND_TO_RUN` starts with `NULL`, it exits after the matching flag file is created.

Extender/Yocto builds do **not** set `GTEST_ENABLE`. All GTest-only symbols and syscall redirects are behind that flag.

## Files

| File | Role |
|------|------|
| `inotify-minidump-watcher.c` | Watcher implementation and `main` |
| `Makefile.am` | Builds `inotify-minidump-watcher` |
| `README.md` | This file |

## Usage

```
inotify-minidump-watcher DIRECTORY COMMAND_TO_RUN COMMAND_ARGS PATTERN...
```

Example:

```
/usr/bin/inotify-minidump-watcher /minidumps /lib/rdk/uploadDumps.sh "" 0 *.dmp
```

`SIGINT` stops a blocking `read` cleanly.

## Build

Built with the rest of `c_sourcecode` (no `GTEST_ENABLE`):

```bash
cd ..
autoreconf -i
./configure
make
```

Output: `watcher/inotify-minidump-watcher`

Install name remains `/usr/bin/inotify-minidump-watcher`.

Link flags stay limited to `-lsecure_wrapper` (plus environment `LDFLAGS`). `-DYOCTO_BUILD` continues to come from the recipe `CFLAGS` and switches `system()` to `v_secure_system()`.

## L1 tests

`unittest/watcher_gtest` compiles this file with `-DGTEST_ENABLE` (same L1 flag as the rest of crashupload):

- `main` is built as `watcher_main`; inotify/libc calls go to mocks
- `STATIC_TESTABLE` makes `directory_watcher` / `process_interrupt_handler` visible (same pattern as `archive.c`)

```bash
cd ../..
./run_ut.sh
```
