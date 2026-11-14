# Crashupload leak-detection scripts

These scripts build [memleakutil](https://github.com/JagadheesanD/memleakutil) and run the `crashupload` binary under `LD_PRELOAD=libmemfnswrap.so`.

The check is advisory. `.github/workflows/detect_leak.yml` is a separate workflow from the native build. A failing case is reported with a GitHub warning and does not fail `native_full_build.yml`.

## Scripts

- `build_memleak.sh` clones, builds, and installs `libmemfnswrap.so` to `/tmp/memleakutil-install`.
- `detect_leak.sh` runs three short crashupload cases and writes reports to `/tmp/crashupload-leak-reports`.

## Local run

```bash
./cov_build.sh
sh scripts/build_memleak.sh
sh scripts/detect_leak.sh
```

## Cases

| Case | Command | Expected exit |
|------|---------|----------------|
| 0 | `crashupload` | 1 |
| 1 | `crashupload "" 0 secure` | 0 |
| 2 | `crashupload "" 1 secure` | 0 |

Cases 1 and 2 use an empty dump directory, so the process stops at the no-dumps path. Upload and `inotify-minidump-watcher` are not instrumented. `inotify-minidump-watcher` calls `system()`, which would inherit `LD_PRELOAD`.

Dump files whose names contain `.dmp` or `_core` are moved aside from the directories crashupload scans, then restored when the script exits. `/tmp/.uploadMinidumps` and `/tmp/.uploadCoredumps` are removed for the run.

Pass or fail follows the process exit code. On exit the library may write `/tmp/hp_<pid>_atexit.dat`, `/tmp/hpf_<pid>_atexit.dat`, and `/tmp/smaps_<pid>_atexit.txt`. The script copies those files into the report directory and does not fail because they contain allocations. Libraries linked into crashupload can still hold memory when the process exits.

## Environment

| Variable | Default | Used by |
|----------|---------|---------|
| `MEMLEAK_INSTALL_DIR` | `/tmp/memleakutil-install` | both |
| `MEMLEAK_JOBS` | `4` | `build_memleak.sh` |
| `MEMLEAK_GIT_URL` | memleakutil GitHub URL | `build_memleak.sh` |
| `MEMLEAK_INSTALL_DEPS` | unset | `build_memleak.sh` (`1` allows apt-get) |
| `CRASHUPLOAD_BIN` | `/usr/local/bin/crashupload` | `detect_leak.sh` |
| `LEAK_REPORT_DIR` | `/tmp/crashupload-leak-reports` | `detect_leak.sh` |
| `LEAK_CASE_TIMEOUT` | `60` | `detect_leak.sh` |
| `PRINT_REPORTS` | `1` | `detect_leak.sh` (`0` lets the caller print the text reports) |
