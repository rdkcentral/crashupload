# Crashupload C source (`c_sourcecode/`)

This directory is the autotools tree for the C binaries:

- **crashupload** — dump discovery, archive, rate-limit, and upload (`src/`)
- **inotify-minidump-watcher** — directory watcher that starts upload on matching file creates (`watcher/`)

## Layout

```
c_sourcecode/
├── configure.ac
├── Makefile.am
├── common/                 # Shared types, constants, errors
├── include/                # Public headers used by crashupload
├── src/                    # crashupload binary
└── watcher/                # inotify-minidump-watcher binary
```

## Build

From this directory:

```bash
autoreconf -i
./configure
make
make install
```

`make` produces:

- `src/crashupload`
- `watcher/inotify-minidump-watcher`

Both are `bin_PROGRAMS` and install to `$prefix/bin` (typically `/usr/bin` on device images).

Yocto/RDK builds pass extra `CFLAGS`/`LDFLAGS` (for example `-DYOCTO_BUILD` and `-lsecure_wrapper`). Do not hard-code those in a way that breaks the existing recipe flags.

Local coverage-style builds used by L1 go through `crashupload/cov_build.sh`, which configures and installs both binaries.

## Tests

L1 (GTest) lives in `../unittest/`. Watcher tests are `watcher_gtest` and are included in `../run_ut.sh`.

```bash
cd ..
./run_ut.sh
```

## Notes

- `src/` and `watcher/` are separate subdirectories so crashupload link flags (curl, rbus, archive, telemetry) are not applied to the watcher.
- The watcher only links `libsecure_wrapper`, matching the legacy `crashupload/src/Makefile`.
