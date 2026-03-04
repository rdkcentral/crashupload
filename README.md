# Crashupload

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](CHANGELOG.md)

A high-performance crash dump collection and upload service for RDK platforms. Automatically discovers, compresses, and securely uploads minidumps and coredumps to centralized crash analysis servers with built-in rate limiting and privacy controls.

## Overview

Crashupload is designed for embedded RDK devices (broadband, video, extenders, media clients) to efficiently handle crash diagnostics. The v2.0 migration from shell scripts to compiled C code delivers **37% fewer decision points**, **35% smaller binary size**, and **40% faster startup** while maintaining full backward compatibility.

### Key Features

- **Multi-format Support**: Handles minidumps (.dmp) and coredumps (core.*, .core)
- **Smart Compression**: Direct compression with automatic /tmp fallback for space-constrained systems
- **Type-Aware Retry**: Aggressive retry for minidumps (5×3s), conservative for coredumps (3×10s)
- **Rate Limiting**: 10 uploads per 10 minutes with crashloop detection (5 uploads/minute)
- **Privacy Controls**: Telemetry opt-out + RBUS privacy mode integration
- **Secure Upload**: TLS 1.2 with OCSP stapling support via libcurl
- **Zero Script Dependencies**: Pure C implementation with ioctl-based networking

## Architecture

```
crashupload
├── c_sourcecode/          # Main C implementation (v2.0)
│   ├── common/            # Shared types, constants, error codes
│   ├── include/           # Public header files
│   └── src/               # Source modules
│       ├── main.c         # 7-step optimized flow
│       ├── config/        # Multi-source config manager
│       ├── scanner/       # Multi-format dump discovery
│       ├── archive/       # Smart compression engine
│       ├── upload/        # TLS 1.2 upload with retry
│       ├── ratelimit/     # Unified rate limiter
│       ├── utils/         # File, network, system utilities
│       └── *Interface/    # RBUS, RFC, T2 telemetry
├── unittest/              # GTest suite (69 test cases)
├── docs/                  # HLD, LLD, diagrams, requirements
└── test/                  # Functional tests

Performance: 100-120ms startup | 6-8MB memory | ~35KB binary
```

### Optimized Design

1. **Consolidated Init**: Single `system_initialize()` call (3 steps → 1)
2. **Combined Prerequisites**: Network + time validation in one check
3. **Unified Privacy**: Opt-out + privacy mode combined decision
4. **Smart Archive**: Direct compression → /tmp fallback optimization
5. **Type-Aware Upload**: Minidump vs coredump specific retry policies
6. **Unified Rate Limit**: Recovery mode + 10/10min limit in single check
7. **Batch Cleanup**: Single directory scan for all cleanup operations

## Building

### Prerequisites

```bash
# Dependencies
- GCC 4.9+ with C11 support
- Autotools (autoconf, automake, libtool)
- OpenSSL 1.0+ (libcrypto for SHA1)
- libcurl 7.0+ with TLS 1.2
- RDK libraries: rdkloggers, rbus, rfc, breakpad, t2
```

### Build Instructions

```bash
# Navigate to C source directory
cd c_sourcecode

# Generate build system
autoreconf -fi

# Configure
./configure --prefix=/usr --sysconfdir=/etc

# Build
make

# Install
sudo make install
```

### Compiler Flags

```bash
CFLAGS="-Wall -Werror -O2 -DT2_EVENT_ENABLED"
```

## Usage

### Systemd Service (Minidump on Startup)

```bash
# Enable and start timer
systemctl enable minidump-on-bootup-upload.timer
systemctl start minidump-on-bootup-upload.timer

# Manual trigger
systemctl start minidump-on-bootup-upload.service
```

### Coredump Upload Path

```bash
# Triggered by systemd path unit
systemctl enable coredump-upload.path
systemctl start coredump-upload.path
```

### Manual Execution

```bash
# Minidump mode
crashupload --type minidump --path /minidumps

# Coredump mode
crashupload --type coredump --path /var/lib/systemd/coredump

# Recovery mode (bypass rate limit for reboot)
crashupload --recovery
```

## Configuration

Configuration is loaded from multiple sources with priority override:

1. **Command-line arguments** (highest priority)
2. **RFC configuration** (via TR-181 parameters)
3. **Device properties** (`/etc/device.properties`)
4. **Default values** (fallback)

### Key Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `upload_url` | Platform-specific | Crash upload server URL |
| `dump_path` | `/minidumps` (minidump)<br>`/var/lib/systemd/coredump` (coredump) | Dump file location |
| `upload_timeout` | 45s | HTTP upload timeout |
| `ratelimit_max` | 10 | Max uploads per window |
| `ratelimit_window` | 600s | Rate limit window (10 min) |

### Privacy Control (RBUS)

```bash
# Check current privacy mode
dmcli eRT getv Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode

# Set to DO_NOT_SHARE (blocks uploads)
dmcli eRT setv Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode string DO_NOT_SHARE
```

## Testing

### Unit Tests (GTest)

```bash
cd unittest

# Generate build system
autoreconf -fi

# Configure
./configure

# Build and run tests
make check

# View results
cat test-suite.log
```

**Test Coverage**: 69 comprehensive test cases across all modules
- Network utilities: 10 tests
- File utilities: 13 tests
- System utilities: 11 tests
- Scanner: 11 tests
- Archive: 11 tests
- Rate limiter: 13 tests

### L1 Unit Testing Coverage

Current code coverage metrics from GTest suite:

```
Lines......: 90.5% (1903 of 2102 lines)
Functions..: 100.0% (89 of 89 functions)
Branches...: 84.3% (1086 of 1288 branches)
```

**Coverage Target**: Maintain >90% line coverage, 100% function coverage, >80% branches coverage

### L2 Functional Tests

```bash
cd test/functional-tests

# Run test suite
./run_tests.sh
```

**Test Status**:
1. ✅ Lock and Exit - Completed
2. ✅ Lock and Wait - Completed
3. 🔄 Minidump Upload - TBD
4. 🔄 Coredump Upload - TBD
5. 🔄 Ratelimit - TBD
6. 🔄 Startup Cleanup - TBD
7. 🔄 OptOut - TBD

## Rate Limiting & Recovery Mode

### Normal Operation
- **Limit**: 10 uploads per 10-minute window
- **Crashloop Detection**: 5 uploads per 1-minute window
- **State Tracking**: `/tmp/.crashupload_ratelimit`

### Recovery Mode (On Reboot)
- Bypasses rate limit for first dump after boot
- Enables upload of crash from previous session
- Self-clears after successful upload

## Telemetry Events (T2)

When T2 telemetry is enabled:
- `SYST_INFO_CrashUpload_Success`: Successful upload
- `SYST_INFO_CrashUpload_Failed`: Upload failure
- `SYST_WARN_NoMinidump`: No dumps found when expected
- `SYST_ERR_RateLimit_Exceeded`: Rate limit triggered

## Directory Structure

```
/minidumps/                           # Minidump storage
/var/lib/systemd/coredump/            # Coredump storage
/opt/logs/crashupload.log             # Application logs
/tmp/.crashupload_ratelimit           # Rate limit state
/tmp/.crashupload_recovery            # Recovery mode flag
/tmp/.deny_dump_uploads_till          # Temporary upload block
/var/run/crashupload.lock             # Process lock file
```

## Legacy Shell Scripts (v1.x)

For backward compatibility, legacy implementation remains:
- `uploadDumps.sh`: Original shell-based implementation
- `uploadDumpsUtils.sh`: Utility functions
- `runDumpUpload.sh`: Wrapper script

**Note**: These are deprecated and will be removed in v3.0.

## Documentation

- [High-Level Design](docs/migration/hld/)
- [Low-Level Design](docs/migration/lld/)
- [Architecture Diagrams](docs/migration/diagrams/)
- [Requirements](docs/migration/requirements/)
- [Implementation Summary](c_sourcecode/IMPLEMENTATION_SUMMARY.md)
- [Changelog](CHANGELOG.md)

## Troubleshooting

### No dumps being uploaded

1. Check privacy settings: `cat /opt/tmtryoptout` (should not exist or be "false")
2. Verify RBUS privacy mode: `dmcli eRT getv Device.X_RDKCENTRAL-COM_Privacy.PrivacyMode`
3. Check rate limit state: `cat /tmp/.crashupload_ratelimit`
4. Review logs: `cat /opt/logs/crashupload.log`

### Rate limit exceeded

```bash
# Clear rate limit state (emergency only)
rm /tmp/.crashupload_ratelimit

# Restart service
systemctl restart minidump-on-bootup-upload.service
```

### Upload failures

1. Verify network connectivity
2. Check upload URL configuration
3. Test TLS handshake: `curl -v https://upload-server`
4. Review certificate validity

## TODO

- RDKEMW-14022
- Implement Minidump Upload test cases
- Implement Coredump Upload test cases
- Implement Ratelimit test cases
- Implement Startup Cleanup test cases
- Implement OptOut test cases

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

All contributors must sign the RDK Contributor License Agreement (CLA).

## License

Copyright 2025 RDK Management

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/rdkcentral/crashupload/issues)
- **Documentation**: [RDK Central Wiki](https://wiki.rdkcentral.com)
- **Email**: support@rdkcentral.com

## Credits

Developed by RDK Management for the RDK community.

Special thanks to all contributors who helped migrate from shell scripts to optimized C implementation.
