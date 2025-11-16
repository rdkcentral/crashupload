# Crashupload C Implementation - Skeleton Code

This directory contains skeleton C implementation for the crashupload migration from shell scripts to C.

## Architecture

Based on **optimized design** from:
- `docs/migration/hld/updateduploadDumps-hld.md`
- `docs/migration/lld/updateduploadDumps-lld.md`
- `docs/migration/diagrams/flowcharts/optimizeduploadDumps-flowcharts.md`
- `docs/migration/diagrams/sequence/updateuploadDumps-sequence.md`
- `docs/migration/requirements/uploadDumps-requirements.md`

## Structure

```
c_sourcecode/
├── common/               # Common type definitions, constants, errors
│   ├── types.h
│   ├── constants.h
│   └── errors.h
├── src/                  # Source code
│   ├── main.c            # Main entry point (7-step optimized flow)
│   ├── init/             # Consolidated initialization
│   ├── config/           # Configuration management
│   ├── platform/         # Platform abstraction
│   ├── core/             # Core processing modules
│   │   ├── scanner.*     # Dump file scanner
│   │   ├── archive_smart.*     # Smart archive creator
│   │   ├── upload_typeaware.*  # Type-aware upload
│   │   └── ratelimit_unified.* # Unified rate limiter
│   ├── utils/            # Utility modules
│   │   ├── prerequisites.*  # Combined network+time check
│   │   ├── privacy.*        # Unified privacy check
│   │   ├── cleanup_batch.*  # Batch cleanup
│   │   ├── lock_manager.*   # Process locking
│   │   └── logger.*         # Logging
│   └── Makefile          # Build system
```

## Key Optimizations

1. **Consolidated Initialization** - Single `system_initialize()` call (3 steps → 1)
2. **Combined Prerequisites** - `prerequisites_wait()` checks network + time together
3. **Unified Privacy** - `privacy_uploads_blocked()` combines opt-out + privacy mode
4. **Smart Archive** - Direct compression first, /tmp fallback if needed
5. **Type-Aware Upload** - Minidump (5 retries, 3s delay) vs Coredump (3 retries, 10s delay)
6. **Unified Rate Limit** - Single check for recovery + 10/10min limit
7. **Batch Cleanup** - Single directory scan for all cleanup operations

## Building

```bash
cd src
make
```

## Status

**SKELETON**: All files contain function signatures and data structures from the design documents, but function bodies need implementation. Each TODO comment indicates what needs to be implemented.

## Next Steps

1. Implement function bodies following TODO markers
2. Add unit tests (GTest framework recommended)
3. Build and test incrementally
4. Validate against shell script behavior
5. Performance test on target platforms

## Performance Targets

Based on optimized design:
- Startup: 100-120ms (vs 150-200ms standard)
- Memory: 6-8MB (vs 8-10MB standard)
- Binary: ~35KB (vs ~45KB standard)
- Decision points: 22 (vs 35 standard) - 37% reduction
