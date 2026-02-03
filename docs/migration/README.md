# Script to C Migration Documentation

This directory contains comprehensive documentation for migrating shell scripts to C code for embedded RDK platforms.

## Overview

The migration documentation provides detailed specifications for converting the crash dump upload scripts (`uploadDumps.sh` and `uploadDumpsUtils.sh`) from shell script to C implementation. The C implementation is designed for embedded systems with low memory and CPU resources, ensuring platform neutrality and portability.

## Documentation Structure

```
docs/migration/
├── README.md                           # This file
├── requirements/                       # Functional requirements
│   ├── uploadDumps-requirements.md     # Main script requirements
│   └── uploadDumpsUtils-requirements.md # Utilities requirements
├── hld/                                # High-Level Design
│   ├── uploadDumps-hld.md              # Main script architecture
│   └── uploadDumpsUtils-hld.md         # Utilities architecture
├── lld/                                # Low-Level Design
│   ├── uploadDumps-lld.md              # Detailed implementation specs
│   └── uploadDumpsUtils-lld.md         # Utilities implementation specs
└── diagrams/
    ├── flowcharts/                     # Process flowcharts
    │   ├── uploadDumps-flowcharts.md   # Main script flows
    │   └── uploadDumpsUtils-flowcharts.md # Utilities flows
    └── sequence/                       # Sequence diagrams
        ├── uploadDumps-sequence.md     # Component interactions
        └── uploadDumpsUtils-sequence.md # Utility interactions
```

## Scripts Covered

### uploadDumps.sh
Main script responsible for processing and uploading crash dump files (coredumps and minidumps) from embedded RDK devices to a crash portal server.

**Key Features:**
- Multi-platform support (broadband, extender, hybrid, mediaclient)
- Dump file detection and processing
- Archive creation with metadata
- Rate limiting and crash loop detection
- Secure upload with TLS 1.2
- Telemetry integration
- Privacy mode support

### uploadDumpsUtils.sh
Utility library providing common functions for network operations, system information retrieval, and file operations.

**Key Functions:**
- Network interface operations (MAC address, IP address)
- System information (uptime, model, process status)
- File operations (modification time, SHA1 checksum)
- Reboot control

## Document Contents

### 1. Requirements Documents

Located in `requirements/`, these documents specify:
- Functional requirements (FR-1 through FR-18 for uploadDumps)
- Input/output specifications
- Dependencies and constraints
- Edge cases and error handling
- Performance requirements
- Migration considerations

**Example:**
```
FR-1: Dump File Detection
- Description: Detect and identify crash dump files
- Input: Directory paths
- Output: List of dump files
- Priority: Critical
```

### 2. High-Level Design (HLD)

Located in `hld/`, these documents describe:
- Overall architecture and design principles
- Module/component breakdown
- Data flow diagrams
- Key algorithms and data structures
- Interfaces and integration points
- Error handling strategy
- Performance considerations
- Security considerations

**Key Modules (uploadDumps):**
1. Main Controller
2. Configuration Manager
3. Platform Abstraction Layer
4. Dump File Scanner
5. Archive Creator
6. Upload Manager
7. Rate Limiter
8. Network Utilities
9. File Utilities
10. String Utilities
11. Lock Manager
12. Logging System

### 3. Low-Level Design (LLD)

Located in `lld/`, these documents provide:
- File and directory structure
- Complete data structure definitions
- Detailed function specifications with signatures
- Implementation algorithms (pseudocode)
- Memory management strategies
- Error handling patterns
- Build system configuration
- Testing specifications

**Example Data Structure:**
```c
typedef struct {
    device_type_t device_type;
    build_type_t build_type;
    dump_type_t dump_type;
    char working_dir[PATH_MAX];
    char portal_url[URL_MAX_LEN];
    // ... more fields
} config_t;
```

### 4. Flowcharts

Located in `diagrams/flowcharts/`, these documents show:
- Main processing flows
- Decision points and branches
- Error handling paths
- Mermaid diagram syntax
- Text-based alternatives for environments with rendering issues

**Included Flowcharts:**
- Main processing loop
- Single dump processing
- Upload with retry
- Cleanup operations
- Rate limiting
- Network utilities
- System information retrieval

### 5. Sequence Diagrams

Located in `diagrams/sequence/`, these documents illustrate:
- Component interactions
- Message flow between modules
- Timing and ordering of operations
- Mermaid diagram syntax
- Text-based alternatives

**Key Sequences:**
- Complete dump upload sequence
- Archive creation sequence
- Upload with retry sequence
- Rate limiting sequence
- Platform initialization sequence

## Design Principles

### 1. Modularity
- Clear separation of concerns
- Well-defined interfaces
- Independent testable components

### 2. Platform Abstraction
- Device-specific code isolated
- Configuration-driven behavior
- Support for multiple platforms

### 3. Resource Efficiency
- Target: < 10MB memory usage
- Target: < 5% CPU during operation
- Minimal dynamic allocations
- Efficient I/O operations

### 4. Error Resilience
- Comprehensive error handling
- Graceful degradation
- No silent failures
- Proper cleanup on all exit paths

### 5. Maintainability
- Clear code structure
- Consistent naming conventions
- Well-documented functions
- Comprehensive test coverage

## Key Migration Considerations

### 1. Language-Specific Challenges

**Shell → C Conversions:**
- Command pipelines → C library calls
- Pattern matching (grep/sed/awk) → C string functions
- File globbing → directory scanning APIs
- Environment variables → configuration management

### 2. External Dependencies

**Minimize:**
- Shell command execution
- Process spawning overhead
- External script calls

**Use Libraries:**
- libcurl for HTTPS uploads
- OpenSSL for SHA1 and TLS
- zlib for compression
- Standard C library for file/network operations

### 3. Performance Improvements

**Expected Gains:**
- 50-90% faster execution (no process spawning)
- Lower memory usage (no shell interpreter)
- More predictable behavior
- Better error handling

### 4. Backward Compatibility

During transition period:
- Provide shell wrappers for C functions
- Support both implementations in parallel
- Gradual migration path

## Implementation Guidelines

### 1. Coding Standards
- Use C11 standard
- Enable all warnings (-Wall -Wextra)
- Follow consistent style
- Document all public APIs

### 2. Memory Management
- Prefer stack allocation
- Free resources in reverse order
- Use RAII-style cleanup patterns
- Implement proper error cleanup paths

### 3. Error Handling
- Return error codes from all functions
- Log errors with context
- Validate all inputs
- Handle all system call failures

### 4. Testing Requirements
- Unit tests for all modules
- Integration tests for workflows
- System tests on target hardware
- Test with real dump files

### 5. Security Requirements
- Validate all inputs
- Sanitize filenames and paths
- Use secure communication (TLS 1.2+)
- Respect privacy settings
- No hardcoded credentials

## Platform Support

### Supported Device Types
1. **Broadband Devices**
   - Special paths: /minidumps, /rdklogs/logs
   - Network: Multi-core interface support
   - Features: dmcli integration

2. **Video Devices (Hybrid/Mediaclient)**
   - Standard paths: /var/lib/systemd/coredump, /opt/minidumps
   - Features: Startup defer (480s), crashed URL logs
   - Privacy: Telemetry opt-out, privacy mode

3. **Extender Devices**
   - Paths: /minidumps, /var/log/messages
   - Features: Partner ID from account file

### Build System Requirements
- GCC 4.8+ or compatible compiler
- Make build system
- Libraries: libcurl, OpenSSL, zlib
- Optional: Yocto SDK for cross-compilation

## Usage Examples

### Reading the Documentation

1. **Start with Requirements** to understand what needs to be implemented
2. **Review HLD** to understand the architecture and design
3. **Study Flowcharts and Sequence Diagrams** to visualize the flows
4. **Refer to LLD** for implementation details

### Implementing a Module

1. Read the module specification in HLD
2. Review the flowchart for the module's logic
3. Check the sequence diagram for interactions
4. Implement using the LLD specifications
5. Write unit tests based on test specifications
6. Integrate and test with other modules

### Example: Implementing Archive Creator

```
1. Read: hld/uploadDumps-hld.md → Section 2.5 (Archive Creator Module)
2. View: diagrams/flowcharts/uploadDumps-flowcharts.md → Archive Creation Flow
3. Check: diagrams/sequence/uploadDumps-sequence.md → Archive Creation Sequence
4. Implement: Use lld/uploadDumps-lld.md → Section 3.5 (Archive Creator)
5. Test: Use lld/uploadDumps-lld.md → Section 7.1 (Unit Tests)
```

## Migration Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Implement utility library (uploadDumpsUtils)
- [ ] Create build system
- [ ] Set up testing framework
- [ ] Validate on target hardware

### Phase 2: Core Modules (Weeks 3-4)
- [ ] Implement configuration manager
- [ ] Implement platform abstraction
- [ ] Implement file scanner
- [ ] Unit test all modules

### Phase 3: Processing Pipeline (Weeks 5-6)
- [ ] Implement archive creator
- [ ] Implement upload manager
- [ ] Implement rate limiter
- [ ] Integration testing

### Phase 4: Integration & Testing (Weeks 7-8)
- [ ] Implement main controller
- [ ] System integration testing
- [ ] Performance testing
- [ ] Security testing

### Phase 5: Deployment (Week 9)
- [ ] Create installation packages
- [ ] Deploy to test devices
- [ ] Monitor and fix issues
- [ ] Documentation updates

## References

### External Documentation
- RDK Documentation: https://wiki.rdkcentral.com/
- POSIX API Reference
- libcurl Documentation: https://curl.se/libcurl/
- OpenSSL Documentation: https://www.openssl.org/docs/

### Related Components
- Breakpoint (crash handler)
- T2 Telemetry System
- RDK Logger
- System Manager (systemd integration)

## Contributing

When updating this documentation:
1. Maintain consistency across all documents
2. Update related diagrams when changing flows
3. Keep code examples in sync with specifications
4. Add test cases for new requirements
5. Document all assumptions and design decisions

## License

This documentation follows the same license as the crashupload component:
```
Copyright 2016 RDK Management

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contact

For questions or clarifications about this migration documentation:
- Open an issue in the GitHub repository
- Contact the RDK Crashupload team
- Refer to RDK Central wiki

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Status:** Complete
