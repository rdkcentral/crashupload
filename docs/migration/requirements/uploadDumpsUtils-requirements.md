# Requirements Document: uploadDumpsUtils.sh

## 1. Overview

The `uploadDumpsUtils.sh` script provides utility functions used by the main upload script (`uploadDumps.sh`) for crash dump processing. It contains helper functions for network operations, system information retrieval, and common operations.

## 2. Functional Requirements

### 2.1 Network Interface Management

#### FR-1: Get WAN MAC Interface Name
- **Function**: `getWanMacInterfaceName()`
- **Description**: Retrieve the WAN interface name used for MAC address
- **Input**: None (reads from `/etc/waninfo.sh` if available)
- **Output**: Interface name string (default: "erouter0")
- **Priority**: Critical
- **Details**:
  - Check for `/etc/waninfo.sh` existence
  - Call `getWanInterfaceName()` if available
  - Fall back to "erouter0" if not available

#### FR-2: Get MAC Address Only
- **Function**: `getMacAddressOnly()`
- **Description**: Extract MAC address from network interface
- **Input**: Interface name from `getWanMacInterfaceName()`
- **Output**: MAC address without colons (e.g., "AABBCCDDEEFF")
- **Priority**: Critical
- **Details**:
  - Use `ifconfig` to get hardware address
  - Extract HWaddr field
  - Remove colon separators
  - Return clean MAC address string

#### FR-3: Get IP Address
- **Function**: `getIPAddress()`
- **Description**: Retrieve the IPv4 address of the WAN interface
- **Input**: WANINTERFACE variable
- **Output**: IPv4 address string
- **Priority**: High
- **Details**:
  - Use `ifconfig` on WAN interface
  - Extract "inet addr" field
  - Exclude IPv6 addresses
  - Return IPv4 address only

#### FR-4: Get CM Interface MAC Address
- **Function**: `getMacAddress()`
- **Description**: Get MAC address from Cable Modem interface
- **Input**: CMINTERFACE variable (default: "wan0")
- **Output**: MAC address with colons (e.g., "AA:BB:CC:DD:EE:FF")
- **Priority**: Medium
- **Details**:
  - Use `ifconfig` on CM interface
  - Extract HWaddr field at position 11
  - Return MAC address with colons preserved

#### FR-5: Get eRouter MAC Address
- **Function**: `getErouterMacAddress()`
- **Description**: Get MAC address from eRouter/WAN interface
- **Input**: wan_interface variable
- **Output**: MAC address with colons
- **Priority**: Medium
- **Details**:
  - Use `ifconfig` on WAN interface
  - Extract HWaddr field
  - Return MAC address with colons

### 2.2 File and System Operations

#### FR-6: Get Last Modified Time of File
- **Function**: `getLastModifiedTimeOfFile()`
- **Description**: Retrieve the last modification timestamp of a file
- **Input**: File path (string)
- **Output**: Timestamp in format "YYYY-MM-DD-HH-MM-SS"
- **Priority**: Critical
- **Details**:
  - Check if file exists
  - Use `stat -c '%y'` to get modification time
  - Format: Remove milliseconds, replace spaces and colons with hyphens
  - Return formatted timestamp string

#### FR-7: Get Current Timestamp
- **Function**: `Timestamp()`
- **Description**: Get current system timestamp
- **Input**: None
- **Output**: Timestamp in format "YYYY-MM-DD HH:MM:SS"
- **Priority**: High
- **Details**:
  - Use `date` command
  - Format: "+%Y-%m-%d %T"
  - Return formatted timestamp

#### FR-8: Get SHA1 Checksum
- **Function**: `getSHA1()`
- **Description**: Calculate SHA1 checksum of a file
- **Input**: File path (string)
- **Output**: SHA1 hash string (40 hexadecimal characters)
- **Priority**: Critical
- **Details**:
  - Use `sha1sum` command
  - Extract only the hash portion (not filename)
  - Return hash string

### 2.3 Process Management

#### FR-9: Process Check
- **Function**: `processCheck()`
- **Description**: Check if a process is running
- **Input**: Process name or pattern (string)
- **Output**: "0" if running, "1" if not running
- **Priority**: Medium
- **Details**:
  - Use `ps -ef` to list processes
  - Filter by provided pattern using `grep`
  - Exclude grep itself from results
  - Return status code as string

### 2.4 System Information

#### FR-10: Get System Uptime
- **Function**: `Uptime()`
- **Description**: Get system uptime in seconds
- **Input**: None
- **Output**: Integer seconds since boot
- **Priority**: Medium
- **Details**:
  - Read `/proc/uptime`
  - Extract first field (total uptime)
  - Remove decimal portion
  - Return integer seconds

#### FR-11: Get Device Model
- **Function**: `getModel()`
- **Description**: Extract device model from version file
- **Input**: None (reads `/fss/gw/version.txt`)
- **Output**: Model name string
- **Priority**: High
- **Details**:
  - Read version file
  - Find line starting with "imagename:"
  - Extract value after colon
  - Take first underscore-separated field
  - Return model name

### 2.5 System Control

#### FR-12: Reboot Function
- **Function**: `rebootFunc()`
- **Description**: Initiate system reboot with logging
- **Input**: 
  - Optional: Process name ($1)
  - Optional: Reason ($2)
- **Output**: None (system reboots)
- **Priority**: High
- **Details**:
  - If no arguments provided:
    - Get parent process from `/proc/$PPID/cmdline`
    - Use default reason message
  - If arguments provided:
    - Use provided process name and reason
  - Call `/rebootNow.sh` with process and reason
  - Script `-s` flag for source
  - Script `-o` flag for reason

## 3. Inputs

### 3.1 Environment Variables
- `CMINTERFACE`: Cable modem interface name (default: "wan0")
- `WANINTERFACE`: WAN interface name (default: "erouter0")
- `wan_interface`: Alternative WAN interface variable

### 3.2 System Files
- `/etc/waninfo.sh`: WAN interface configuration (optional)
- `/proc/uptime`: System uptime information
- `/fss/gw/version.txt`: Device version information
- `/proc/$PPID/cmdline`: Parent process command line

### 3.3 Function Arguments
- File paths for operations (stat, sha1sum)
- Process names for checking
- Process and reason for reboot

## 4. Outputs

### 4.1 String Outputs
- MAC addresses (with or without colons)
- IP addresses (IPv4)
- Timestamps (formatted strings)
- SHA1 hashes (hexadecimal strings)
- Model names
- Process status ("0" or "1")
- Uptime (integer as string)

### 4.2 System Effects
- System reboot (from `rebootFunc()`)
- No file creation or modification
- No state persistence

## 5. Dependencies

### 5.1 System Commands
- `ifconfig`: Network interface configuration
- `grep`: Pattern matching
- `cut`: Text extraction
- `sed`: Stream editing
- `date`: Timestamp generation
- `stat`: File information
- `sha1sum`: Checksum calculation
- `ps`: Process listing
- `cat`: File reading
- `awk`: Text processing

### 5.2 External Scripts
- `/etc/waninfo.sh` (optional): WAN interface helper
- `/rebootNow.sh`: System reboot script

### 5.3 System Resources
- `/proc/uptime`: Kernel uptime information
- `/proc/$PPID/cmdline`: Process information
- Network interfaces (virtual files in `/sys` or device drivers)

## 6. Constraints

### 6.1 Platform Constraints
- Must work on embedded Linux systems
- Must support busybox utilities (limited versions)
- Must handle missing optional files gracefully
- Network interface names may vary by platform

### 6.2 Performance Constraints
- Functions should execute quickly (milliseconds)
- Minimal CPU usage for simple operations
- No memory leaks or resource exhaustion
- No blocking operations except reboot

### 6.3 Compatibility Constraints
- Support both traditional and systemd-based systems
- Work with various network configurations
- Handle missing or unavailable interfaces
- Support different filesystem layouts

## 7. Edge Cases and Error Handling

### 7.1 Edge Cases

#### EC-1: Missing WAN Interface
- **Scenario**: WAN interface does not exist or is down
- **Handling**: Use default interface name "erouter0"

#### EC-2: Empty MAC Address
- **Scenario**: ifconfig returns no HWaddr
- **Handling**: Return empty string (caller must handle)

#### EC-3: File Does Not Exist
- **Scenario**: File path provided to `getLastModifiedTimeOfFile()` does not exist
- **Handling**: Return empty result (stat fails silently)

#### EC-4: Invalid Version File
- **Scenario**: `/fss/gw/version.txt` does not exist or has wrong format
- **Handling**: Return empty string or partial result

#### EC-5: Process Not Found
- **Scenario**: Process name does not match any running process
- **Handling**: Return "1" (not running)

#### EC-6: Reboot Without Arguments
- **Scenario**: `rebootFunc()` called with no parameters
- **Handling**: Auto-detect caller from $PPID and use default reason

### 7.2 Error Conditions

#### ERR-1: Command Not Found
- **Error**: Required system command not available
- **Handling**: Function fails, returns empty or error value
- **Recovery**: Caller must handle empty returns

#### ERR-2: Permission Denied
- **Error**: Insufficient permissions to read file or interface
- **Handling**: Command fails, returns empty result
- **Recovery**: Caller must handle gracefully

#### ERR-3: Invalid Input
- **Error**: Function called with invalid or malformed input
- **Handling**: Undefined behavior (shell functions don't validate)
- **Recovery**: Caller must provide valid input

#### ERR-4: Network Interface Down
- **Error**: Interface exists but is not active
- **Handling**: ifconfig may return partial information
- **Recovery**: Use available data or defaults

## 8. Quality Attributes

### 8.1 Reliability
- Functions must be idempotent (safe to call multiple times)
- No side effects except for `rebootFunc()`
- Consistent return values for same inputs
- Handle missing resources gracefully

### 8.2 Performance
- Fast execution (< 100ms for most functions)
- Minimal resource usage
- No unnecessary process spawning
- Efficient text processing

### 8.3 Maintainability
- Simple, single-purpose functions
- Clear function names
- Minimal dependencies
- No global state modification

### 8.4 Portability
- Support busybox and GNU utilities
- Work across RDK platforms
- Handle platform-specific differences
- Use POSIX-compatible commands where possible

### 8.5 Usability
- Simple function interfaces
- Predictable behavior
- Consistent output formats
- Easy to source and use

## 9. Migration Considerations for C Implementation

### 9.1 System Calls vs. Command Execution
- Replace `ifconfig` with `getifaddrs()` or netlink sockets
- Replace `stat` command with `stat()` system call
- Replace `ps` with `/proc` filesystem reading or process APIs
- Use system time functions instead of `date` command

### 9.2 String Manipulation
- Implement robust string parsing for MAC addresses
- Handle timestamp formatting with `strftime()`
- Implement SHA1 using crypto libraries (OpenSSL or similar)
- Replace shell text processing with C string functions

### 9.3 Network Interface Access
- Use `ioctl()` with SIOCGIFHWADDR for MAC addresses
- Use `ioctl()` with SIOCGIFADDR for IP addresses
- Consider using `getifaddrs()` for modern systems
- Handle both IPv4 and IPv6 appropriately

### 9.4 Error Handling
- Implement proper return codes (not strings)
- Use errno for system call errors
- Provide error messages or logging
- Validate all inputs

### 9.5 Configuration
- Read interface names from configuration files
- Support runtime configuration changes
- Implement fallback defaults
- Use consistent configuration format

### 9.6 Reboot Functionality
- Use `reboot()` system call with proper privileges
- Implement proper shutdown sequence
- Log reboot reason appropriately
- Handle cleanup before reboot

### 9.7 File Operations
- Use standard C file I/O (`fopen`, `fread`, etc.)
- Implement proper error checking
- Handle large files efficiently
- Close file descriptors properly

### 9.8 Optimization Opportunities
- Cache frequently accessed values (MAC address, model)
- Reduce system command invocations
- Use efficient algorithms for text parsing
- Minimize memory allocations

### 9.9 Testing Considerations
- Mock network interfaces for testing
- Provide test fixtures for file operations
- Support unit testing of individual functions
- Allow dependency injection for external resources

### 9.10 Memory Management
- Use static buffers where appropriate (embedded systems)
- Avoid dynamic allocation for small strings
- Implement proper cleanup on errors
- Consider memory pools for frequent allocations
