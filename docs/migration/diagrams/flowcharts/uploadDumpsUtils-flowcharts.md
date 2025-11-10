# Flowcharts: uploadDumpsUtils.sh Migration

## Get MAC Address Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([getMacAddressOnly]) --> CheckCache{MAC Cached?}
    
    CheckCache -->|Yes & Fresh| ReturnCached[Return Cached MAC]
    ReturnCached --> End1([Return])
    
    CheckCache -->|No or Stale| GetInterface[Get WAN Interface Name]
    GetInterface --> CheckWanInfo{/etc/waninfo.sh exists?}
    
    CheckWanInfo -->|Yes| SourceScript[Source waninfo.sh]
    SourceScript --> CallFunction[Call getWanInterfaceName]
    CallFunction --> SetInterface[Set interface name]
    SetInterface --> QueryInterface
    
    CheckWanInfo -->|No| UseDefault[Use default: erouter0]
    UseDefault --> QueryInterface[Query Interface Hardware Address]
    
    QueryInterface --> TryMethod1{Try getifaddrs?}
    
    TryMethod1 -->|Available| CallGetifaddrs[Call getifaddrs]
    CallGetifaddrs --> IterateIfs[Iterate Interfaces]
    IterateIfs --> FindMatch{Interface Name Match?}
    
    FindMatch -->|Yes| ExtractHwaddr1[Extract Hardware Address]
    ExtractHwaddr1 --> FreeIfaddrs[Free ifaddrs]
    FreeIfaddrs --> FormatMAC
    
    FindMatch -->|No| NextIf[Next Interface]
    NextIf --> IterateIfs
    
    TryMethod1 -->|Not Available| TryMethod2{Try ioctl?}
    
    TryMethod2 -->|Available| OpenSocket[Open Socket AF_INET]
    OpenSocket --> SetIfreq[Set ifreq struct with interface name]
    SetIfreq --> CallIoctl[Call ioctl SIOCGIFHWADDR]
    CallIoctl --> CheckResult{Success?}
    
    CheckResult -->|Yes| ExtractHwaddr2[Extract Hardware Address]
    ExtractHwaddr2 --> CloseSocket[Close Socket]
    CloseSocket --> FormatMAC[Format MAC Address]
    
    CheckResult -->|No| LogError[Log Error]
    LogError --> CloseSocket2[Close Socket]
    CloseSocket2 --> ReturnEmpty[Return Empty]
    ReturnEmpty --> End2([Return Error])
    
    TryMethod2 -->|Not Available| ReturnEmpty
    
    FormatMAC --> RemoveColons[Remove Colon Separators]
    RemoveColons --> ToUpper[Convert to Uppercase]
    ToUpper --> CacheResult[Cache Result]
    CacheResult --> ReturnMAC[Return MAC Address]
    ReturnMAC --> End3([Return Success])
    
    style Start fill:#90EE90
    style End1 fill:#90EE90
    style End2 fill:#FF6B6B
    style End3 fill:#90EE90
    style QueryInterface fill:#87CEEB
    style FormatMAC fill:#FFD700
```

## Get File Modification Time Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([getLastModifiedTimeOfFile]) --> ValidateInput{Input Valid?}
    
    ValidateInput -->|No| ReturnEmpty1[Return Empty]
    ReturnEmpty1 --> End1([Return Error])
    
    ValidateInput -->|Yes| CheckFile{File Exists?}
    
    CheckFile -->|No| ReturnEmpty2[Return Empty]
    ReturnEmpty2 --> End2([Return Error])
    
    CheckFile -->|Yes| CallStat[Call stat system call]
    CallStat --> CheckStat{stat Success?}
    
    CheckStat -->|No| LogError[Log Error]
    LogError --> ReturnEmpty3[Return Empty]
    ReturnEmpty3 --> End3([Return Error])
    
    CheckStat -->|Yes| ExtractMtime[Extract st_mtime]
    ExtractMtime --> ConvertToTm[Convert to struct tm]
    ConvertToTm --> FormatTimestamp[Format: YYYY-MM-DD-HH-MM-SS]
    FormatTimestamp --> ReturnTimestamp[Return Timestamp String]
    ReturnTimestamp --> End4([Return Success])
    
    style Start fill:#90EE90
    style End1 fill:#FF6B6B
    style End2 fill:#FF6B6B
    style End3 fill:#FF6B6B
    style End4 fill:#90EE90
    style CallStat fill:#87CEEB
```

## Get SHA1 Checksum Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([getSHA1]) --> ValidateInput{Input Valid?}
    
    ValidateInput -->|No| ReturnError1[Return Error]
    ReturnError1 --> End1([Return Error])
    
    ValidateInput -->|Yes| OpenFile[Open File for Reading]
    OpenFile --> CheckOpen{File Opened?}
    
    CheckOpen -->|No| LogError[Log Error]
    LogError --> ReturnError2[Return Error]
    ReturnError2 --> End2([Return Error])
    
    CheckOpen -->|Yes| InitSHA1[Initialize SHA1 Context]
    InitSHA1 --> ReadLoop{More Data to Read?}
    
    ReadLoop -->|Yes| ReadChunk[Read 8KB Chunk]
    ReadChunk --> UpdateSHA1[Update SHA1 Context]
    UpdateSHA1 --> ReadLoop
    
    ReadLoop -->|No| FinalizeSHA1[Finalize SHA1]
    FinalizeSHA1 --> CloseFile[Close File]
    CloseFile --> ConvertToHex[Convert to Hex String]
    ConvertToHex --> ReturnHash[Return SHA1 Hash]
    ReturnHash --> End3([Return Success])
    
    style Start fill:#90EE90
    style End1 fill:#FF6B6B
    style End2 fill:#FF6B6B
    style End3 fill:#90EE90
    style ReadLoop fill:#87CEEB
    style UpdateSHA1 fill:#FFD700
```

## Process Check Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([processCheck]) --> OpenProcDir[Open /proc Directory]
    OpenProcDir --> CheckOpen{Directory Opened?}
    
    CheckOpen -->|No| ReturnError[Return 1 Not Running]
    ReturnError --> End1([Return])
    
    CheckOpen -->|Yes| ReadEntry[Read Directory Entry]
    ReadEntry --> CheckEntry{More Entries?}
    
    CheckEntry -->|No| CloseDir[Close Directory]
    CloseDir --> ReturnNotFound[Return 1 Not Running]
    ReturnNotFound --> End2([Return])
    
    CheckEntry -->|Yes| IsNumeric{Entry Name is Number?}
    
    IsNumeric -->|No| ReadEntry
    
    IsNumeric -->|Yes| BuildPath[Build Path: /proc/PID/cmdline]
    BuildPath --> OpenCmdline[Open cmdline File]
    OpenCmdline --> CheckCmdlineOpen{File Opened?}
    
    CheckCmdlineOpen -->|No| ReadEntry
    
    CheckCmdlineOpen -->|Yes| ReadCmdline[Read cmdline Content]
    ReadCmdline --> CloseCmdline[Close cmdline]
    CloseCmdline --> SearchPattern{Process Name Match?}
    
    SearchPattern -->|No| ReadEntry
    
    SearchPattern -->|Yes| CloseDir2[Close Directory]
    CloseDir2 --> ReturnFound[Return 0 Running]
    ReturnFound --> End3([Return])
    
    style Start fill:#90EE90
    style End1 fill:#FFB6C1
    style End2 fill:#FFB6C1
    style End3 fill:#90EE90
    style ReadEntry fill:#87CEEB
```

## Get System Uptime Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([Uptime]) --> TryMethod1{sysinfo Available?}
    
    TryMethod1 -->|Yes| CallSysinfo[Call sysinfo]
    CallSysinfo --> CheckSysinfo{Success?}
    
    CheckSysinfo -->|Yes| ExtractUptime1[Extract uptime field]
    ExtractUptime1 --> ReturnUptime1[Return Uptime Seconds]
    ReturnUptime1 --> End1([Return Success])
    
    CheckSysinfo -->|No| TryMethod2
    
    TryMethod1 -->|No| TryMethod2{Try /proc/uptime?}
    
    TryMethod2 -->|Yes| OpenProcUptime[Open /proc/uptime]
    OpenProcUptime --> CheckOpen{File Opened?}
    
    CheckOpen -->|No| ReturnError[Return Error]
    ReturnError --> End2([Return Error])
    
    CheckOpen -->|Yes| ReadFirstField[Read First Field]
    ReadFirstField --> CloseFile[Close File]
    CloseFile --> ParseDouble[Parse as Double]
    ParseDouble --> ConvertToInt[Convert to Integer]
    ConvertToInt --> ReturnUptime2[Return Uptime Seconds]
    ReturnUptime2 --> End3([Return Success])
    
    TryMethod2 -->|No| ReturnError
    
    style Start fill:#90EE90
    style End1 fill:#90EE90
    style End2 fill:#FF6B6B
    style End3 fill:#90EE90
    style CallSysinfo fill:#87CEEB
```

## Get Device Model Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([getModel]) --> CheckCache{Model Cached?}
    
    CheckCache -->|Yes| ReturnCached[Return Cached Model]
    ReturnCached --> End1([Return Success])
    
    CheckCache -->|No| CheckFile{/fss/gw/version.txt exists?}
    
    CheckFile -->|No| ReturnEmpty[Return Empty]
    ReturnEmpty --> End2([Return Error])
    
    CheckFile -->|Yes| OpenFile[Open version.txt]
    OpenFile --> CheckOpen{File Opened?}
    
    CheckOpen -->|No| ReturnEmpty
    
    CheckOpen -->|Yes| ReadLines{Read Lines}
    
    ReadLines -->|More Lines| ParseLine[Read Line]
    ParseLine --> CheckImagename{Starts with imagename:?}
    
    CheckImagename -->|No| ReadLines
    
    CheckImagename -->|Yes| ExtractValue[Extract Value After :]
    ExtractValue --> SplitUnderscore[Split by Underscore]
    SplitUnderscore --> GetFirstField[Get First Field]
    GetFirstField --> CloseFile[Close File]
    CloseFile --> CacheModel[Cache Model]
    CacheModel --> ReturnModel[Return Model Name]
    ReturnModel --> End3([Return Success])
    
    ReadLines -->|No More| CloseFile2[Close File]
    CloseFile2 --> ReturnEmpty
    
    style Start fill:#90EE90
    style End1 fill:#90EE90
    style End2 fill:#FF6B6B
    style End3 fill:#90EE90
    style ReadLines fill:#87CEEB
```

## Reboot Function Flow

### Mermaid Diagram

```mermaid
flowchart TD
    Start([rebootFunc]) --> CheckArgs{Arguments Provided?}
    
    CheckArgs -->|No| GetParent[Get Parent Process from /proc/PPID/cmdline]
    GetParent --> SetDefault[Set Default Reason]
    SetDefault --> CallReboot
    
    CheckArgs -->|Yes| UseProvided[Use Provided Process and Reason]
    UseProvided --> CallReboot[Call /rebootNow.sh]
    
    CallReboot --> SetFlags[Set -s Process Flag]
    SetFlags --> SetReason[Set -o Reason Flag]
    SetReason --> Execute[Execute rebootNow.sh]
    Execute --> End([System Reboots])
    
    style Start fill:#90EE90
    style End fill:#FF6B6B
    style Execute fill:#87CEEB
```

## Text-Based Flowchart Alternative

For environments with Mermaid rendering issues:

### Get MAC Address Flow (Text)

```
START getMacAddressOnly()
  |
  v
[MAC cached & fresh?]
  |
  +--[Yes]--> Return cached MAC --> RETURN(success)
  |
  +--[No]--> Get WAN interface name
              |
              v
           [/etc/waninfo.sh exists?]
              |
              +--[Yes]--> Source script --> Call getWanInterfaceName() --> Set interface
              |                                                                |
              +--[No]--> Use default interface (erouter0)--------------------+
                                                                              |
                                                                              v
                                                                           Query interface hardware address
                                                                              |
                                                                              v
                                                                           [getifaddrs() available?]
                                                                              |
                                                                              +--[Yes]--> Call getifaddrs()
                                                                              |             |
                                                                              |             v
                                                                              |          Iterate interfaces
                                                                              |             |
                                                                              |             v
                                                                              |          [Interface name match?]
                                                                              |             |
                                                                              |             +--[Yes]--> Extract hwaddr --> Free ifaddrs
                                                                              |             |                                |
                                                                              |             +--[No]--> Next interface ------+
                                                                              |                                             |
                                                                              +--[No]--> [ioctl() available?]              |
                                                                                           |                               |
                                                                                           +--[Yes]--> Open socket        |
                                                                                           |             |                |
                                                                                           |             v                |
                                                                                           |          Set ifreq struct    |
                                                                                           |             |                |
                                                                                           |             v                |
                                                                                           |          Call ioctl()        |
                                                                                           |             |                |
                                                                                           |             v                |
                                                                                           |          [Success?]          |
                                                                                           |             |                |
                                                                                           |             +--[Yes]--> Extract hwaddr --> Close socket
                                                                                           |             |                               |
                                                                                           |             +--[No]--> Log error --> Close socket --> RETURN(error)
                                                                                           |                                             |
                                                                                           +--[No]--> RETURN(error)                    |
                                                                                                                                       |
                                                                                                                                       v
                                                                                                                                    Format MAC address
                                                                                                                                       |
                                                                                                                                       v
                                                                                                                                    Remove colons
                                                                                                                                       |
                                                                                                                                       v
                                                                                                                                    Convert to uppercase
                                                                                                                                       |
                                                                                                                                       v
                                                                                                                                    Cache result
                                                                                                                                       |
                                                                                                                                       v
                                                                                                                                    RETURN(MAC address)
```

### Get File Modification Time Flow (Text)

```
START getLastModifiedTimeOfFile(filepath)
  |
  v
[Input valid?]
  |
  +--[No]--> RETURN(empty)
  |
  +--[Yes]--> [File exists?]
                |
                +--[No]--> RETURN(empty)
                |
                +--[Yes]--> Call stat(filepath)
                              |
                              v
                           [stat() success?]
                              |
                              +--[No]--> Log error --> RETURN(empty)
                              |
                              +--[Yes]--> Extract st_mtime
                                            |
                                            v
                                         Convert time_t to struct tm
                                            |
                                            v
                                         Format: YYYY-MM-DD-HH-MM-SS
                                            |
                                            v
                                         RETURN(timestamp string)
```

### Get SHA1 Checksum Flow (Text)

```
START getSHA1(filepath)
  |
  v
[Input valid?]
  |
  +--[No]--> RETURN(error)
  |
  +--[Yes]--> Open file for reading
                |
                v
             [File opened?]
                |
                +--[No]--> Log error --> RETURN(error)
                |
                +--[Yes]--> Initialize SHA1 context
                              |
                              v
                           WHILE (data available)
                              |
                              v
                           Read 8KB chunk
                              |
                              v
                           Update SHA1 context
                              |
                              v
                           END WHILE
                              |
                              v
                           Finalize SHA1
                              |
                              v
                           Close file
                              |
                              v
                           Convert digest to hex string
                              |
                              v
                           RETURN(SHA1 hash)
```

### Process Check Flow (Text)

```
START processCheck(process_name)
  |
  v
Open /proc directory
  |
  v
[Directory opened?]
  |
  +--[No]--> RETURN(1 - not running)
  |
  +--[Yes]--> WHILE (read directory entry)
                |
                v
             [Entry is numeric (PID)?]
                |
                +--[No]--> Continue to next entry
                |
                +--[Yes]--> Build path: /proc/PID/cmdline
                              |
                              v
                           Open cmdline file
                              |
                              v
                           [File opened?]
                              |
                              +--[No]--> Continue to next entry
                              |
                              +--[Yes]--> Read cmdline content
                                            |
                                            v
                                         Close cmdline
                                            |
                                            v
                                         [Process name matches?]
                                            |
                                            +--[No]--> Continue to next entry
                                            |
                                            +--[Yes]--> Close directory
                                                          |
                                                          v
                                                       RETURN(0 - running)
              |
              v
           END WHILE
              |
              v
           Close directory
              |
              v
           RETURN(1 - not running)
```

### Get System Uptime Flow (Text)

```
START Uptime()
  |
  v
[sysinfo() available?]
  |
  +--[Yes]--> Call sysinfo()
  |             |
  |             v
  |          [Success?]
  |             |
  |             +--[Yes]--> Extract uptime field --> RETURN(uptime)
  |             |
  |             +--[No]-----+
  |                         |
  +--[No]-----------------+
                          |
                          v
                       [Try /proc/uptime?]
                          |
                          +--[Yes]--> Open /proc/uptime
                          |             |
                          |             v
                          |          [File opened?]
                          |             |
                          |             +--[No]--> RETURN(error)
                          |             |
                          |             +--[Yes]--> Read first field
                          |                           |
                          |                           v
                          |                        Close file
                          |                           |
                          |                           v
                          |                        Parse as double
                          |                           |
                          |                           v
                          |                        Convert to integer
                          |                           |
                          |                           v
                          |                        RETURN(uptime)
                          |
                          +--[No]--> RETURN(error)
```

### Get Device Model Flow (Text)

```
START getModel()
  |
  v
[Model cached?]
  |
  +--[Yes]--> RETURN(cached model)
  |
  +--[No]--> [/fss/gw/version.txt exists?]
              |
              +--[No]--> RETURN(empty)
              |
              +--[Yes]--> Open version.txt
                            |
                            v
                         [File opened?]
                            |
                            +--[No]--> RETURN(empty)
                            |
                            +--[Yes]--> WHILE (read lines)
                                          |
                                          v
                                       [Line starts with "imagename:"?]
                                          |
                                          +--[No]--> Continue to next line
                                          |
                                          +--[Yes]--> Extract value after ":"
                                                        |
                                                        v
                                                     Split by underscore "_"
                                                        |
                                                        v
                                                     Get first field
                                                        |
                                                        v
                                                     Close file
                                                        |
                                                        v
                                                     Cache model
                                                        |
                                                        v
                                                     RETURN(model name)
                                        |
                                        v
                                     END WHILE
                                        |
                                        v
                                     Close file
                                        |
                                        v
                                     RETURN(empty)
```

### Reboot Function Flow (Text)

```
START rebootFunc(process_name, reason)
  |
  v
[Arguments provided?]
  |
  +--[No]--> Get parent process from /proc/$PPID/cmdline
  |            |
  |            v
  |         Set default reason message
  |            |
  +--[Yes]-----+
               |
               v
            Call /rebootNow.sh with:
              -s process_name
              -o reason
               |
               v
            Execute script
               |
               v
            SYSTEM REBOOTS
```

## Summary of Utility Functions

### Network Functions:
1. **getMacAddressOnly**: Get MAC without colons
2. **getIPAddress**: Get IPv4 address of interface
3. **getMacAddress**: Get MAC with colons (CM interface)
4. **getErouterMacAddress**: Get eRouter MAC with colons

### System Information Functions:
5. **Uptime**: Get system uptime in seconds
6. **getModel**: Get device model from version file
7. **processCheck**: Check if process is running
8. **Timestamp**: Get current timestamp

### File Functions:
9. **getLastModifiedTimeOfFile**: Get file mtime formatted
10. **getSHA1**: Calculate SHA1 checksum of file

### Control Functions:
11. **rebootFunc**: Initiate system reboot with logging

### Performance Characteristics:
- **Cached operations**: < 1ms (MAC, model)
- **File operations**: 1-10ms (stat, small files)
- **Network queries**: 5-20ms (interface info)
- **SHA1 calculation**: ~100ms per MB
- **Process check**: 20-100ms (depends on process count)
