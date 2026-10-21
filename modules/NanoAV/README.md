# NanoAV Lite

**NanoAV Lite** is a lightweight Windows endpoint protection tool built with C# and .NET Framework 4.8. It provides real-time threat detection, file monitoring, C2/beacon detection, and reverse shell prevention using heuristic analysis and threat intelligence feeds.

## Overview

NanoAV Lite operates as a COM server that persists via the Windows Run key. It monitors file system activity, memory processes, and network connections to detect and mitigate malware threats including:

- Known malware files (via hash lookup against public databases)
- Suspicious unsigned DLLs/WINMDs in risky locations
- Command & Control (C2) communication patterns
- Beacon-like network behavior (consistent intervals with low jitter)
- Reverse shell command lines and processes
- IP rotation attacks (many unique remote IPs from a single process)

## Features

- **Real-time File Monitoring**: Scans files on creation/modification using Windows WMI event watchers
- **Hash-Based Detection**: Checks files against Circl.lu, Cymru MHR, and MalwareBazaar threat intel
- **Digital Signature Validation**: Authenticode signature verification for executables and DLLs
- **Behavioral Analysis**: Detects suspicious code patterns, LOLBins, and malware indicators
- **C2 Detection Engine**: Score-based C2 communication detection with beacon identification
- **Reverse Shell Killer**: Detects and terminates reverse shell attempts via command-line analysis
- **Firewall Auto-Block**: Blocks suspicious outbound C2 IPs via Windows Firewall
- **Automatic Quarantine**: Moves threats to a dedicated quarantine directory
- **Logging**: Comprehensive logging to NanoAV.log and blocked.log

## Requirements

- Windows 10 or later (64-bit)
- .NET Framework 4.8 or later
- Administrator privileges for full functionality (COM registration, firewall rules, process termination)

## Building

```powershell
# Build the project using the provided script
.\build-nanoav.ps1
```

This produces:
- `bin\NanoAV.dll` - COM server DLL
- `bin\NanoAV.exe` - Bootstrap installer

## Installation

Run `NanoAV.exe` as Administrator to install and register the COM server:

```powershell
# Run as Administrator
.\bin\NanoAV.exe
```

Installation steps:
1. Copies `NanoAV.exe` to `C:\ProgramData\NanoAV\NanoAV.dll`
2. Registers the COM server using `regasm.exe /codebase`
3. Adds an entry to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
4. Creates the persistence task and starts monitoring

## Configuration

Configuration is defined in `NanoConfig.cs`:

| Setting | Default | Description |
|---------|---------|-------------|
| BaseDirectory | `C:\ProgramData\NanoAV` | Installation directory |
| EnableMemoryScanning | `true` | Enable memory scanning |
| EnableRealtimeMonitor | `true` | Enable file system monitoring |
| EnableC2Detection | `true` | Enable C2 connection analysis |
| EnableFirewallAutoBlock | `true` | Auto-block C2 IPs via firewall |
| EnableBeaconDetection | `true` | Detect beacon behavior |
| EnableReverseShellKill | `true` | Terminate reverse shell processes |
| AutoQuarantine | `true` | Auto-quarantine threats |
| DeepScanIntervalHours | `6` | Interval for deep file scans |
| MemoryScanIntervalSec | `300` | Memory scan frequency |

## ThreatIntel Integration

NanoAV Lite integrates with multiple public threat intelligence sources:

- **Circl.lu Hash Lookup**: Checks SHA256 hashes against known-good databases
- **Cymru Malware Hash Registry**: Detection threshold (default: ≥60% vendors flagging)
- **MalwareBazaar**: Checks against abuse.ch's malware database

## File Extensions Monitored

The tool monitors over 300 executable and script extensions including:
- Executables: `.exe`, `.dll`, `.sys`, `.ocx`, `.scr`, `.com`, `.msi`, `.drv`
- Scripts: `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.wsf`
- Documents with macros: `.docm`, `.xlsm`, `.pptm`, `.dotm`
- Archives: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.iso`

See `Config.MonitoredExtensions` for the complete list.

## Output Files

| File | Description |
|------|-------------|
| `NanoAV.log` | Main operation log (install, scans, alerts) |
| `blocked.log` | Record of blocked file executions |
| `memory_hits.log` | Memory scan threat findings |
| `known_files.db` | Internal hash database (safe/bad files) |
| `NanoAV_pids.txt` | Registered NanoAV process IDs |

## Architecture

### Components

- `NanoAV.cs` - Entry point and installation logic
- `NanoComServer.cs` - COM server registration and lifecycle
- `NanoFileScanner.cs` - File hashing, signature verification, quarantine operations
- `NanoThreatAnalysis.cs` - Threat analysis and file blocking
- `NanoC2Engine.cs` - C2 detection, beacon tracking, reverse shell killer
- `NanoMemoryScanner.cs` - Memory process scanning for malicious patterns
- `NanoThreatIntel.cs` - Integration with threat intelligence APIs
- `NanoDatabase.cs` - Internal hash database (SQLite-like)
- `NanoLogger.cs` - Logging infrastructure
- `NanoAlerts.cs` - Alert delivery system
- `NanoWmi.cs` - WMI event watchers for file monitoring
- `NanoNative.cs` - P/Invoke for native Windows APIs (TCP connections, processes)
- `NanoProcessHelper.cs` - Process utilities (command line retrieval)
- `NanoPidRegistry.cs` - Process ID tracking to avoid self-blocking
- `NanoAutoStart.cs` - Windows autorun persistence management
- `NanoBehavior.cs` - Behavioral analysis heuristics
- `NanoAssemblyInfo.cs` - Assembly metadata

## Legal Disclaimer

**NanoAV Lite is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.**

This software is intended for educational and research purposes only. It is not a substitute for enterprise-grade antivirus or endpoint protection solutions. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction. The developers of NanoAV Lite are not responsible for any damage or data loss that may result from the use of this software.

By using NanoAV Lite, you acknowledge that you have read, understood, and agree to be bound by this disclaimer.

---

**Author**: Gorstak  
**License**: MIT  
**Project**: [NanoAV](https://github.com/gorstak/NanoAV)
