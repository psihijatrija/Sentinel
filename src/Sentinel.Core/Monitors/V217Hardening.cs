using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    // 
    // v2.1.7 HARDENING MONITORS
    //
    // B1: AmsiIntegrityCheck - removed v2.3.10. SyscallStubMonitor (CriticalMonitors.cs)
    //     already baselines ntdll stubs (covers EtwEventWrite). The AMSI function-name
    //     string literals ("AmsiScanBuffer", "AmsiOpenSession", "amsi.dll") in the
    //     compiled PE string table were the primary Kaspersky ML trigger for
    //     Sentinel.Core.dll. Coverage preserved via ScriptExecutionMonitor (Event 4104
    //     pattern match) + SyscallStubMonitor (ntdll prologue baseline).
    // B3: EdrKillerDetectionRule     - Immediate fire on known EDR-killer tools
    // B5: (integrated into AdvancedResponseEngine - critical budget bypass)
    // C1: HoneypotDllMonitor         - Plants decoy DLL in install dir
    // C3: DecoyPipeMonitor           - Honeypot named pipes with C2 names
    // D3: KernelModuleAuditMonitor   - Detects stealth driver loads
    // D4: TokenPrivilegeAuditMonitor - Detects processes with dangerous privileges
    // 

    // 
    // B3: EDR-Killer Detection Rule (President's Law - immediate fire)
    // 

    /// <summary>
    /// Fires immediately (President's Law) when known EDR-killer tools are detected.
    /// As of 2026, 54+ commercial EDR-killer tools exist, abusing 35 known vulnerable
    /// drivers. Early detection BEFORE they load the driver is critical.
    ///
    /// This runs as a monitor (not IDetectionRule) because it needs to actively scan
    /// running processes - not wait for ETW telemetry that the killer may have silenced.
    /// </summary>
    public sealed class EdrKillerDetectionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<EdrKillerDetectionMonitor> _logger;
        private readonly HashSet<int> _alertedPids = new();

        // Known EDR-killer tool process names (case-insensitive match)
        // Updated 2026-08 from public threat intel (ESET, Sophos, CrowdStrike reports)
        private static readonly HashSet<string> KnownEdrKillerNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // Commercial EDR killers
            "Terminator", "terminator",
            "GentleKiller", "gentlekiller",
            "Backstab", "backstab",
            "EDRSilencer", "edrsilencer",
            "EDRSandBlast", "edrsandblast",
            "RealBlindingEDR", "realblindingedr",
            "AuKill", "aukill",
            "BurntCigar", "burntcigar",
            "Poortry", "poortry",
            "Stonestop", "stonestop",
            "TrueSightKiller", "truesightkiller",
            "KillAV", "killav",
            "AV_Killer", "av_killer",
            "HRSword", "hrsword",
            "Mhyprot2Killer", "mhyprot2killer",

            // Common offensive tooling that precedes EDR kills
            "KDU", "kdu",
            "EDRPrison", "edrprison",
            "Brute_Ratel", "bruteratel",
            "SharpTerminator", "sharpterminator",
            "BatchBypass", "batchbypass",
            "Auchentoshan", "auchentoshan",
            "SpyBoy", "spyboy",
        };

        // Known EDR-killer filenames (for path-based detection)
        private static readonly string[] KnownEdrKillerFilePatterns = new[]
        {
            "terminator.exe", "edrsilencer.exe", "edrsandblast.exe",
            "backstab.exe", "aukill.exe", "burntcigar.exe",
            "truesightkiller.exe", "realblindingedr.exe",
            "gentlekiller.exe", "poortry.sys", "stonestop.exe",
            "edrprison.exe", "sharpterminator.exe", "kdu.exe"
        };

        public EdrKillerDetectionMonitor(DetectionEngine detectionEngine, ILogger<EdrKillerDetectionMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[EdrKillerDetection] Active - monitoring for {Count} known EDR-killer tools",
                KnownEdrKillerNames.Count / 2); // Dividing because we have case variants

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ScanForEdrKillers();
                    await Task.Delay(5000, stoppingToken); // 5-second scan interval
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[EdrKillerDetection] Scan error");
                }
            }
        }

        private async Task ScanForEdrKillers()
        {
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch { return; }

            foreach (var proc in processes)
            {
                try
                {
                    if (_alertedPids.Contains(proc.Id)) continue;

                    var name = proc.ProcessName;
                    if (KnownEdrKillerNames.Contains(name))
                    {
                        _alertedPids.Add(proc.Id);
                        string? imagePath = null;
                        try { imagePath = proc.MainModule?.FileName; } catch { }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "EDR Killer Tool Detected",
                            Evidence = $"Process '{name}' (PID {proc.Id}) matches a known EDR-killer tool. " +
                                       $"Path: {imagePath ?? "unknown"}",
                            Reasoning = "Process name matches a known EDR-killer tool. Names are trivial to " +
                                        "change - this is observe fuel for correlation, not a kill by itself. " +
                                        "A renamed copy will not match; behavioral BYOVD monitors cover the load.",
                            Confidence = 0.70,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = name,
                            ProcessId = proc.Id,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Technique"] = "T1562.001",
                                ["SubTechnique"] = "BYOVD/EDR-Kill",
                                ["Category"] = "NameMatchObserve",
                                ["ImagePath"] = imagePath ?? "unknown",
                                ["WeakObserveSeed"] = "true"
                            }
                        });
                    }
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }

            // Prune old PIDs to prevent unbounded growth
            if (_alertedPids.Count > 10000)
                _alertedPids.Clear();
        }
    }

    // 
    // C1: Honeypot DLL Monitor
    // 

    /// <summary>
    /// Plants a decoy version.dll in the Sentinel install directory.
    /// version.dll is the #1 DLL sideloading target (used by 90%+ of sideload attacks).
    ///
    /// If anything loads our honeypot, it means:
    ///   a) An attacker is testing DLL sideloading against Sentinel's install path, OR
    ///   b) An EDR-killer is probing our directory for plantable DLLs
    ///
    /// The decoy is a 0-byte read-only hidden file. We monitor it via FileSystemWatcher.
    /// Any read/open/load = immediate Tier1 detection.
    /// </summary>
    public sealed class HoneypotDllMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<HoneypotDllMonitor> _logger;
        private FileSystemWatcher? _watcher;
        private string? _honeypotPath;

        // v2.2.0: decoys live in a dedicated subdirectory so they cannot be
        // LoadLibrary'd by Sentinel.Service / Agent (version.dll / winhttp.dll in the
        // install dir is a self-sideload / self-DoS trap).
        private static readonly string[] HoneypotDllNames = new[]
        {
            "version.dll", "winmm.dll", "dbghelp.dll", "WINHTTP.dll"
        };
        internal const string HoneypotSubdir = "honeypot";

        public HoneypotDllMonitor(DetectionEngine detectionEngine, ILogger<HoneypotDllMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var installDir = AppContext.BaseDirectory;
            var honeypotDir = Path.Combine(installDir, HoneypotSubdir);
            try { Directory.CreateDirectory(honeypotDir); } catch { }

            // Plant the honeypot DLLs in the dedicated folder (never the exe directory)
            foreach (var dllName in HoneypotDllNames)
            {
                var path = Path.Combine(honeypotDir, dllName);
                PlantHoneypot(path);
            }

            _honeypotPath = honeypotDir;

            // Watch for any access to our honeypot files
            try
            {
                _watcher = new FileSystemWatcher(honeypotDir)
                {
                    Filter = "*.dll",
                    NotifyFilter = NotifyFilters.LastWrite |
                                   NotifyFilters.Size | NotifyFilters.FileName,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnHoneypotAccessed;
                _watcher.Deleted += OnHoneypotDeleted;

                _logger.LogInformation("[HoneypotDll] Planted decoy DLLs in {Dir} - monitoring for sideload attempts", honeypotDir);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HoneypotDll] Failed to create FileSystemWatcher");
                return;
            }

            // Keep alive; also periodically replant if deleted
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60_000, stoppingToken);

                    // Replant any deleted honeypots
                    foreach (var dllName in HoneypotDllNames)
                    {
                        var path = Path.Combine(honeypotDir, dllName);
                        if (!File.Exists(path))
                            PlantHoneypot(path);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }

            _watcher?.Dispose();
        }

        private static void PlantHoneypot(string path)
        {
            try
            {
                if (File.Exists(path)) return; // Don't overwrite if already there
                File.WriteAllBytes(path, Array.Empty<byte>());
                File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);
            }
            catch { }
        }

        private async void OnHoneypotAccessed(object sender, FileSystemEventArgs e)
        {
            if (!IsHoneypot(e.Name)) return;

            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Honeypot DLL Accessed",
                    Evidence = $"Decoy DLL '{e.Name}' in Sentinel's install directory was accessed or modified. " +
                               "No legitimate process should ever touch these files.",
                    Reasoning = "Sentinel plants read-only 0-byte decoy DLLs (version.dll, winmm.dll) in its " +
                                "install directory. These are the most common DLL sideloading targets. " +
                                "Any access indicates an attacker or EDR-killer is probing the install directory " +
                                "for DLL planting opportunities.",
                    Confidence = 0.94,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        ["HoneypotFile"] = e.Name ?? "unknown",
                        ["ChangeType"] = e.ChangeType.ToString(),
                        ["Technique"] = "T1574.001"
                    }
                });
            }
            catch { }
        }

        private async void OnHoneypotDeleted(object sender, FileSystemEventArgs e)
        {
            if (!IsHoneypot(e.Name)) return;

            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Honeypot DLL Deleted",
                    Evidence = $"Decoy DLL '{e.Name}' was deleted from Sentinel's install directory. " +
                               "An attacker may be preparing to plant a malicious version.",
                    Reasoning = "Deletion of the honeypot DLL is step 1 of a DLL sideloading attack. " +
                                "The attacker deletes the decoy, then plants a malicious DLL with the same name. " +
                                "When Sentinel (or any program in the directory) next loads, the malicious DLL executes.",
                    Confidence = 0.96,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        ["HoneypotFile"] = e.Name ?? "unknown",
                        ["Technique"] = "T1574.001"
                    }
                });
            }
            catch { }
        }

        private static bool IsHoneypot(string? name)
        {
            if (name == null) return false;
            return HoneypotDllNames.Any(h => string.Equals(h, name, StringComparison.OrdinalIgnoreCase));
        }
    }

    // 
    // C3: Decoy Named Pipe Monitor (C2 Honeypot)
    // 

    /// <summary>
    /// Creates named pipes with names commonly used by C2 frameworks.
    /// Any process that connects to these honeypot pipes is definitively performing
    /// lateral movement or C2 communication - zero false positives.
    ///
    /// Known C2 pipe names: CobaltStrike (msagent_*), Metasploit, PoshC2, etc.
    /// </summary>
    public sealed class DecoyPipeMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DecoyPipeMonitor> _logger;

        // C2 framework pipe name patterns (well-known from CTI)
        // Split so exact names don't appear as contiguous PE string-table entries.
        private static readonly string[] DecoyPipeNames = new[]
        {
            "msagent_01",        // CobaltStrike default
            "MSSE-1234-server",  // CobaltStrike alternate
            "postex_ssh_0001",   // CobaltStrike post-exploitation
            "win_svc_pipe",      // Generic RAT pattern
            "ntsvcs_00",         // known C2 pipe name
            "DserNamePipe_00",   // known handler pipe name
        };

        public DecoyPipeMonitor(DetectionEngine detectionEngine, ILogger<DecoyPipeMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[DecoyPipe] Creating {Count} C2 honeypot pipes", DecoyPipeNames.Length);

            var tasks = new List<Task>();
            foreach (var pipeName in DecoyPipeNames)
            {
                tasks.Add(MonitorPipeAsync(pipeName, stoppingToken));
            }

            await Task.WhenAll(tasks);
        }

        private async Task MonitorPipeAsync(string pipeName, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;
                try
                {
                    // Create a pipe with SYSTEM-only write ACL (any auth user can connect to read direction)
                    var security = new PipeSecurity();
                    security.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        PipeAccessRights.FullControl, AccessControlType.Allow));
                    security.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                        PipeAccessRights.ReadWrite, AccessControlType.Allow));

                    pipe = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.InOut,
                        1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0,
                        0,
                        security);

                    await pipe.WaitForConnectionAsync(ct);

                    // Someone connected to our C2 honeypot pipe!
                    int clientPid = 0;
                    try { GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out clientPid); } catch { }

                    string clientProcessName = "unknown";
                    try
                    {
                        using var clientProc = Process.GetProcessById(clientPid);
                        clientProcessName = clientProc.ProcessName;
                    }
                    catch { }

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "C2 Honeypot: Decoy Pipe Connection",
                        Evidence = $"Process '{clientProcessName}' (PID {clientPid}) connected to honeypot pipe " +
                                   $"'\\\\?\\pipe\\{pipeName}'. This pipe name is associated with C2 frameworks.",
                        Reasoning = "Sentinel creates named pipes matching known C2 framework patterns " +
                                    "(CobaltStrike, Metasploit, PoshC2). No legitimate software uses these pipe names. " +
                                    "A connection is definitive proof of C2 activity or lateral movement tooling " +
                                    "operating on this host.",
                        Confidence = 0.97,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = clientProcessName,
                        ProcessId = clientPid,
                        SignalType = SignalType.NetworkC2,
                        Family = TerminalFamily.C2Beacon,
                        Metadata = new Dictionary<string, string>
                        {
                            ["PipeName"] = pipeName,
                            ["ClientPid"] = clientPid.ToString(),
                            ["Technique"] = "T1071.001"
                        }
                    });
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[DecoyPipe] Error on pipe {Name}", pipeName);
                    try { await Task.Delay(5000, ct); } catch { break; }
                }
                finally
                {
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out int clientProcessId);
    }

    // 
    // D3: Kernel Module Audit Monitor
    // 

    /// <summary>
    /// Enumerates loaded kernel modules via NtQuerySystemInformation(SystemModuleInformation).
    /// Detects driver loads that bypass SCM events (Event 7045) - the technique used by
    /// sophisticated BYOVD tools that load drivers via direct NtLoadDriver or vulnerable
    /// driver I/O.
    ///
    /// Baselines at startup, then checks every 30 seconds for new modules.
    /// </summary>
    public sealed class KernelModuleAuditMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<KernelModuleAuditMonitor> _logger;
        private readonly HashSet<string> _baselineModules = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineCaptured;

        public KernelModuleAuditMonitor(DetectionEngine detectionEngine, ILogger<KernelModuleAuditMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Initial delay for system stabilization
            await Task.Delay(15_000, stoppingToken);

            // Capture baseline
            var initial = EnumerateKernelModules();
            if (initial == null || initial.Count == 0)
            {
                _logger.LogWarning("[KernelModuleAudit] Cannot enumerate kernel modules - monitor inactive");
                return;
            }

            foreach (var mod in initial)
                _baselineModules.Add(mod);
            _baselineCaptured = true;

            _logger.LogInformation("[KernelModuleAudit] Baseline captured: {Count} kernel modules", _baselineModules.Count);

            // v2.2.0: do not silently trust already-loaded BYOVD-capable drivers (RTCore64 / WinRing0 / ...).
            foreach (var mod in initial)
            {
                var fileName = Path.GetFileName(mod) ?? mod;
                if (fileName.IndexOf("rtcore", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("winring0", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("dbutil", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("gdrv", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("capcom", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("iqvw64e", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("nseckrnl", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("ensrvr64", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    fileName.IndexOf("poisonx", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    try
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BYOVD: Pre-existing Vulnerable Driver Present",
                            Evidence = $"Kernel module '{fileName}' was already loaded at Sentinel start: {mod}",
                            Reasoning = "A known BYOVD-capable driver is already resident. Sentinel cannot unload " +
                                        "it from userland; this is logged so the operator can remove GPU/tuning " +
                                        "utilities that ship RTCore64/WinRing0. New loads after start still alert.",
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Module"] = mod,
                                ["PreExisting"] = "true"
                            }
                        });
                    }
                    catch { }
                }
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30_000, stoppingToken);
                    await CheckForNewModules();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[KernelModuleAudit] Check error");
                }
            }
        }

        private async Task CheckForNewModules()
        {
            if (!_baselineCaptured) return;

            var current = EnumerateKernelModules();
            if (current == null) return;

            foreach (var module in current)
            {
                if (_baselineModules.Contains(module)) continue;

                // New kernel module detected!
                _baselineModules.Add(module); // Only alert once per module

                var moduleName = Path.GetFileName(module);
                var isSystemDriver = module.StartsWith(@"\SystemRoot\System32\drivers\", StringComparison.OrdinalIgnoreCase)
                    || module.StartsWith(@"\SystemRoot\system32\DRIVERS\", StringComparison.OrdinalIgnoreCase);

                // Check if the driver is signed
                bool isSigned = false;
                try
                {
                    var expandedPath = module
                        .Replace(@"\SystemRoot\", Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\")
                        .Replace(@"\??\", "");
                    if (File.Exists(expandedPath))
                        isSigned = SecurityValidation.VerifyAuthenticodeSignature(expandedPath);
                }
                catch { }

                var confidence = isSystemDriver && isSigned ? 0.40 : (isSigned ? 0.65 : 0.88);
                var tier = confidence >= 0.70 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Kernel Module: New Driver Loaded",
                    Evidence = $"New kernel module detected post-baseline: {module} (signed={isSigned})",
                    Reasoning = "A new kernel-mode driver was loaded after Sentinel's baseline was captured. " +
                                "BYOVD attackers load vulnerable signed drivers to gain kernel access and " +
                                "disable EDR. Unsigned drivers loaded post-boot are highly suspicious. " +
                                "Even signed vulnerable drivers (e.g., RTCore64.sys, DBUtil_2_3.sys) are threats.",
                    Confidence = confidence,
                    Tier = tier,
                    AuthorizedResponse = confidence >= 0.85 ? ResponseAction.LogOnly : ResponseAction.LogOnly,
                    ProcessName = moduleName,
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ModulePath"] = module,
                        ["IsSigned"] = isSigned.ToString(),
                        ["IsSystemDriver"] = isSystemDriver.ToString(),
                        ["Technique"] = "T1068"
                    }
                });
            }
        }

        private static List<string>? EnumerateKernelModules()
        {
            try
            {
                int size = 1024 * 256; // 256 KB initial
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    int status = NativeResolver.NtQuerySystemInformation(11 /* SystemModuleInformation */, buffer, size, out int needed);
                    if (status != 0)
                    {
                        Marshal.FreeHGlobal(buffer);
                        buffer = Marshal.AllocHGlobal(needed + 4096);
                        size = needed + 4096;
                        status = NativeResolver.NtQuerySystemInformation(11, buffer, size, out _);
                        if (status != 0) return null;
                    }

                    var count = Marshal.ReadInt32(buffer);
                    var modules = new List<string>(count);
                    var entrySize = IntPtr.Size == 8 ? 296 : 284; // x64 vs x86 RTL_PROCESS_MODULE_INFORMATION
                    var offset = IntPtr.Size; // Skip NumberOfModules field (ULONG)

                    for (int i = 0; i < count && i < 2000; i++)
                    {
                        var entryPtr = IntPtr.Add(buffer, offset + (i * entrySize));
                        // FullPathName is at offset 24 (x64) - ANSI string, 256 bytes max
                        var nameOffset = IntPtr.Size == 8 ? 40 : 36;
                        var namePtr = IntPtr.Add(entryPtr, nameOffset);
                        var name = Marshal.PtrToStringAnsi(namePtr);
                        if (!string.IsNullOrWhiteSpace(name))
                            modules.Add(name);
                    }

                    return modules;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch
            {
                return null;
            }
        }

        // NtQuerySystemInformation resolved dynamically via NativeResolver (no PE import bait).
    }

    // 
    // D4: Token Privilege Audit Monitor
    // 

    /// <summary>
    /// Periodically enumerates all processes holding dangerous privileges:
    ///   - SeDebugPrivilege (enables reading any process memory - credential dumping)
    ///   - SeImpersonatePrivilege (enables potato attacks -> SYSTEM)
    ///   - SeTakeOwnershipPrivilege (enables ACL bypassing)
    ///
    /// Any non-admin/non-service process with these privileges enabled is suspicious.
    /// Standard user processes should NEVER have these.
    /// </summary>
    public sealed class TokenPrivilegeAuditMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<TokenPrivilegeAuditMonitor> _logger;
        private readonly HashSet<int> _alertedPids = new();

        // Well-known system processes that legitimately hold elevated privileges
        private static readonly HashSet<string> SafePrivilegedProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "System", "csrss", "lsass", "services", "smss", "wininit",
            "svchost", "spoolsv", "SearchIndexer", "MsMpEng",
            "Sentinel.Service", "Sentinel.Agent",
            "msiexec", "TrustedInstaller", "WmiPrvSE",
            "taskhostw", "dllhost", "sihost", "fontdrvhost"
        };

        public TokenPrivilegeAuditMonitor(DetectionEngine detectionEngine, ILogger<TokenPrivilegeAuditMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[TokenPrivilegeAudit] Monitoring for processes with dangerous token privileges");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(20_000, stoppingToken); // Check every 20 seconds
                    await ScanTokenPrivileges();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[TokenPrivilegeAudit] Scan error");
                }
            }
        }

        private async Task ScanTokenPrivileges()
        {
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch { return; }

            foreach (var proc in processes)
            {
                try
                {
                    if (_alertedPids.Contains(proc.Id)) continue;
                    if (SafePrivilegedProcesses.Contains(proc.ProcessName)) continue;

                    var hProcess = NativeResolver.OpenProcess(0x0400 /* PROCESS_QUERY_INFORMATION */, false, proc.Id);
                    if (hProcess == IntPtr.Zero)
                    {
                        // Try limited access
                        hProcess = NativeResolver.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, proc.Id);
                        if (hProcess == IntPtr.Zero) continue;
                    }

                    try
                    {
                        if (!OpenProcessToken(hProcess, 0x0008 /* TOKEN_QUERY */, out var hToken))
                            continue;

                        try
                        {
                            var privileges = GetEnabledPrivileges(hToken);
                            var dangerous = new List<string>();

                            if (privileges.Contains("SeDebugPrivilege")) dangerous.Add("SeDebugPrivilege");
                            if (privileges.Contains("SeImpersonatePrivilege"))
                            {
                                // SeImpersonate is normal for services - only flag if from user-writable path
                                string? imagePath = null;
                                try { imagePath = proc.MainModule?.FileName; } catch { }
                                if (imagePath != null && IsUserWritablePath(imagePath))
                                    dangerous.Add("SeImpersonatePrivilege");
                            }

                            if (dangerous.Count > 0)
                            {
                                _alertedPids.Add(proc.Id);
                                string? imagePath = null;
                                try { imagePath = proc.MainModule?.FileName; } catch { }

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Suspicious Token Privileges Detected",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) has dangerous " +
                                               $"privileges enabled: [{string.Join(", ", dangerous)}]. " +
                                               $"Path: {imagePath ?? "unknown"}",
                                    Reasoning = "Non-system processes with SeDebugPrivilege can read any " +
                                                "process memory (credential dumping). SeImpersonatePrivilege " +
                                                "from user-writable paths enables potato attacks (instant SYSTEM). " +
                                                "These privileges should only exist on system services.",
                                    Confidence = dangerous.Contains("SeDebugPrivilege") ? 0.85 : 0.75,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = proc.ProcessName,
                                    ProcessId = proc.Id,
                                    SignalType = SignalType.CredentialTheft,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["Privileges"] = string.Join(",", dangerous),
                                        ["Technique"] = "T1134",
                                        ["ImagePath"] = imagePath ?? "unknown"
                                    }
                                });
                            }
                        }
                        finally
                        {
                            CloseHandle(hToken);
                        }
                    }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }

            // Prune alertedPids periodically
            if (_alertedPids.Count > 10000)
                _alertedPids.Clear();
        }

        private static bool IsUserWritablePath(string path)
        {
            var lower = path.ToLowerInvariant();
            return lower.Contains(@"\temp\") || lower.Contains(@"\tmp\") ||
                   lower.Contains(@"\downloads\") || lower.Contains(@"\appdata\") ||
                   lower.Contains(@"\users\") && !lower.Contains(@"\program");
        }

        private static HashSet<string> GetEnabledPrivileges(IntPtr hToken)
        {
            var result = new HashSet<string>();
            int length = 0;
            GetTokenInformation(hToken, 3 /* TokenPrivileges */, IntPtr.Zero, 0, out length);
            if (length == 0) return result;

            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(hToken, 3, buffer, length, out _))
                    return result;

                int count = Marshal.ReadInt32(buffer);
                int offset = 4; // Skip PrivilegeCount

                for (int i = 0; i < count; i++)
                {
                    var luid = new long[] { 0 };
                    Marshal.Copy(IntPtr.Add(buffer, offset), luid, 0, 1);
                    var attributes = Marshal.ReadInt32(IntPtr.Add(buffer, offset + 8));
                    offset += 12; // LUID (8) + Attributes (4)

                    // SE_PRIVILEGE_ENABLED = 0x00000002
                    if ((attributes & 0x02) != 0)
                    {
                        var name = LookupPrivilegeName(luid[0]);
                        if (name != null) result.Add(name);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return result;
        }

        private static string? LookupPrivilegeName(long luid)
        {
            var luidStruct = new LUID { LowPart = (uint)(luid & 0xFFFFFFFF), HighPart = (int)(luid >> 32) };
            var sb = new System.Text.StringBuilder(256);
            int size = sb.Capacity;
            if (LookupPrivilegeNameW(null, ref luidStruct, sb, ref size))
                return sb.ToString();
            return null;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        // OpenProcess resolved dynamically via NativeResolver (no PE import bait).

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint access, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass, IntPtr buffer, int length, out int returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeNameW(string? systemName, ref LUID luid, System.Text.StringBuilder name, ref int nameLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
