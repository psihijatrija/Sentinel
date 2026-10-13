using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.7: ETW Provider Tamper Monitor - detects ETW provider stripping and EtwEventWrite patching.
    /// 
    /// Blind spot addressed: Attackers can patch ntdll!EtwEventWrite in OTHER processes (not just
    /// Sentinel's own, which SyscallStubMonitor covers) to blind all ETW consumers for those processes.
    /// They can also use logman/wevtutil to stop/modify security trace sessions. Current EtwSessionGuard
    /// only watches Sentinel's own session - it doesn't detect global ETW manipulation.
    /// 
    /// Detection approach:
    /// - Monitor for logman.exe, wevtutil.exe, tracerpt.exe command-line patterns that stop/modify
    ///   security-relevant ETW sessions or providers
    /// - Periodically enumerate active ETW sessions and detect session removal/modification
    /// - Check EtwEventWrite prologue in critical processes (lsass, svchost hosting Security EventLog)
    ///   for patches (NOP, RET, JMP instructions replacing the standard prologue)
    /// - Detect Security Event Log service disruption (EventLog service stopped or providers removed)
    /// 
    /// Response: Tier1 KillProcessTree for confirmed ETW/provider manipulation.
    ///           Tier2 for suspicious session enumeration patterns.
    /// Scans every 30s. Remote prologue reads via <see cref="NativeProcessMemory"/> (dynamic APIs).
    /// </summary>
    public sealed class EtwProviderTamperMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<EtwProviderTamperMonitor> _logger;

        // Baseline of active ETW session names
        private HashSet<string> _baselineSessions = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineCaptured;

        // Track alerted items to prevent spam
        private readonly HashSet<string> _alertedItems = new(StringComparer.OrdinalIgnoreCase);

        // Critical ETW sessions that should never be stopped
        private static readonly HashSet<string> CriticalSessions = new(StringComparer.OrdinalIgnoreCase)
        {
            "EventLog-Security", "EventLog-System", "EventLog-Application",
            "SentinelUnifiedTrace", "DiagTrack", "Circular Kernel Context Logger",
            "UBPM", "NetTrace", "NtfsLog", "WdiContextLog",
            // v2.6.0: DNS Client Operational log - DnsQueryMonitor reads event IDs 3006/3008 from
            // this session. An attacker disabling it blinds all DNS-layer detections (DGA, rapid
            // query, covert mesh, webhook sink correlations).
            "Microsoft-Windows-DNS Client Events/Operational",
        };

        // Command patterns indicating ETW manipulation
        private static readonly (string Pattern, string Description, double Confidence)[] EtwManipulationPatterns = new[]
        {
            ("logman stop", "ETW session stop via logman", 0.88),
            ("logman delete", "ETW session delete via logman", 0.92),
            ("logman update.*-ets", "ETW session modification via logman", 0.82),
            ("wevtutil cl security", "Security event log cleared", 0.95),
            ("wevtutil cl system", "System event log cleared", 0.90),
            ("wevtutil sl.*enabled:false", "Event log channel disabled", 0.88),
            ("sc stop eventlog", "EventLog service stop attempt", 0.92),
            ("sc config eventlog.*disabled", "EventLog service disabled", 0.95),
            ("Set-EtwTraceSession.*-AutologgerDisabled", "ETW autologger disabled via PowerShell", 0.85),
            ("Remove-EtwTraceProvider", "ETW trace provider removed via PowerShell", 0.88),
            ("logman.*Microsoft-Windows-Threat-Intelligence", "Threat Intelligence ETW provider targeted", 0.95),
            ("logman.*Microsoft-Windows-Kernel-Process", "Kernel Process ETW provider targeted", 0.92),
        };

        // P/Invoke for ETW session enumeration
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int QueryAllTracesW(
            [Out] IntPtr[] propertyArray,
            uint propertyArrayCount,
            out uint sessionCount);

        public EtwProviderTamperMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<EtwProviderTamperMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[EtwProviderTamperMonitor] Started - monitoring ETW provider integrity");
            await Task.Delay(30000, ct); // Let other monitors start first

            // Capture baseline ETW sessions
            _baselineSessions = EnumerateEtwSessions();
            _baselineCaptured = true;
            _logger.LogDebug("[EtwProviderTamperMonitor] Baselined {Count} active ETW sessions", _baselineSessions.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    await CheckEtwSessionIntegrityAsync(ct);
                    await CheckProcessEtwPatchingAsync(ct);
                    await CheckEtwManipulationProcessesAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[EtwProviderTamperMonitor] Scan error"); }
            }
        }

        /// <summary>
        /// Check if any critical ETW sessions have been stopped since baseline.
        /// </summary>
        private async Task CheckEtwSessionIntegrityAsync(CancellationToken ct)
        {
            if (!_baselineCaptured) return;

            var currentSessions = EnumerateEtwSessions();

            foreach (var session in CriticalSessions)
            {
                if (ct.IsCancellationRequested) break;
                if (!_baselineSessions.Contains(session)) continue; // Wasn't active at baseline
                if (currentSessions.Contains(session)) continue; // Still active

                string alertKey = $"session:{session}";
                if (_alertedItems.Contains(alertKey)) continue;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Critical ETW Session Stopped",
                    Evidence = $"Critical ETW session '{session}' was active at baseline but is no longer running. " +
                               $"This blinds the Security Event Log, Kernel Process tracing, or Sentinel's own telemetry.",
                    Reasoning = "A critical ETW trace session was stopped. Attackers disable ETW sessions to blind EDR/SIEM " +
                                "before performing malicious actions. This is a common EDR-evasion technique (MITRE T1562.006).",
                    Confidence = 0.92,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly, // Can't kill - session already gone
                    SignalType = SignalType.AntiTamper,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                });
                _alertedItems.Add(alertKey);
            }

            // Update baseline with current state (only add, never remove critical sessions)
            foreach (var session in currentSessions)
                _baselineSessions.Add(session);
        }

        /// <summary>
        /// Check EtwEventWrite prologue in critical processes (lsass, EventLog host).
        /// Uses ReadProcessMemory for remote byte comparison. Function address is resolved
        /// via PE export table walk (no GetProcAddress P/Invoke - avoids AV evasion heuristic).
        /// </summary>
        private async Task CheckProcessEtwPatchingAsync(CancellationToken ct)
        {
            IntPtr ntdll = GetModuleHandleW("ntdll.dll");
            if (ntdll == IntPtr.Zero) return;
            IntPtr etwAddr = PeExportResolver.GetExportAddress(ntdll, "EtwEventWrite");
            if (etwAddr == IntPtr.Zero) return;

            // Self reference (own process handle does not need OpenProcess)
            byte[] ourPrologue = new byte[8];
            if (!NativeProcessMemory.CopyRemote(Process.GetCurrentProcess().Handle, etwAddr, ourPrologue, out _))
                return;

            // RET / NOP / JMP short / JMP near - common ETW blind patches
            byte[] patchedBytes = { 0xC3, 0x90, 0xEB, 0xE9 };

            foreach (int pid in GetCriticalEtwProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string alertKey = $"patch:{pid}";
                if (_alertedItems.Contains(alertKey)) continue;
                if (!NativeProcessMemory.CanInspect(pid)) continue;

                uint access = NativeProcessMemory.PROCESS_VM_READ | NativeProcessMemory.PROCESS_QUERY_LIMITED_INFORMATION;
                IntPtr h = NativeProcessMemory.OpenRemoteHandle(access, pid);
                if (h == IntPtr.Zero) continue;

                try
                {
                    byte[] remote = new byte[8];
                    if (!NativeProcessMemory.CopyRemote(h, etwAddr, remote, out int read) || read < 4)
                        continue;

                    bool isPatched = Array.IndexOf(patchedBytes, remote[0]) >= 0;
                    if (!isPatched)
                    {
                        int diff = 0;
                        for (int i = 0; i < Math.Min(read, ourPrologue.Length); i++)
                            if (remote[i] != ourPrologue[i]) diff++;
                        isPatched = diff >= 3;
                    }

                    if (!isPatched) continue;

                    string processName = "unknown";
                    try { using var p = Process.GetProcessById(pid); processName = p.ProcessName; } catch { }

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: EtwEventWrite Patched in Critical Process",
                        Evidence = $"ntdll!EtwEventWrite patched in '{processName}' (PID {pid}). " +
                                   $"Bytes: [{string.Join(" ", remote.Take(4).Select(b => b.ToString("X2")))}]",
                        Reasoning = "In-memory EtwEventWrite patch blinds ETW consumers (MITRE T1562.006).",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.AntiTamper,
                        ProcessName = processName,
                        ProcessId = pid,
                    });
                    _alertedItems.Add(alertKey);
                }
                finally
                {
                    NativeProcessMemory.CloseHandle(h);
                }
            }
        }

        private List<int> GetCriticalEtwProcesses()
        {
            var pids = new List<int>();
            try
            {
                // lsass - credential telemetry + LSASS audit events
                foreach (var proc in Process.GetProcessesByName("lsass"))
                {
                    pids.Add(proc.Id);
                    proc.Dispose();
                }

                // EventLog service host - runs in a svchost; supplies Security/System/Application logs
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ProcessId FROM Win32_Service WHERE Name = 'EventLog' AND State = 'Running'");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    if (pid > 4 && !pids.Contains(pid)) pids.Add(pid);
                }

                // v2.6.0: All powershell.exe / pwsh.exe instances.
                // An attacker can patch EtwEventWrite inside their own PowerShell process to
                // blind 4104 Script Block Logging for that session without touching lsass or
                // the EventLog service. EtwProviderTamperMonitor previously missed this path.
                // We cap at 8 PowerShell PIDs per cycle to bound scan time.
                int psCount = 0;
                foreach (var psName in new[] { "powershell", "pwsh" })
                {
                    foreach (var proc in Process.GetProcessesByName(psName))
                    {
                        if (psCount++ >= 8) { proc.Dispose(); break; }
                        if (!pids.Contains(proc.Id))
                            pids.Add(proc.Id);
                        proc.Dispose();
                    }
                }
            }
            catch { }
            return pids;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandleW(string lpModuleName);

        /// <summary>
        /// Check running processes for ETW manipulation tools (logman, wevtutil with bad args).
        /// </summary>
        private async Task CheckEtwManipulationProcessesAsync(CancellationToken ct)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE " +
                    "Name = 'logman.exe' OR Name = 'wevtutil.exe' OR Name = 'tracerpt.exe'");

                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    if (ct.IsCancellationRequested) break;

                    string? cmdLine = obj["CommandLine"]?.ToString();
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    int pid = Convert.ToInt32(obj["ProcessId"]);
                    string name = obj["Name"]?.ToString() ?? "unknown";
                    string alertKey = $"cmd:{pid}:{cmdLine!.GetHashCode()}";
                    if (_alertedItems.Contains(alertKey)) continue;

                    foreach (var (pattern, desc, confidence) in EtwManipulationPatterns)
                    {
                        if (System.Text.RegularExpressions.Regex.IsMatch(
                            cmdLine, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Anti-Tamper: ETW/Event Log Manipulation Detected",
                                Evidence = $"Process '{name}' (PID {pid}) executing ETW manipulation: {desc}. " +
                                           $"CmdLine: {Truncate(cmdLine, 200)}",
                                Reasoning = "A process is actively manipulating ETW trace sessions or Windows Event Log channels. " +
                                            "Disabling ETW providers or clearing event logs is a hallmark of EDR evasion and " +
                                            "anti-forensics (MITRE T1562.006, T1070.001).",
                                Confidence = confidence,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                SignalType = SignalType.AntiTamper,
                                // Terminal Evasion: rule name matches the "ETW/Event Log Manipulation"
                                // Evasion fragment (kill-grade). Preserves current substring classification.
                                Family = TerminalFamily.Evasion,
                                ProcessName = name,
                                ProcessId = pid,
                            });
                            _alertedItems.Add(alertKey);
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[EtwProviderTamperMonitor] WMI process scan error");
            }
        }

        private HashSet<string> EnumerateEtwSessions()
        {
            var sessions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                // Use QueryAllTraces to enumerate active sessions
                // Allocate array for up to 64 sessions
                const int maxSessions = 64;
                const int propertiesSize = 1024; // EVENT_TRACE_PROPERTIES size estimate

                var propertyPtrs = new IntPtr[maxSessions];
                for (int i = 0; i < maxSessions; i++)
                {
                    propertyPtrs[i] = Marshal.AllocHGlobal(propertiesSize);
                    Marshal.WriteInt32(propertyPtrs[i], propertiesSize); // Wnode.BufferSize
                    Marshal.WriteInt32(propertyPtrs[i], 4, 0); // Clear remaining
                    // LoggerNameOffset at offset 120 (approximate)
                    Marshal.WriteInt32(propertyPtrs[i], 120, 200);
                }

                try
                {
                    int result = QueryAllTracesW(propertyPtrs, maxSessions, out uint sessionCount);
                    if (result == 0)
                    {
                        for (uint i = 0; i < sessionCount; i++)
                        {
                            try
                            {
                                // Read logger name from offset
                                int nameOffset = Marshal.ReadInt32(propertyPtrs[i], 120);
                                if (nameOffset > 0 && nameOffset < propertiesSize - 2)
                                {
                                    string? name = Marshal.PtrToStringUni(propertyPtrs[i] + nameOffset);
                                    if (!string.IsNullOrEmpty(name))
                                        sessions.Add(name);
                                }
                            }
                            catch { }
                        }
                    }
                }
                finally
                {
                    for (int i = 0; i < maxSessions; i++)
                        Marshal.FreeHGlobal(propertyPtrs[i]);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[EtwProviderTamperMonitor] Failed to enumerate ETW sessions");

                // Fallback: use logman query output parsing
                try
                {
                    using var proc = new Process();
                    proc.StartInfo = new ProcessStartInfo("logman", "query -ets")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    proc.Start();
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(5000);

                    foreach (var line in output.Split('\n'))
                    {
                        string trimmed = line.Trim();
                        if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("Data Collector") &&
                            !trimmed.StartsWith("---") && !trimmed.StartsWith("The command"))
                        {
                            sessions.Add(trimmed);
                        }
                    }
                }
                catch { }
            }

            return sessions;
        }

        private static string Truncate(string s, int maxLen) =>
            s.Length <= maxLen ? s : s[..maxLen] + "...";
    }
}
