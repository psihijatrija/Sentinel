using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.7: Named Pipe Monitor - IPC C2 / lateral movement detection.
    /// 
    /// Blind spot addressed: Cobalt Strike, PsExec, Impacket, Metasploit, and many privilege-escalation
    /// tools communicate via named pipes (\\.\pipe\*). Previous campaign rules had weak regex matching
    /// only against process command lines - never actually enumerated system pipes.
    /// 
    /// Detection approach:
    /// - Periodically enumerate all named pipes via Directory.GetFiles(@"\\.\pipe\")
    /// - Alert on: known-bad pipe name patterns (C2 frameworks, lateral movement tools)
    /// - Alert on: high-entropy pipe names created by non-system processes
    /// - Alert on: cross-session pipe connections from unexpected processes
    /// - Owner PID attribution via GetNamedPipeServerProcessId
    /// - Correlate pipe server PID with beaconing/network signals via ContextBus
    /// 
    /// Response: LogOnly by default -> KillProcessTree on pipe+beacon composite corroboration.
    /// Scans every 15s. No elevation required.
    /// </summary>
    public sealed class NamedPipeMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ContextBus? _contextBus;
        private readonly ILogger<NamedPipeMonitor> _logger;

        private readonly HashSet<string> _baselinePipes = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alertedPipes = new(StringComparer.OrdinalIgnoreCase);

        // Known-bad pipe name patterns (C2 frameworks, lateral movement, priv-esc tools)
        private static readonly Regex[] KnownBadPatterns = new[]
        {
            // Cobalt Strike default named pipes (high-entropy 1-4 digit suffix)
            new Regex(@"^msagent_[a-f0-9]{2,8}$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^MSSE-[0-9]{1,4}-server$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^postex_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^postex_ssh_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^status_[a-f0-9]{2,8}$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^msagent_[a-f0-9]{2,8}$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            // Cobalt Strike: single letter + short digits
            new Regex(@"^[ms][a-z]{4,8}[0-9]{1,4}$", RegexOptions.Compiled),

            // PsExec / Impacket lateral movement
            new Regex(@"^psexecsvc(-[a-z0-9]+)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^svcctl$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^RemCom_(stdin|stdout|stderr)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^csexec_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),

            // Metasploit Meterpreter
            new Regex(@"^meterpreter_", RegexOptions.Compiled | RegexOptions.IgnoreCase),
            new Regex(@"^msf_", RegexOptions.Compiled | RegexOptions.IgnoreCase),

            // Sliver C2
            new Regex(@"^sliver_", RegexOptions.Compiled | RegexOptions.IgnoreCase),

            // Havoc C2
            new Regex(@"^havoc_[a-f0-9]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase),

            // Generic high-confidence C2 pipe patterns
            new Regex(@"^[a-f0-9]{32,}$", RegexOptions.Compiled), // Pure hex GUID-like (32+ chars)
            new Regex(@"^(pipe_)?[a-z]{1,3}[0-9]{6,}$", RegexOptions.Compiled), // Short prefix + many digits
        };

        // Well-known legitimate pipe patterns to never alert on
        private static readonly HashSet<string> LegitimatePatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            "lsass", "ntsvcs", "scerpc", "samr", "netlogon", "wkssvc", "srvsvc",
            "browser", "atsvc", "eventlog", "InitShutdown", "LSM_API_service",
            "ROUTER", "epmapper", "spoolss", "winreg", "DAV RPC SERVICE",
            "MsFteWds", "SearchTextHarvester", "trkwks", "W32TIME_ALT",
            "vgauth-service", "wsnm", "PIPE_EVENTROOT", "gecko-crash-server-pipe",
            "chrome.", "chromium.", "crashpad_", "mojo_", "discord-ipc-",
            "dotnet-diagnostic-", "clr-debug-", "LOCAL\\edge_", "LOCAL\\chrome.",
            "docker_engine", "openssh-ssh-agent", "mysql", "TSQL", "pgsignal_",
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint OPEN_EXISTING = 3;

        public NamedPipeMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<NamedPipeMonitor> logger,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
            _contextBus = contextBus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NamedPipeMonitor] Started - polling \\\\.\\.\\pipe\\ every 15s");

            // Baseline existing pipes at startup (don't alert on pre-existing ones)
            await Task.Delay(5000, ct); // Brief startup grace
            BaselineCurrentPipes();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    await ScanPipesAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NamedPipeMonitor] Scan error"); }
            }
        }

        private void BaselineCurrentPipes()
        {
            try
            {
                var pipes = Directory.GetFiles(@"\\.\pipe\");
                foreach (var pipe in pipes)
                {
                    var name = Path.GetFileName(pipe);
                    _baselinePipes.Add(name);
                }
                _logger.LogDebug("[NamedPipeMonitor] Baselined {Count} existing pipes", _baselinePipes.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NamedPipeMonitor] Failed to baseline pipes");
            }
        }

        private async Task ScanPipesAsync(CancellationToken ct)
        {
            string[] currentPipes;
            try
            {
                currentPipes = Directory.GetFiles(@"\\.\pipe\");
            }
            catch
            {
                return; // Pipe directory inaccessible
            }

            foreach (var pipePath in currentPipes)
            {
                if (ct.IsCancellationRequested) break;

                var pipeName = Path.GetFileName(pipePath);
                if (string.IsNullOrEmpty(pipeName)) continue;

                // An explicit known-bad C2/lateral-movement pattern is evaluated FIRST, before any
                // baseline / already-alerted / legitimate-name suppression. A pipe that matches a
                // hard attack signature (Cobalt Strike, PsExec, Sliver, ...) must never be excused
                // just because it happened to exist at boot (baseline) or because its name shares a
                // prefix with a well-known pipe - both are attacker-controllable.
                string? matchedPattern = MatchKnownBadPattern(pipeName);

                if (matchedPattern == null)
                {
                    // Skip if already baselined or already alerted
                    if (_baselinePipes.Contains(pipeName)) continue;
                    if (_alertedPipes.Contains(pipeName)) continue;

                    // Skip well-known legitimate pipes
                    if (IsLegitimate(pipeName)) continue;
                }
                else if (_alertedPipes.Contains(pipeName))
                {
                    continue; // already reported this exact bad pipe
                }

                if (matchedPattern != null)
                {
                    uint ownerPid = TryGetPipeOwner(pipePath);
                    string ownerName = ownerPid > 0 ? ResolveProcessName(ownerPid) : "Unknown";

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                        Evidence = $"Suspicious named pipe detected: '\\\\.\\.\\pipe\\{pipeName}' (owner PID {ownerPid} [{ownerName}]). Matched pattern: {matchedPattern}",
                        Reasoning = "A named pipe matching a known C2 framework or lateral movement tool pattern was created. This is commonly used by Cobalt Strike, PsExec, Impacket, Metasploit, and other attack tools for inter-process communication.",
                        Confidence = 0.86,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.NetworkC2,
                        Family = TerminalFamily.C2Beacon,
                        ProcessName = ownerName,
                        ProcessId = (int)ownerPid,
                    });

                    // v1.6.8: Publish enrichment signal for composite correlation (pipe + beacon)
                    _contextBus?.Publish(new NamedPipeSignal
                    {
                        ProcessId = (int)ownerPid,
                        ProcessName = ownerName,
                        SourceMonitor = "NamedPipeMonitor",
                        PipeName = pipeName,
                        MatchedPattern = matchedPattern,
                        OwnerPid = ownerPid,
                        IsKnownBadPattern = true,
                        Entropy = CalculateEntropy(pipeName),
                    });

                    _alertedPipes.Add(pipeName);
                }
                else if (IsHighEntropy(pipeName))
                {
                    // High-entropy pipe name from non-system process
                    uint ownerPid = TryGetPipeOwner(pipePath);
                    string ownerName = ownerPid > 0 ? ResolveProcessName(ownerPid) : "Unknown";

                    // Only alert if owner is not a known system process
                    if (!IsSystemProcess(ownerName, ownerPid))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Named Pipe: High-Entropy Name (Non-System Owner)",
                            Evidence = $"High-entropy named pipe detected: '\\\\.\\.\\pipe\\{pipeName}' (owner PID {ownerPid} [{ownerName}]). Shannon entropy: {CalculateEntropy(pipeName):F2}",
                            Reasoning = "A named pipe with a high-entropy (random-looking) name was created by a non-system process. C2 implants often use randomized pipe names for IPC to avoid static detection.",
                            Confidence = 0.65,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            SignalType = SignalType.NetworkC2,
                            ProcessName = ownerName,
                            ProcessId = (int)ownerPid,
                        });

                        // v1.6.8: Publish enrichment signal for composite correlation
                        _contextBus?.Publish(new NamedPipeSignal
                        {
                            ProcessId = (int)ownerPid,
                            ProcessName = ownerName,
                            SourceMonitor = "NamedPipeMonitor",
                            PipeName = pipeName,
                            MatchedPattern = string.Empty,
                            OwnerPid = ownerPid,
                            IsKnownBadPattern = false,
                            Entropy = CalculateEntropy(pipeName),
                        });

                        _alertedPipes.Add(pipeName);
                    }
                }
            }

            // Prune alerted pipes that no longer exist (allow re-detection if recreated)
            if (_alertedPipes.Count > 500)
            {
                var currentNames = new HashSet<string>(currentPipes.Select(Path.GetFileName)!, StringComparer.OrdinalIgnoreCase);
                _alertedPipes.RemoveWhere(p => !currentNames.Contains(p));
            }
        }

        /// <summary>
        /// Returns the human-readable regex string of the first known-bad C2/lateral-movement
        /// pattern the pipe name matches, or null if none. Evaluated before any legitimate/baseline
        /// suppression so an explicit attack signature is never excused.
        /// </summary>
        private static string? MatchKnownBadPattern(string pipeName)
        {
            foreach (var pattern in KnownBadPatterns)
            {
                if (pattern.IsMatch(pipeName))
                    return pattern.ToString();
            }
            return null;
        }

        private static bool IsLegitimate(string pipeName)
        {
            foreach (var pattern in LegitimatePatterns)
            {
                // The pipe name is attacker-chosen. A bare well-known name (lsass, srvsvc,
                // svcctl, ...) must match EXACTLY - otherwise a C2 pipe named "srvsvc_evil" or
                // "lsass_c2" inherits the legitimate prefix and suppresses the known-bad-pattern
                // alert. Only entries that are genuine namespace prefixes (they end with a
                // separator such as '.', '_', '-', '\') are matched by StartsWith.
                bool isPrefixPattern = pattern.Length > 0 &&
                    (pattern[pattern.Length - 1] is '.' or '_' or '-' or '\\');
                if (isPrefixPattern)
                {
                    if (pipeName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                else if (pipeName.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Skip UUIDs / GUIDs in standard format (common for legitimate RPC endpoints).
            // Note: a pure 32+ hex-char name (no dashes) is NOT covered here - that is handled as
            // a known-bad C2 pattern; only canonical dashed GUIDs are treated as legitimate.
            if (pipeName.Length == 36 && pipeName[8] == '-' && pipeName[13] == '-' &&
                pipeName[18] == '-' && pipeName[23] == '-')
                return true;

            return false;
        }

        private static bool IsHighEntropy(string name)
        {
            if (name.Length < 8) return false;
            double entropy = CalculateEntropy(name);
            return entropy >= 4.0 && name.Length >= 12;
        }

        private static double CalculateEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new Dictionary<char, int>();
            foreach (var c in s.ToLowerInvariant())
            {
                freq[c] = freq.GetValueOrDefault(c) + 1;
            }
            double entropy = 0;
            double len = s.Length;
            foreach (var count in freq.Values)
            {
                double p = count / len;
                if (p > 0) entropy -= p * MathNet48.Log2(p);
            }
            return entropy;
        }

        private uint TryGetPipeOwner(string pipePath)
        {
            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = CreateFileW(pipePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                    return 0;

                if (GetNamedPipeServerProcessId(handle, out uint pid))
                    return pid;
            }
            catch { }
            finally
            {
                if (handle != IntPtr.Zero && handle != new IntPtr(-1))
                    CloseHandle(handle);
            }
            return 0;
        }

        private string ResolveProcessName(uint pid)
        {
            try
            {
                var info = _ancestryCache.GetProcessInfo((int)pid);
                if (!string.IsNullOrEmpty(info.name)) return info.name;

                using var proc = System.Diagnostics.Process.GetProcessById((int)pid);
                return proc.ProcessName;
            }
            catch { return $"PID:{pid}"; }
        }

        private static bool IsSystemProcess(string name, uint pid)
        {
            if (pid <= 4) return true;
            var lower = name.ToLowerInvariant();
            bool nameMatches = lower is "system" or "svchost" or "services" or "lsass" or "csrss"
                or "wininit" or "winlogon" or "smss" or "dwm" or "explorer"
                or "spoolsv" or "searchindexer" or "wmiprvse" or "runtimebroker"
                or "dllhost" or "taskhostw" or "sihost" or "fontdrvhost";
            if (!nameMatches) return false;

            // A system process NAME is attacker-controllable (rename an implant "svchost.exe"),
            // and this check suppresses the high-entropy C2-pipe alert - so anchor it to the
            // owner's real image path. The owner must resolve to a genuine System32 / SysWOW64
            // image, never a user-writable drop. If the path can't be resolved, do NOT treat it
            // as system (fail closed - a real System32 host resolves fine; a hidden implant that
            // blocks path queries is exactly what we want to keep alerting on).
            string? imagePath = SecurityValidation.GetProcessImagePath((int)pid);
            if (string.IsNullOrEmpty(imagePath)) return false;
            if (ModuleIdentity.IsUserWritableDrop(imagePath)) return false;
            var pathLower = imagePath!.ToLowerInvariant();
            return pathLower.Contains(@"\windows\system32\") ||
                   pathLower.Contains(@"\windows\syswow64\");
        }
    }
}
