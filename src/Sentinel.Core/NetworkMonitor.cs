using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors active TCP connections for behavioral anomalies:
    /// - Connections to non-standard ports from system binaries
    /// - High-frequency outbound connections (beaconing)
    /// - Connections from processes running in suspicious paths
    /// Purely behavioral - no domain/IP blocklists.
    /// </summary>
    public sealed class NetworkMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BeaconingDetector _beaconingDetector;
        private readonly ILogger<NetworkMonitor> _logger;
        private readonly BehavioralBaselineService? _behavioralBaseline;
        private readonly System.Threading.Timer _timer;
        private readonly ConcurrentDictionary<string, int> _connectionCounts = new();

        // Emit-dedup for LogOnly behavioral network heuristics. ScanConnections runs every 200ms,
        // so a single process making many connections (e.g. an installer or updater) would emit
        // the same LogOnly detection thousands of times and bloat the event log. Track the last
        // emit time per (rule + process identity) and suppress repeats within the re-alert window.
        private readonly ConcurrentDictionary<string, DateTime> _lastEmit = new();
        private static readonly TimeSpan EmitReAlertWindow = TimeSpan.FromMinutes(10);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromMilliseconds(200);

        private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "bash", "sh"
        };

        private static readonly HashSet<int> StandardPorts = new() { 80, 443, 53, 8080, 8443 };

        /// <summary>
        /// v1.8.3: Align with default IPSec attack-only set - ports users never need that
        /// malware/legacy remote shells use. SSH/RDP/SMB/DB are NOT listed (legitimate use).
        /// Connections here are LogOnly indicators unless multi-signal attack corroborates.
        /// </summary>
        private static readonly HashSet<int> KnownMaliciousPorts = new()
        {
            23,    // Telnet
            69,    // TFTP
            111,   // RPCBind/Portmapper
            512,   // rexec
            513,   // rlogin
            514,   // rsh
            666,   // Trojan
            1234,  // RAT default
            1337,  // Backdoor
            4444,  // Meterpreter
            7777,  // Backdoor
            12345, // NetBus
            31337, // BackOrifice
            54321  // BackOrifice 2000
        };

        private static string GetPortDescription(int port) => port switch
        {
            23 => "Telnet",
            69 => "TFTP",
            111 => "RPCBind/Portmapper",
            512 => "rexec",
            513 => "rlogin",
            514 => "rsh",
            666 => "Trojan",
            1234 => "RAT",
            1337 => "Backdoor",
            4444 => "Meterpreter",
            7777 => "Backdoor",
            12345 => "NetBus",
            31337 => "BackOrifice",
            54321 => "BackOrifice2K",
            _ => $"Port {port}"
        };

        public NetworkMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ProcessAncestryCache ancestryCache,
            BeaconingDetector beaconingDetector,
            ILogger<NetworkMonitor> logger,
            BehavioralBaselineService? behavioralBaseline = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _ancestryCache = ancestryCache;
            _beaconingDetector = beaconingDetector;
            _behavioralBaseline = behavioralBaseline;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanConnections, null, ScanInterval, ScanInterval);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;
            public uint remoteScopeId;
            public uint remotePort;
            public uint state;
            public uint owningPid;
        }

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            uint ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved);

        private static int GetPort(uint portDword)
        {
            return (int)((portDword & 0xFF) << 8 | (portDword & 0xFF00) >> 8);
        }

        private static bool IsOutbound(string ipStr)
        {
            if (string.IsNullOrEmpty(ipStr)) return false;
            if (ipStr == "0.0.0.0" || ipStr == "255.255.255.255") return false;
            if (IPAddress.TryParse(ipStr, out var ip))
            {
                if (IPAddress.IsLoopback(ip)) return false;
                return true;
            }
            return false;
        }

        private static bool IsSuspiciousPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path!.ToLowerInvariant();
            return lower.Contains(@"\temp\") || lower.Contains(@"\downloads\");
        }

        /// <summary>
        /// HARDENING v1.3.0: Verifies browser identity by checking BOTH name AND that the
        /// binary resides in a Program Files or Windows Apps directory (not Temp/Downloads).
        /// Previously name-only - malware named "chrome.exe" in Temp bypassed network detection.
        /// </summary>
        private static bool IsKnownBrowser(string? processName, string? imagePath = null)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            var lower = processName!.ToLowerInvariant();
            bool nameMatches = lower == "chrome" || lower == "chrome.exe" ||
                   lower == "msedge" || lower == "msedge.exe" ||
                   lower == "firefox" || lower == "firefox.exe" ||
                   lower == "brave" || lower == "brave.exe" ||
                   lower == "opera" || lower == "opera.exe" ||
                   lower == "vivaldi" || lower == "vivaldi.exe" ||
                   lower == "safari" || lower == "safari.exe";

            if (!nameMatches) return false;

            // Name matches - verify path is legitimate (not temp/downloads/staging)
            if (string.IsNullOrEmpty(imagePath)) return false;
            var pathLower = imagePath!.ToLowerInvariant();
            return pathLower.Contains(@"\program files") ||
                   pathLower.Contains(@"\windowsapps\") ||
                   pathLower.Contains(@"\appdata\local\google\") ||
                   pathLower.Contains(@"\appdata\local\microsoft\edge\") ||
                   pathLower.Contains(@"\appdata\local\bravesoftware\") ||
                   pathLower.Contains(@"\appdata\local\vivaldi\");
        }

        private static string? GetProcessImagePath(int pid)
        {
            return SecurityValidation.GetProcessImagePath(pid);
        }

        /// <summary>
        /// Rate-limits a repetitive LogOnly detection to once per <see cref="EmitReAlertWindow"/>
        /// per (rule, process-identity) key. Returns true if the caller should emit; false to
        /// suppress a duplicate. Prevents a single chatty process from flooding the event log.
        /// </summary>
        private bool ShouldEmitThrottled(string ruleKey, string processName, string? imagePath)
        {
            var key = $"{ruleKey}|{processName}|{imagePath ?? ""}";
            var now = DateTime.UtcNow;
            if (_lastEmit.TryGetValue(key, out var last) && (now - last) < EmitReAlertWindow)
            {
                return false;
            }
            _lastEmit[key] = now;

            // Opportunistic cleanup so the dictionary cannot grow unbounded over a long uptime.
            if (_lastEmit.Count > 4096)
            {
                foreach (var kv in _lastEmit)
                {
                    if (now - kv.Value > EmitReAlertWindow)
                    {
                        _lastEmit.TryRemove(kv.Key, out _);
                    }
                }
            }
            return true;
        }

        private void ScanConnections(object? state)
        {
            try
            {
                int myPid = System.Net48Environment.ProcessId;
                var currentCounts = new Dictionary<string, int>();

                void ProcessConnection(string localIp, string remoteIp, int localPort, int remotePort, int owningPid)
                {
                    if (owningPid <= 4 || owningPid == myPid) return;

                    var key = $"{remoteIp}:{remotePort}";
                    currentCounts[key] = currentCounts.GetValueOrDefault(key) + 1;

                    if (IsOutbound(remoteIp))
                    {
                        var processName = "unknown";
                        var (parentPid, name) = _ancestryCache.GetParent(owningPid);
                        if (name != "unknown")
                        {
                            processName = name;
                        }
                        else
                        {
                            try
                            {
                                using var p = Process.GetProcessById(owningPid);
                                processName = p.ProcessName;
                            }
                            catch
                            {
                                // Ignore
                            }
                        }

                        var imagePath = GetProcessImagePath(owningPid);

                        // 1. Record connection in statistical beaconing detector
                        _beaconingDetector.RecordConnection(remoteIp, remotePort, owningPid, processName, imagePath, "Established");

                        // 1.5. Record connection in behavioral baseline
                        _behavioralBaseline?.RecordNetworkConnection(processName, remoteIp, remotePort);

                        // 2. Behavioral checks - v1.8.3 observe-first:
                        // Single-signal path/port/shell heuristics are LogOnly. Users may use
                        // SSH, RDP, torrents, P2P, portable tools freely. Kill only when a
                        // multi-signal composite or confirmed attack rule fires elsewhere.

                        // A. Shell process outbound to non-standard port (ssh, scp, git, etc.)
                        if (ShellProcesses.Contains(processName) && !StandardPorts.Contains(remotePort)
                            && ShouldEmitThrottled("ReverseShell", processName, imagePath))
                        {
                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Reverse Shell: Suspicious Outbound Connection",
                                Evidence = $"Shell process '{processName}' (PID {owningPid}) connected to non-standard remote port {remotePort} ({remoteIp}:{remotePort})",
                                Reasoning = "A shell opened a non-HTTP(S) outbound connection. Often legitimate (ssh, scp, custom tools). " +
                                            "Logged as an indicator; kill requires corroborating attack signals (injection, token theft, AMSI bypass, etc.).",
                                Confidence = 0.45,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                SignalType = SignalType.SuspiciousProcess,
                                ProcessName = processName,
                                ProcessId = owningPid,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "WeakObserveSeed", "true" },
                                    { "RemoteAddress", remoteIp },
                                    { "RemotePort", remotePort.ToString() },
                                    { "LocalAddress", localIp },
                                    { "LocalPort", localPort.ToString() }
                                }
                            });
                        }

                        // B. Outbound connection from temp/downloads path - observe only
                        if (IsSuspiciousPath(imagePath) &&
                            !IsKnownBrowser(processName, imagePath) &&
                            !InstallerHeuristics.IsBenignPortableWorkContext(processName, imagePath) &&
                            ShouldEmitThrottled("SuspiciousPathConn", processName, imagePath))
                        {
                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Attack Tool: Connection from Suspicious Path",
                                Evidence = $"Process '{processName}' (PID {owningPid}) running from '{imagePath}' connected to {remoteIp}:{remotePort}",
                                Reasoning = "A binary from Temp/Downloads initiated outbound network activity. Common for portable tools, " +
                                            "UUP dump, torrents, and installers. Logged only - never kill on path alone.",
                                Confidence = 0.40,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = processName,
                                ProcessId = owningPid,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "ImagePath", imagePath ?? "" },
                                    { "RemoteAddress", remoteIp },
                                    { "RemotePort", remotePort.ToString() },
                                    { "LocalAddress", localIp },
                                    { "LocalPort", localPort.ToString() }
                                }
                            });
                        }

                        // C. Attack-only ports (Telnet, Meterpreter defaults, etc.).
                        // Games (Unreal 7777) and browsers are civilians - skip.
                        // Remaining process on 4444/31337/... is the attack (v2.5.3).
                        if (KnownMaliciousPorts.Contains(remotePort) || KnownMaliciousPorts.Contains(localPort))
                        {
                            if (IsKnownBrowser(processName, imagePath) ||
                                SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                            {
                                // skip the 90
                            }
                            else
                            {
                                int suspiciousPort = KnownMaliciousPorts.Contains(remotePort) ? remotePort : localPort;
                                bool isOutbound = KnownMaliciousPorts.Contains(remotePort);
                                string direction = isOutbound ? "outbound to" : "inbound from";
                                string targetAddr = isOutbound ? remoteIp : localIp;

                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Network Indicator: Classic Malware Port",
                                    Evidence = $"Process '{processName}' (PID {owningPid}) has {direction} {targetAddr}:{suspiciousPort}. " +
                                               $"Full connection: {localIp}:{localPort} -> {remoteIp}:{remotePort}",
                                    Reasoning = $"Port {suspiciousPort} ({GetPortDescription(suspiciousPort)}) is in the attack-only " +
                                                "block set (legacy shells / classic RAT ports). Games and browsers are skipped. " +
                                                "This process is not that - kill-grade C2.",
                                    Confidence = 0.86,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = processName,
                                    ProcessId = owningPid,
                                    SignalType = SignalType.NetworkC2,
                                    Family = TerminalFamily.C2Beacon,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        { "RemoteAddress", remoteIp },
                                        { "RemotePort", remotePort.ToString() },
                                        { "LocalAddress", localIp },
                                        { "LocalPort", localPort.ToString() },
                                        { "SuspiciousPort", suspiciousPort.ToString() },
                                        { "Direction", isOutbound ? "Outbound" : "Inbound" },
                                        { "TargetIP", isOutbound ? remoteIp : localIp }
                                    }
                                });
                            }
                        }

                        // 3. Submit network telemetry context to telemetry pipeline
                        var telemetry = new NetworkTelemetry
                        {
                            Type = "NetworkConnection",
                            ProcessId = owningPid,
                            ProcessName = processName,
                            LocalAddress = localIp,
                            LocalPort = localPort,
                            RemoteAddress = remoteIp,
                            RemotePort = remotePort,
                            Protocol = "TCP",
                            State = "ESTABLISHED",
                            Timestamp = DateTime.UtcNow
                        };
                        var context = _fusionEngine.FeedEvent(telemetry);
                        _detectionEngine.SubmitTelemetry(context);
                    }
                }

                // --- Part A: Scan IPv4 Connections ---
                int ipv4Size = 0;
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref ipv4Size, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    IntPtr ipv4Buffer = Marshal.AllocHGlobal(ipv4Size);
                    try
                    {
                        ret = GetExtendedTcpTable(ipv4Buffer, ref ipv4Size, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                        if (ret == 0)
                        {
                            int numEntries = Marshal.ReadInt32(ipv4Buffer);
                            int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                            for (int i = 0; i < numEntries; i++)
                            {
                                IntPtr rowPtr = IntPtr.Add(ipv4Buffer, 4 + i * structSize);
                                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                                if (row.state != 5) continue; // Established

                                var localIp = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                                var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                                var localPort = GetPort(row.localPort);
                                var remotePort = GetPort(row.remotePort);

                                ProcessConnection(localIp, remoteIp, localPort, remotePort, (int)row.owningPid);
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ipv4Buffer);
                    }
                }

                // --- Part B: Scan IPv6 Connections ---
                int ipv6Size = 0;
                ret = GetExtendedTcpTable(IntPtr.Zero, ref ipv6Size, true, 23, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    IntPtr ipv6Buffer = Marshal.AllocHGlobal(ipv6Size);
                    try
                    {
                        ret = GetExtendedTcpTable(ipv6Buffer, ref ipv6Size, true, 23, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                        if (ret == 0)
                        {
                            int numEntries = Marshal.ReadInt32(ipv6Buffer);
                            int structSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                            for (int i = 0; i < numEntries; i++)
                            {
                                IntPtr rowPtr = IntPtr.Add(ipv6Buffer, 4 + i * structSize);
                                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                                if (row.state != 5) continue; // Established

                                var localIp = new IPAddress(row.localAddr).ToString();
                                var remoteIp = new IPAddress(row.remoteAddr).ToString();
                                var localPort = GetPort(row.localPort);
                                var remotePort = GetPort(row.remotePort);

                                ProcessConnection(localIp, remoteIp, localPort, remotePort, (int)row.owningPid);
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ipv6Buffer);
                    }
                }

                // Update counts and prune stale entries
                foreach (var (key, count) in currentCounts)
                {
                    _connectionCounts[key] = count;
                }

                var staleKeys = _connectionCounts.Keys.Except(currentCounts.Keys).ToList();
                foreach (var k in staleKeys)
                {
                    _connectionCounts.TryRemove(k, out _);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
