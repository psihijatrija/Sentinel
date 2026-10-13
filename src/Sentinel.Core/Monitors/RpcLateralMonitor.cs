using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.7: RPC Lateral Movement Monitor - detects outbound lateral movement via RPC/DCOM/WMI/WinRM.
    /// 
    /// Blind spot addressed: IPSec policy blocks inbound connections to dangerous ports, but doesn't
    /// detect OUTBOUND lateral movement from compromised user tools. An attacker with code execution
    /// can use WMI, DCOM, remote SCM, remote registry, or WinRM to move laterally to other machines.
    /// 
    /// Detection approach:
    /// - Monitor outbound TCP connections to ports 135 (RPC endpoint mapper), 445 (SMB/named pipes),
    ///   5985/5986 (WinRM HTTP/HTTPS) from suspicious parent processes
    /// - Detect command-line patterns: "wmic /node:", "Invoke-Command -ComputerName",
    ///   "winrs -r:", "sc \\\\host", "reg \\\\host", "schtasks /s host"
    /// - Flag script/office/LOLBin processes initiating lateral movement connections
    /// - Cross-reference with process ancestry (shell -> wmic, office -> powershell -> lateral)
    /// 
    /// Response: Tier1 KillProcessTree for confirmed lateral movement command patterns.
    ///           Tier2 LogOnly for suspicious port connections from non-system processes.
    /// Scans every 10s. No elevation required.
    /// </summary>
    public sealed class RpcLateralMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<RpcLateralMonitor> _logger;

        // Track already-alerted (pid, remote) pairs to prevent spam
        private readonly ConcurrentDictionary<string, DateTime> _alertedConnections = new();

        // Lateral movement ports
        private static readonly HashSet<int> LateralPorts = new() { 135, 445, 5985, 5986 };

        // Suspicious parent processes that should NOT be initiating lateral movement
        private static readonly HashSet<string> SuspiciousLateralParents = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
            "winword", "excel", "powerpnt", "outlook", "msaccess",
            "rundll32", "regsvr32", "msbuild", "installutil", "csc",
            "wmic", "wmiprvse", "wmiadap",
            "msg", // v2.1.5: Remote message delivery - RPC access probe / social engineering vector
        };

        // Command-line patterns indicating explicit lateral movement intent
        private static readonly (string Pattern, string Description)[] LateralCommandPatterns = new[]
        {
            (@"wmic\s+/node:", "WMI remote execution (wmic /node:)"),
            (@"wmic\s+.*\s+/node:", "WMI remote execution (wmic /node:)"),
            (@"invoke-command\s+.*-computername", "PowerShell remoting (Invoke-Command)"),
            (@"invoke-command\s+.*-cn\s", "PowerShell remoting (Invoke-Command -CN)"),
            (@"new-pssession\s+.*-computername", "PowerShell remoting (New-PSSession)"),
            (@"enter-pssession\s+.*-computername", "PowerShell remoting (Enter-PSSession)"),
            (@"winrs\s+.*-r:", "Windows Remote Shell (winrs)"),
            (@"sc\s+\\\\", "Remote service control (sc \\\\host)"),
            (@"schtasks\s+.*(/s|/S)\s+", "Remote scheduled task (schtasks /s)"),
            (@"reg\s+(query|add|delete)\s+\\\\", "Remote registry (reg \\\\host)"),
            (@"net\s+use\s+\\\\", "Remote share mapping (net use \\\\)"),
            (@"psexec\s+.*\\\\", "PsExec lateral movement"),
            (@"copy\s+.*\\\\.*\$", "Copy to admin share (C$/ADMIN$)"),
            (@"xcopy\s+.*\\\\.*\$", "Xcopy to admin share"),
            (@"msg\s+.*(/server:|/SERVER:)", "Remote message delivery (msg /server:) - RPC access probe"),
        };

        // P/Invoke for GetExtendedTcpTable
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen,
            bool sort, int ipVersion, int tableClass, uint reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;
        private const int MIB_TCP_STATE_ESTAB = 5;
        private const int MIB_TCP_STATE_SYN_SENT = 3;

        public RpcLateralMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<RpcLateralMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RpcLateralMonitor] Started - monitoring outbound lateral movement ports");
            await Task.Delay(8000, ct); // Startup grace

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    await ScanOutboundLateralAsync(ct);
                    PruneAlertCache();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RpcLateralMonitor] Scan error"); }
            }
        }

        private async Task ScanOutboundLateralAsync(CancellationToken ct)
        {
            var connections = GetTcpConnections();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;
                if (!LateralPorts.Contains(conn.RemotePort)) continue;
                if (conn.ProcessId <= 4) continue;

                // Skip connections to localhost
                if (IsLocalAddress(conn.RemoteAddress)) continue;

                string processName = ResolveProcessName(conn.ProcessId);
                string alertKey = $"{conn.ProcessId}:{conn.RemoteAddress}:{conn.RemotePort}";

                // Already alerted this connection
                if (_alertedConnections.ContainsKey(alertKey)) continue;

                // Check if the process or its parent is suspicious
                bool isSuspiciousProcess = SuspiciousLateralParents.Contains(processName);
                var parentInfo = _ancestryCache.GetParent(conn.ProcessId);
                string parentName = parentInfo.name ?? "";

                if (isSuspiciousProcess || SuspiciousLateralParents.Contains(parentName))
                {
                    // Check command line for explicit lateral movement patterns
                    string? cmdLine = GetCommandLine(conn.ProcessId);
                    string? matchedPattern = null;

                    if (!string.IsNullOrEmpty(cmdLine))
                    {
                        foreach (var (pattern, desc) in LateralCommandPatterns)
                        {
                            if (System.Text.RegularExpressions.Regex.IsMatch(
                                cmdLine, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                            {
                                matchedPattern = desc;
                                break;
                            }
                        }
                    }

                    if (matchedPattern != null)
                    {
                        // Confirmed lateral movement command
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Lateral Movement: Outbound RPC/WMI/WinRM Command",
                            Evidence = $"Process '{processName}' (PID {conn.ProcessId}) executing lateral movement: {matchedPattern}. " +
                                       $"Target: {conn.RemoteAddress}:{conn.RemotePort}. CmdLine: {Truncate(cmdLine!, 200)}",
                            Reasoning = "A process is executing a confirmed lateral movement command targeting a remote host via RPC, WMI, or WinRM. " +
                                        "This is a strong indicator of active lateral movement (MITRE T1021).",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            SignalType = SignalType.NetworkC2,
                            Family = TerminalFamily.C2Beacon,
                            ProcessName = processName,
                            ProcessId = conn.ProcessId,
                        });
                    }
                    else
                    {
                        // Suspicious connection without confirmed command pattern
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Lateral Movement: Suspicious Outbound RPC/SMB Connection",
                            Evidence = $"Process '{processName}' (PID {conn.ProcessId}) connected to {conn.RemoteAddress}:{conn.RemotePort} " +
                                       $"(parent: '{parentName}'). Port {conn.RemotePort} is used for {GetPortDescription(conn.RemotePort)}.",
                            Reasoning = "A script host, Office application, or LOLBin process established an outbound connection to a lateral movement port. " +
                                        "Legitimate administrative tools are rarely launched from these parent processes.",
                            Confidence = 0.62,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            SignalType = SignalType.NetworkC2,
                            ProcessName = processName,
                            ProcessId = conn.ProcessId,
                        });
                    }

                    _alertedConnections[alertKey] = DateTime.UtcNow;
                }
            }
        }

        private struct TcpConnection
        {
            public int ProcessId;
            public string RemoteAddress;
            public int RemotePort;
            public int State;
        }

        private List<TcpConnection> GetTcpConnections()
        {
            var results = new List<TcpConnection>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref bufferSize, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int offset = 4;
                int entrySize = 24; // MIB_TCPROW_OWNER_PID size

                for (int i = 0; i < numEntries && i < 10000; i++)
                {
                    IntPtr entryPtr = buffer + offset + (i * entrySize);
                    int state = Marshal.ReadInt32(entryPtr, 0);

                    // Only interested in ESTABLISHED or SYN_SENT
                    if (state != MIB_TCP_STATE_ESTAB && state != MIB_TCP_STATE_SYN_SENT) continue;

                    uint remoteAddr = (uint)Marshal.ReadInt32(entryPtr, 8);
                    int remotePort = IPAddress.NetworkToHostOrder((short)Marshal.ReadInt16(entryPtr, 12)) & 0xFFFF;
                    int pid = Marshal.ReadInt32(entryPtr, 20);

                    if (!LateralPorts.Contains(remotePort)) continue;

                    var ipBytes = BitConverter.GetBytes(remoteAddr);
                    string remoteIp = new IPAddress(ipBytes).ToString();

                    results.Add(new TcpConnection
                    {
                        ProcessId = pid,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        State = state
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }

        private string ResolveProcessName(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch { return $"PID:{pid}"; }
        }

        private static string? GetCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (System.Management.ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString();
                }
            }
            catch { }
            return null;
        }

        private static bool IsLocalAddress(string ip)
        {
            return ip == "127.0.0.1" || ip == "0.0.0.0" || ip.StartsWith("127.");
        }

        private static string GetPortDescription(int port) => port switch
        {
            135 => "RPC Endpoint Mapper (DCOM/WMI lateral)",
            445 => "SMB/Named Pipes (PsExec, file shares, remote registry)",
            5985 => "WinRM HTTP (PowerShell remoting)",
            5986 => "WinRM HTTPS (PowerShell remoting)",
            _ => $"port {port}"
        };

        private static string Truncate(string s, int maxLen) =>
            s.Length <= maxLen ? s : s[..maxLen] + "...";

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            foreach (var kvp in _alertedConnections)
            {
                if (kvp.Value < cutoff)
                    _alertedConnections.TryRemove(kvp.Key, out _);
            }
        }
    }
}
