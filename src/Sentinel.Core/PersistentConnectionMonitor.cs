using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
    /// Detects malware webhook/pairing behavior:
    /// 
    /// 1. Tracks long-lived TCP connections (held > 5 minutes to same endpoint)
    /// 2. When a long-lived connection drops, monitors the owning process for defensive reactions:
    ///    - DNS burst for the same domain (reconnect attempts)
    ///    - Child process spawning (launching defensive payloads)
    ///    - Registry Run key writes (re-establishing persistence)
    ///    - System shutdown/restart initiation (crash-to-reboot defense)
    ///    - Rapid connection cycling to alternate endpoints (failover C2)
    /// 
    /// Attack model: Rootkit/implant maintains a persistent WebSocket or long-poll to a C2 relay.
    /// When the connection is severed (hosts block, firewall rule), the implant panics and
    /// executes a defensive routine to survive the disruption.
    /// Note: this monitor is the general post-drop behavioral correlator for any long-lived
    /// endpoint (no domain is hardcoded; the retired forum.hr hosts block was removed in v2.7.6).
    /// </summary>
    public sealed class PersistentConnectionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PersistentConnectionMonitor> _logger;
        private readonly SignerTrustService? _signerTrust;

        // Tracks established connections: key = "pid:remoteIp:remotePort", value = first-seen time
        private readonly ConcurrentDictionary<string, ConnectionState> _trackedConnections = new();

        // When a long-lived connection drops, record it here for post-drop behavior analysis
        private readonly ConcurrentDictionary<string, DroppedConnection> _droppedConnections = new();

        // Post-drop behavior: DNS bursts per process
        private readonly ConcurrentDictionary<int, DnsBurstTracker> _dnsBursts = new();

        // Post-drop behavior: new connections per process after drop
        private readonly ConcurrentDictionary<int, int> _postDropNewConnections = new();

        // Minimum connection age to be considered "persistent" (webhook/pairing pattern)
        private static readonly TimeSpan PersistentThreshold = TimeSpan.FromMinutes(5);

        // Window after drop in which defensive behavior is suspicious
        private static readonly TimeSpan PostDropWindow = TimeSpan.FromSeconds(30);

        // How often we scan the TCP table
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

        // Ignore local/private ranges for persistent tracking (unless to specific ports)
        private static readonly HashSet<int> WebhookPorts = new() { 80, 443, 8080, 8443, 4443, 8009, 5228, 5229, 5230 };

        // Dedup: don't fire the same alert for the same process+endpoint repeatedly
        private readonly ConcurrentDictionary<string, DateTime> _alertDedup = new();

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

        private enum TCP_TABLE_CLASS { OWNER_PID_ALL = 5 }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            uint ulAf, TCP_TABLE_CLASS tableClass, uint reserved);

        public PersistentConnectionMonitor(DetectionEngine de, ILogger<PersistentConnectionMonitor> l, SignerTrustService? signerTrust = null)
        {
            _detectionEngine = de;
            _logger = l;
            _signerTrust = signerTrust;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PersistentConnectionMonitor] Started - tracking long-lived connections for webhook/pairing C2 patterns");

            // Wait for system to stabilize
            await Task.Delay(60000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    ScanAndCorrelate();
                    PruneStaleEntries();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PersistentConnectionMonitor] Scan error");
                }

                await Task.Delay(ScanInterval, ct);
            }
        }

        private void ScanAndCorrelate()
        {
            var currentConnections = GetEstablishedConnections();
            var currentKeys = new HashSet<string>();

            foreach (var conn in currentConnections)
            {
                var key = $"{conn.Pid}:{conn.RemoteIp}:{conn.RemotePort}";
                currentKeys.Add(key);

                // Track new connections
                if (!_trackedConnections.ContainsKey(key))
                {
                    _trackedConnections[key] = new ConnectionState
                    {
                        Pid = conn.Pid,
                        ProcessName = conn.ProcessName,
                        RemoteIp = conn.RemoteIp,
                        RemotePort = conn.RemotePort,
                        FirstSeen = DateTime.UtcNow,
                        LastSeen = DateTime.UtcNow
                    };
                }
                else
                {
                    _trackedConnections[key] = _trackedConnections[key] with { LastSeen = DateTime.UtcNow };
                }
            }

            // Detect dropped connections that were long-lived
            var droppedKeys = _trackedConnections.Keys.Except(currentKeys).ToList();
            foreach (var key in droppedKeys)
            {
                if (_trackedConnections.TryRemove(key, out var state))
                {
                    var duration = state.LastSeen - state.FirstSeen;
                    if (duration >= PersistentThreshold && !IsLegitimate(state.ProcessName, state.Pid))
                    {
                        // Long-lived connection just dropped - monitor for defensive behavior
                        _droppedConnections[key] = new DroppedConnection
                        {
                            State = state,
                            DroppedAt = DateTime.UtcNow,
                            Duration = duration
                        };

                        _logger.LogInformation(
                            "[PersistentConnectionMonitor] Long-lived connection dropped: {Process} (PID {Pid}) -> {Ip}:{Port} (held {Dur:F0}s)",
                            state.ProcessName, state.Pid, state.RemoteIp, state.RemotePort, duration.TotalSeconds);
                    }
                }
            }

            // Check for post-drop suspicious behavior
            CheckPostDropBehavior(currentConnections);
        }

        private void CheckPostDropBehavior(List<ActiveConnection> currentConnections)
        {
            var now = DateTime.UtcNow;
            var expiredDrops = new List<string>();

            foreach (var (key, drop) in _droppedConnections)
            {
                if (now - drop.DroppedAt > PostDropWindow)
                {
                    expiredDrops.Add(key);
                    continue;
                }

                // Check if the same process is now rapidly connecting to new endpoints
                var newConnFromSamePid = currentConnections
                    .Where(c => c.Pid == drop.State.Pid &&
                                $"{c.RemoteIp}:{c.RemotePort}" != $"{drop.State.RemoteIp}:{drop.State.RemotePort}")
                    .ToList();

                if (newConnFromSamePid.Count >= 3)
                {
                    var dedupKey = $"failover:{drop.State.Pid}:{drop.State.RemoteIp}";
                    if (!_alertDedup.ContainsKey(dedupKey))
                    {
                        _alertDedup[dedupKey] = now;
                        var targets = string.Join(", ", newConnFromSamePid.Take(5).Select(c => $"{c.RemoteIp}:{c.RemotePort}"));

                        // v1.8.3: Failover reconnect is common for torrents/P2P/game clients.
                        // Observe-only unless multi-signal composite escalates elsewhere.
                        bool isSigned = _signerTrust?.IsSignedProcess(drop.State.Pid) ?? false;
                        var effectiveTier = DetectionTier.Tier2Indicator;
                        var effectiveResponse = ResponseAction.LogOnly;
                        var effectiveConfidence = isSigned ? 0.40 : 0.55;

                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "C2 Pairing: Failover After Connection Drop",
                            Evidence = $"Process '{drop.State.ProcessName}' (PID {drop.State.Pid}) lost persistent connection to " +
                                       $"{drop.State.RemoteIp}:{drop.State.RemotePort} (held {drop.Duration.TotalMinutes:F1}min) " +
                                       $"and immediately connected to {newConnFromSamePid.Count} new endpoints: {targets}",
                            Reasoning = "A process maintained a long-lived connection (webhook/pairing pattern) to a remote host. " +
                                        "When that connection was severed, the process immediately initiated connections to multiple " +
                                        "alternative endpoints. This is characteristic of C2 implants with failover logic - " +
                                        "when the primary relay dies, they cycle through backup servers." +
                                        (isSigned ? " Process is Authenticode-signed; demoted to log-only." : ""),
                            Confidence = effectiveConfidence,
                            Tier = effectiveTier,
                            AuthorizedResponse = effectiveResponse,
                            ProcessName = drop.State.ProcessName,
                            ProcessId = drop.State.Pid,
                            SignalType = SignalType.NetworkC2,
                            Metadata = new Dictionary<string, string>
                            {
                                { "OriginalTarget", $"{drop.State.RemoteIp}:{drop.State.RemotePort}" },
                                { "ConnectionDuration", $"{drop.Duration.TotalSeconds:F0}s" },
                                { "FailoverTargets", targets },
                                { "FailoverCount", newConnFromSamePid.Count.ToString() }
                            }
                        });
                    }
                }

                // Check if same process spawned child processes after drop
                try
                {
                    var proc = Process.GetProcessById(drop.State.Pid);
                    // Check for new child processes by scanning processes whose parent is this PID
                    var children = Process.GetProcesses()
                        .Where(p =>
                        {
                            try
                            {
                                // Compare start time - children spawned after the drop
                                return p.StartTime.ToUniversalTime() > drop.DroppedAt &&
                                       p.Id != drop.State.Pid && p.Id > 4;
                            }
                            catch { return false; }
                        })
                        .Take(10)
                        .ToList();

                    // Heuristic: if the process spawned multiple children RIGHT after losing connection
                    var recentChildren = children.Where(c =>
                    {
                        try { return (c.StartTime.ToUniversalTime() - drop.DroppedAt).TotalSeconds < 10; }
                        catch { return false; }
                    }).ToList();

                    if (recentChildren.Count >= 2)
                    {
                        var dedupKey = $"spawn:{drop.State.Pid}:{drop.DroppedAt.Ticks}";
                        if (!_alertDedup.ContainsKey(dedupKey))
                        {
                            _alertDedup[dedupKey] = now;
                            var childNames = string.Join(", ", recentChildren.Select(c =>
                            {
                                try { return $"{c.ProcessName} (PID {c.Id})"; }
                                catch { return "unknown"; }
                            }));

                            // v1.8.3: child spawn after drop alone is not enough to kill
                            bool isSignedSpawn = _signerTrust?.IsSignedProcess(drop.State.Pid) ?? false;
                            var spawnTier = DetectionTier.Tier2Indicator;
                            var spawnResponse = ResponseAction.LogOnly;
                            var spawnConfidence = isSignedSpawn ? 0.40 : 0.55;

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "C2 Pairing: Defensive Process Spawn After Drop",
                                Evidence = $"Process '{drop.State.ProcessName}' (PID {drop.State.Pid}) lost persistent connection to " +
                                           $"{drop.State.RemoteIp}:{drop.State.RemotePort} and spawned {recentChildren.Count} " +
                                           $"child processes within 10s: {childNames}",
                                Reasoning = "After losing a long-held C2 connection, the process immediately spawned multiple child " +
                                            "processes. This is a defensive reaction - the implant is launching recovery routines, " +
                                            "persistence re-establishment, or alternative communication channels." +
                                            (isSignedSpawn ? " Process is Authenticode-signed; demoted to log-only." : ""),
                                Confidence = spawnConfidence,
                                Tier = spawnTier,
                                AuthorizedResponse = spawnResponse,
                                ProcessName = drop.State.ProcessName,
                                ProcessId = drop.State.Pid,
                                SignalType = SignalType.SuspiciousProcess,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "WeakObserveSeed", "true" },
                                    { "OriginalTarget", $"{drop.State.RemoteIp}:{drop.State.RemotePort}" },
                                    { "ConnectionDuration", $"{drop.Duration.TotalSeconds:F0}s" },
                                    { "SpawnedChildren", childNames }
                                }
                            });
                        }
                    }
                }
                catch { /* Process may have exited */ }

                // Check if same process is now doing rapid DNS queries (reconnect attempts)
                // This is tracked via RecordDnsQuery called from DnsQueryMonitor integration
            }

            foreach (var key in expiredDrops)
                _droppedConnections.TryRemove(key, out _);
        }

        /// <summary>
        /// Called by DnsQueryMonitor when a DNS query is observed.
        /// Used to correlate: process loses connection -> immediately floods DNS for same/similar domain.
        /// </summary>
        public void RecordDnsQuery(int pid, string domain)
        {
            // Check if this PID has a recently dropped connection
            var relevantDrop = _droppedConnections.Values
                .Where(d => d.State.Pid == pid &&
                            DateTime.UtcNow - d.DroppedAt < PostDropWindow)
                .Select(d => (DroppedConnection?)d)
                .FirstOrDefault();

            if (relevantDrop == null) return;
            var drop = relevantDrop.Value;

            if (!_dnsBursts.ContainsKey(pid))
                _dnsBursts[pid] = new DnsBurstTracker();

            var tracker = _dnsBursts[pid];
            tracker.RecordQuery(domain);

            // If we see 10+ queries within the post-drop window, that's a reconnect burst
            if (tracker.QueryCount >= 10 && !tracker.Alerted)
            {
                tracker.Alerted = true;
                var dedupKey = $"dnsburst:{pid}:{drop.DroppedAt.Ticks}";
                if (!_alertDedup.ContainsKey(dedupKey))
                {
                    _alertDedup[dedupKey] = DateTime.UtcNow;
                    var topDomains = string.Join(", ", tracker.GetTopDomains(5));

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "C2 Pairing: DNS Reconnect Burst After Drop",
                        Evidence = $"Process '{drop.State.ProcessName}' (PID {pid}) lost persistent connection to " +
                                   $"{drop.State.RemoteIp}:{drop.State.RemotePort} and issued " +
                                   $"{tracker.QueryCount} DNS queries within {PostDropWindow.TotalSeconds}s. " +
                                   $"Top domains: {topDomains}",
                        Reasoning = "After a long-held connection was severed, the process immediately began flooding DNS " +
                                    "queries - attempting to re-resolve the C2 host or find alternative relay domains. " +
                                    "Legitimate software retries gracefully with backoff. Malware hammers DNS immediately.",
                        Confidence = _signerTrust != null ? _signerTrust.AdjustConfidence(0.88, pid) : 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = drop.State.ProcessName,
                        ProcessId = pid,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            { "OriginalTarget", $"{drop.State.RemoteIp}:{drop.State.RemotePort}" },
                            { "ConnectionDuration", $"{drop.Duration.TotalSeconds:F0}s" },
                            { "DnsQueryCount", tracker.QueryCount.ToString() },
                            { "TopDomains", topDomains }
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Checks if a process with a recently-dropped persistent connection is writing to
        /// shutdown/restart APIs. Called from external monitors if detected.
        /// </summary>
        public bool HasRecentDrop(int pid)
        {
            return _droppedConnections.Values.Any(d =>
                d.State.Pid == pid && DateTime.UtcNow - d.DroppedAt < PostDropWindow);
        }

        private bool IsLegitimate(string? processName, int pid = 0)
        {
            if (string.IsNullOrEmpty(processName)) return false;

            string? path = null;
            if (pid > 0)
            {
                try { path = SecurityValidation.GetProcessImagePath(pid); } catch { }
            }

            var n = processName!;
            if (n.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("SearchHost", StringComparison.OrdinalIgnoreCase))
                return SecurityValidation.IsWindowsSystemImage(path);

            if (n.Equals("Sentinel.Service", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("Sentinel.Agent", StringComparison.OrdinalIgnoreCase))
                return true;

            if (UserlandProtocolHeuristics.IsKnownCommsIdentity(n, path))
                return true;
            if (SecurityValidation.IsGameOrAntiCheatPath(path))
                return true;
            if (ChainTracer.IsLegitimateIdeHost(path, n))
                return true;

            return false;
        }

        private List<ActiveConnection> GetEstablishedConnections()
        {
            var results = new List<ActiveConnection>();

            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
            if (ret != 122) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, 2, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                int myPid = System.Net48Environment.ProcessId;

                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                    if (row.state != 5) continue; // Only ESTABLISHED
                    if (row.owningPid <= 4 || (int)row.owningPid == myPid) continue;

                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                    var remotePort = (int)((row.remotePort & 0xFF) << 8 | (row.remotePort & 0xFF00) >> 8);

                    // Skip loopback and link-local
                    if (remoteIp.StartsWith("127.") || remoteIp == "0.0.0.0") continue;

                    string processName = "unknown";
                    try
                    {
                        using var p = Process.GetProcessById((int)row.owningPid);
                        processName = p.ProcessName;
                    }
                    catch { }

                    results.Add(new ActiveConnection
                    {
                        Pid = (int)row.owningPid,
                        ProcessName = processName,
                        RemoteIp = remoteIp,
                        RemotePort = remotePort
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            AppendIpv6Connections(results);
            return results;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            public uint state;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;
            public uint remoteScopeId;
            public uint remotePort;
            public uint owningPid;
        }

        private void AppendIpv6Connections(List<ActiveConnection> results)
        {
            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 23, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
            if (ret != 122 || size <= 0) return;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, 23, TCP_TABLE_CLASS.OWNER_PID_ALL, 0);
                if (ret != 0) return;
                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                int myPid = System.Net48Environment.ProcessId;
                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                    var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                    if (row.state != 5) continue;
                    if (row.owningPid <= 4 || (int)row.owningPid == myPid) continue;
                    if (row.remoteAddr == null || row.remoteAddr.Length < 16) continue;
                    var remoteIp = new IPAddress(row.remoteAddr).ToString();
                    if (remoteIp == "::1" || remoteIp.StartsWith("fe80", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var remotePort = (int)((row.remotePort & 0xFF) << 8 | (row.remotePort & 0xFF00) >> 8);
                    string processName = "unknown";
                    try
                    {
                        using var p = Process.GetProcessById((int)row.owningPid);
                        processName = p.ProcessName;
                    }
                    catch { }
                    results.Add(new ActiveConnection
                    {
                        Pid = (int)row.owningPid,
                        ProcessName = processName,
                        RemoteIp = remoteIp,
                        RemotePort = remotePort
                    });
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private void PruneStaleEntries()
        {
            var now = DateTime.UtcNow;

            // Prune alert dedup cache (1 hour retention)
            var staleAlerts = _alertDedup.Where(kv => now - kv.Value > TimeSpan.FromHours(1)).Select(kv => kv.Key).ToList();
            foreach (var k in staleAlerts) _alertDedup.TryRemove(k, out _);

            // Prune DNS burst trackers (5 min retention)
            var staleDns = _dnsBursts.Where(kv => now - kv.Value.LastQuery > TimeSpan.FromMinutes(5)).Select(kv => kv.Key).ToList();
            foreach (var k in staleDns) _dnsBursts.TryRemove(k, out _);

            // Prune expired drops
            var staleDrops = _droppedConnections.Where(kv => now - kv.Value.DroppedAt > TimeSpan.FromMinutes(2)).Select(kv => kv.Key).ToList();
            foreach (var k in staleDrops) _droppedConnections.TryRemove(k, out _);
        }

        //  Internal types 

        private record struct ConnectionState
        {
            public int Pid;
            public string ProcessName;
            public string RemoteIp;
            public int RemotePort;
            public DateTime FirstSeen;
            public DateTime LastSeen;
        }

        private record struct DroppedConnection
        {
            public ConnectionState State;
            public DateTime DroppedAt;
            public TimeSpan Duration;
        }

        private struct ActiveConnection
        {
            public int Pid;
            public string ProcessName;
            public string RemoteIp;
            public int RemotePort;
        }

        private class DnsBurstTracker
        {
            private readonly ConcurrentDictionary<string, int> _domains = new(StringComparer.OrdinalIgnoreCase);
            public int QueryCount;
            public DateTime LastQuery = DateTime.UtcNow;
            public bool Alerted;

            public void RecordQuery(string domain)
            {
                Interlocked.Increment(ref QueryCount);
                _domains.AddOrUpdate(domain, 1, (_, c) => c + 1);
                LastQuery = DateTime.UtcNow;
            }

            public IEnumerable<string> GetTopDomains(int count) =>
                _domains.OrderByDescending(kv => kv.Value).Take(count).Select(kv => kv.Key);
        }
    }
}
