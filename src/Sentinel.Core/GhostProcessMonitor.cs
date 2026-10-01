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
    /// Detects "ghost" processes - PIDs with active outbound network connections
    /// whose process name cannot be resolved or was recorded as empty/unknown.
    ///
    /// This is the exact blind spot exploited by PlugX and similar RATs:
    ///   1. RAT uses DLL sideloading via legitimate binary (e.g., GoogleUpdate.exe)
    ///   2. The legitimate binary gets hollowed or the process exits quickly
    ///   3. TCP connections persist under the original PID (or re-spawned PID)
    ///   4. ProcessAncestryCache records empty name from hollowed ETW event
    ///   5. BeaconingDetector fires but process name is empty - low forensic value
    ///
    /// This monitor catches the gap: any PID with established outbound connections
    /// that cannot be resolved to a valid, signed process image is immediately
    /// suspicious and investigated.
    ///
    /// MitM / fake-Chromecast chain (post-incident):
    ///   Planted root cert -> invisible/hollowed process -> TCP to rogue Cast :8008/:8009.
    /// When MitmDefense is on, ghost->Cast/rogue-IP is immediate kill + isolate (no 2-scan wait).
    ///
    /// Scan interval: 15 seconds (catches short-lived RAT processes between
    /// BeaconingDetector's 30s analysis cycle).
    /// </summary>
    public sealed class GhostProcessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly SentinelConfig _config;
        private readonly PhantomDeviceMonitor? _phantomDeviceMonitor;
        private readonly ContextBus? _contextBus;
        private readonly ILogger<GhostProcessMonitor> _logger;

        // Track already-alerted PIDs to avoid flooding
        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();

        // Track PIDs seen with ghost connections across multiple scans for confidence building
        private readonly ConcurrentDictionary<int, GhostProcessState> _ghostTracking = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan StaleTimeout = TimeSpan.FromMinutes(10);

        // Ports commonly abused by RATs masquerading as legitimate traffic
        private static readonly HashSet<int> SuspiciousMasqueradePorts = new()
        {
            5228, // Google FCM - PlugX favorite
            8009, // Chromecast - lateral movement indicator
            4443, // Common C2 alt-HTTPS
            8443, // Alt HTTPS
            8080, // Alt HTTP
            1194, // OpenVPN
            6667, // IRC (C2)
            6697, // IRC over TLS
        };

        public GhostProcessMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            SentinelConfig config,
            ILogger<GhostProcessMonitor> logger,
            PhantomDeviceMonitor? phantomDeviceMonitor = null,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _config = config;
            _phantomDeviceMonitor = phantomDeviceMonitor;
            _contextBus = contextBus;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[GhostProcessMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanForGhostProcessesAsync(ct);
                    PruneStaleEntries();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[GhostProcessMonitor] Scan error"); }
            }
        }

        private async Task ScanForGhostProcessesAsync(CancellationToken ct)
        {
            var connections = GetEstablishedOutboundConnections();

            // Group by PID
            var connectionsByPid = connections.GroupBy(c => c.OwningPid);

            foreach (var group in connectionsByPid)
            {
                if (ct.IsCancellationRequested) break;

                int pid = group.Key;
                if (pid <= 4) continue;

                // Skip if recently alerted
                if (_alertedPids.TryGetValue(pid, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                // Try to resolve the process
                var resolution = ResolveProcess(pid);

                if (resolution.IsGhost)
                {
                    // Track ghost across scans for confidence building
                    var state = _ghostTracking.GetOrAdd(pid, _ => new GhostProcessState());
                    state.SeenCount++;
                    state.LastSeen = DateTimeOffset.UtcNow;
                    state.Connections = group.ToList();

                    // HARDENING: Immediate alert for high-confidence indicators without
                    // waiting for 2 scans. An attacker can exfiltrate data within a single
                    // 15-second scan cycle and close the connection before the second scan.
                    bool hasHighConfidencePort = group.Any(c =>
                        SuspiciousMasqueradePorts.Contains(c.RemotePort) ||
                        c.RemotePort == 4444 || c.RemotePort == 5555 ||  // Common reverse shells (meterpreter, etc.)
                        c.RemotePort == 1337 || c.RemotePort == 31337 || // Hacker convention ports
                        c.RemotePort == 9001 || c.RemotePort == 9090);   // Tor/common C2

                    bool connectsToBlockedDevice = _phantomDeviceMonitor != null &&
                        group.Any(c => _phantomDeviceMonitor.IsBlockedDevice(c.RemoteAddress));

                    // MitM suite: invisible process talking to Cast / known rogue Chromecast IP
                    bool mitmGhostCast = IsMitmGhostCastRelay(group);

                    if (hasHighConfidencePort || connectsToBlockedDevice || mitmGhostCast || state.SeenCount >= 2)
                    {
                        await EmitGhostDetection(pid, resolution, state, ct);
                        _alertedPids[pid] = DateTimeOffset.UtcNow;

                        // Publish enrichment signal for cross-monitor consumption
                        _contextBus?.Publish(new GhostProcessSignal
                        {
                            ProcessId = pid,
                            ProcessName = resolution.Name ?? "UNRESOLVABLE",
                            SourceMonitor = "GhostProcessMonitor",
                            Destinations = state.Connections.Select(c => $"{c.RemoteAddress}:{c.RemotePort}").Distinct().Take(10).ToList(),
                            ScansSeen = state.SeenCount,
                            ConnectsToBlockedDevice = connectsToBlockedDevice,
                            HasSuspiciousPort = hasHighConfidencePort || mitmGhostCast
                        });
                    }
                }
                else if (resolution.IsEmptyName)
                {
                    // Process exists but has empty name - ETW recorded it with blank ImageName
                    // This is a strong indicator of process hollowing or image swap
                    var conns = group.ToList();
                    bool hasSuspiciousPort = conns.Any(c => SuspiciousMasqueradePorts.Contains(c.RemotePort));
                    bool mitmGhostCast = IsMitmGhostCastRelay(conns);

                    if (hasSuspiciousPort || mitmGhostCast)
                    {
                        await EmitEmptyNameDetection(pid, resolution, conns, ct);
                        _alertedPids[pid] = DateTimeOffset.UtcNow;
                    }
                    else
                    {
                        // Track across scans even for non-suspicious ports
                        var state = _ghostTracking.GetOrAdd(pid, _ => new GhostProcessState());
                        state.SeenCount++;
                        state.LastSeen = DateTimeOffset.UtcNow;
                        state.Connections = conns;

                        if (state.SeenCount >= 3) // More conservative for non-suspicious ports
                        {
                            await EmitEmptyNameDetection(pid, resolution, conns, ct);
                            _alertedPids[pid] = DateTimeOffset.UtcNow;
                        }
                    }
                }
            }
        }

        private async Task EmitGhostDetection(int pid, ProcessResolution resolution,
            GhostProcessState state, CancellationToken ct)
        {
            var destinations = string.Join(", ",
                state.Connections.Select(c => $"{c.RemoteAddress}:{c.RemotePort}").Distinct().Take(5));

            bool hasSuspiciousPort = state.Connections.Any(c => SuspiciousMasqueradePorts.Contains(c.RemotePort));
            bool mitmGhostCast = IsMitmGhostCastRelay(state.Connections);

            // Escalation: if connecting to a device PhantomDeviceMonitor already blocked/flagged,
            // this is confirmed C2 via a rogue LAN relay. Kill it + chain trace.
            bool connectsToBlockedDevice = _phantomDeviceMonitor != null &&
                state.Connections.Any(c => _phantomDeviceMonitor.IsBlockedDevice(c.RemoteAddress));
            bool connectsToPhantomDevice = !connectsToBlockedDevice && _phantomDeviceMonitor != null &&
                state.Connections.Any(c => IsPrivateIp(c.RemoteAddress) && _phantomDeviceMonitor.IsPhantomDevice(c.RemoteAddress));

            double confidence;
            ResponseAction response;
            string ruleName = "Ghost Process: Unresolvable PID with Active Network";

            if (mitmGhostCast || connectsToBlockedDevice)
            {
                confidence = 0.96;
                response = ResponseAction.KillProcessTree;
                if (mitmGhostCast)
                    ruleName = "Ghost Process: Invisible Process -> Fake Chromecast / Rogue Cast (MitM chain)";
            }
            else if (connectsToPhantomDevice && hasSuspiciousPort)
            {
                confidence = 0.92;
                response = ResponseAction.KillProcessTree;
            }
            else if (hasSuspiciousPort)
            {
                confidence = 0.88;
                response = ResponseAction.KillProcessTree;
            }
            else
            {
                confidence = 0.78;
                response = ResponseAction.NetworkIsolate;
            }

            var castTarget = state.Connections
                .FirstOrDefault(c => (c.RemotePort == 8008 || c.RemotePort == 8009) && IsPrivateIp(c.RemoteAddress));
            var targetIp = castTarget?.RemoteAddress
                ?? state.Connections.Select(c => c.RemoteAddress).FirstOrDefault(IsPrivateIp)
                ?? "";

            var metadata = new Dictionary<string, string>
            {
                ["Destinations"] = destinations,
                ["ConnectionCount"] = state.Connections.Count.ToString(),
                ["ScansSeen"] = state.SeenCount.ToString(),
                ["HasSuspiciousPort"] = hasSuspiciousPort.ToString(),
                ["ConnectsToBlockedDevice"] = connectsToBlockedDevice.ToString(),
                ["MitmGhostCast"] = mitmGhostCast.ToString()
            };
            if (mitmGhostCast || connectsToBlockedDevice)
            {
                metadata["MitmDefense"] = "true";
                if (!string.IsNullOrEmpty(targetIp))
                    metadata["TargetIP"] = targetIp;
            }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"PID {pid} has {state.Connections.Count} established outbound connection(s) " +
                           $"to [{destinations}] but cannot be resolved to a running process. " +
                           $"Observed in {state.SeenCount} consecutive scans." +
                           (connectsToBlockedDevice ? " TARGET IS A BLOCKED PHANTOM DEVICE." : "") +
                           (mitmGhostCast ? " MITM CHAIN: invisible process <-> Cast/rogue Chromecast." : ""),
                Reasoning = "A process ID owns active outbound TCP connections but the process " +
                            "cannot be resolved via Process.GetProcessById or the ancestry cache. " +
                            "This occurs when a process exits but its connections persist (orphaned sockets), " +
                            "or when a RAT uses process hollowing/DLL sideloading causing the host process " +
                            "to terminate while the injected code's network activity continues under the original PID. " +
                            (mitmGhostCast
                                ? "Post-incident MitM pattern: planted root cert powers trust for an invisible process " +
                                  "that C2s through a fake Chromecast (Cast :8008/:8009) on the LAN - kill + isolate."
                                : connectsToBlockedDevice
                                    ? "The target IP is a device already blocked by PhantomDeviceMonitor - confirmed C2 relay."
                                    : "PlugX, ShadowPad, and Mustang Panda specifically exploit this technique."),
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = response,
                ProcessName = resolution.Name ?? "UNRESOLVABLE",
                ProcessId = pid,
                SignalType = mitmGhostCast ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
                Metadata = metadata
            });
        }

        /// <summary>
        /// Invisible process talking to Cast ports or known rogue Cast IPs under MitmDefense.
        /// Matches the planted-cert -> ghost process -> fake Chromecast C2 pattern.
        /// </summary>
        private bool IsMitmGhostCastRelay(IEnumerable<ConnectionInfo> connections)
        {
            if (!ProductPosture.AllowsMitmDefenseMutations(_config))
                return false;
            var mitm = _config.MitmDefense;
            if (mitm == null || !mitm.AutoBlockRogueCast)
                return false;

            var known = new HashSet<string>(
                mitm.KnownRogueCastIps ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);

            foreach (var c in connections)
            {
                if (known.Contains(c.RemoteAddress))
                    return true;
                if (IsPrivateIp(c.RemoteAddress) && (c.RemotePort == 8008 || c.RemotePort == 8009))
                    return true;
            }
            return false;
        }

        private async Task EmitEmptyNameDetection(int pid, ProcessResolution resolution,
            List<ConnectionInfo> connections, CancellationToken ct)
        {
            var destinations = string.Join(", ",
                connections.Select(c => $"{c.RemoteAddress}:{c.RemotePort}").Distinct().Take(5));

            bool hasSuspiciousPort = connections.Any(c => SuspiciousMasqueradePorts.Contains(c.RemotePort));
            bool mitmGhostCast = IsMitmGhostCastRelay(connections);

            // Escalation: ghost + connecting to blocked/phantom device = confirmed C2
            bool connectsToBlockedDevice = _phantomDeviceMonitor != null &&
                connections.Any(c => _phantomDeviceMonitor.IsBlockedDevice(c.RemoteAddress));
            bool connectsToPhantomOnCastPort = !connectsToBlockedDevice && _phantomDeviceMonitor != null &&
                connections.Any(c => IsPrivateIp(c.RemoteAddress) &&
                    (c.RemotePort == 8009 || c.RemotePort == 8008) &&
                    _phantomDeviceMonitor.IsPhantomDevice(c.RemoteAddress));

            double confidence;
            ResponseAction response;
            string ruleName = "Ghost Process: Empty Name with Active Network";

            if (mitmGhostCast || connectsToBlockedDevice || connectsToPhantomOnCastPort)
            {
                confidence = 0.96;
                response = ResponseAction.KillProcessTree;
                if (mitmGhostCast)
                    ruleName = "Ghost Process: Empty-Name Process -> Fake Chromecast (MitM chain)";
            }
            else if (hasSuspiciousPort)
            {
                confidence = 0.85;
                response = ResponseAction.KillProcessTree;
            }
            else
            {
                confidence = 0.72;
                response = ResponseAction.LogOnly;
            }

            var castTarget = connections
                .FirstOrDefault(c => (c.RemotePort == 8008 || c.RemotePort == 8009) && IsPrivateIp(c.RemoteAddress));
            var metadata = new Dictionary<string, string>
            {
                ["Destinations"] = destinations,
                ["ImagePath"] = resolution.ImagePath ?? "unknown",
                ["HasSuspiciousPort"] = hasSuspiciousPort.ToString(),
                ["ConnectsToBlockedDevice"] = connectsToBlockedDevice.ToString(),
                ["MitmGhostCast"] = mitmGhostCast.ToString()
            };
            if (mitmGhostCast || connectsToBlockedDevice || connectsToPhantomOnCastPort)
            {
                metadata["MitmDefense"] = "true";
                if (castTarget != null)
                    metadata["TargetIP"] = castTarget.RemoteAddress;
            }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"PID {pid} has {connections.Count} established outbound connection(s) " +
                           $"to [{destinations}] but process name is empty/blank. " +
                           $"Image path: '{resolution.ImagePath ?? "unknown"}'" +
                           (connectsToBlockedDevice ? " TARGET IS A BLOCKED PHANTOM DEVICE." : "") +
                           (mitmGhostCast ? " MITM CHAIN: hollowed process <-> fake Chromecast." : ""),
                Reasoning = "A process with an empty/unresolvable name is maintaining active outbound " +
                            "network connections. Empty process names in ETW telemetry indicate the " +
                            "ImageName field was blank at process creation - a hallmark of process hollowing " +
                            "(T1055.012) where the original image is unmapped after spawn. " +
                            (mitmGhostCast
                                ? "Planted cert + hollowed process + Cast :8009 = MitM fake-Chromecast C2; kill authorized."
                                : connectsToBlockedDevice || connectsToPhantomOnCastPort
                                    ? "The target is a confirmed rogue LAN device - kill authorized."
                                    : "RATs like PlugX use this to evade name-based allowlists in security tools."),
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = response,
                ProcessName = string.IsNullOrEmpty(resolution.Name) ? "EMPTY_NAME" : resolution.Name!,
                ProcessId = pid,
                SignalType = mitmGhostCast ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
                Metadata = metadata
            });
        }

        private ProcessResolution ResolveProcess(int pid)
        {
            var resolution = new ProcessResolution();

            // 1. Check ancestry cache
            var (_, cachedName) = _ancestryCache.GetParent(pid);
            if (cachedName != "unknown" && !string.IsNullOrEmpty(cachedName))
            {
                resolution.Name = cachedName;
                resolution.Source = "cache";
                return resolution;
            }

            // 2. Try direct process query
            try
            {
                using var proc = Process.GetProcessById(pid);
                resolution.Name = proc.ProcessName;
                try { resolution.ImagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                resolution.Source = "direct";

                if (string.IsNullOrEmpty(resolution.Name))
                {
                    resolution.IsEmptyName = true;
                }
                return resolution;
            }
            catch (ArgumentException)
            {
                // Process doesn't exist - true ghost
                resolution.IsGhost = true;
                resolution.Source = "none";
                return resolution;
            }
            catch (InvalidOperationException)
            {
                resolution.IsGhost = true;
                resolution.Source = "none";
                return resolution;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Access denied - process exists but we can't read it
                // Still suspicious if ancestry cache has empty name
                if (cachedName == "unknown" || string.IsNullOrEmpty(cachedName))
                {
                    resolution.IsEmptyName = true;
                    resolution.Name = cachedName;
                }
                resolution.Source = "access_denied";
                return resolution;
            }
        }

        private static List<ConnectionInfo> GetEstablishedOutboundConnections()
        {
            var results = new List<ConnectionInfo>();

            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 122) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, 2,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                int myPid = System.Net48Environment.ProcessId;

                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                    if (row.state != 5) continue; // Established only
                    if (row.owningPid <= 4 || row.owningPid == myPid) continue;

                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();

                    // Skip loopback and link-local
                    if (remoteIp.StartsWith("127.") || remoteIp.StartsWith("0.") || remoteIp == "0.0.0.0")
                        continue;

                    var remotePort = (int)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));

                    results.Add(new ConnectionInfo
                    {
                        OwningPid = (int)row.owningPid,
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }

        private void PruneStaleEntries()
        {
            var cutoff = DateTimeOffset.UtcNow - StaleTimeout;
            foreach (var key in _ghostTracking.Keys.ToArray())
            {
                if (_ghostTracking.TryGetValue(key, out var state) && state.LastSeen < cutoff)
                    _ghostTracking.TryRemove(key, out _);
            }

            foreach (var key in _alertedPids.Keys.ToArray())
            {
                if (_alertedPids.TryGetValue(key, out var time) && time < cutoff)
                    _alertedPids.TryRemove(key, out _);
            }
        }

        #region P/Invoke

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, TCP_TABLE_CLASS tableClass, uint reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_OWNER_PID_ALL = 5
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

        #endregion

        #region Internal Types

        private static bool IsPrivateIp(string ip)
        {
            if (ip.StartsWith("10.")) return true;
            if (ip.StartsWith("192.168.")) return true;
            if (ip.StartsWith("172."))
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2 && int.TryParse(parts[1], out int second))
                    return second >= 16 && second <= 31;
            }
            return false;
        }

        private sealed class ConnectionInfo
        {
            public int OwningPid { get; set; }
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
        }

        private sealed class GhostProcessState
        {
            public int SeenCount { get; set; }
            public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
            public List<ConnectionInfo> Connections { get; set; } = new();
        }

        private sealed class ProcessResolution
        {
            public string? Name { get; set; }
            public string? ImagePath { get; set; }
            public string Source { get; set; } = "none";
            public bool IsGhost { get; set; }
            public bool IsEmptyName { get; set; }
        }

        #endregion
    }
}
