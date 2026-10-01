using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    /// Observes optional OS/vendor services that may phone home while remaining legitimate
    /// (DiagTrack, whesvc, dmwappushservice, ...).
    ///
    /// Product law (v1.9.9): OBSERVE ONLY for this class of activity.
    /// Does not kill processes, stop services, or firewall-block destinations.
    /// Destructive response remains reserved for chain-confirmed malice
    /// (credential dump, C2 beaconing, ransomware encryption, reverse shell, token theft, exfil chains).
    ///
    /// Events are Tier2 + LogOnly + WeakObserveSeed so they never seed chain nukes.
    /// </summary>
    public sealed class PrivacyServiceOutboundMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ServiceProcessMap _serviceMap;
        private readonly SentinelConfig _config;
        private readonly ILogger<PrivacyServiceOutboundMonitor> _logger;

        // Dedup: service|remote|port -> last emit
        private readonly ConcurrentDictionary<string, DateTimeOffset> _outboundAlerted = new(StringComparer.OrdinalIgnoreCase);
        // Dedup: service name -> last "running" emit
        private readonly ConcurrentDictionary<string, DateTimeOffset> _runningAlerted = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan OutboundDedup = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan RunningDedup = TimeSpan.FromHours(1);

        /// <summary>Built-in optional privacy / diagnostics inventory (short SCM names).</summary>
        internal static readonly IReadOnlyDictionary<string, (string Class, string Label)> DefaultInventory =
            new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase)
            {
                ["DiagTrack"] = ("Telemetry", "Connected User Experiences and Telemetry"),
                ["dmwappushservice"] = ("Telemetry", "Device Management Wireless Application Protocol Push"),
                ["whesvc"] = ("Diagnostics", "Windows Health and Optimized Experiences"),
                ["PcaSvc"] = ("Compatibility", "Program Compatibility Assistant Service"),
                ["WerSvc"] = ("Diagnostics", "Windows Error Reporting Service"),
                ["wisvc"] = ("Telemetry", "Windows Insider Service"),
            };

        /// <summary>Services that must never be reaction targets (future HardReact) or mislabeled critical.</summary>
        internal static readonly HashSet<string> DefaultNeverTouch = new(StringComparer.OrdinalIgnoreCase)
        {
            "EventLog", "BFE", "MpsSvc", "WinDefend", "wscsvc", "SecurityHealthService",
            "Dnscache", "CryptSvc", "RpcSs", "DcomLaunch", "LanmanServer", "LanmanWorkstation",
            "Schedule", "PlugPlay", "Power", "BrokerInfrastructure", "SystemEventsBroker",
            "UserManager", "LSM", "SamSs", "Winmgmt", "Sentinel", "SentinelService",
            "wuauserv", "BITS", "DoSvc", "mpssvc", "WdNisSvc", "WinDefend",
        };

        public PrivacyServiceOutboundMonitor(
            DetectionEngine detectionEngine,
            ServiceProcessMap serviceMap,
            SentinelConfig config,
            ILogger<PrivacyServiceOutboundMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _serviceMap = serviceMap;
            _config = config;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            var posture = _config.ServiceExfilPosture ?? new ServiceExfilPostureConfig();
            if (!posture.Enabled)
            {
                _logger.LogInformation("[PrivacyServiceOutboundMonitor] Disabled via ServiceExfilPosture.Enabled=false");
                return;
            }

            // MVP: always observe-only regardless of Mode enum value if reaction paths are not implemented.
            // Soft/Hard would require ProductPosture opt-in in a future version.
            _logger.LogInformation(
                "[PrivacyServiceOutboundMonitor] Started - observe-only privacy service outbound (Mode={Mode})",
                posture.Mode);

            // Stagger after SystemIntegrity group start
            try { await Task.Delay(TimeSpan.FromSeconds(5), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var intervalSec = Math.Max(5, posture.ScanIntervalSeconds);
                    await Task.Delay(TimeSpan.FromSeconds(intervalSec), ct);
                    await ScanOnceAsync(posture, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PrivacyServiceOutboundMonitor] Scan error");
                }
            }
        }

        private async Task ScanOnceAsync(ServiceExfilPostureConfig posture, CancellationToken ct)
        {
            _serviceMap.Refresh(TimeSpan.FromSeconds(Math.Max(5, posture.ScanIntervalSeconds - 5)), ct);

            var inventory = BuildInventory(posture);
            var allowlist = new HashSet<string>(
                posture.Allowlist ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);

            // Map service -> pid for inventory members that are running
            var servicePids = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var svc in inventory.Keys)
            {
                if (allowlist.Contains(svc)) continue;
                if (_serviceMap.TryGetPidForService(svc, out var pid) && pid > 4)
                    servicePids[svc] = pid;
            }

            // Emit "running" awareness (hourly) for inventory members currently running
            foreach (var kv in servicePids)
            {
                await EmitRunningIfNeededAsync(kv.Key, kv.Value, inventory[kv.Key], ct);
            }

            if (servicePids.Count == 0) return;

            var pidsOfInterest = new HashSet<int>(servicePids.Values);
            var connections = GetEstablishedOutboundPublic(pidsOfInterest);

            foreach (var conn in connections)
            {
                // Attribute connection to all inventory services on that PID
                foreach (var svc in servicePids.Where(s => s.Value == conn.Pid).Select(s => s.Key))
                {
                    if (allowlist.Contains(svc)) continue;
                    await EmitOutboundIfNeededAsync(svc, conn, inventory[svc], ct);
                }
            }
        }

        private static Dictionary<string, (string Class, string Label)> BuildInventory(ServiceExfilPostureConfig posture)
        {
            // net48: no Dictionary(IReadOnlyDictionary) overload that accepts our tuple map.
            var map = new Dictionary<string, (string Class, string Label)>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in DefaultInventory)
                map[kv.Key] = kv.Value;
            foreach (var extra in posture.Inventory ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(extra)) continue;
                var name = extra.Trim();
                if (!map.ContainsKey(name))
                    map[name] = ("Custom", name);
            }
            return map;
        }

        private async Task EmitRunningIfNeededAsync(
            string serviceName, int pid, (string Class, string Label) meta, CancellationToken ct)
        {
            var now = DateTimeOffset.UtcNow;
            if (_runningAlerted.TryGetValue(serviceName, out var last) && now - last < RunningDedup)
                return;
            _runningAlerted[serviceName] = now;

            var display = _serviceMap.GetDisplayName(serviceName);
            if (string.IsNullOrEmpty(display) || display == serviceName)
                display = meta.Label;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Privacy: Optional Service Running",
                Evidence = $"Optional service '{serviceName}' ({display}) is running (PID {pid}). Class={meta.Class}.",
                Reasoning =
                    "This service is optional OS/vendor telemetry or diagnostics. " +
                    "Sentinel observes only - no stop, no kill, no firewall. " +
                    "Host mutation is reserved for chain-confirmed malice " +
                    "(credential dump, C2, ransomware, reverse shell, token theft).",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = serviceName,
                ProcessId = pid,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    ["ServiceName"] = serviceName,
                    ["DisplayName"] = display,
                    ["PrivacyClass"] = meta.Class,
                    ["ObserveOnly"] = "true",
                    ["WeakObserveSeed"] = "true",
                    ["ServiceExfilPosture"] = "Observe",
                }
            });
        }

        private async Task EmitOutboundIfNeededAsync(
            string serviceName,
            OutboundConn conn,
            (string Class, string Label) meta,
            CancellationToken ct)
        {
            var key = $"{serviceName}|{conn.RemoteIp}|{conn.RemotePort}";
            var now = DateTimeOffset.UtcNow;
            if (_outboundAlerted.TryGetValue(key, out var last) && now - last < OutboundDedup)
                return;
            _outboundAlerted[key] = now;

            // Prune stale dedup entries opportunistically
            if (_outboundAlerted.Count > 500)
            {
                foreach (var k in _outboundAlerted.Keys.ToArray())
                {
                    if (_outboundAlerted.TryGetValue(k, out var t) && now - t > OutboundDedup)
                        _outboundAlerted.TryRemove(k, out _);
                }
            }

            var display = _serviceMap.GetDisplayName(serviceName);
            if (string.IsNullOrEmpty(display) || display == serviceName)
                display = meta.Label;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Privacy: Optional Service Outbound",
                Evidence =
                    $"Optional service '{serviceName}' ({display}) PID {conn.Pid} -> {conn.RemoteIp}:{conn.RemotePort} (public).",
                Reasoning =
                    "Outbound connection from a known optional telemetry/diagnostics service. " +
                    "This is awareness only (observe/work-first). Not classified as malware. " +
                    "Does not authorize kill, service stop, or network isolate. " +
                    "Malicious exfil still requires separate chain-confirmed signals.",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = serviceName,
                ProcessId = conn.Pid,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    ["ServiceName"] = serviceName,
                    ["DisplayName"] = display,
                    ["PrivacyClass"] = meta.Class,
                    ["RemoteIP"] = conn.RemoteIp,
                    ["RemotePort"] = conn.RemotePort.ToString(),
                    ["ObserveOnly"] = "true",
                    ["WeakObserveSeed"] = "true",
                    ["ServiceExfilPosture"] = "Observe",
                }
            });
        }

        #region TCP table

        private static List<OutboundConn> GetEstablishedOutboundPublic(HashSet<int> pids)
        {
            var results = new List<OutboundConn>();
            if (pids == null || pids.Count == 0) return results;

            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 122) return results; // ERROR_INSUFFICIENT_BUFFER

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, 2,
                    TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < numEntries; i++)
                {
                    IntPtr rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                    if (row.state != 5) continue; // Established
                    int pid = (int)row.owningPid;
                    if (!pids.Contains(pid)) continue;

                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                    if (IsNonPublicRemote(remoteIp)) continue;

                    var remotePort = (int)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));
                    results.Add(new OutboundConn
                    {
                        Pid = pid,
                        RemoteIp = remoteIp,
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

        internal static bool IsNonPublicRemote(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return true;
            if (ip.StartsWith("127.") || ip.StartsWith("0.") || ip == "0.0.0.0") return true;
            if (ip.StartsWith("10.")) return true;
            if (ip.StartsWith("192.168.")) return true;
            if (ip.StartsWith("169.254.")) return true;
            // 172.16.0.0 - 172.31.255.255
            if (ip.StartsWith("172."))
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2 && int.TryParse(parts[1], out var second) && second >= 16 && second <= 31)
                    return true;
            }
            return false;
        }

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

        private sealed class OutboundConn
        {
            public int Pid;
            public string RemoteIp = "";
            public int RemotePort;
        }

        #endregion
    }
}
