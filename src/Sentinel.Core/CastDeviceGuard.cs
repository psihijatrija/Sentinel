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
    /// MITM defense component: watches browser/LAN connections to Cast ports (8008/8009)
    /// and blocks fake Chromecast / rogue Cast relays that weaponize open Chrome tabs as C2.
    ///
    /// Modes:
    ///   - Default (MitmDefense off, empty TrustedCastDevices): observe-only.
    ///   - TrustedCastDevices non-empty: enforce allowlist (block unlisted LAN Cast IPs).
    ///   - MitmDefense.Enabled + AutoBlockRogueCast: block known-rogue MAC/IP and
    ///     phantom Google-spoof Cast devices; leave legitimate baselined Cast alone.
    ///
    /// Incident (2026-06): 192.168.1.100 with OUI B0-B3-69 (SDMC, not Google) on :8009
    /// held a persistent Chrome Cast channel - C2 relay through "open tab" path.
    /// Paired with TlsCertificateMonitor (planted roots) and NullSessionGuard FCM block
    /// ("Send Tab to Self" via push after token theft).
    /// </summary>
    public sealed class CastDeviceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly PhantomDeviceMonitor? _phantomDeviceMonitor;
        private readonly ILogger<CastDeviceGuard> _logger;

        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedConnections = new();
        private readonly ConcurrentDictionary<string, string> _blockedIps = new();
        private bool _legacyCastBlocksCleaned;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly int[] CastPorts = { 8008, 8009 };
        private const string CastBlockRulePrefix = "Sentinel-CastGuard-Block-";

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        /// <summary>Real Google Cast hardware OUIs (not B0-B3-69 - that is SDMC / spoof).</summary>
        private static readonly HashSet<string> RealGoogleCastOuis = new(StringComparer.OrdinalIgnoreCase)
        {
            "F4-F5-D8", "54-60-09", "A4-77-33", "30-FD-38", "48-D6-D5",
            "6C-AD-F8", "E4-F0-42", "20-DF-B9", "94-EB-2C"
        };

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll")]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

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
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        public CastDeviceGuard(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<CastDeviceGuard> logger,
            PhantomDeviceMonitor? phantomDeviceMonitor = null)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
            _phantomDeviceMonitor = phantomDeviceMonitor;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            var mitm = _config.MitmDefense ?? new MitmDefenseConfig();
            var trusted = _config.TrustedCastDevices ?? Array.Empty<string>();
            bool enforceAllowlist = trusted.Length > 0;
            bool mitmRogueBlock = ProductPosture.AllowsMitmDefenseMutations(_config) && mitm.AutoBlockRogueCast;

            _logger.LogInformation(
                "[CastDeviceGuard] Started - allowlist={Allow} mitmRogueBlock={Mitm}. Trusted={Count} RoguePrefixes={Prefixes}",
                enforceAllowlist ? "ENFORCE" : "off",
                mitmRogueBlock ? "ON" : "OFF",
                trusted.Length,
                mitmRogueBlock
                    ? string.Join(",", mitm.RogueCastMacPrefixes ?? Array.Empty<string>())
                    : "n/a");

            if (enforceAllowlist || mitmRogueBlock)
                DeleteCastToDeviceInboundRules();

            // Only wipe legacy blocks when fully observe (no allowlist, no MITM suite)
            if (!enforceAllowlist && !mitmRogueBlock && !_legacyCastBlocksCleaned)
            {
                RemoveLegacyCastGuardBlocks();
                _legacyCastBlocksCleaned = true;
            }

            // Re-apply known rogue IPs from config immediately
            if (mitmRogueBlock)
            {
                foreach (var ip in mitm.KnownRogueCastIps ?? Array.Empty<string>())
                {
                    if (IPAddress.TryParse(ip, out _))
                        await EnsureFirewallBlock(ip);
                }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanAndRespond(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CastDeviceGuard] Error"); }
            }
        }

        private void RemoveLegacyCastGuardBlocks()
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var toRemove = new List<string>();
                foreach (dynamic rule in policy.Rules)
                {
                    try
                    {
                        string? name = rule.Name as string;
                        if (name != null && name.StartsWith(CastBlockRulePrefix))
                            toRemove.Add(name);
                    }
                    catch { }
                }

                foreach (var name in toRemove)
                {
                    try { policy.Rules.Remove(name); } catch { }
                }

                if (toRemove.Count > 0)
                {
                    _logger.LogWarning(
                        "[CastDeviceGuard] Removed {Count} leftover CastGuard firewall rules (observe-only mode)",
                        toRemove.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Legacy Cast block cleanup failed");
            }
        }

        private void DeleteCastToDeviceInboundRules()
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var toDelete = new List<string>();
                foreach (dynamic rule in policy.Rules)
                {
                    string name = (string)rule.Name;
                    int direction = (int)rule.Direction; // 1 = Inbound

                    if (direction == 1 &&
                        (name.Contains("Cast to Device") ||
                         name.Contains("Media Center Extenders") ||
                         name.Contains("RTSP-Streaming-In") ||
                         name.Contains("HTTP-Streaming-In") ||
                         name.Contains("RTCP-Streaming-In")))
                    {
                        toDelete.Add(name);
                    }
                }

                foreach (var name in toDelete)
                {
                    try { policy.Rules.Remove(name); } catch { }
                }

                if (toDelete.Count > 0)
                {
                    _logger.LogWarning(
                        "[CastDeviceGuard] DELETED {Count} inbound Cast/Media streaming firewall rules (attack surface removal)",
                        toDelete.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Failed to delete Cast inbound rules");
            }
        }

        private async Task ScanAndRespond(CancellationToken ct)
        {
            var trusted = _config.TrustedCastDevices ?? Array.Empty<string>();
            bool enforceAllowlist = trusted.Length > 0;
            var mitm = _config.MitmDefense ?? new MitmDefenseConfig();
            bool mitmRogueBlock = ProductPosture.AllowsMitmDefenseMutations(_config) && mitm.AutoBlockRogueCast;

            var arpByIp = GetArpIpToMac();
            var connections = GetEstablishedTcpConnections();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;
                if (!CastPorts.Contains(conn.RemotePort)) continue;
                if (!IsPrivateIp(conn.RemoteAddress)) continue;

                if (enforceAllowlist &&
                    trusted.Contains(conn.RemoteAddress, StringComparer.OrdinalIgnoreCase))
                    continue;

                arpByIp.TryGetValue(conn.RemoteAddress, out var mac);
                mac ??= "";

                bool isRogue = mitmRogueBlock && IsRogueCastTarget(conn.RemoteAddress, mac, mitm);
                bool unlistedUnderAllowlist = enforceAllowlist &&
                    !trusted.Contains(conn.RemoteAddress, StringComparer.OrdinalIgnoreCase);

                // Pure observe: no allowlist, no MITM suite
                if (!isRogue && !unlistedUnderAllowlist)
                {
                    await EmitObserveOnly(conn);
                    continue;
                }

                string procName;
                try
                {
                    using var proc = Process.GetProcessById(conn.OwnerPid);
                    procName = proc.ProcessName;
                }
                catch { continue; }

                await EnsureFirewallBlock(conn.RemoteAddress);

                // Close the weaponized open-tab Cast channel: kill non-browser trees;
                // browsers stay up (user work) - firewall already cuts :8008/:8009 to the rogue.
                bool isBrowser = BrowserProcesses.Contains(procName);
                if (!isBrowser && ProductPosture.AllowsMitmDefenseMutations(_config))
                {
                    try { HardeningModule.SafeKillProcessTree(conn.OwnerPid); }
                    catch { }
                }

                var alertKey = $"{conn.RemoteAddress}:{conn.RemotePort}";
                if (_alertedConnections.TryGetValue(alertKey, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                _alertedConnections[alertKey] = DateTimeOffset.UtcNow;

                string reason = isRogue
                    ? $"Rogue Cast / fake Chromecast (MAC={mac}). MitmDefense AutoBlockRogueCast."
                    : "IP not in TrustedCastDevices allowlist.";

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = isRogue
                        ? "Cast Device Guard: Fake Chromecast / Rogue Cast Blocked"
                        : "Cast Device Guard: Unauthorized Cast Connection Blocked",
                    Evidence = $"Process '{procName}' (PID {conn.OwnerPid}) -> " +
                               $"{conn.RemoteAddress}:{conn.RemotePort} MAC={mac}. {reason} Firewall block applied.",
                    Reasoning = "Chrome/Edge maintain Cast sessions on 8008/8009. A rogue LAN device " +
                                "spoofing Chromecast becomes a C2 relay through open browser tabs - same " +
                                "class as FCM 'Send Tab to Self' after MitM token theft. Firewall block " +
                                "severs the channel; non-browser processes to the rogue are killed.",
                    Confidence = 0.93,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    ProcessName = procName,
                    ProcessId = conn.OwnerPid,
                    SignalType = SignalType.NetworkC2,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RemoteIP"] = conn.RemoteAddress,
                        ["RemotePort"] = conn.RemotePort.ToString(),
                        ["MAC"] = mac,
                        ["IsBrowser"] = isBrowser.ToString(),
                        ["IsRogue"] = isRogue.ToString(),
                        ["Mode"] = isRogue ? "mitm-rogue-block" : "enforce-allowlist",
                        ["MitmDefense"] = "true",
                        ["TargetIP"] = conn.RemoteAddress,
                        ["FirewallBlocked"] = "True"
                    }
                });
            }
        }

        private async Task EmitObserveOnly(TcpConnectionInfo conn)
        {
            var observeKey = $"obs:{conn.RemoteAddress}:{conn.RemotePort}";
            if (_alertedConnections.TryGetValue(observeKey, out var lastObs) &&
                DateTimeOffset.UtcNow - lastObs < AlertCooldown)
                return;
            _alertedConnections[observeKey] = DateTimeOffset.UtcNow;

            string obsProc;
            try
            {
                using var proc = Process.GetProcessById(conn.OwnerPid);
                obsProc = proc.ProcessName;
            }
            catch { return; }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Cast Device Guard: Cast Connection Observed",
                Evidence = $"Process '{obsProc}' (PID {conn.OwnerPid}) -> " +
                           $"{conn.RemoteAddress}:{conn.RemotePort}. Observe-only.",
                Reasoning = "Cast-port traffic observed. MitmDefense off and TrustedCastDevices empty - " +
                            "log only so Chromecast keeps working. Enable Sentinel:MitmDefense:Enabled " +
                            "after a fake Cast / MitM incident, or set TrustedCastDevices allowlist.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = obsProc,
                ProcessId = conn.OwnerPid,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    ["RemoteIP"] = conn.RemoteAddress,
                    ["RemotePort"] = conn.RemotePort.ToString(),
                    ["Mode"] = "observe-only",
                    ["WeakObserveSeed"] = "true",
                    ["FirewallBlocked"] = "False"
                }
            });
        }

        /// <summary>
        /// Rogue if: known bad IP, known spoof OUI (e.g. B0-B3-69), or phantom device
        /// presenting a Google Cast OUI (spoofed real Google MAC after baseline).
        /// </summary>
        private bool IsRogueCastTarget(string ip, string mac, MitmDefenseConfig mitm)
        {
            foreach (var known in mitm.KnownRogueCastIps ?? Array.Empty<string>())
            {
                if (string.Equals(known, ip, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (_blockedIps.ContainsKey(ip))
                return true;

            if (_phantomDeviceMonitor != null && _phantomDeviceMonitor.IsBlockedDevice(ip))
                return true;

            var oui = MacToOui(mac);
            if (string.IsNullOrEmpty(oui))
                return false;

            foreach (var prefix in mitm.RogueCastMacPrefixes ?? Array.Empty<string>())
            {
                var norm = NormalizeOui(prefix);
                if (string.Equals(norm, oui, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Phantom + real-Google OUI on Cast = spoof of Google hardware after boot
            if (RealGoogleCastOuis.Contains(oui) &&
                _phantomDeviceMonitor != null &&
                _phantomDeviceMonitor.IsPhantomDevice(ip))
                return true;

            return false;
        }

        private static string MacToOui(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return "";
            var norm = mac.Replace(':', '-').ToUpperInvariant();
            var parts = norm.Split('-');
            if (parts.Length < 3) return "";
            return $"{parts[0]}-{parts[1]}-{parts[2]}";
        }

        private static string NormalizeOui(string prefix)
        {
            var p = (prefix ?? "").Replace(':', '-').ToUpperInvariant().Trim();
            var parts = p.Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
                return $"{parts[0]}-{parts[1]}-{parts[2]}";
            return p;
        }

        private async Task EnsureFirewallBlock(string ip)
        {
            if (!IPAddress.TryParse(ip, out var parsed) ||
                IPAddress.IsLoopback(parsed) ||
                parsed.Equals(IPAddress.Any) ||
                parsed.Equals(IPAddress.IPv6Any) ||
                parsed.Equals(IPAddress.Broadcast))
            {
                _logger.LogDebug("[CastDeviceGuard] Refusing firewall block for invalid IP: {IP}", ip);
                return;
            }

            ip = parsed.ToString();
            if (_blockedIps.ContainsKey(ip)) return;
            try
            {
                var safeLabel = ip.Replace('.', '_').Replace(':', '_');
                var ruleName = $"{CastBlockRulePrefix}{safeLabel}";
                var psi = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}-OUT\" dir=out action=block remoteip={ip} enable=yes")
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
                };
                using (var proc = Process.Start(psi))
                { if (proc != null) await proc.WaitForExitAsync(); }

                psi.Arguments = $"advfirewall firewall add rule name=\"{ruleName}-IN\" dir=in action=block remoteip={ip} enable=yes";
                using (var proc = Process.Start(psi))
                { if (proc != null) await proc.WaitForExitAsync(); }

                _blockedIps[ip] = ruleName;
                _logger.LogWarning("[CastDeviceGuard] Firewall block (MITM/rogue Cast): {IP}", ip);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Firewall rule failed for {IP}", ip);
            }
        }

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

        private static Dictionary<string, string> GetArpIpToMac()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size <= 0) return map;
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buffer, ref size, false) != 0) return map;
                    int entries = Marshal.ReadInt32(buffer);
                    int entrySize = Marshal.SizeOf<MIB_IPNETROW>();
                    var entryPtr = buffer + 4;
                    for (int i = 0; i < entries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_IPNETROW>(entryPtr + (i * entrySize));
                        if (row.dwType == 2) continue; // invalid
                        var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                        var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                        if (mac != "00-00-00-00-00-00")
                            map[ip] = mac;
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return map;
        }

        private List<TcpConnectionInfo> GetEstablishedTcpConnections()
        {
            var results = new List<TcpConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
            if (size == 0) return results;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0) != 0) return results;
                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                        IntPtr.Add(buffer, 4 + i * structSize));
                    if (row.state != 5 || row.owningPid <= 4) continue;
                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                    var remotePort = (int)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));
                    results.Add(new TcpConnectionInfo
                    { OwnerPid = (int)row.owningPid, RemoteAddress = remoteIp, RemotePort = remotePort });
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return results;
        }

        private class TcpConnectionInfo
        {
            public int OwnerPid { get; set; }
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
        }
    }
}
