// Network Integrity Monitor Group - ARP spoof detection, DNS validation, public IP monitoring, WiFi security, and phantom device detection

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // ARP Spoof Monitor - detects duplicate MAC for gateway IP
    // 
    public sealed class ArpSpoofMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ArpSpoofMonitor> _logger;
        private string? _baselineGatewayMac;
        private string? _gatewayIp;
        private readonly ConcurrentDictionary<string, string> _arpBaseline = new(); // IP -> MAC

        public ArpSpoofMonitor(DetectionEngine de, ILogger<ArpSpoofMonitor> l) { _detectionEngine = de; _logger = l; }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int macLen);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int CreateIpNetEntry(ref MIB_IPNETROW pArpEntry);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpNetEntry(ref MIB_IPNETROW pArpEntry);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        private void SetStaticGatewayArp(string ip, string mac)
        {
            try
            {
                var ipAddr = IPAddress.Parse(ip);
                var ipBytes = ipAddr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);

                if (GetBestInterface(ipInt, out int ifIndex) != 0)
                {
                    _logger.LogWarning("[ArpSpoofMonitor] Failed to get best interface for Gateway IP {IP}", ip);
                    return;
                }

                var macBytes = mac.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray();
                if (macBytes.Length < 6) return;

                var row = new MIB_IPNETROW
                {
                    dwIndex = ifIndex,
                    dwPhysAddrLen = 6,
                    mac0 = macBytes[0],
                    mac1 = macBytes[1],
                    mac2 = macBytes[2],
                    mac3 = macBytes[3],
                    mac4 = macBytes[4],
                    mac5 = macBytes[5],
                    dwAddr = (int)ipInt,
                    dwType = 4 // 4 = Static
                };

                // Delete any existing entry to prevent duplicates
                DeleteIpNetEntry(ref row);
                int ret = CreateIpNetEntry(ref row);
                if (ret == 0)
                {
                    _logger.LogInformation("[ArpSpoofMonitor] Static ARP lock established for Gateway {IP} -> {MAC} on interface {Index}", ip, mac, ifIndex);
                }
                else
                {
                    _logger.LogWarning("[ArpSpoofMonitor] CreateIpNetEntry failed: {Error}", ret);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ArpSpoofMonitor] Failed to set static ARP");
            }
        }

        private void DeleteStaticGatewayArp(string ip)
        {
            try
            {
                var ipAddr = IPAddress.Parse(ip);
                var ipBytes = ipAddr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);

                if (GetBestInterface(ipInt, out int ifIndex) != 0) return;

                var row = new MIB_IPNETROW
                {
                    dwIndex = ifIndex,
                    dwAddr = (int)ipInt
                };
                DeleteIpNetEntry(ref row);
                _logger.LogInformation("[ArpSpoofMonitor] Static ARP lock removed for Gateway {IP}", ip);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ArpSpoofMonitor] Failed to delete static ARP");
            }
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            if (_gatewayIp != null)
            {
                DeleteStaticGatewayArp(_gatewayIp);
            }
            await base.StopAsync(ct);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ArpSpoofMonitor] Started");
            var initialGatewayIp = GetDefaultGateway();
            if (initialGatewayIp != null)
            {
                _gatewayIp = initialGatewayIp;
                var initialGatewayMac = ResolveMac(initialGatewayIp);
                if (initialGatewayMac != null)
                {
                    _baselineGatewayMac = initialGatewayMac;
                    SetStaticGatewayArp(initialGatewayIp, initialGatewayMac);
                }
            }

            // Baseline ARP table
            var initial = GetArpTable();
            foreach (var (ip, mac) in initial)
                _arpBaseline[ip] = mac;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    // === Check Gateway IP changes ===
                    var currentGatewayIp = GetDefaultGateway();
                    if (currentGatewayIp != _gatewayIp)
                    {
                        var oldGatewayIp = _gatewayIp;
                        if (oldGatewayIp != null)
                        {
                            DeleteStaticGatewayArp(oldGatewayIp);
                        }
                        _gatewayIp = currentGatewayIp;
                        if (currentGatewayIp != null)
                        {
                            var currentGatewayMac = ResolveMac(currentGatewayIp);
                            if (currentGatewayMac != null)
                            {
                                _baselineGatewayMac = currentGatewayMac;
                                SetStaticGatewayArp(currentGatewayIp, currentGatewayMac);
                            }
                        }
                    }

                    // === Check 1: Gateway MAC change ===
                    var gwIpForMacCheck = _gatewayIp;
                    if (gwIpForMacCheck != null)
                    {
                        var currentMac = ResolveMac(gwIpForMacCheck);
                        var baseMac = _baselineGatewayMac;
                        if (baseMac != null && currentMac != null && currentMac != baseMac)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ARP Spoof: Gateway MAC Changed",
                                Evidence = $"Gateway {gwIpForMacCheck} MAC changed from {baseMac} to {currentMac}",
                                Reasoning = "The default gateway MAC address changed at runtime, indicating a possible ARP spoofing or MitM attack on the local network.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.NetworkIsolate,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                SignalType = SignalType.NetworkC2,
                                Metadata = new Dictionary<string, string>
                                {
                                    { "TargetIP", gwIpForMacCheck },
                                    { "MitmDefense", "true" },
                                    // Evidence-independence: all signals derived from this one
                                    // gateway MAC change share a root observation, so they cannot
                                    // stack into multiple "independent" MitM vectors.
                                    { BehavioralCorrelationEngine.ObservationKeyMeta, $"gw-mac:{gwIpForMacCheck}" }
                                }
                            });
                            _baselineGatewayMac = currentMac;
                            SetStaticGatewayArp(gwIpForMacCheck, currentMac);
                        }
                    }

                    // === Check 2: Multiple IPs sharing same MAC (ARP table poisoning) ===
                    var currentArp = GetArpTable();
                    var macToIps = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (ip, mac) in currentArp)
                    {
                        if (!macToIps.ContainsKey(mac)) macToIps[mac] = new List<string>();
                        macToIps[mac].Add(ip);
                    }

                    foreach (var (mac, ips) in macToIps)
                    {
                        if (ips.Count < 3) continue; // Normal: 1 IP per MAC. 2 = maybe DHCP transition. 3+ = poisoning
                        if (mac == "FF-FF-FF-FF-FF-FF") continue;
                        if (mac.StartsWith("01-00-5E")) continue; // Multicast

                        // Is the gateway IP one of them? That's the worst case.
                        bool includesGateway = _gatewayIp != null && ips.Contains(_gatewayIp);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "ARP Spoof: Multiple IPs Sharing MAC",
                            Evidence = $"MAC {mac} is associated with {ips.Count} IPs: [{string.Join(", ", ips.Take(5))}]{(includesGateway ? " (INCLUDES GATEWAY)" : "")}",
                            Reasoning = "Multiple IP addresses resolve to the same MAC address in the ARP table. " +
                                        "This is a strong indicator of ARP table poisoning, where an attacker responds " +
                                        "to ARP requests for multiple IPs with their own MAC to intercept traffic. " +
                                        (includesGateway ? "The gateway IP is affected - all outbound traffic may be intercepted." : ""),
                            Confidence = includesGateway ? 0.92 : 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = includesGateway ? ResponseAction.NetworkIsolate : ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            SignalType = includesGateway ? SignalType.NetworkC2 : SignalType.Generic,
                            Metadata = new Dictionary<string, string>
                            {
                                ["MAC"] = mac,
                                ["AffectedIPs"] = string.Join(";", ips),
                                ["IncludesGateway"] = includesGateway.ToString(),
                                ["TargetIP"] = includesGateway ? (_gatewayIp ?? "") : "",
                                ["MitmDefense"] = includesGateway ? "true" : "false",
                                // Root observation = the shared MAC. If the gateway is one of the
                                // poisoned IPs, key on the gateway so this collapses with the
                                // gateway-MAC-change signal (same underlying ARP fact).
                                [BehavioralCorrelationEngine.ObservationKeyMeta] =
                                    includesGateway ? $"gw-mac:{_gatewayIp}" : $"arp-mac:{mac}"
                            }
                        });
                    }

                    // === Check 3: IP-to-MAC change for known hosts ===
                    foreach (var (ip, mac) in currentArp)
                    {
                        if (_arpBaseline.TryGetValue(ip, out var prevMac) && prevMac != mac)
                        {
                            // Skip gateway (handled above with higher confidence)
                            if (ip == _gatewayIp) continue;

                            // MAC changed for a known host - possible targeted spoof
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ARP Spoof: Host MAC Changed",
                                Evidence = $"Host {ip} MAC changed from {prevMac} to {mac}",
                                Reasoning = "A known network host's MAC address changed, which may indicate ARP spoofing targeting that specific host for traffic interception.",
                                Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    // Root observation = this specific host's ARP entry change.
                                    [BehavioralCorrelationEngine.ObservationKeyMeta] = $"arp-host:{ip}"
                                }
                            });
                        }
                        _arpBaseline[ip] = mac;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ArpSpoofMonitor] Error"); }
            }
        }

        private static List<(string Ip, string Mac)> GetArpTable()
        {
            var results = new List<(string, string)>();
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size == 0) return results;
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buffer, ref size, false) != 0) return results;
                    int entries = Marshal.ReadInt32(buffer);
                    int entrySize = Marshal.SizeOf<MIB_IPNETROW>();
                    for (int i = 0; i < entries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_IPNETROW>(IntPtr.Add(buffer, 4 + i * entrySize));
                        if (row.dwType == 2) continue; // Invalid entry
                        var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                        if (ip.StartsWith("224.") || ip == "255.255.255.255") continue;
                        var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                        if (mac == "00-00-00-00-00-00") continue;
                        results.Add((ip, mac));
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return results;
        }

        private static string? GetDefaultGateway()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    var gw = ni.GetIPProperties().GatewayAddresses
                        .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                    if (gw != null) return gw.Address.ToString();
                }
            }
            catch { }
            return null;
        }

        private static string? ResolveMac(string ip)
        {
            try
            {
                var addr = IPAddress.Parse(ip);
                var ipBytes = addr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);
                var mac = new byte[6];
                int macLen = mac.Length;
                if (SendARP(ipInt, 0, mac, ref macLen) == 0)
                    return BitConverter.ToString(mac, 0, macLen);
            }
            catch { }
            return null;
        }
    }


    // 
    // DNS Response Validation Monitor - detects DNS poisoning via TTL anomalies
    // 
    public sealed class DnsResponseValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DnsResponseValidationMonitor> _logger;
        private readonly ConcurrentDictionary<string, IPAddress[]> _baselineResolutions = new();

        public DnsResponseValidationMonitor(DetectionEngine de, ILogger<DnsResponseValidationMonitor> l) { _detectionEngine = de; _logger = l; }

        // Accumulates all known-good IPs per domain across CDN rotations
        private readonly ConcurrentDictionary<string, HashSet<string>> _knownSubnets = new();

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DnsResponseValidationMonitor] Started");
            var watchDomains = new[] { "login.microsoftonline.com", "accounts.google.com", "github.com" };

            // Pre-populate known Microsoft, Google, and GitHub subnets to prevent false positives from global CDNs
            var msSubnets = _knownSubnets.GetOrAdd("login.microsoftonline.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "20.190", "40.126", "20.20", "20.231", "20.150", "20.50", "52.150", "52.160", "2603:1036", "2603:1026", "2603:1046" })
                msSubnets.Add(net);

            var googleSubnets = _knownSubnets.GetOrAdd("accounts.google.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "172.217", "142.250", "142.251", "216.58", "74.125", "172.253", "108.177", "64.233", "2607:f8b0" })
                googleSubnets.Add(net);

            var githubSubnets = _knownSubnets.GetOrAdd("github.com", _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            foreach (var net in new[] { "140.82", "192.30", "185.199", "20.200", "20.201", "20.205", "4.225", "143.204", "2600:9000", "2a04:4e42" })
                githubSubnets.Add(net);

            // Resolve each domain multiple times over 2 minutes to build a robust baseline
            // CDN/anycast services rotate IPs frequently - single-shot baselines cause false positives
            for (int round = 0; round < 3; round++)
            {
                foreach (var d in watchDomains)
                {
                    try
                    {
                        var addrs = await DnsNet48.GetHostAddressesAsync(d, ct);
                        _baselineResolutions[d] = addrs;
                        var subnets = _knownSubnets.GetOrAdd(d, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                        foreach (var a in addrs)
                        {
                            subnets.Add(GetSubnet(a.ToString()));
                        }
                    }
                    catch { }
                }
                if (round < 2) await Task.Delay(40000, ct);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    foreach (var domain in watchDomains)
                    {
                        try
                        {
                            var current = await DnsNet48.GetHostAddressesAsync(domain, ct);
                            if (_baselineResolutions.TryGetValue(domain, out var baseline))
                            {
                                var currentSet = new HashSet<string>(current.Select(a => a.ToString()));
                                var baselineSet = new HashSet<string>(baseline.Select(a => a.ToString()));

                                // Phase 1: Check exact IP overlap (normal case)
                                if (currentSet.Overlaps(baselineSet))
                                {
                                    // IPs overlap - normal CDN rotation, update baseline
                                    _baselineResolutions[domain] = current;
                                    var subnets = _knownSubnets.GetOrAdd(domain, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                                    foreach (var a in current) subnets.Add(GetSubnet(a.ToString()));
                                    continue;
                                }

                                // Phase 2: No exact overlap - check if new IPs are in known subnets
                                var knownNets = _knownSubnets.GetOrAdd(domain, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                                var newSubnets = current.Select(a => GetSubnet(a.ToString())).ToHashSet();
                                bool allInKnownSubnets = newSubnets.All(s => knownNets.Contains(s));

                                if (allInKnownSubnets)
                                {
                                    // Same /16 or /32 subnets - CDN rotation, not poisoning
                                    _baselineResolutions[domain] = current;
                                    foreach (var a in current) knownNets.Add(GetSubnet(a.ToString()));
                                    continue;
                                }

                                // Phase 3: IPs moved to a completely different subnet - likely poisoning
                                var suspiciousIps = currentSet.Except(baselineSet).ToList();
                                var metadata = new Dictionary<string, string>
                                {
                                    { "Domain", domain },
                                    { "TargetIP", suspiciousIps.FirstOrDefault() ?? "" },
                                    { "AllNewIPs", string.Join(";", suspiciousIps) },
                                    // Root observation = this domain's resolution shift; an
                                    // independent vector from any ARP/route/adapter fact.
                                    { BehavioralCorrelationEngine.ObservationKeyMeta, $"dns-domain:{domain}" }
                                };

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "DNS Poisoning: Critical Domain Resolution Changed",
                                    Evidence = $"Domain '{domain}' resolved to {string.Join(",", currentSet)} (baseline: {string.Join(",", baselineSet)}, known subnets: {string.Join(",", knownNets)})",
                                    Reasoning = "A critical authentication domain resolved to IPs in completely different subnets from all previously observed addresses, indicating possible DNS poisoning.",
                                    Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                                    ProcessName = "SYSTEM", ProcessId = 0,
                                    Metadata = metadata
                                });
                            }
                            _baselineResolutions[domain] = current;
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DnsResponseValidationMonitor] Error"); }
            }
        }

        /// <summary>Extract subnet prefix (first two octets for IPv4 /16, or first two segments for IPv6 /32) for CDN rotation tolerance.</summary>
        private static string GetSubnet(string ip)
        {
            if (ip.IndexOf(':') >= 0)
            {
                var parts = ip.Split(':');
                return parts.Length >= 2 ? $"{parts[0]}:{parts[1]}" : ip;
            }
            else
            {
                var parts = ip.Split('.');
                return parts.Length >= 2 ? $"{parts[0]}.{parts[1]}" : ip;
            }
        }
    }


    // 
    // Public IP Monitor - detects VPN/proxy changes
    // 
    public sealed class PublicIpMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PublicIpMonitor> _logger;
        private string? _baselineIp;

        public PublicIpMonitor(DetectionEngine de, ILogger<PublicIpMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PublicIpMonitor] Started");
            _baselineIp = await GetPublicIp(ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(300000, ct);
                    var currentIp = await GetPublicIp(ct);
                    if (_baselineIp != null && currentIp != null && currentIp != _baselineIp)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: Public IP Address Changed",
                            Evidence = $"Public IP changed from {_baselineIp} to {currentIp}",
                            Reasoning = "The system's public IP address changed at runtime. This may indicate VPN activation/deactivation, network switch, or traffic rerouting via a compromised gateway.",
                            Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["OldIP"] = _baselineIp,
                                ["NewIP"] = currentIp
                            }
                        });
                        _baselineIp = currentIp;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PublicIpMonitor] Error"); }
            }
        }

        private static async Task<string?> GetPublicIp(CancellationToken ct)
        {
            try
            {
                using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                return (await http.GetStringAsync("https://api.ipify.org")).Trim();
            }
            catch { return null; }
        }
    }


    // 
    // WiFi Security Monitor - detects open/WEP networks
    // 
    public sealed class WifiSecurityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WifiSecurityMonitor> _logger;
        private readonly HashSet<string> _alertedProfiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<DateTimeOffset> _disconnectHistory = new();
        private string? _baselineBssid;
        private string? _baselineSsid;

        private const int DeauthThreshold = 4;         // 4+ disconnects in window = deauth flood
        private static readonly TimeSpan DeauthWindow = TimeSpan.FromMinutes(2);

        public WifiSecurityMonitor(DetectionEngine de, ILogger<WifiSecurityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WifiSecurityMonitor] Started");

            // Capture initial SSID/BSSID baseline
            var initial = GetCurrentWifiState();
            _baselineSsid = initial.ssid;
            _baselineBssid = initial.bssid;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct); // 15s scan interval

                    var current = GetCurrentWifiState();

                    // === Check 1: Deauth flood detection ===
                    // If we were connected and now disconnected, record it
                    if (_baselineSsid != null && current.ssid == null)
                    {
                        _disconnectHistory.Add(DateTimeOffset.UtcNow);

                        // Prune old disconnects
                        var cutoff = DateTimeOffset.UtcNow - DeauthWindow;
                        _disconnectHistory.RemoveAll(t => t < cutoff);

                        if (_disconnectHistory.Count >= DeauthThreshold)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Deauthentication Flood Detected",
                                Evidence = $"Wi-Fi disconnected {_disconnectHistory.Count} times in {DeauthWindow.TotalMinutes} minutes (SSID: '{_baselineSsid}')",
                                Reasoning = "Repeated Wi-Fi disconnections in rapid succession indicate a deauthentication flood attack. " +
                                            "Attackers send forged deauth frames to force clients off the network, often as a precursor " +
                                            "to evil twin AP deployment or WPA handshake capture.",
                                Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SSID"] = _baselineSsid ?? "",
                                    ["DisconnectCount"] = _disconnectHistory.Count.ToString(),
                                    // Deauth flood and evil-twin BSSID change are intentionally
                                    // DISTINCT observations (the two-step evil-twin sequence), so
                                    // they carry different keys and remain independent vectors.
                                    [BehavioralCorrelationEngine.ObservationKeyMeta] = $"wifi-deauth:{_baselineSsid}"
                                }
                            });
                            _disconnectHistory.Clear(); // Reset after alert
                            _ = ToggleWifiAdapterAsync(ct);
                        }
                    }

                    // === Check 2: BSSID change on same SSID (evil twin) ===
                    if (current.ssid != null && current.bssid != null &&
                        current.ssid == _baselineSsid && _baselineBssid != null &&
                        current.bssid != _baselineBssid)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WiFi Security: BSSID Changed (Possible Evil Twin)",
                            Evidence = $"BSSID changed from {_baselineBssid} to {current.bssid} while SSID remains '{current.ssid}'",
                            Reasoning = "The access point's hardware address (BSSID) changed while connected to the same SSID. " +
                                        "This can indicate an evil twin attack where the attacker creates a fake AP with the same name, " +
                                        "or a legitimate roaming event between APs. Correlate with deauth events.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                ["SSID"] = current.ssid,
                                ["OldBSSID"] = _baselineBssid,
                                ["NewBSSID"] = current.bssid,
                                // Distinct root observation from the deauth flood (the AP identity
                                // change itself), so the two-step evil-twin sequence still counts
                                // as two independent vectors.
                                [BehavioralCorrelationEngine.ObservationKeyMeta] = $"wifi-bssid:{current.bssid}"
                            }
                        });
                        _baselineBssid = current.bssid;
                    }

                    // === Check 3: Encryption downgrade ===
                    if (current.ssid != null && current.auth != null)
                    {
                        bool isInsecure = current.auth.Contains("Open") ||
                                          current.auth.Contains("WEP");
                        if (isInsecure && !_alertedProfiles.Contains(current.ssid))
                        {
                            _alertedProfiles.Add(current.ssid);
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Insecure/Open Network Connected",
                                Evidence = $"Connected to '{current.ssid}' with authentication: {current.auth}",
                                Reasoning = "System is connected to a Wi-Fi network with weak or no encryption. " +
                                            "Open and WEP networks allow trivial traffic interception. If this was previously " +
                                            "a WPA2 network, it may indicate an encryption downgrade attack.",
                                Confidence = 0.55, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }

                    // === Check 4: Public network profile (registry-based, original check) ===
                    CheckPublicNetworkProfiles();

                    // Update baseline
                    if (current.ssid != null)
                    {
                        _baselineSsid = current.ssid;
                        if (current.bssid != null) _baselineBssid = current.bssid;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WifiSecurityMonitor] Error"); }
            }
        }

        private void CheckPublicNetworkProfiles()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
                if (key == null) return;

                foreach (var profileName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var profile = key.OpenSubKey(profileName);
                        if (profile == null) continue;

                        var name = profile.GetValue("ProfileName")?.ToString();
                        var category = profile.GetValue("Category");

                        if (category is int cat && cat == 0 && !string.IsNullOrEmpty(name))
                        {
                            if (_alertedProfiles.Contains(name!)) continue;
                            _alertedProfiles.Add(name!);

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WiFi Security: Public/Unsecured Network Connected",
                                Evidence = $"Connected to public network profile: '{name}'",
                                Reasoning = "System is connected to a network categorized as Public, which may lack encryption and be vulnerable to traffic interception.",
                                Confidence = 0.45, Tier = DetectionTier.Tier2Indicator,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        /// <summary>
        /// Gets current Wi-Fi state from the WLAN interface registry.
        /// Uses the Windows WLAN AutoConfig service state stored in registry.
        /// </summary>
        private static (string? ssid, string? bssid, string? auth) GetCurrentWifiState()
        {
            try
            {
                // Read current wireless connection from the Wlansvc Interfaces registry
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\Wlansvc\Parameters\Interfaces");
                if (key == null) return (null, null, null);

                foreach (var ifGuid in key.GetSubKeyNames())
                {
                    using var ifKey = key.OpenSubKey(ifGuid);
                    if (ifKey == null) continue;

                    // CurrentConnection subkey has SSID and BSSID
                    using var connKey = ifKey.OpenSubKey("CurrentConnection");
                    if (connKey == null) continue;

                    var ssidBytes = connKey.GetValue("SSID") as byte[];
                    var bssidBytes = connKey.GetValue("BSSID") as byte[];
                    var authMode = connKey.GetValue("AuthMode")?.ToString();

                    string? ssid = ssidBytes != null
                        ? System.Text.Encoding.UTF8.GetString(ssidBytes).TrimEnd('\0')
                        : null;
                    string? bssid = bssidBytes != null && bssidBytes.Length >= 6
                        ? BitConverter.ToString(bssidBytes, 0, 6)
                        : null;

                    if (!string.IsNullOrEmpty(ssid))
                        return (ssid, bssid, authMode);
                }
            }
            catch { }

            // Fallback: check NetworkList for connected interface info
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 &&
                        ni.OperationalStatus == OperationalStatus.Up)
                    {
                        return (ni.Name, null, null); // At least we know we're connected to Wi-Fi
                    }
                }
            }
            catch { }

            return (null, null, null);
        }

        private async Task ToggleWifiAdapterAsync(CancellationToken ct)
        {
            try
            {
                var wifiInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);
                
                if (wifiInterface == null) return;
                
                int ifIndex = wifiInterface.GetIPProperties().GetIPv4Properties().Index;
                _logger.LogInformation("[WifiSecurityMonitor] Deauth flood recovery: Toggling Wi-Fi adapter '{Name}' (Index {Index})", wifiInterface.Name, ifIndex);

                // Use WMI to disable and enable the adapter
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery($"SELECT * FROM MSFT_NetAdapter WHERE InterfaceIndex = {ifIndex}");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    _logger.LogInformation("[WifiSecurityMonitor] Disabling adapter...");
                    obj.InvokeMethod("Disable", null);
                    await Task.Delay(2000, ct);
                    _logger.LogInformation("[WifiSecurityMonitor] Re-enabling adapter...");
                    obj.InvokeMethod("Enable", null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WifiSecurityMonitor] Failed to toggle Wi-Fi adapter");
            }
        }
    }


    // 
    // Remote Access Monitor - detects RAT indicators (RDP, VNC, etc.)
    // 
    public sealed class RemoteAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RemoteAccessMonitor> _logger;
        // Per-PID dedup: once we alert on a PID, don't alert again until the process exits
        private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();

        // 35+ known remote access tools - both legitimate and commonly abused.
        // TeamViewer / AnyDesk / mstsc / cloudflared stay LogOnly (the 90).
        // ngrok / chisel / frpc / tailcat-class tunnels are kill-grade (v2.5.3).
        private static readonly string[] RemoteAccessProcessNames =
        {
            // Commercial remote desktop/support
            "teamviewer", "teamviewer_service", "tv_w32", "tv_x64",
            "anydesk", "anydesk.exe",
            "rustdesk", "rustdesk-service",
            "radmin", "rserver3", "radminserver",
            "logmein", "logmeinrescue", "lmi_rescue",
            "bomgar", "bomgar-scc", "bomgar-rdp",
            "connectwise", "screenconnect",
            "splashtop", "splashtopstreamer", "srmanager",
            "supremo", "supremoservice",
            "ammyy", "ammyyadmin", "aa_v3",
            "ultraviewer", "ultraviewerservice",
            "parsec", "parsecd",
            "chrome remote desktop", "remoting_host",
            "dwservice", "dwagent",
            "meshagent", "meshcentral",
            "getscreen", "getscreen.me",
            // VNC implementations
            "vnc", "vncserver", "vncviewer", "winvnc", "tvnserver", "uvnc",
            "tightvnc", "tigervnc", "realvnc",
            // RDP-related (non-standard)
            "rdpwrap", "rdpcheck", "rdpclip",
            // Potentially unwanted - often deployed by attackers
            "ngrok", "frpc", "frps", "cloudflared", // Tunneling
            "chisel", "rathole", "bore", // Reverse tunnels
            "tailcat", "derper", "wireproxy", "onetun", "boringtun", // userspace WG / magicsock
            "innernet", "sliver",
            "mstsc", // Standard RDP client - context matters
        };

        public RemoteAccessMonitor(DetectionEngine de, ILogger<RemoteAccessMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RemoteAccessMonitor] Started - monitoring {Count} known remote access tools", RemoteAccessProcessNames.Length);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);

                    // Prune alerted PIDs for processes that have exited (every cycle)
                    foreach (var pid in _alertedPids.Keys.ToArray())
                    {
                        try { Process.GetProcessById(pid); }
                        catch (ArgumentException) { _alertedPids.TryRemove(pid, out _); }
                    }

                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            var name = proc.ProcessName.ToLowerInvariant();
                            if (RemoteAccessProcessNames.Any(r => name.Contains(r)))
                            {
                                // Skip if we already alerted on this PID
                                if (_alertedPids.ContainsKey(proc.Id)) continue;
                                _alertedPids[proc.Id] = DateTime.UtcNow;
                                // Tunneling tools (ngrok, frpc, chisel, tailcat) ARE the attack.
                                // cloudflared is a homelab civilian - log only, like TeamViewer.
                                bool isTunnel = name.Contains("ngrok") || name.Contains("frpc") ||
                                                name.Contains("chisel") || name.Contains("rathole") ||
                                                name.Contains("bore") ||
                                                name.Contains("tailcat") || name.Contains("wireproxy") ||
                                                name.Contains("onetun") || name.Contains("boringtun") ||
                                                name.Contains("innernet") || name.Contains("derper") ||
                                                name.Contains("sliver");

                                string? imagePath = null;
                                try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }

                                bool fromSuspiciousPath = imagePath != null &&
                                    (imagePath.Contains(@"\Temp\") ||
                                     imagePath.Contains(@"\Downloads\"));

                                var confidence = isTunnel ? (fromSuspiciousPath ? 0.90 : 0.86) : 0.55;
                                var tier = isTunnel
                                    ? DetectionTier.Tier1Behavioral
                                    : DetectionTier.Tier2Indicator;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = isTunnel
                                        ? "Remote Access: Tunneling Tool Detected"
                                        : "Remote Access: Known RAT Process Running",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) running{(imagePath != null ? $" from '{imagePath}'" : "")}",
                                    Reasoning = isTunnel
                                        ? "A reverse tunneling tool was detected (ngrok/chisel/frpc/tailcat-class). " +
                                          "Official Tailscale and cloudflared are not this rule. Kill-grade C2."
                                        : "A remote access tool process was detected. TeamViewer/AnyDesk/RDP are civilians - log only.",
                                    Confidence = confidence, Tier = tier,
                                    AuthorizedResponse = isTunnel
                                        ? ResponseAction.KillProcessTree
                                        : ResponseAction.LogOnly,
                                    SignalType = isTunnel ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                            }
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RemoteAccessMonitor] Error"); }
            }
        }
    }


    // 
    // Phantom Device Monitor - detects & blocks unauthorized network devices
    // 
    public sealed class PhantomDeviceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<PhantomDeviceMonitor> _logger;
        private readonly ConcurrentDictionary<string, NetworkDevice> _knownDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedIps = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Returns true if the given IP has been identified and blocked as a phantom/rogue device.
        /// Used by GhostProcessMonitor to escalate ghost processes connecting to blocked devices
        /// from NetworkIsolate to KillProcessTree.
        /// </summary>
        public bool IsBlockedDevice(string ip) => _blockedIps.ContainsKey(ip);

        /// <summary>
        /// Returns true if any phantom device was blocked within the specified time window.
        /// Used by VolumeMountMonitor to correlate new volume mounts with recent phantom device
        /// blocks - the attacker's fallback pattern creates a staging drive after their C2 relay
        /// gets cut off.
        /// </summary>
        public bool HasRecentBlock(TimeSpan window)
        {
            var threshold = DateTime.UtcNow - window;
            return _blockedIps.Values.Any(blockTime => blockTime > threshold);
        }

        /// <summary>
        /// Returns true if the given IP belongs to a device that was detected after startup
        /// (regardless of whether it was blocked). Used for correlation.
        /// </summary>
        public bool IsPhantomDevice(string ip) => _knownDevices.Values.Any(d => d.Ip == ip) && !_trustedIps.Contains(ip);

        private static readonly int[] SuspiciousPorts = { 8008, 8009, 8443, 5555, 5353, 9222, 2323, 4443 };

        private static readonly Dictionary<string, string> OuiLookup = new(StringComparer.OrdinalIgnoreCase)
        {
            // B0-B3-69 is Shenzhen SDMC (set-top / OTT) - NOT Google. In-incident it was
            // spoofed as "Google Chromecast" to pass naive OUI trust. Treat as cast-spoof OUI.
            { "B0-B3-69", "Shenzhen SDMC (cast-spoof OUI)" },
            { "F4-F5-D8", "Google" }, { "54-60-09", "Google" },
            { "A4-77-33", "Google" }, { "30-FD-38", "Google" }, { "48-D6-D5", "Google" },
            { "E8-DE-27", "TP-Link" }, { "50-C7-BF", "TP-Link" },
            { "DC-A6-32", "Raspberry Pi" }, { "B8-27-EB", "Raspberry Pi" }, { "E4-5F-01", "Raspberry Pi" },
            { "00-0C-29", "VMware" }, { "00-50-56", "VMware" },
            { "08-00-27", "VirtualBox" },
        };

        public PhantomDeviceMonitor(
            DetectionEngine de, SentinelConfig config, JsonlEventLogger logger,
            ILogger<PhantomDeviceMonitor> l)
        {
            _detectionEngine = de; _config = config; _eventLogger = logger; _logger = l;
        }

        [DllImport("iphlpapi.dll")]
        private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PhantomDeviceMonitor] Started");

            // Clean up any orphaned firewall rules from previous sessions
            // (service restart leaves Sentinel-Block-PhantomDevice-* rules behind)
            CleanupOrphanedFirewallRules();

            // Always trust the default gateway and local machine IPs - never alert on them
            foreach (var gw in GetDefaultGatewayIps())
                _trustedIps.Add(gw);
            foreach (var localIp in GetLocalIps())
                _trustedIps.Add(localIp);

            var initial = GetArpTable();
            foreach (var dev in initial)
                _knownDevices[dev.Mac] = dev;
            _logger.LogInformation("[PhantomDeviceMonitor] Baseline: {Count} devices, {Trusted} trusted IPs", _knownDevices.Count, _trustedIps.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(45000, ct);

                    var current = GetArpTable();
                    foreach (var dev in current)
                    {
                        if (dev.Mac == "FF-FF-FF-FF-FF-FF") continue;
                        if (dev.Mac.StartsWith("01-00-5E")) continue;
                        if (dev.Mac.StartsWith("33-33-")) continue;
                        if (_trustedIps.Contains(dev.Ip)) continue;

                        if (!_knownDevices.ContainsKey(dev.Mac))
                        {
                            _knownDevices[dev.Mac] = dev;

                            var manufacturer = LookupManufacturer(dev.Mac);
                            var suspiciousService = await ProbeSuspiciousPorts(dev.Ip, ct);

                            var confidence = 0.75;
                            var tier = DetectionTier.Tier1Behavioral;
                            var reasoning = $"A new network device appeared that was not present at Sentinel startup. Manufacturer: {manufacturer}.";

                            if (suspiciousService != null)
                            {
                                // High-risk ports that always warrant blocking
                                bool isHighRisk = suspiciousService.Contains("ADB") || 
                                                  suspiciousService.Contains("Telnet") || 
                                                  suspiciousService.Contains("DevTools") || 
                                                  suspiciousService.Contains("Pharos");

                                if (isHighRisk)
                                {
                                    confidence = 0.90;
                                }

                                // Cast ports (8008/8009) on a new device: check if any ghost/empty-name
                                // process is actively connecting to this device IP. If yes, this isn't a
                                // Chromecast - it's a C2 relay masquerading as one (PlugX technique).
                                // MitmDefense: also promote cast-spoof OUI (B0-B3-69 / known rogue) without ghost wait.
                                if (!isHighRisk && 
                                    (suspiciousService.Contains("Cast") ||
                                     suspiciousService.Contains("8008")))
                                {
                                    if (HasGhostConnectionTo(dev.Ip))
                                    {
                                        confidence = 0.95;
                                        reasoning += " CORRELATED: Invisible/empty-name process talking to this Cast endpoint " +
                                                     "(planted-cert -> ghost -> fake Chromecast MitM chain).";
                                    }
                                    else if (IsMitmRogueCastDevice(dev.Ip, dev.Mac, manufacturer))
                                    {
                                        confidence = 0.93;
                                        reasoning += " MitmDefense: MAC/OUI matches known cast-spoof / rogue Chromecast IOC " +
                                                     "(e.g. B0-B3-69 SDMC used as fake Google Cast).";
                                    }
                                }

                                reasoning += $" Device has an open {suspiciousService} port, which is commonly used for screen casting, debugging, or remote access.";
                            }
                            else if (IsMitmRogueCastDevice(dev.Ip, dev.Mac, manufacturer))
                            {
                                confidence = 0.90;
                                reasoning += " MitmDefense: device MAC/IP is a known rogue Cast IOC.";
                            }

                            var metadata = new Dictionary<string, string>
                            {
                                ["DeviceIP"] = dev.Ip,
                                ["DeviceMAC"] = dev.Mac,
                                ["Manufacturer"] = manufacturer
                            };
                            if (confidence >= 0.90 && ProductPosture.AllowsMitmDefenseMutations(_config))
                                metadata["MitmDefense"] = "true";

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = confidence >= 0.92
                                    ? "Phantom Device: Fake Chromecast / Rogue Cast Relay"
                                    : "Phantom Device: New Unauthorized Network Device",
                                Evidence = $"New device: IP={dev.Ip}, MAC={dev.Mac}, Manufacturer={manufacturer}{(suspiciousService != null ? $", Open={suspiciousService}" : "")}",
                                Reasoning = reasoning,
                                Confidence = confidence, Tier = tier,
                                AuthorizedResponse = confidence >= 0.90
                                    ? ResponseAction.NetworkIsolate
                                    : ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                SignalType = confidence >= 0.90 ? SignalType.NetworkC2 : SignalType.Generic,
                                Metadata = metadata
                            });

                            // Block under MitmDefense or general inline mutation when high confidence
                            if ((ProductPosture.AllowsMitmDefenseMutations(_config) && confidence >= 0.90) ||
                                (ResponsePolicy.MayPerformInlineHostMutation(_config) && confidence >= 0.85))
                                await BlockDevice(dev.Ip, dev.Mac, manufacturer, suspiciousService);
                        }
                        else
                        {
                            var known = _knownDevices[dev.Mac];
                            if (known.Ip != dev.Ip)
                                _knownDevices[dev.Mac] = dev;
                        }
                    }

                    await CleanupDepartedBlocks(current);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PhantomDeviceMonitor] Error"); }
            }
        }

        /// <summary>
        /// On startup, removes any firewall rules from a previous session that were left behind
        /// (e.g., after a service restart). Without this, blocked devices stay blocked forever
        /// because the in-memory _blockedIps dictionary is empty on restart.
        /// </summary>
        private void CleanupOrphanedFirewallRules()
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
                    string name = (string)rule.Name;
                    if (name.StartsWith("Sentinel-Block-PhantomDevice-"))
                        toRemove.Add(name);
                }
                foreach (var name in toRemove)
                {
                    try { policy.Rules.Remove(name); } catch { }
                }
                if (toRemove.Count > 0)
                    _logger.LogInformation("[PhantomDeviceMonitor] Cleaned up {Count} orphaned firewall rules from previous session", toRemove.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[PhantomDeviceMonitor] Failed to clean up orphaned firewall rules");
            }
        }

        private async Task BlockDevice(string ip, string mac, string manufacturer, string? suspiciousService)
        {
            try
            {
                if (_blockedIps.ContainsKey(ip)) return;
                var ruleName = $"Sentinel-Block-PhantomDevice-{ip.Replace('.', '_')}";

                // Use Windows Firewall COM API instead of shelling to netsh
                AddFirewallRule($"{ruleName}-OUT", ip, 2); // Outbound block
                AddFirewallRule($"{ruleName}-IN", ip, 1);  // Inbound block
                // Block mDNS/SSDP discovery to prevent auto-reconnection
                AddFirewallRule($"{ruleName}-MDNS", "224.0.0.251", 2, protocol: 17, remotePort: 5353);
                AddFirewallRule($"{ruleName}-SSDP", "239.255.255.250", 2, protocol: 17, remotePort: 1900);

                _blockedIps[ip] = DateTime.UtcNow;

                await _eventLogger.LogEventAsync("response", new ResponseEvent
                {
                    ProcessId = 0,
                    ProcessName = "PhantomDeviceMonitor",
                    ActionTaken = "FIREWALL_BLOCK+DISCOVERY_BLOCK",
                    Reason = $"Blocked phantom device IP={ip} MAC={mac} Manufacturer={manufacturer} SuspiciousPort={suspiciousService ?? "none"}"
                });

                _logger.LogWarning("[PhantomDeviceMonitor] BLOCKED device IP={Ip} MAC={Mac} Manufacturer={Mfg}", ip, mac, manufacturer);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PhantomDeviceMonitor] Failed to block device {Ip}", ip);
            }
        }

        private static void AddFirewallRule(string name, string remoteIp, int direction, int protocol = 256, int remotePort = 0)
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                dynamic? rule = Activator.CreateInstance(ruleType);
                if (rule == null) return;

                rule.Name = name;
                rule.Direction = direction;
                rule.Action = 0; // Block
                rule.RemoteAddresses = remoteIp;
                rule.Enabled = true;
                rule.Profiles = 0x7FFFFFFF; // All profiles

                if (protocol != 256) // 256 = Any
                {
                    rule.Protocol = protocol; // 17 = UDP, 6 = TCP
                    if (remotePort > 0) rule.RemotePorts = remotePort.ToString();
                }

                policy.Rules.Add(rule);
            }
            catch { }
        }

        private static void RemoveFirewallRule(string name)
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;
                policy.Rules.Remove(name);
            }
            catch { }
        }

        private Task CleanupDepartedBlocks(List<NetworkDevice> currentDevices)
        {
            var currentIps = new HashSet<string>(currentDevices.Select(d => d.Ip));
            var toRemove = new List<string>();
            foreach (var kvp in _blockedIps)
            {
                if (!currentIps.Contains(kvp.Key) && DateTime.UtcNow - kvp.Value > TimeSpan.FromMinutes(10))
                {
                    try
                    {
                        var ruleName = $"Sentinel-Block-PhantomDevice-{kvp.Key.Replace('.', '_')}";
                        RemoveFirewallRule($"{ruleName}-OUT");
                        RemoveFirewallRule($"{ruleName}-IN");
                        RemoveFirewallRule($"{ruleName}-MDNS");
                        RemoveFirewallRule($"{ruleName}-SSDP");
                        toRemove.Add(kvp.Key);
                        _logger.LogInformation("[PhantomDeviceMonitor] Removed block for departed device {Ip}", kvp.Key);
                    }
                    catch { }
                }
            }
            foreach (var ip in toRemove) _blockedIps.TryRemove(ip, out _);
            return Task.CompletedTask;
        }

        private static async Task<string?> ProbeSuspiciousPorts(string ip, CancellationToken ct)
        {
            foreach (var port in SuspiciousPorts)
            {
                try
                {
                    using var client = new System.Net.Sockets.TcpClient();
                    using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                    await client.ConnectAsync(IPAddress.Parse(ip), port);
                    var serviceName = port switch
                    {
                        8008 => "HTTP-Alt (Cast discovery)",
                        8009 => "Google Cast",
                        8443 => "HTTPS-Alt",
                        5555 => "ADB (Android Debug Bridge)",
                        5353 => "mDNS",
                        9222 => "Chrome DevTools Protocol",
                        2323 => "Telnet-Alt",
                        4443 => "Pharos",
                        _ => $"Port {port}"
                    };
                    return $"{serviceName} (port {port})";
                }
                catch { }
            }
            return null;
        }

        private static string LookupManufacturer(string mac)
        {
            if (mac.Length >= 8)
            {
                var prefix = mac[..8];
                if (OuiLookup.TryGetValue(prefix, out var mfg))
                    return mfg;
            }
            return "Unknown";
        }

        /// <summary>
        /// MitmDefense: known rogue Cast IP or cast-spoof OUI (B0-B3-69 etc.).
        /// </summary>
        private bool IsMitmRogueCastDevice(string ip, string mac, string manufacturer)
        {
            if (!ProductPosture.AllowsMitmDefenseMutations(_config))
                return false;
            var mitm = _config.MitmDefense;
            if (mitm == null || !mitm.AutoBlockRogueCast)
                return false;

            foreach (var known in mitm.KnownRogueCastIps ?? Array.Empty<string>())
            {
                if (string.Equals(known, ip, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            var oui = mac.Length >= 8 ? mac[..8].Replace(':', '-').ToUpperInvariant() : "";
            foreach (var prefix in mitm.RogueCastMacPrefixes ?? Array.Empty<string>())
            {
                var norm = (prefix ?? "").Replace(':', '-').ToUpperInvariant();
                if (norm.Length >= 8) norm = norm[..8];
                if (string.Equals(norm, oui, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (manufacturer.Contains("cast-spoof", StringComparison.OrdinalIgnoreCase) ||
                manufacturer.Contains("SDMC", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static List<NetworkDevice> GetArpTable()
        {
            var devices = new List<NetworkDevice>();
            try
            {
                int size = 0;
                GetIpNetTable(IntPtr.Zero, ref size, false);
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (GetIpNetTable(buffer, ref size, false) == 0)
                    {
                        int entries = Marshal.ReadInt32(buffer);
                        var entryPtr = buffer + 4;
                        int entrySize = Marshal.SizeOf<MIB_IPNETROW>();
                        for (int i = 0; i < entries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_IPNETROW>(entryPtr + (i * entrySize));
                            if (row.dwType == 2) continue;
                            var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr)).ToString();
                            var mac = $"{row.mac0:X2}-{row.mac1:X2}-{row.mac2:X2}-{row.mac3:X2}-{row.mac4:X2}-{row.mac5:X2}";
                            if (mac != "00-00-00-00-00-00")
                                devices.Add(new NetworkDevice { Ip = ip, Mac = mac, EntryType = row.dwType });
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return devices;
        }

        private static IEnumerable<string> GetDefaultGatewayIps()
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var gw in nic.GetIPProperties().GatewayAddresses)
                {
                    var addr = gw.Address.ToString();
                    if (addr != "0.0.0.0" && addr != "::")
                        yield return addr;
                }
            }
        }

        private static IEnumerable<string> GetLocalIps()
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    yield return ua.Address.ToString();
            }
        }

        /// <summary>
        /// Checks if any unresolvable/empty-name process has active TCP connections to the given IP.
        /// This correlates phantom device detection with ghost process behavior - if a process we
        /// can't identify is talking to the new device, it's likely C2, not a Chromecast.
        /// </summary>
        private static bool HasGhostConnectionTo(string targetIp)
        {
            try
            {
                int size = 0;
                var ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
                if (ret != 122) return false;

                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    ret = GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0);
                    if (ret != 0) return false;

                    int numEntries = Marshal.ReadInt32(buffer);
                    int structSize = 24; // sizeof MIB_TCPROW_OWNER_PID (6 uint = 24 bytes)
                    int myPid = System.Net48Environment.ProcessId;

                    for (int i = 0; i < numEntries; i++)
                    {
                        var rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                        uint state = (uint)Marshal.ReadInt32(rowPtr, 0);
                        uint remoteAddr = (uint)Marshal.ReadInt32(rowPtr, 12);
                        uint owningPid = (uint)Marshal.ReadInt32(rowPtr, 20);

                        if (state != 5) continue; // Established only
                        if (owningPid <= 4 || owningPid == myPid) continue;

                        var remoteIp = new IPAddress(BitConverter.GetBytes(remoteAddr)).ToString();
                        if (!remoteIp.Equals(targetIp)) continue;

                        // Found a connection to the target IP - check if the owning process is resolvable
                        try
                        {
                            using var proc = Process.GetProcessById((int)owningPid);
                            var name = proc.ProcessName;
                            if (string.IsNullOrEmpty(name)) return true; // Empty name = ghost
                        }
                        catch (ArgumentException) { return true; } // Process doesn't exist = ghost
                        catch (InvalidOperationException) { return true; }
                        catch { }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return false;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        internal class NetworkDevice
        {
            public string Ip { get; set; } = "";
            public string Mac { get; set; } = "";
            public int EntryType { get; set; }
        }
    }


}
