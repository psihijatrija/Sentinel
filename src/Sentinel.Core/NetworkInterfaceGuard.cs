using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors and hardens network interface state:
    /// - Detects and removes network bridges via SetupAPI (DIF_REMOVE)
    /// - Re-enables disabled physical adapters via WMI (MSFT_NetAdapter)
    /// - Locks adapter DNS configuration to baseline registry values
    /// - Enforces global DNS-over-HTTPS (DoH) parameters
    /// </summary>
    public sealed class NetworkInterfaceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<NetworkInterfaceGuard> _logger;

        private readonly HashSet<int> _baselinePhysicalInterfaceIndices = new();
        private readonly Dictionary<string, string> _baselineDnsServers = new(StringComparer.OrdinalIgnoreCase);

        // v2.8.2: baseline of ALL network adapters (physical AND virtual) present at startup,
        // keyed by InterfaceIndex. Used to detect a NEW adapter appearing at runtime - a USB
        // Ethernet dongle, a rogue Wi-Fi NIC, or an overlay/VPN virtual adapter
        // (WireGuard/Tailscale/OpenVPN). Attacker "adds his network to mine" begins with an
        // adapter appearing; Windows does not surface this, so it was previously a silent gap.
        private readonly HashSet<int> _baselineAllInterfaceIndices = new();
        private bool _adapterBaselineCaptured;

        private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(15);
        private const string InterfacesKeyPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

        #region SetupAPI P/Invoke

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid classGuid;
            public int devInst;
            public IntPtr reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            string? Enumerator,
            IntPtr hwndParent,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            int MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            int Property,
            out int PropertyRegDataType,
            byte[]? PropertyBuffer,
            int PropertyBufferSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiCallClassInstaller(
            int installFunction,
            IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData);

        private const int DIGCF_PRESENT = 0x00000002;
        private const int SPDRP_SERVICE = 0x00000004;
        private const int DIF_REMOVE = 0x00000005;

        private static readonly Guid GUID_DEVCLASS_NET = new Guid("{4d36e972-e325-11ce-bfc1-08002be10318}");

        #endregion

        public NetworkInterfaceGuard(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<NetworkInterfaceGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NetworkInterfaceGuard] Started");

            // Baseline current configurations
            BaselinePhysicalAdapters();
            BaselineAllAdapters();
            BaselineDnsServers();
            EnforceSecureDoh();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(CheckInterval, ct);

                    // 1. Detect and remove network bridges
                    CheckAndRemoveBridges();

                    // 2. Re-enable disabled physical network adapters
                    await CheckAndRestoreDisabledAdaptersAsync(ct);

                    // 3. Monitor and lock DNS configuration
                    await CheckAndLockDnsAsync(ct);

                    // 4. Ensure DoH remains enabled
                    EnforceSecureDoh();

                    // 5. Detect a NEW network adapter appearing since baseline (v2.8.2)
                    CheckForNewAdapters();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error in execution loop");
                }
            }
        }

        /// <summary>
        /// v2.6.0: On-demand network clean for the VPN-shield remediation chain.
        ///
        /// Unlike the periodic loop (which gates cleaning on
        /// <see cref="ResponsePolicy.MayPerformInlineHostMutation"/>), this is invoked ONLY by
        /// <c>VpnShieldEngine</c> after a network-tamper incident is already chain-confirmed
        /// and the user is behind the protective tunnel - so the mutation is already authorized.
        /// It unbridges, re-enables disabled physical adapters, and restores DNS to baseline.
        /// Best-effort and non-throwing (graceful degradation).
        /// </summary>
        public async Task ForceCleanAsync(CancellationToken ct)
        {
            try { RemoveNetworkBridge(); } catch (Exception ex) { _logger.LogDebug(ex, "[NetworkInterfaceGuard] ForceClean: bridge removal error"); }
            try { await RestoreDisabledAdaptersAsync(ct).ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "[NetworkInterfaceGuard] ForceClean: adapter restore error"); }
            try { RestoreDnsToBaseline(); } catch (Exception ex) { _logger.LogDebug(ex, "[NetworkInterfaceGuard] ForceClean: DNS restore error"); }
        }

        /// <summary>
        /// v2.6.0: Returns true when the interface state matches the clean baseline captured at
        /// startup - no network bridge present, no baselined physical adapter left disabled, and
        /// every interface's registry DNS matches its baseline. Used by <c>VpnShieldEngine</c> to
        /// decide when it is safe to drop the protective tunnel. Fail-safe: on any error this
        /// returns <c>false</c> (treat as "not verified clean", keep the shield up).
        /// </summary>
        public bool IsNetworkClean()
        {
            try
            {
                // 1. No network bridge interface present.
                bool hasBridge = NetworkInterface.GetAllNetworkInterfaces()
                    .Any(ni => ni.Description.Contains("MAC Bridge") ||
                               ni.Description.Contains("Multiplexor Driver"));
                if (hasBridge) return false;

                // 2. No baselined physical adapter left administratively down.
                try
                {
                    var scope = new ManagementScope(@"root\StandardCimv2");
                    scope.Connect();
                    var query = new ObjectQuery("SELECT InterfaceIndex, AdminStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                    using var searcher = new ManagementObjectSearcher(scope, query);
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        int index = Convert.ToInt32(obj["InterfaceIndex"]);
                        int adminStatus = Convert.ToInt32(obj["AdminStatus"]);
                        if (_baselinePhysicalInterfaceIndices.Contains(index) && adminStatus == 2)
                            return false; // a baselined adapter is still Down
                    }
                }
                catch { return false; }

                // 3. Every interface's registry DNS matches its baseline.
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (_baselineDnsServers.TryGetValue(ni.Id, out var baselineDns))
                    {
                        var currentDns = GetRegistryDns(ni.Id);
                        if (!string.IsNullOrEmpty(currentDns) && !currentDns!.Equals(baselineDns))
                            return false; // DNS still drifted from baseline
                    }
                }

                return true;
            }
            catch
            {
                return false; // fail-safe: unknown state == not clean
            }
        }

        private async Task RestoreDisabledAdaptersAsync(CancellationToken ct)
        {
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, AdminStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    if (ct.IsCancellationRequested) return;
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    int adminStatus = Convert.ToInt32(obj["AdminStatus"]);
                    if (_baselinePhysicalInterfaceIndices.Contains(index) && adminStatus == 2)
                    {
                        _logger.LogWarning("[NetworkInterfaceGuard] VPN-shield clean: re-enabling adapter '{Name}' (Index {Index})", name, index);
                        obj.InvokeMethod("Enable", null);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] RestoreDisabledAdaptersAsync error");
            }
            await Task.CompletedTask;
        }

        private void RestoreDnsToBaseline()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (_baselineDnsServers.TryGetValue(ni.Id, out var baselineDns))
                {
                    var currentDns = GetRegistryDns(ni.Id);
                    if (!string.IsNullOrEmpty(currentDns) && !currentDns!.Equals(baselineDns))
                    {
                        SetRegistryDns(ni.Id, baselineDns);
                    }
                }
            }
        }

        private void BaselinePhysicalAdapters()
        {
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, Virtual, InterfaceStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    int status = Convert.ToInt32(obj["InterfaceStatus"]);

                    _baselinePhysicalInterfaceIndices.Add(index);
                    _logger.LogInformation("[NetworkInterfaceGuard] Baselined physical network adapter: '{Name}' (Index {Index}, Status {Status})", name, index, status);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to baseline physical network adapters");
            }
        }

        /// <summary>
        /// v2.8.2: Baseline the full adapter set (physical AND virtual) present at startup, so a
        /// new adapter appearing at runtime can be detected. Keyed by InterfaceIndex. Unlike
        /// <see cref="BaselinePhysicalAdapters"/> this deliberately includes virtual adapters, so an
        /// overlay/VPN adapter (WireGuard/Tailscale/OpenVPN) installed AFTER Sentinel starts is
        /// flagged as new rather than silently ignored.
        /// </summary>
        private void BaselineAllAdapters()
        {
            try
            {
                foreach (var idx in EnumerateAllAdapterIndices())
                    _baselineAllInterfaceIndices.Add(idx);
                _adapterBaselineCaptured = true;
                _logger.LogInformation("[NetworkInterfaceGuard] Baselined {Count} network adapters (physical + virtual) for new-adapter detection", _baselineAllInterfaceIndices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to baseline adapter set for new-adapter detection");
            }
        }

        /// <summary>
        /// Enumerates every current network adapter (physical and virtual) as
        /// (InterfaceIndex, Name, Virtual). Best-effort; returns empty on failure.
        /// </summary>
        private static IEnumerable<(int Index, string Name, bool Virtual)> EnumerateAdapters()
        {
            var results = new List<(int, string, bool)>();
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, Virtual FROM MSFT_NetAdapter");
                using var searcher = new ManagementObjectSearcher(scope, query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    bool virt = false;
                    try { virt = Convert.ToBoolean(obj["Virtual"]); } catch { }
                    results.Add((index, name, virt));
                }
            }
            catch { }
            return results;
        }

        private static IEnumerable<int> EnumerateAllAdapterIndices()
        {
            foreach (var (index, _, _) in EnumerateAdapters())
                yield return index;
        }

        /// <summary>
        /// v2.8.2: Detect a network adapter that appeared AFTER the startup baseline. This is the
        /// on-host half of "attacker adds his network to mine" - a rogue USB NIC, a second Wi-Fi
        /// adapter, or an overlay/VPN virtual adapter. Windows surfaces no user-visible event for
        /// this, so without this check it was a silent coverage gap.
        ///
        /// Emitted as Tier2 / LogOnly OBSERVE-FUEL, never a kill: adding an adapter is a legitimate
        /// admin action and cannot be a solo kill signal (behavioral-only kill authority). Its value
        /// is as an independent MitM leg feeding the network-tamper VPN-shield composite - a new
        /// adapter alongside an ARP/DNS/route tamper is strong evidence of an active local MitM.
        /// We never auto-remove the adapter (too destructive / FP-prone for a legitimate dongle).
        /// </summary>
        private void CheckForNewAdapters()
        {
            if (!_adapterBaselineCaptured) return;
            try
            {
                foreach (var (index, name, virt) in EnumerateAdapters())
                {
                    if (_baselineAllInterfaceIndices.Contains(index)) continue;

                    // New adapter since baseline. Record it, then add to baseline so we alert once.
                    _baselineAllInterfaceIndices.Add(index);

                    bool overlayVpn = IsOverlayVpnAdapterName(name);
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: New Adapter Appeared",
                        Evidence = $"A network adapter not present at startup appeared: '{name}' " +
                                   $"(InterfaceIndex {index}, {(virt ? "virtual" : "physical")}" +
                                   $"{(overlayVpn ? ", overlay/VPN" : "")}).",
                        Reasoning = "A new network adapter was added to the host after Sentinel started - a USB " +
                                    "Ethernet dongle, an additional Wi-Fi NIC, or an overlay/VPN virtual adapter " +
                                    "(WireGuard/Tailscale/OpenVPN). This is the on-host beginning of adding a second " +
                                    "network path that an attacker could route or intercept traffic through. It is a " +
                                    "legitimate admin action on its own (LogOnly observe), but combined with any ARP / " +
                                    "DNS / route / gateway tamper it is an independent leg of a local man-in-the-middle " +
                                    "chain and helps raise the protective VPN shield.",
                        Confidence = overlayVpn ? 0.55 : 0.45,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.Generic,
                        Metadata = new Dictionary<string, string>
                        {
                            ["AdapterName"] = name,
                            ["InterfaceIndex"] = index.ToString(),
                            ["Virtual"] = virt.ToString(),
                            ["OverlayVpn"] = overlayVpn.ToString(),
                            // Root observation = this specific new adapter, so it is one
                            // independent tamper vector and cannot self-stack.
                            [BehavioralCorrelationEngine.ObservationKeyMeta] = $"new-adapter:{index}"
                        }
                    });

                    _logger.LogWarning("[NetworkInterfaceGuard] New network adapter appeared: '{Name}' (Index {Index}, virtual={Virtual}, overlayVpn={Overlay})",
                        name, index, virt, overlayVpn);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking for new adapters");
            }
        }

        private static readonly string[] OverlayVpnNameFragments = new[]
        {
            "wireguard", "tailscale", "nordlynx", "openvpn", "tap-windows", "proton",
            "cloudflare", "warp", "zerotier", "tunnel", "wintun", "vpn",
        };

        private static bool IsOverlayVpnAdapterName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            var n = name.ToLowerInvariant();
            return OverlayVpnNameFragments.Any(f => n.Contains(f));
        }

        private void BaselineDnsServers()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && 
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var props = ni.GetIPProperties();
                        var dns = props.DnsAddresses
                            .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            .Select(a => a.ToString())
                            .ToList();
                        
                        if (dns.Count > 0)
                        {
                            var dnsStr = string.Join(",", dns);
                            _baselineDnsServers[ni.Id] = dnsStr;
                            _logger.LogInformation("[NetworkInterfaceGuard] Baselined DNS for interface {Name} ({Guid}): {DNS}", ni.Name, ni.Id, dnsStr);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to baseline DNS servers");
            }
        }

        private void CheckAndRemoveBridges()
        {
            try
            {
                // Check if any adapter in NetworkInterface list is a bridge
                var bridgeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.Description.Contains("MAC Bridge") || 
                                 ni.Description.Contains("Multiplexor Driver"))
                    .ToList();

                if (bridgeInterfaces.Count == 0) return;

                foreach (var bridge in bridgeInterfaces)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network: Unauthorized Network Bridge Detected",
                        Evidence = $"Network bridge interface discovered: '{bridge.Name}' ({bridge.Description})",
                        Reasoning = "A network adapter bridge was created on the system. Network bridges allow lateral movement pivoting, bypassing the host firewall, and direct traffic routing into secure network segments.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // We handle unbridging ourselves
                        ProcessName = "SYSTEM", ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            // Root observation = this specific bridge interface.
                            [BehavioralCorrelationEngine.ObservationKeyMeta] = $"bridge:{bridge.Id}"
                        }
                    });
                }

                // Active response: remove the bridge device via SetupAPI
                if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                {
                    RemoveNetworkBridge();
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking network bridges");
            }
        }

        private void RemoveNetworkBridge()
        {
            Guid netClassGuid = GUID_DEVCLASS_NET;
            IntPtr deviceInfoSet = SetupDiGetClassDevs(ref netClassGuid, null, IntPtr.Zero, DIGCF_PRESENT);
            if (deviceInfoSet == (IntPtr)(-1)) return;

            try
            {
                var deviceInfoData = new SP_DEVINFO_DATA();
                deviceInfoData.cbSize = Marshal.SizeOf(deviceInfoData);
                int index = 0;

                while (SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfoData))
                {
                    string service = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_SERVICE);
                    if (service.Equals("bridge") || 
                        service.Equals("macbridge"))
                    {
                        _logger.LogWarning("[NetworkInterfaceGuard] Found MAC Bridge device (Service: {Service}). Removing...", service);
                        
                        bool success = SetupDiCallClassInstaller(DIF_REMOVE, deviceInfoSet, ref deviceInfoData);
                        if (success)
                        {
                            _logger.LogInformation("[NetworkInterfaceGuard] Successfully uninstalled MAC Bridge device.");
                        }
                        else
                        {
                            int error = Marshal.GetLastWin32Error();
                            _logger.LogWarning("[NetworkInterfaceGuard] Failed to uninstall MAC Bridge device. SetupAPI Error: {Error}", error);
                        }
                        break;
                    }
                    index++;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error during SetupAPI bridge removal");
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }
        }

        private async Task CheckAndRestoreDisabledAdaptersAsync(CancellationToken ct)
        {
            try
            {
                var scope = new ManagementScope(@"root\StandardCimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT InterfaceIndex, Name, AdminStatus FROM MSFT_NetAdapter WHERE Virtual = false");
                using var searcher = new ManagementObjectSearcher(scope, query);
                
                foreach (ManagementObject obj in searcher.Get())
                {
                    int index = Convert.ToInt32(obj["InterfaceIndex"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    int adminStatus = Convert.ToInt32(obj["AdminStatus"]);

                    if (_baselinePhysicalInterfaceIndices.Contains(index) && adminStatus == 2) // 2 = Down/Disabled
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network: Primary Adapter Disabled",
                            Evidence = $"Physical network adapter '{name}' (Index {index}) was disabled (AdminStatus changed to Down).",
                            Reasoning = "A physical network adapter that was previously active has been disabled. This could indicate malware attempting to sever network connectivity or execute off-line evasion tactics.",
                            Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });

                        if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                        {
                            _logger.LogWarning("[NetworkInterfaceGuard] Active Response: Re-enabling network adapter '{Name}' (Index {Index})", name, index);
                            obj.InvokeMethod("Enable", null);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking/restoring network adapters");
            }
        }

        private async Task CheckAndLockDnsAsync(CancellationToken ct)
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (_baselineDnsServers.TryGetValue(ni.Id, out var baselineDns))
                    {
                        var currentDns = GetRegistryDns(ni.Id);
                        if (!string.IsNullOrEmpty(currentDns) && !currentDns!.Equals(baselineDns))
                        {
                            // v-next: tune confidence by the reputation of the NEW resolver.
                            // A change TO a well-known public resolver (Cloudflare/Google/Quad9/...)
                            // is usually a benign provider switch; the classic hijack points DNS at
                            // an unknown attacker-controlled server. Down-weight the known-good case;
                            // keep high confidence when the new server is unrecognized.
                            bool newDnsAllKnown = PublicDnsResolvers.AllKnownPublicResolvers(currentDns);
                            double dnsConfidence = newDnsAllKnown ? 0.45 : 0.88;
                            string dnsReasoning = newDnsAllKnown
                                ? "A process changed the network adapter's DNS servers to a well-known public resolver. " +
                                  "This is frequently a legitimate provider switch, but an unexpected change can still " +
                                  "indicate tampering - reported at reduced confidence as an observe-only signal."
                                : "An unauthorized process modified the network adapter's DNS settings to an unrecognized " +
                                  "server. Pointing resolution at an attacker-controlled resolver is a common hijacking " +
                                  "technique to redirect web traffic to malicious servers.";

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Network: Unauthorized DNS Change",
                                Evidence = $"DNS NameServer configuration for interface '{ni.Name}' changed from '{baselineDns}' to '{currentDns}' in Registry." +
                                           (newDnsAllKnown ? " New servers are known public resolvers." : " New servers are not recognized public resolvers."),
                                Reasoning = dnsReasoning,
                                Confidence = dnsConfidence, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    // Root observation = this interface's DNS config change.
                                    [BehavioralCorrelationEngine.ObservationKeyMeta] = $"dns-iface:{ni.Id}"
                                }
                            });

                            if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                            {
                                SetRegistryDns(ni.Id, baselineDns);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkInterfaceGuard] Error checking/locking DNS");
            }
        }

        private string? GetRegistryDns(string interfaceGuid)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKeyPath}\{interfaceGuid}");
                return key?.GetValue("NameServer")?.ToString();
            }
            catch { return null; }
        }

        private void SetRegistryDns(string interfaceGuid, string dnsServers)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKeyPath}\{interfaceGuid}", writable: true);
                if (key != null)
                {
                    key.SetValue("NameServer", dnsServers, RegistryValueKind.String);
                    _logger.LogInformation("[NetworkInterfaceGuard] Restored DNS servers on interface {Guid} to secure baseline: {DNS}", interfaceGuid, dnsServers);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[NetworkInterfaceGuard] Failed to set DNS servers on interface {Guid}", interfaceGuid);
            }
        }

        private void EnforceSecureDoh()
        {
            // REMOVED: This conflicts with BrowserDnsPolicyGuard which disables DoH to enforce
            // hosts-file-based blocking. BrowserDnsPolicyGuard is the authoritative policy -
            // the hosts file is the DNS override mechanism for this system.
            // NetworkInterfaceGuard should NOT re-enable DoH.
        }

        private static string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property)
        {
            int requiredSize = 0;
            SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                byte[] buffer = new byte[requiredSize];
                if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, buffer, buffer.Length, out _))
                {
                    return System.Text.Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }
            }
            return string.Empty;
        }
    }
}
