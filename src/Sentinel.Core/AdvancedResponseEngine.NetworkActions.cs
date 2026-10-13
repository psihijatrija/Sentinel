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

namespace Sentinel.Core
{
    // Network / certificate response executors and P/Invoke helpers for
    // AdvancedResponseEngine. Split out of the main file for reviewability;
    // this is the SAME type (partial class) - no behavior change. These are the
    // low-level host-mutation primitives; the Tier1/observe-until-chain gating that
    // authorizes calling them lives in the decision layer in AdvancedResponseEngine.cs.
    public partial class AdvancedResponseEngine
    {
        private void RemoveCertificateFromStore(string thumbprint)
        {
            var stores = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser)
            };

            foreach (var (storeName, storeLocation) in stores)
            {
                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);

                    var certs = store.Certificates.Find(
                        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        thumbprint,
                        validOnly: false);

                    foreach (var cert in certs)
                    {
                        store.Remove(cert);
                        _eventLogger.LogEventAsync("debug", new { Message = $"Successfully removed cert {thumbprint} from {storeName} ({storeLocation})" }).GetAwaiter().GetResult();
                    }
                }
                catch (Exception ex)
                {
                    _eventLogger.LogEventAsync("debug", new { Message = $"Failed to open/remove cert {thumbprint} from {storeName} ({storeLocation}): {ex.Message}" }).GetAwaiter().GetResult();
                }
            }
        }

        private void IsolateNetworkTarget(string ip, string ruleName)
        {
            var safeName = ip.Replace('.', '_').Replace(':', '_');
            var fwRule = $"Sentinel-Isolate-{safeName}";

            try
            {
                // Use Windows Firewall COM API (INetFwPolicy2) instead of shelling out to netsh.
                // This avoids Process.Start patterns that AV engines flag as malware behavior.
                var fwPolicyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (fwPolicyType == null) return;
                dynamic? fwPolicy = Activator.CreateInstance(fwPolicyType);
                if (fwPolicy == null) return;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType == null) return;

                // Outbound block
                dynamic? outRule = Activator.CreateInstance(ruleType);
                if (outRule != null)
                {
                    outRule.Name = $"{fwRule}-OUT";
                    outRule.Description = $"Sentinel: Block outbound to {ip} ({ruleName})";
                    outRule.Direction = 2; // NET_FW_RULE_DIR_OUT
                    outRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    outRule.RemoteAddresses = ip;
                    outRule.Enabled = true;
                    outRule.Profiles = 0x7FFFFFFF; // All profiles
                    fwPolicy.Rules.Add(outRule);
                }

                // Inbound block
                dynamic? inRule = Activator.CreateInstance(ruleType);
                if (inRule != null)
                {
                    inRule.Name = $"{fwRule}-IN";
                    inRule.Description = $"Sentinel: Block inbound from {ip} ({ruleName})";
                    inRule.Direction = 1; // NET_FW_RULE_DIR_IN
                    inRule.Action = 0;    // NET_FW_ACTION_BLOCK
                    inRule.RemoteAddresses = ip;
                    inRule.Enabled = true;
                    inRule.Profiles = 0x7FFFFFFF;
                    fwPolicy.Rules.Add(inRule);
                }
            }
            catch (Exception ex)
            {
                // Fallback: if COM fails (e.g., service not running), log and continue
                _eventLogger.LogEventAsync("debug", new { Message = $"Firewall COM failed for {ip}: {ex.Message}" }).GetAwaiter().GetResult();
            }
        }

        private static void FlushDnsCache()
        {
            try
            {
                // DnsFlushResolverCache is a documented public API - not a shell-out
                DnsFlushResolverCache();
            }
            catch { }
        }

        /// <summary>
        /// v1.8.1: Drop a single IPv4 ARP cache entry without shelling to <c>arp.exe</c>.
        /// Restores NetworkIsolate parity with v5.9.0 (firewall + ARP + DNS flush).
        /// </summary>
        private static void FlushArpEntry(string ip)
        {
            try
            {
                if (!IPAddress.TryParse(ip, out var addr) ||
                    addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return;

                var ipBytes = addr.GetAddressBytes();
                uint ipInt = BitConverter.ToUInt32(ipBytes, 0);
                if (GetBestInterface(ipInt, out int ifIndex) != 0)
                    return;

                var row = new MibIpNetRow
                {
                    dwIndex = ifIndex,
                    dwAddr = unchecked((int)ipInt)
                };
                DeleteIpNetEntry(ref row);
            }
            catch { }
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetBestInterface(uint dwDestAddr, out int pdwBestIfIndex);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int DeleteIpNetEntry(ref MibIpNetRow pArpEntry);

        [StructLayout(LayoutKind.Sequential)]
        private struct MibIpNetRow
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            public byte mac0, mac1, mac2, mac3, mac4, mac5, mac6, mac7;
            public int dwAddr;
            public int dwType;
        }

        /// <summary>
        /// v1.6.1: Avoid firewall-blocking major public resolvers / well-known CDN anycast
        /// prefixes when decoy beaconing tries to force NetworkIsolate collateral damage.
        /// Not exhaustive - best-effort guardrail.
        /// </summary>
        private static bool IsLikelyCdnOrPublicResolver(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4)
            {
                // Cloudflare 1.1.1.0/24, 1.0.0.0/24
                if (bytes[0] == 1 && (bytes[1] == 1 || bytes[1] == 0)) return true;
                // Google DNS 8.8.8.0/24, 8.8.4.0/24
                if (bytes[0] == 8 && bytes[1] == 8) return true;
                // Quad9 9.9.9.0/24
                if (bytes[0] == 9 && bytes[1] == 9 && bytes[2] == 9) return true;
            }
            return false;
        }

        private static bool IsMulticastOrUnspecified(IPAddress ip)
        {
            if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip)) return true;
            if (ip.IsIPv6Multicast) return true;
            var bytes = ip.GetAddressBytes();
            // IPv4 multicast 224.0.0.0/4
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && bytes.Length == 4
                && bytes[0] >= 224 && bytes[0] <= 239)
                return true;
            return false;
        }
    }
}
