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
    public partial class AdvancedResponseEngine
    {
        private IReadOnlyList<ResponseEffect> RemoveCertificateFromStore(string thumbprint)
        {
            var results = new List<ResponseEffect>();
            if (string.IsNullOrWhiteSpace(thumbprint) || thumbprint.Length < 40 || !thumbprint.All(Uri.IsHexDigit))
                return new[] { new ResponseEffect { Action = "CertificateRemoval", Target = thumbprint,
                    Status = ResponseExecutionStatus.Refused, Detail = "Valid certificate thumbprint was not supplied." } };
            var stores = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser)
            };
            foreach (var (storeName, storeLocation) in stores)
            {
                var effect = new ResponseEffect { Action = "CertificateRemoval", Target = $"{storeLocation}/{storeName}/{thumbprint}" };
                try
                {
                    using (var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation))
                    {
                        store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
                        var certs = store.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                            thumbprint, validOnly: false);
                        foreach (var cert in certs) { using (cert) store.Remove(cert); }
                    }
                    using var readBack = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    readBack.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                    var remaining = readBack.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                        thumbprint, validOnly: false);
                    effect.Status = remaining.Count == 0 ? ResponseExecutionStatus.Verified : ResponseExecutionStatus.Failed;
                    effect.Detail = remaining.Count == 0 ? "Certificate absent on independent store read-back."
                        : "Certificate remains in the store after removal.";
                    foreach (var cert in remaining) cert.Dispose();
                }
                catch (Exception ex)
                {
                    effect.Status = ResponseExecutionStatus.Failed;
                    effect.Detail = "Store removal/read-back failed: " + ex.Message;
                }
                results.Add(effect);
            }
            return results;
        }

        private ResponseEffect IsolateNetworkTarget(string ip, string ruleName)
        {
            var effect = new ResponseEffect { Action = "FirewallRules", Target = ip };
            var safeName = ip.Replace('.', '_').Replace(':', '_');
            var fwRule = $"Sentinel-Isolate-{safeName}";
            int verifiedRules = 0;
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                    ?? throw new InvalidOperationException("Windows Firewall COM policy is unavailable.");
                dynamic policy = Activator.CreateInstance(policyType)
                    ?? throw new InvalidOperationException("Windows Firewall policy could not be opened.");
                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                    ?? throw new InvalidOperationException("Windows Firewall rule API is unavailable.");
                foreach (int direction in new[] { 2, 1 })
                {
                    dynamic rule = Activator.CreateInstance(ruleType)
                        ?? throw new InvalidOperationException("Unable to create firewall rule.");
                    rule.Name = fwRule + (direction == 2 ? "-OUT" : "-IN");
                    rule.Description = $"Sentinel: Block {ip} ({ruleName})";
                    rule.Direction = direction;
                    rule.Action = 0;
                    rule.RemoteAddresses = ip;
                    rule.Enabled = true;
                    rule.Profiles = 0x7FFFFFFF;
                    policy.Rules.Add(rule);
                    dynamic readBack = policy.Rules.Item((string)rule.Name);
                    string remote = (string)readBack.RemoteAddresses;
                    string address = remote.Split('/')[0];
                    bool sameAddress = IPAddress.TryParse(address, out var actual) && IPAddress.TryParse(ip, out var expected) && actual.Equals(expected);
                    if (!(bool)readBack.Enabled || (int)readBack.Action != 0 || (int)readBack.Direction != direction ||
                        (int)readBack.Profiles != 0x7FFFFFFF || !sameAddress || (int)readBack.Protocol != 256 ||
                        !string.IsNullOrEmpty((string)readBack.ApplicationName) || !string.IsNullOrEmpty((string)readBack.ServiceName))
                        throw new InvalidOperationException("Installed firewall rule did not match the requested unrestricted block rule.");
                    verifiedRules++;
                }
                // Installed rules alone cannot isolate traffic if the active firewall profile is disabled.
                if ((int)policy.LocalPolicyModifyState != 0)
                    throw new InvalidOperationException("Active firewall policy does not permit unrestricted local rule changes.");
                int activeProfiles = (int)policy.CurrentProfileTypes;
                if (activeProfiles == 0) throw new InvalidOperationException("Active firewall profile could not be established.");
                foreach (int profile in new[] { 1, 2, 4 })
                    if ((activeProfiles & profile) != 0 && !(bool)policyType.InvokeMember("FirewallEnabled",
                        System.Reflection.BindingFlags.GetProperty, null, (object)policy, new object[] { profile })!)
                        throw new InvalidOperationException("Firewall is disabled on an active profile.");
                effect.Status = ResponseExecutionStatus.Verified;
                effect.Detail = "Inbound/outbound all-protocol block rules read back correctly; active firewall profiles enabled. This verifies policy configuration, not an end-to-end connectivity test.";
            }
            catch (Exception ex)
            {
                effect.Status = verifiedRules > 0 ? ResponseExecutionStatus.PartiallyCompleted : ResponseExecutionStatus.Failed;
                effect.Detail = "Firewall configuration/read-back failed: " + ex.Message;
            }
            return effect;
        }

        private static ResponseEffect FlushDnsCache()
        {
            var effect = new ResponseEffect { Action = "DnsCacheCleanup", Target = "resolver" };
            try
            {
                bool succeeded = DnsFlushResolverCache() != 0;
                effect.Status = succeeded ? ResponseExecutionStatus.Verified : ResponseExecutionStatus.Failed;
                effect.Detail = succeeded ? "DNS resolver API confirmed synchronous cache flush." : "DNS resolver API reported failure.";
            }
            catch (Exception ex) { effect.Status = ResponseExecutionStatus.Failed; effect.Detail = ex.Message; }
            return effect;
        }

        private static ResponseEffect FlushArpEntry(string ip)
        {
            var effect = new ResponseEffect { Action = "ArpCacheCleanup", Target = ip };
            try
            {
                if (!IPAddress.TryParse(ip, out var addr)) throw new ArgumentException("Invalid ARP target.");
                if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    effect.Status = ResponseExecutionStatus.Verified;
                    effect.Detail = "No IPv4 ARP entry applies to this IPv6 target.";
                    return effect;
                }
                uint ipInt = BitConverter.ToUInt32(addr.GetAddressBytes(), 0);
                int routeStatus = GetBestInterface(ipInt, out int ifIndex);
                if (routeStatus != 0) throw new InvalidOperationException("Interface lookup failed: " + routeStatus);
                var row = new MibIpNetRow { dwIndex = ifIndex, dwAddr = unchecked((int)ipInt) };
                int status = DeleteIpNetEntry(ref row);
                effect.Status = status == 0 || status == 1168 ? ResponseExecutionStatus.Verified : ResponseExecutionStatus.Failed;
                effect.Detail = status == 0 ? "IP helper API confirmed synchronous entry deletion."
                    : status == 1168 ? "ARP entry already absent." : "ARP deletion failed: " + status;
            }
            catch (Exception ex) { effect.Status = ResponseExecutionStatus.Failed; effect.Detail = ex.Message; }
            return effect;
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
