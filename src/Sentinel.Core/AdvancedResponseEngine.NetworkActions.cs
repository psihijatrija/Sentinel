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
        private bool RemoveCertificateFromStore(string thumbprint)
        {
            var stores = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser)
            };

            // Validate before Windows path/store parsing and collect every live context
            // before the first mutation. An unreadable store refuses the entire action.
            if (thumbprint.Length != 40 || thumbprint.Any(c => !Uri.IsHexDigit(c))) return false;
            var opened = new List<System.Security.Cryptography.X509Certificates.X509Store>();
            var targets = new List<(System.Security.Cryptography.X509Certificates.X509Store Store,
                System.Security.Cryptography.X509Certificates.X509Certificate2 Cert)>();
            try
            {
                foreach (var (storeName, storeLocation) in stores)
                {
                    var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    opened.Add(store);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite |
                        System.Security.Cryptography.X509Certificates.OpenFlags.OpenExistingOnly);
                    foreach (var cert in store.Certificates.Find(
                        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, thumbprint, false))
                        targets.Add((store, cert));
                }
                if (targets.Count == 0 || targets.Any(t => !CertSuspicionAnalyzer.IsSuspicious(t.Cert))) return false;
                foreach (var target in targets)
                {
                    if (!CertSuspicionAnalyzer.IsSuspicious(target.Cert)) return false;
                    target.Store.Remove(target.Cert);
                }
                foreach (var store in opened)
                {
                    var remaining = store.Certificates.Find(
                        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, thumbprint, false);
                    try { if (remaining.Count != 0) return false; }
                    finally { foreach (var cert in remaining) cert.Dispose(); }
                }
                return true;
            }
            catch (Exception ex)
            {
                _eventLogger.LogEventAsync("certificate_removal_failed", new { Thumbprint = thumbprint, Error = ex.Message }).GetAwaiter().GetResult();
                return false;
            }
            finally
            {
                foreach (var target in targets) target.Cert.Dispose();
                foreach (var store in opened) store.Dispose();
            }
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
