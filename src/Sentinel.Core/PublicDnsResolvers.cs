using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// v-next: Known-good public DNS resolver allowlist.
    ///
    /// Sentinel treats every DNS NameServer change as suspicious, but not all changes are equal.
    /// A change TO a reputable public resolver (Cloudflare, Google, Quad9, OpenDNS, AdGuard, ...)
    /// is far more likely to be a user or legitimate tool switching providers than a hijack to an
    /// attacker-controlled server. This set lets <see cref="NetworkInterfaceGuard"/> lower its
    /// confidence when the NEW resolver is well-known, and keep high confidence for unknown IPs
    /// (the classic DNS-hijack shape: point resolution at an attacker's box).
    ///
    /// The IP set was compiled independently from public resolver documentation; it is factual
    /// address data, not third-party code.
    /// </summary>
    public static class PublicDnsResolvers
    {
        // Curated set of widely-used, reputable public resolver IPs (IPv4 + common IPv6).
        // Not exhaustive by design - membership means "reputable/known", absence does not imply
        // "malicious"; it only means Sentinel will not down-weight the change.
        private static readonly HashSet<string> KnownResolvers = new(StringComparer.OrdinalIgnoreCase)
        {
            // Cloudflare / APNIC
            "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            // Google Public DNS
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            // Quad9
            "9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.112", "149.112.112.10", "149.112.112.11",
            "2620:fe::fe", "2620:fe::9",
            // Cisco OpenDNS / Umbrella
            "208.67.222.222", "208.67.220.220", "208.67.222.220", "208.67.220.222",
            "208.67.222.123", "208.67.220.123",
            // AdGuard DNS
            "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",
            "176.103.130.130", "176.103.130.131",
            // Verisign
            "64.6.64.6", "64.6.65.6",
            // Level3 / CenturyLink
            "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "209.244.0.3", "209.244.0.4",
            // DNS.WATCH
            "84.200.69.80", "84.200.70.40",
            // Comodo Secure DNS
            "8.26.56.26", "8.20.247.20",
            // Yandex DNS
            "77.88.8.8", "77.88.8.1",
            // CleanBrowsing
            "185.228.168.9", "185.228.169.9", "185.228.168.168", "185.228.169.168",
            // ControlD
            "76.76.2.0", "76.76.10.0",
            // Alternate DNS
            "76.76.19.19", "76.223.122.150",
            // NextDNS anycast
            "45.90.28.0", "45.90.30.0",
            // SafeDNS / Neustar UltraDNS
            "195.46.39.39", "195.46.39.40", "156.154.70.1", "156.154.71.1",
        };

        /// <summary>
        /// True when <paramref name="ip"/> is a known reputable public resolver.
        /// </summary>
        public static bool IsKnownPublicResolver(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return KnownResolvers.Contains(ip!.Trim());
        }

        /// <summary>
        /// True when a comma/space/semicolon-separated NameServer list resolves ENTIRELY to
        /// known reputable public resolvers. An empty/blank list is not "known".
        /// A single unknown server makes the whole set unknown - the safe bias for a hijack check.
        /// </summary>
        public static bool AllKnownPublicResolvers(string? nameServerList)
        {
            if (string.IsNullOrWhiteSpace(nameServerList)) return false;

            var servers = nameServerList!
                .Split(new[] { ',', ' ', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .ToList();

            if (servers.Count == 0) return false;
            return servers.All(IsKnownPublicResolver);
        }
    }
}
