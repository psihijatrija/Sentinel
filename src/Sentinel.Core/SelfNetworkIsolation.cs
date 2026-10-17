using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    public sealed class SelfNetworkBlockRule
    {
        public string Name { get; }
        public string ApplicationPath { get; }
        public int Direction { get; }
        public const string Group = "Sentinel Offline Isolation";
        // All non-loopback IPv4/IPv6 destinations, including LAN and link-local addresses.
        // Explicit block rules win over allow rules; loopback must be excluded from the block.
        public const string RemoteAddresses = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        public SelfNetworkBlockRule(string name, string applicationPath, int direction)
        {
            Name = name;
            ApplicationPath = applicationPath;
            Direction = direction;
        }
    }

    public interface ISelfNetworkFirewall
    {
        void UpsertAndVerify(SelfNetworkBlockRule rule);
        void Remove(string name);
        void VerifyEnabled();
    }

    /// <summary>Owns only fixed, program-scoped rules; never changes the host's default policy.</summary>
    public sealed class SelfNetworkIsolation
    {
        private readonly ISelfNetworkFirewall _firewall;
        private readonly string _installDirectory;
        public SelfNetworkIsolation(ISelfNetworkFirewall firewall, string installDirectory)
        {
            _firewall = firewall;
            _installDirectory = Path.GetFullPath(installDirectory);
        }

        public IEnumerable<SelfNetworkBlockRule> Rules
        {
            get
            {
                foreach (var executable in new[] { "Sentinel.Service.exe", "Sentinel.Agent.exe", "SentinelAutoRotate.exe" })
                    foreach (var direction in new[] { 1, 2 })
                        yield return new SelfNetworkBlockRule(
                            "Sentinel-Offline-" + executable + (direction == 1 ? "-IN" : "-OUT"),
                            Path.Combine(_installDirectory, executable), direction);
            }
        }

        public void Apply()
        {
            // Stable rule names allow upgrades to repair/repoint rules without duplicates.
            foreach (var rule in Rules) _firewall.UpsertAndVerify(rule);
            _firewall.VerifyEnabled();
        }

        public void Remove()
        {
            foreach (var rule in Rules) _firewall.Remove(rule.Name);
        }
    }
}
