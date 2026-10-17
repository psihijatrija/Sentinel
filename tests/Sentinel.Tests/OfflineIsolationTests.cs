using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class OfflineIsolationTests
    {
        private sealed class Firewall : ISelfNetworkFirewall
        {
            public readonly Dictionary<string, SelfNetworkBlockRule> Stored = new();
            public bool Enabled = true;
            public void UpsertAndVerify(SelfNetworkBlockRule rule) => Stored[rule.Name] = rule;
            public void Remove(string name) => Stored.Remove(name);
            public void VerifyEnabled() { if (!Enabled) throw new InvalidOperationException("Disabled firewall"); }
        }

        [Fact]
        public void UpgradeRepairsRulesWithoutDuplicatesAndUninstallPreservesUnrelatedRules()
        {
            var firewall = new Firewall();
            firewall.Stored["unrelated"] = new SelfNetworkBlockRule("unrelated", "other.exe", 2);
            var old = new SelfNetworkIsolation(firewall, Path.Combine(Path.GetTempPath(), "old"));
            old.Apply();
            var current = new SelfNetworkIsolation(firewall, Path.Combine(Path.GetTempPath(), "new"));
            current.Apply(); current.Apply();
            Assert.Equal(7, firewall.Stored.Count);
            Assert.All(current.Rules, rule =>
                Assert.Equal(rule.ApplicationPath, firewall.Stored[rule.Name].ApplicationPath));
            Assert.Equal(3, current.Rules.Select(r => r.ApplicationPath).Distinct().Count());
            Assert.All(current.Rules.GroupBy(r => r.ApplicationPath), rules =>
                Assert.Equal(new[] { 1, 2 }, rules.Select(r => r.Direction).OrderBy(d => d).ToArray()));
            current.Remove();
            Assert.Equal("unrelated", Assert.Single(firewall.Stored).Key);
        }

        [Fact]
        public void DisabledFirewallIsReportedAfterAllPersistentRulesAreInstalled()
        {
            var firewall = new Firewall { Enabled = false };
            var isolation = new SelfNetworkIsolation(firewall, Path.GetTempPath());
            Assert.Throws<InvalidOperationException>(() => isolation.Apply());
            Assert.Equal(6, firewall.Stored.Count);
        }

        [Theory]
        [InlineData("127.0.0.1", false)]
        [InlineData("127.42.3.4", false)]
        [InlineData("::1", false)]
        [InlineData("1.1.1.1", true)]
        [InlineData("192.168.1.1", true)]
        [InlineData("169.254.1.1", true)]
        [InlineData("126.255.255.255", true)]
        [InlineData("128.0.0.0", true)]
        [InlineData("2606:4700:4700::1111", true)]
        [InlineData("fe80::1", true)]
        [InlineData("fc00::1", true)]
        public void RuleScopeBlocksExternalAndLanButPreservesLoopback(string address, bool expected)
        {
            var candidate = IPAddress.Parse(address).GetAddressBytes();
            bool covered = SelfNetworkBlockRule.RemoteAddresses.Split(',').Any(range =>
            {
                var bounds = range.Split('-').Select(v => IPAddress.Parse(v).GetAddressBytes()).ToArray();
                return candidate.Length == bounds[0].Length
                    && Compare(candidate, bounds[0]) >= 0 && Compare(candidate, bounds[1]) <= 0;
            });
            Assert.Equal(expected, covered);
        }

        private static int Compare(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++) { int c = a[i].CompareTo(b[i]); if (c != 0) return c; }
            return 0;
        }

        private sealed class CountingHandler : HttpMessageHandler
        {
            public int Requests;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            { Requests++; throw new InvalidOperationException("No transport may be used"); }
        }

        [Fact]
        public async Task ReputationNeverContactsInjectedClientsEvenWithLegacyOnlineConfiguration()
        {
            var handler = new CountingHandler();
            using var client = new HttpClient(handler);
            var config = new ThreatReportingConfig { Enabled = true, ProxyEndpoint = "https://example.com", ProxySharedSecret = "old-installation-secret" };
            var service = new HashReputationService(null!, config, NullLogger<HashReputationService>.Instance, client, client, client);
            foreach (var hash in new[] { new string('0', 64), new string('a', 64), "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1" })
                Assert.Equal(HashVerdict.Unknown, await service.GetVerdictAsync(hash, sha1: new string('a', 40)));
            Assert.Equal(0, handler.Requests);
            Assert.False(config.Enabled);
            Assert.Null(config.ProxyEndpoint);
            Assert.Null(config.ProxySharedSecret);
            var reports = new AutoIncidentReportingConfig { MirrorEvidenceOffHost = true, ReportThreatIntel = true };
            Assert.False(reports.MirrorEvidenceOffHost);
            Assert.False(reports.ReportThreatIntel);
        }
    }
}
