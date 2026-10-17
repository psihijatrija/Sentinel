using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// B1 (durable evidence survival) - off-host evidence mirror contract (R2/R4/R5).
    /// Verifies fail-closed behavior, the signed request contract for /report/evidence,
    /// payload minimality (no secrets/file contents), and the opt-in config default.
    /// </summary>
    public class DurableEvidenceMirrorTests
    {
        [Fact]
        public void MirrorEvidenceOffHost_DefaultsToFalse()
        {
            // R5: opt-in. Off-host mirroring must be disabled on clean installs.
            Assert.False(new AutoIncidentReportingConfig().MirrorEvidenceOffHost);
        }

        [Fact]
        public void EvidenceSummary_SerializesWithoutSecretsOrFileContents()
        {
            var summary = new EvidenceSummary
            {
                ReportId = "AUTO_20260909_000000_TestRule_1000",
                SentinelVersion = "2.5.7",
                Host = "TEST-HOST",
                SealedUtc = DateTime.UtcNow.ToString("O"),
                Rule = "Active Ransomware Chain",
                SignalType = "Ransomware",
                Tier = "Tier1Behavioral",
                Confidence = 0.99,
                ProcessName = "evil.exe",
                ProcessId = 1000,
                Hashes = new[] { "a".PadRight(64, 'a') },
                Ips = new[] { "203.0.113.10" },
                Urls = new[] { "http://malicious.example/c2" },
                ManifestSha256 = "b".PadRight(64, 'b'),
                ManifestHmacSha256 = "c".PadRight(64, 'c')
            };

            var json = JsonSerializer.Serialize(summary);

            // Must carry the useful summary + origin proof...
            Assert.Contains("AUTO_20260909_000000_TestRule_1000", json);
            Assert.Contains("ManifestHmacSha256", json);

            // ...but never a shared secret or raw file content marker.
            Assert.Empty(ThreatReportingConfig.CompiledProxySharedSecret);
            Assert.DoesNotContain("ProxySharedSecret", json);
            Assert.DoesNotContain("BEGIN", json); // no embedded file blobs / PEM-style content
        }

        [Fact]
        public void EvidenceRoute_CannotCreateOutboundRequestWithLegacyCredentials()
        {
            var config = new ThreatReportingConfig { Enabled = true, ProxySharedSecret = "test-shared-secret-32chars!!!!" };
            var body = JsonSerializer.Serialize(new EvidenceSummary { ReportId = "R1" });
            var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost("https://example.test", "/report/evidence", body, config);
            Assert.Null(request);
            Assert.NotNull(error);
            Assert.False(config.Enabled);
            Assert.Null(config.ProxySharedSecret);
        }

        [Fact]
        public void EvidenceRoute_FailsClosed_WhenSecretMissingOrShort()
        {
            // R2/FR-11: fail closed - no signed request can be built without a valid secret.
            var config = new ThreatReportingConfig { ProxySharedSecret = "short" };
            var body = JsonSerializer.Serialize(new EvidenceSummary { ReportId = "R1" });

            var (request, err) = ProxyAuthHelper.CreateAuthenticatedPost(
                "https://example.test", "/report/evidence", body, config);

            Assert.Null(request);
            Assert.NotNull(err);
        }

        [Fact]
        public void ReportEvidenceAsync_NeverThrows_AndSkipsWhenDisabled()
        {
            // Fail-closed at the service level: disabled reporting => no-op, no throw.
            var config = new ThreatReportingConfig
            {
                Enabled = false,
                ProxyEndpoint = "https://example.test",
                ProxySharedSecret = "test-shared-secret-32chars!!!!"
            };
            var service = new ThreatReportService(
                config, Microsoft.Extensions.Logging.Abstractions.NullLogger<ThreatReportService>.Instance);

            var ex = Record.Exception(() =>
                service.ReportEvidenceAsync(new EvidenceSummary { ReportId = "R1" })
                       .GetAwaiter().GetResult());
            Assert.Null(ex);
        }

        [Fact]
        public void ReportEvidenceAsync_NeverThrows_OnNullSummary()
        {
            var config = new ThreatReportingConfig
            {
                Enabled = true,
                ProxyEndpoint = "https://example.test",
                ProxySharedSecret = "test-shared-secret-32chars!!!!"
            };
            var service = new ThreatReportService(
                config, Microsoft.Extensions.Logging.Abstractions.NullLogger<ThreatReportService>.Instance);

            var ex = Record.Exception(() =>
                service.ReportEvidenceAsync(null!).GetAwaiter().GetResult());
            Assert.Null(ex);
        }
    }
}
