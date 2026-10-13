using System;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class V238DeliveryAndPinningTests
    {
        [Fact]
        public void CirclAndMalwareBazaarPins_AreWellFormedBase64Sha256()
        {
            Assert.True(ProxyAuthHelper.CirclHashlookupPins.Length >= 2);
            Assert.True(ProxyAuthHelper.MalwareBazaarPins.Length >= 2);
            foreach (var pin in ProxyAuthHelper.CirclHashlookupPins.Concat(ProxyAuthHelper.MalwareBazaarPins))
            {
                var bytes = Convert.FromBase64String(pin);
                Assert.Equal(32, bytes.Length);
            }
        }

        [Fact]
        public void ReputationPin_Mismatch_RejectsSelfSignedCert()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                "CN=SentinelPinMismatch",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            Assert.False(ProxyAuthHelper.IsPinMatch(cert, ProxyAuthHelper.CirclHashlookupPins));
            Assert.False(ProxyAuthHelper.IsPinMatch(cert, ProxyAuthHelper.MalwareBazaarPins));

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://hashlookup.circl.lu/");
            Assert.False(ProxyAuthHelper.ValidateCertificatePin(
                request, cert, chain: null, SslPolicyErrors.None, ProxyAuthHelper.CirclHashlookupPins));
        }

        [Fact]
        public void ReputationPin_SslError_IsRejectedEvenIfPinsEmptyCheck()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                "CN=SentinelPinSslFail",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://mb-api.abuse.ch/");
            Assert.False(ProxyAuthHelper.ValidateCertificatePin(
                request, cert, null, SslPolicyErrors.RemoteCertificateNameMismatch, ProxyAuthHelper.MalwareBazaarPins));
        }

        [Fact]
        public async Task GetVerdictAsync_UnknownOnPinOrTransportFailure_NeverSafe()
        {
            var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "rep_pin_" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                using var failing = new HttpClient(new PinMismatchHandler()) { Timeout = TimeSpan.FromSeconds(2) };
                var service = new HashReputationService(
                    cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance,
                    circlClient: failing, malwareBazaarClient: failing);

                var sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                var verdict = await service.GetVerdictAsync(sha256);

                Assert.Equal(HashVerdict.Unknown, verdict);
                Assert.NotEqual(HashVerdict.Safe, HashReputationService.UnknownOnPinnedLookupFailure());
            }
            finally
            {
                try { System.IO.Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void HostWideDeliveryFuel_RecognizesMotwIsoWpad()
        {
            Assert.True(BehavioralCorrelationEngine.IsHostWideDeliveryFuel(new DetectionEvent
            { RuleName = "CVE Class: Script Dropper Missing Mark-of-the-Web" }));
            Assert.True(BehavioralCorrelationEngine.IsHostWideDeliveryFuel(new DetectionEvent
            { RuleName = "CVE Class: Disk Image Missing Mark-of-the-Web" }));
            Assert.True(BehavioralCorrelationEngine.IsHostWideDeliveryFuel(new DetectionEvent
            { RuleName = "WPAD Auto-Proxy PAC Changed" }));
            Assert.False(BehavioralCorrelationEngine.IsHostWideDeliveryFuel(new DetectionEvent
            { RuleName = "Cast Device Guard: New Device" }));
        }

        [Fact]
        public async Task Composite_MotwHostWideFuel_PlusC2_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "CVE Class: Script Dropper Missing Mark-of-the-Web",
                ProcessId = 0,
                ProcessName = "drop.js",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing",
                ProcessId = 8181,
                ProcessName = "powershell",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal("MOTW Bypass Execution Chain", composite!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
        }

        [Fact]
        public async Task Composite_WpadHostWideFuel_PlusC2_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "WPAD Auto-Proxy PAC Changed",
                ProcessId = 0,
                ProcessName = "SYSTEM",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Data Exfil: Bulk Upload",
                ProcessId = 9191,
                ProcessName = "msedge",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal("WPAD Proxy Hijack Chain", composite!.RuleName);
        }

        [Fact]
        public void ScriptDropper_And_AppInstallerPackage_Extensions()
        {
            Assert.True(CveCoverageHeuristics.IsScriptDropperExtension(@"C:\Users\x\Downloads\payload.hta"));
            Assert.True(CveCoverageHeuristics.IsScriptDropperExtension("drop.ps1"));
            Assert.False(CveCoverageHeuristics.IsScriptDropperExtension("readme.txt"));
            Assert.True(CveCoverageHeuristics.IsAppInstallerPackagePath("evil.appx"));
            Assert.True(CveCoverageHeuristics.IsAppInstallerPackagePath("setup.appxbundle"));
            Assert.False(CveCoverageHeuristics.IsAppInstallerPackagePath("setup.exe"));
        }

        [Fact]
        public void AttackTechniqueMap_ScriptDropperMotw()
        {
            var ids = AttackTechniqueMap.Resolve("CVE Class: Script Dropper Missing Mark-of-the-Web");
            Assert.Contains("T1553.005", ids);
        }

        private sealed class PinMismatchHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromException<HttpResponseMessage>(
                    new HttpRequestException("The SSL connection could not be established (SPKI pin mismatch)."));
            }
        }
    }
}
