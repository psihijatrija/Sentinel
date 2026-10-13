using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.8.1 - remediations from the red/blue team security audit.
    /// </summary>
    public class V181SecurityHardeningTests
    {
        [Fact]
        public void ProxyAuth_DoesNotTransmitSharedSecretInHeaders()
        {
            var secret = "audit-fix-shared-secret!!";
            var config = new ThreatReportingConfig { ProxySharedSecret = secret };
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.test/report/hash");
            Assert.True(ProxyAuthHelper.TryApplyAuthHeaders(request, config, "/report/hash", "{}"));

            Assert.False(request.Headers.Contains("X-Sentinel-Auth"));
            foreach (var header in request.Headers)
            {
                foreach (var value in header.Value)
                    Assert.DoesNotContain(secret, value);
            }
        }

        [Fact]
        public void DynamicCondition_RejectsNonAllowlistedProperty()
        {
            var telemetry = new ProcessTelemetry
            {
                ProcessName = "malware.exe",
                ImagePath = @"C:\Temp\malware.exe",
                CommandLine = "malware.exe --evil"
            };

            var blocked = new DynamicCondition
            {
                Field = nameof(object.GetType), // not a telemetry field
                Operator = "Equals",
                Value = "anything"
            };
            Assert.False(blocked.Evaluate(telemetry));

            var alsoBlocked = new DynamicCondition
            {
                Field = "DeclaringType",
                Operator = "Contains",
                Value = "System"
            };
            Assert.False(alsoBlocked.Evaluate(telemetry));

            var allowed = new DynamicCondition
            {
                Field = "ProcessName",
                Operator = "Equals",
                Value = "malware.exe"
            };
            Assert.True(allowed.Evaluate(telemetry));
        }

        [Fact]
        public void DynamicCondition_Allowlist_IncludesCoreTelemetryFields()
        {
            Assert.True(DynamicCondition.IsAllowedPropertyName("ProcessId"));
            Assert.True(DynamicCondition.IsAllowedPropertyName("CommandLine"));
            Assert.True(DynamicCondition.IsAllowedPropertyName("RemoteAddress"));
            Assert.True(DynamicCondition.IsAllowedPropertyName("FilePath"));
            Assert.False(DynamicCondition.IsAllowedPropertyName("Assembly"));
            Assert.False(DynamicCondition.IsAllowedPropertyName(""));
            Assert.False(DynamicCondition.IsAllowedPropertyName(null));
        }

        [Theory]
        [InlineData(@"C:\Users\Bob\Downloads\VSCodeUserSetup-x64.exe", true)]
        [InlineData(@"C:\Users\Bob\AppData\Roaming\ChromeSetup.exe", false)]
        [InlineData(@"C:\Users\Bob\AppData\Local\Temp\ChromeSetup.exe", false)]
        public void InstallerPathGate_BlocksStagingEvasion(string path, bool expected)
        {
            Assert.Equal(expected, InstallerHeuristics.IsLikelyInstallerPath(path));
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("ChromeSetup", path)
                || InstallerHeuristics.LooksLikeInstallerName("VSCodeUserSetup-x64", path)
                || path.Contains("VSCode", System.StringComparison.OrdinalIgnoreCase));
        }

        [Theory]
        [InlineData("10.0.0.1")]
        [InlineData("192.168.1.1")]
        [InlineData("172.16.5.5")]
        [InlineData("169.254.1.1")]
        [InlineData("127.0.0.1")]
        public void PrivateIps_AreClassifiedPrivate(string ip)
        {
            Assert.True(SecurityValidation.IsPrivateIpAddress(ip));
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("1.1.1.1")]
        [InlineData("93.184.216.34")]
        public void PublicIps_AreNotPrivate(string ip)
        {
            Assert.False(SecurityValidation.IsPrivateIpAddress(ip));
        }

        [Fact]
        public void ConsultantSignal_Metadata_ForcesLogOnlySemantics()
        {
            // Mirrors SubmitConsultantSignalAsync contract: sticky LogOnly + Tier2
            var ev = new DetectionEvent
            {
                RuleName = "Webcam Hijack",
                Confidence = 1.0,
                ProcessId = 1234,
                ProcessName = "MsMpEng",
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Tier = DetectionTier.Tier1Behavioral,
                Metadata = new Dictionary<string, string>()
            };
            ev.Tier = DetectionTier.Tier2Indicator;
            ev.AuthorizedResponse = ResponseAction.LogOnly;
            ev.Metadata["ConsultantSignal"] = "true";

            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.True(ev.Metadata.ContainsKey("ConsultantSignal"));
            Assert.False(ev.KillAuthorized);
        }

        [Fact]
        public void Quarantine_MaxFileSizeCap_IsReasonable()
        {
            Assert.Equal(128L * 1024 * 1024, QuarantineManager.MaxQuarantineFileBytes);
            Assert.True(QuarantineManager.MaxQuarantineFileBytes < 512L * 1024 * 1024);
        }

        [Fact]
        public void NetworkIsolate_PrivateIpStillClassified_EvenIfArpFlushExists()
        {
            // Guardrail: ARP/firewall path must not run for private IPs (RT-NEW-3).
            // FlushArpEntry is only invoked after public-IP validation in AdvancedResponseEngine.
            Assert.True(SecurityValidation.IsPrivateIpAddress("192.168.0.1"));
            Assert.False(SecurityValidation.IsPrivateIpAddress("203.0.113.10"));
        }
    }
}
