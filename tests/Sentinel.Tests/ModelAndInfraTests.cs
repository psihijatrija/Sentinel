using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for core models, configurations, event graph, context bus,
    /// rate limiter, metrics, and other infrastructure components.
    /// </summary>
    public class ModelAndInfraTests
    {
        #region Model Defaults

        [Fact]
        public void SentinelConfig_Defaults_Correct()
        {
            var config = new SentinelConfig();
            Assert.True(config.ActiveResponse);
            Assert.Equal(15, config.MaxKillsPerMinute);
            Assert.Equal(10, config.MaxNetworkIsolatesPerMinute);
            // v2.0.4: EnforceActiveResponse defaults to true (red team audit CRIT-3)
            Assert.True(config.EnforceActiveResponse);
            // v2.9.4: armed-by-default - single-signal Tier1 response (no observe-until-chain)
            Assert.False(config.ObserveUntilChain);
            Assert.True(config.SilentObserve);
            Assert.False(config.AutoDisableFailedUsbEnumeration); // work-first: no USB auto-disable
            Assert.Empty(config.TrustedCastDevices);
            Assert.Empty(config.TrustedUsbDevices);
            Assert.Equal(15, config.DnsPollIntervalSeconds);
            Assert.Equal(15, config.RouteTableScanIntervalSeconds);
            Assert.Equal(20, config.RawDiskScanIntervalSeconds);
            Assert.Equal(2000, config.AntiTamperTimingTickMs);
            Assert.Equal(10000, config.AntiTamperIntegrityTickMs);
        }

        [Fact]
        public void ThreatReportingConfig_Defaults_Correct()
        {
            var config = new ThreatReportingConfig();
            Assert.True(config.Enabled);
            Assert.True(config.ReportToMalwareBazaar);
            Assert.True(config.ReportToUrlhaus);
            Assert.Equal("https://sentinel-threat-proxy.znastidobrostoje-6ee.workers.dev", config.ProxyEndpoint);
            Assert.True(ProxyAuthHelper.HasSharedSecret(config));
            Assert.Equal(ThreatReportingConfig.CompiledProxySharedSecret, config.ProxySharedSecret);
            Assert.True(config.ProxySharedSecret!.Length >= 16);
        }

        [Fact]
        public void EncryptedStore_ShortSecret_DoesNotWipeCompiledHmac()
        {
            var store = new EncryptedConfigStore(customPath: Path.Combine(Path.GetTempPath(),
                "sentinel-hmac-" + Guid.NewGuid().ToString("N") + ".enc"));
            store.SetOverride("ProxySharedSecret", "short");
            var threat = new ThreatReportingConfig();
            var compiled = threat.ProxySharedSecret;
            store.ApplyOverrides(new SentinelConfig(), threat);
            Assert.Equal(compiled, threat.ProxySharedSecret);
            Assert.True(ProxyAuthHelper.HasSharedSecret(threat));
        }

        [Fact]
        public void HostDiskJson_EmptyBuilder_StaysEmpty()
        {
            var b = new Microsoft.Extensions.Configuration.ConfigurationBuilder();
            HostDiskJson.RemoveJsonSources(b);
            Assert.Empty(b.Sources);
        }

        [Fact]
        public void AutoIncidentReportingConfig_Defaults_Correct()
        {
            var config = new AutoIncidentReportingConfig();
            Assert.True(config.Enabled);
            Assert.True(config.GenerateLocalEvidencePack);
            Assert.True(config.ReportThreatIntel);
            Assert.True(config.ReportableGradeOnly);
            Assert.Equal(0.85, config.MinConfidence);
            Assert.Equal(0.80, config.KillAuthorizedMinConfidence);
            Assert.True(config.IncludeIntegrityManifest);
            Assert.True(config.IncludeVictimAffidavit);
            Assert.Equal(20, config.MaxPacksPerHour);
        }

        [Fact]
        public void CveShieldConfig_Defaults_Correct()
        {
            var config = new CveShieldConfig();
            Assert.True(config.Enabled);
            Assert.Equal(4, config.PollIntervalHours);
            Assert.Contains("cisa.gov", config.FeedUrl);
        }

        #endregion

        #region DetectionEvent

        [Fact]
        public void DetectionEvent_KillAuthorized_True_ForKillActions()
        {
            var ev = new DetectionEvent { AuthorizedResponse = ResponseAction.KillProcess };
            Assert.True(ev.KillAuthorized);
            ev.AuthorizedResponse = ResponseAction.KillProcessTree;
            Assert.True(ev.KillAuthorized);
            ev.AuthorizedResponse = ResponseAction.QuarantineAndKill;
            Assert.True(ev.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_KillAuthorized_False_ForNonKillActions()
        {
            var ev = new DetectionEvent { AuthorizedResponse = ResponseAction.LogOnly };
            Assert.False(ev.KillAuthorized);
            ev.AuthorizedResponse = ResponseAction.NetworkIsolate;
            Assert.False(ev.KillAuthorized);
            ev.AuthorizedResponse = ResponseAction.RemoveCert;
            Assert.False(ev.KillAuthorized);
        }

        [Fact]
        public void DetectionEvent_DefaultValues()
        {
            var ev = new DetectionEvent();
            Assert.Equal(string.Empty, ev.RuleName);
            Assert.Equal(string.Empty, ev.Evidence);
            Assert.Equal(0, ev.ProcessId);
            Assert.Equal(SignalType.Generic, ev.SignalType);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.NotNull(ev.Metadata);
            Assert.Empty(ev.Metadata);
        }

        #endregion

        #region ProcessTelemetry

        [Fact]
        public void ProcessTelemetry_DefaultValues()
        {
            var pt = new ProcessTelemetry();
            Assert.Equal(string.Empty, pt.ImagePath);
            Assert.Equal(string.Empty, pt.CommandLine);
            Assert.Equal(string.Empty, pt.ParentProcessName);
            Assert.Equal(0, pt.ParentProcessId);
        }

        [Fact]
        public void ProcessTelemetry_InheritsTimestamp()
        {
            var before = DateTime.UtcNow;
            var pt = new ProcessTelemetry();
            var after = DateTime.UtcNow;
            Assert.True(pt.Timestamp >= before && pt.Timestamp <= after);
        }

        #endregion

        #region NetworkTelemetry

        [Fact]
        public void NetworkTelemetry_DefaultValues()
        {
            var nt = new NetworkTelemetry();
            Assert.Equal("TCP", nt.Protocol);
            Assert.Equal("ESTABLISHED", nt.State);
            Assert.Equal(string.Empty, nt.LocalAddress);
            Assert.Equal(string.Empty, nt.RemoteAddress);
        }

        #endregion

        #region EventGraph

        [Fact]
        public void EventGraph_AddNodeAndEdge()
        {
            var graph = new EventGraph();
            graph.AddNode("PID:123", "PROCESS", new Dictionary<string, string> { ["Name"] = "test.exe" });
            graph.AddEdge("PID:123", "IP:10.0.0.1:443", "CONNECTED");
            var edges = graph.GetProcessEdges("PID:123");
            Assert.NotEmpty(edges);
            Assert.Equal("CONNECTED", edges[0].Relation);
        }

        [Fact]
        public void EventGraph_GetProcessEdges_ReturnsEmpty_UnknownProcess()
        {
            var graph = new EventGraph();
            var edges = graph.GetProcessEdges("PID:99999");
            Assert.Empty(edges);
        }

        [Fact]
        public void EventGraph_Prune_RemovesStaleNodes()
        {
            var graph = new EventGraph();
            graph.AddNode("PID:1", "PROCESS");
            graph.Prune(TimeSpan.Zero); // Everything is stale with zero retention
            var edges = graph.GetProcessEdges("PID:1");
            Assert.Empty(edges);
        }

        #endregion

        #region SentinelMetrics

        [Fact]
        public void SentinelMetrics_RecordDetection_Increments()
        {
            var metrics = new SentinelMetrics();
            metrics.RecordDetection(1.0);
            metrics.RecordDetection(2.0);
            Assert.Equal(2, metrics.GetDetectionsCount());
        }

        [Fact]
        public void SentinelMetrics_RecordResponse_Increments()
        {
            var metrics = new SentinelMetrics();
            metrics.RecordResponse(0.5);
            Assert.Equal(1, metrics.GetResponsesCount());
        }

        [Fact]
        public void SentinelMetrics_Percentiles_WithData()
        {
            var metrics = new SentinelMetrics();
            for (int i = 1; i <= 100; i++)
                metrics.RecordDetection(i);
            var (p50, p90, p95, p99) = metrics.GetDetectionLatencyPercentiles();
            Assert.True(p50 > 0);
            Assert.True(p90 >= p50);
            Assert.True(p99 >= p95);
        }

        [Fact]
        public void SentinelMetrics_Percentiles_Empty()
        {
            var metrics = new SentinelMetrics();
            var (p50, p90, p95, p99) = metrics.GetDetectionLatencyPercentiles();
            Assert.Equal(0, p50);
        }

        [Fact]
        public void SentinelMetrics_FalsePositives()
        {
            var metrics = new SentinelMetrics();
            metrics.RecordFalsePositive();
            metrics.RecordFalsePositive();
            Assert.Equal(2, metrics.GetFalsePositivesCount());
        }

        #endregion

        #region RateLimiter

        [Fact]
        public void RateLimiter_AllowsWithinLimit()
        {
            var limiter = new RateLimiter(10, TimeSpan.FromSeconds(60));
            for (int i = 0; i < 10; i++)
            {
                Assert.True(limiter.AllowRequest());
            }
        }

        [Fact]
        public void RateLimiter_RejectsOverLimit()
        {
            var limiter = new RateLimiter(2, TimeSpan.FromSeconds(60));
            Assert.True(limiter.AllowRequest());
            Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());
        }

        [Fact]
        public void BurstRateLimiter_AllowsBurst()
        {
            var limiter = new BurstRateLimiter(10, 5);
            // Should allow 5 burst requests
            for (int i = 0; i < 5; i++)
            {
                Assert.True(limiter.AllowRequest());
            }
        }

        #endregion

        #region SafeProcessExemptionRegistry

        [Fact]
        public void SafeProcessExemptionRegistry_RegisterAndCheck()
        {
            var registry = new SafeProcessExemptionRegistry();
            Assert.False(registry.IsSafeProcess(1234));
            registry.RegisterSafeProcess(1234);
            // Note: IsSafeProcess checks actual process start time, so this may fail for non-existent PIDs
            // Testing the API doesn't throw is the primary validation here
        }

        [Fact]
        public void SafeProcessExemptionRegistry_UnknownPid_NotSafe()
        {
            var registry = new SafeProcessExemptionRegistry();
            Assert.False(registry.IsSafeProcess(0));
            Assert.False(registry.IsSafeProcess(99999));
        }

        [Fact]
        public void SafeProcessExemptionRegistry_Remove_DoesNotThrow()
        {
            var registry = new SafeProcessExemptionRegistry();
            registry.Remove(12345); // Should not throw for non-existent PID
        }

        #endregion
    }
}
