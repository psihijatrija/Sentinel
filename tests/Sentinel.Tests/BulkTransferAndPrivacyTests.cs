using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.9.9 - bulk-transfer (torrent) must not seed Exfil chains; privacy services observe-only.
    /// </summary>
    public class BulkTransferAndPrivacyTests
    {
        [Theory]
        [InlineData("qbittorrent")]
        [InlineData("qBittorrent.exe")]
        [InlineData("uTorrent")]
        [InlineData("transmission-qt")]
        [InlineData("deluge")]
        [InlineData("aria2c")]
        [InlineData("tixati")]
        public void BulkTransferNoise_RecognizesKnownClients(string name)
        {
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName(name));
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("svchost")]
        [InlineData("malware")]
        [InlineData("")]
        [InlineData(null)]
        public void BulkTransferNoise_DoesNotMatchUnrelated(string? name)
        {
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName(name));
        }

        [Fact]
        public void Privacy_OptionalServiceOutbound_IsPureUxObserveNoise()
        {
            var d = new DetectionEvent
            {
                RuleName = "Privacy: Optional Service Outbound",
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Metadata = new Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                    ["ObserveOnly"] = "true",
                    ["ServiceName"] = "whesvc"
                }
            };

            Assert.True(ResponsePolicy.IsPureUxObserveNoise(d));
            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void BulkTransferUpload_IsPureUxAndNotExfilTerminal()
        {
            var d = new DetectionEvent
            {
                RuleName = "Traffic Anomaly: Bulk Transfer Upload (Observe)",
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Confidence = 0.40,
                Metadata = new Dictionary<string, string>
                {
                    ["BulkTransfer"] = "true",
                    ["WeakObserveSeed"] = "true",
                    ["ObserveOnly"] = "true",
                    ["BulkTransferClient"] = "qbittorrent"
                }
            };

            Assert.True(ResponsePolicy.IsPureUxObserveNoise(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
        }

        [Fact]
        public void OutboundVolumeSpike_RenamedRule_IsNotExfilTerminal()
        {
            // Old name "Data Exfiltration: Outbound Volume Spike" matched Exfil fragments.
            // New host-wide rule must not.
            var d = new DetectionEvent
            {
                RuleName = "Traffic Anomaly: Outbound Volume Spike",
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Confidence = 0.55,
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                    ["ObserveOnly"] = "true"
                }
            };

            Assert.True(ResponsePolicy.IsPureUxObserveNoise(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
        }

        [Fact]
        public void OldExfilVolumeRuleName_WouldClassifyAsExfil_DocumentedRegressionGuard()
        {
            // Documents why we renamed the rule - keep this classification as knowledge.
            var old = new DetectionEvent
            {
                RuleName = "Data Exfiltration: Outbound Volume Spike",
                Confidence = 0.90,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };
            Assert.Equal("Exfil", ResponsePolicy.ClassifyTerminalOutcome(old));
        }

        [Fact]
        public void ServiceExfilPosture_DefaultsToObserveEnabled()
        {
            var cfg = new SentinelConfig();
            Assert.NotNull(cfg.ServiceExfilPosture);
            Assert.True(cfg.ServiceExfilPosture.Enabled);
            Assert.Equal(ServiceExfilPostureMode.Observe, cfg.ServiceExfilPosture.Mode);
        }

        [Fact]
        public void PrivacyInventory_ContainsWhesvcAndDiagTrack()
        {
            Assert.Contains("whesvc", PrivacyServiceOutboundMonitor.DefaultInventory.Keys);
            Assert.Contains("DiagTrack", PrivacyServiceOutboundMonitor.DefaultInventory.Keys);
            Assert.Contains("EventLog", PrivacyServiceOutboundMonitor.DefaultNeverTouch);
            Assert.Contains("WinDefend", PrivacyServiceOutboundMonitor.DefaultNeverTouch);
        }

        [Fact]
        public void Privacy_IsNonPublicRemote_SkipsRfc1918()
        {
            Assert.True(PrivacyServiceOutboundMonitor.IsNonPublicRemote("10.0.0.1"));
            Assert.True(PrivacyServiceOutboundMonitor.IsNonPublicRemote("192.168.1.1"));
            Assert.True(PrivacyServiceOutboundMonitor.IsNonPublicRemote("172.16.5.5"));
            Assert.True(PrivacyServiceOutboundMonitor.IsNonPublicRemote("127.0.0.1"));
            Assert.False(PrivacyServiceOutboundMonitor.IsNonPublicRemote("8.8.8.8"));
            Assert.False(PrivacyServiceOutboundMonitor.IsNonPublicRemote("1.1.1.1"));
        }

        [Fact]
        public async Task PrivacyServiceOutboundMonitor_StartsAndStopsCleanly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_privacy_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var config = new SentinelConfig { ActiveResponse = false };
                var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
                var responseEngine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(tempDir));
                var iocScanner = new IoCScanner(cache);
                var reputationService = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
                var correlationEngine = new BehavioralCorrelationEngine();
                var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
                var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
                var fileReputationEngine = new FileReputationEngine(reputationService, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);

                var engine = new DetectionEngine(
                    new List<IDetectionRule>(), metrics, logger, responseEngine,
                    iocScanner, reputationService, fileReputationEngine, correlationEngine, scoringEngine,
                    NullLogger<DetectionEngine>.Instance);

                var map = new ServiceProcessMap(NullLogger<ServiceProcessMap>.Instance);
                var monitor = new PrivacyServiceOutboundMonitor(
                    engine, map, config, NullLogger<PrivacyServiceOutboundMonitor>.Instance);

                await monitor.StartAsync(CancellationToken.None);
                await Task.Delay(80);
                await monitor.StopAsync(CancellationToken.None);

                engine.Stop();
                await logger.DisposeAsync();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void ServiceProcessMap_Refresh_DoesNotThrow()
        {
            var map = new ServiceProcessMap();
            map.Refresh(TimeSpan.Zero);
            Assert.True(map.MappedServiceCount >= 0);
            _ = map.TryGetPidForService("EventLog", out _);
            _ = map.GetDisplayName("EventLog");
        }
    }
}
