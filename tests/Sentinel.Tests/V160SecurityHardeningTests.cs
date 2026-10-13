using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>v1.6.0 audit-remediation unit tests.</summary>
    public class V160SecurityHardeningTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelMetrics _metrics;

        public V160SecurityHardeningTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_v160_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _metrics = new SentinelMetrics();
        }

        public void Dispose()
        {
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void SentinelConfig_Defaults_EnforceActiveResponseAndKillBudget()
        {
            var cfg = new SentinelConfig();
            Assert.True(cfg.ActiveResponse);
            // v2.0.4: EnforceActiveResponse defaults to true (red team audit CRIT-3)
            Assert.True(cfg.EnforceActiveResponse);
            // v2.9.4: armed-by-default posture - respond on single Tier1 signals, do not
            // wait for a multi-signal chain (post-incident hardening on this product line).
            Assert.False(cfg.ObserveUntilChain);
            Assert.Equal(15, cfg.MaxKillsPerMinute);
        }

        [Fact]
        public async Task AdvancedResponseEngine_RateLimitsKills()
        {
            var config = new SentinelConfig
            {
                ActiveResponse = true, ObserveUntilChain = false,
                MaxKillsPerMinute = 3
            };
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "q"));
            var engine = new AdvancedResponseEngine(config, _metrics, _eventLogger, quarantine);

            // Emit more kill-authorized detections than the budget allows.
            // Use a non-existent PID so SafeKillProcessTree is a no-op / fails soft.
            // KillAuthorized is derived from AuthorizedResponse >= KillProcess.
            for (int i = 0; i < 5; i++)
            {
                await engine.HandleAsync(new DetectionEvent
                {
                    RuleName = "TestKillRule",
                    ProcessId = 999990 + i,
                    ProcessName = "nonexistent_test_proc",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcess,
                    SignalType = SignalType.SuspiciousProcess
                });
            }

            // Read response log with share-read (logger may still hold the handle)
            var logPath = Path.Combine(_tempDir, "events.jsonl");
            Assert.True(File.Exists(logPath));
            string text;
            using (var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(fs))
            {
                text = await reader.ReadToEndAsync();
            }
            Assert.True(
                text.Contains("RATE_LIMITED", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("rate-limited", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("MaxKillsPerMinute", StringComparison.OrdinalIgnoreCase),
                "Expected kill rate-limit evidence in event log. Log was:\n" + text);
        }

        [Fact]
        public async Task ThreatReportService_SkipsWithoutSharedSecret()
        {
            var config = new ThreatReportingConfig
            {
                Enabled = true,
                ProxyEndpoint = "https://example.invalid",
                ProxySharedSecret = null
            };
            var svc = new ThreatReportService(config, NullLogger<ThreatReportService>.Instance);
            Assert.NotNull(svc);
            await svc.ReportHashAsync("a" + new string('0', 63), Array.Empty<string>(), "test");
        }

        [Fact]
        public async Task AntiTamperGuard_ForcesActiveResponseAtStartup()
        {
            var config = new SentinelConfig
            {
                ActiveResponse = false,
                EnforceActiveResponse = true, ObserveUntilChain = false
            };

            var cacheStore = new SecureCacheStore(_tempDir);
            var allowlist = new AllowlistService(cacheStore, NullLogger<AllowlistService>.Instance);
            var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var correlationEngine = new BehavioralCorrelationEngine();
            var hashRepService = new HashReputationService(cacheStore, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var iocScanner = new IoCScanner(cacheStore);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileRepEngine = new FileReputationEngine(hashRepService, signerTrust, cacheStore, NullLogger<FileReputationEngine>.Instance);
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "quarantine"));
            var responseEngine = new AdvancedResponseEngine(config, _metrics, _eventLogger, quarantine, allowlist);
            var detectionEngine = new DetectionEngine(
                new List<IDetectionRule>(), _metrics, _eventLogger, responseEngine,
                iocScanner, hashRepService, fileRepEngine, correlationEngine, scoringEngine,
                NullLogger<DetectionEngine>.Instance);

            var guard = new AntiTamperGuard(
                detectionEngine, _eventLogger, config, NullLogger<AntiTamperGuard>.Instance);

            await guard.StartAsync(default);
            Assert.True(config.ActiveResponse);

            guard.Dispose();
            detectionEngine.Stop();
        }
    }
}
