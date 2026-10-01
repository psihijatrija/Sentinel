using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.8.2 - Agentic AI + package supply-chain runtime monitors.
    /// </summary>
    public class V182FeatureTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ProcessAncestryCache _ancestryCache;

        public V182FeatureTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_V182_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _eventLogger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            var metrics = new SentinelMetrics();
            var config = new SentinelConfig { ActiveResponse = false, EnforceActiveResponse = false };
            var cacheStore = new SecureCacheStore(_tempDir);
            var allowlist = new AllowlistService(cacheStore, NullLogger<AllowlistService>.Instance);
            var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var correlationEngine = new BehavioralCorrelationEngine();
            var hashRepService = new HashReputationService(cacheStore, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var iocScanner = new IoCScanner(cacheStore);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileRepEngine = new FileReputationEngine(hashRepService, signerTrust, cacheStore, NullLogger<FileReputationEngine>.Instance);
            var quarantine = new QuarantineManager(Path.Combine(_tempDir, "quarantine"));
            var responseEngine = new AdvancedResponseEngine(config, metrics, _eventLogger, quarantine, allowlist);

            _detectionEngine = new DetectionEngine(
                new List<IDetectionRule>(), metrics, _eventLogger, responseEngine,
                iocScanner, hashRepService, fileRepEngine, correlationEngine, scoringEngine,
                NullLogger<DetectionEngine>.Instance);
            _ancestryCache = new ProcessAncestryCache();
        }

        public void Dispose()
        {
            _detectionEngine.Stop();
            _ancestryCache.Dispose();
            _eventLogger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { /* best effort */ }
        }

        [Fact]
        public void AgenticProcessMonitor_CanBeConstructed()
        {
            using var mon = new AgenticProcessMonitor(
                _detectionEngine, _ancestryCache, NullLogger<AgenticProcessMonitor>.Instance);
            Assert.NotNull(mon);
        }

        [Fact]
        public void PackageRuntimeMonitor_CanBeConstructed()
        {
            using var mon = new PackageRuntimeMonitor(
                _detectionEngine, _ancestryCache, NullLogger<PackageRuntimeMonitor>.Instance);
            Assert.NotNull(mon);
        }

        [Fact]
        public async Task AgenticProcessMonitor_StartsAndStopsCleanly()
        {
            using var mon = new AgenticProcessMonitor(
                _detectionEngine, _ancestryCache, NullLogger<AgenticProcessMonitor>.Instance);
            await mon.StartAsync(CancellationToken.None);
            await Task.Delay(150);
            await mon.StopAsync(CancellationToken.None);
        }

        [Fact]
        public async Task PackageRuntimeMonitor_StartsAndStopsCleanly()
        {
            using var mon = new PackageRuntimeMonitor(
                _detectionEngine, _ancestryCache, NullLogger<PackageRuntimeMonitor>.Instance);
            await mon.StartAsync(CancellationToken.None);
            await Task.Delay(150);
            await mon.StopAsync(CancellationToken.None);
        }
    }
}
