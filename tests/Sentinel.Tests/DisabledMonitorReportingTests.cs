using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Sentinel.Core.Monitors;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// A monitor that is intentionally off (optional feature disabled by config, or a
    /// genuinely-absent OS capability) must be reported HONESTLY as disabled - never counted
    /// as running, never flagged as failed, and never resurrected by a stray heartbeat. This
    /// is the correct fix for the miscounted EtwThreatIntelMonitor (off by default via
    /// EnableIntelThreatIntel=false), replacing the earlier behaviour where a non-heartbeating
    /// no-op was watchdog-killed and the dashboard read "needs attention".
    ///
    /// These assert registry state transitions directly (the watchdog only ever acts on the
    /// Running state, so a Disabled monitor is structurally exempt from it). No detection tier
    /// or response contract is involved in this change.
    /// </summary>
    public class DisabledMonitorReportingTests
    {
        private static MonitorRegistry NewRegistry(out string tempDir)
        {
            tempDir = Path.Combine(Path.GetTempPath(), "sentinel_test_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(tempDir);
            var eventLogger = new JsonlEventLogger(Path.Combine(tempDir, "events.jsonl"));
            var metrics = new SentinelMetrics();
            var responseEngine = new AdvancedResponseEngine(
                new SentinelConfig { ActiveResponse = false }, metrics, eventLogger, new QuarantineManager(tempDir));
            var cache = new SecureCacheStore(tempDir);
            var iocScanner = new IoCScanner(cache);
            var reputation = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance, signerTrust);
            var fileRep = new FileReputationEngine(reputation, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);
            var scoring = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var detectionEngine = new DetectionEngine(
                new System.Collections.Generic.List<IDetectionRule>(), metrics, eventLogger, responseEngine,
                iocScanner, reputation, fileRep, new BehavioralCorrelationEngine(), scoring,
                NullLogger<DetectionEngine>.Instance);
            return new MonitorRegistry(detectionEngine, eventLogger, NullLogger<MonitorRegistry>.Instance);
        }

        [Fact]
        public void DisabledMonitor_IsReportedDisabled_NotRunning_NotFailed()
        {
            var reg = NewRegistry(out var dir);
            try
            {
                reg.Register("OptionalX", MonitorCategory.ThreatIntel, null);
                reg.MarkDisabled("OptionalX", "off by config");

                var stats = reg.GetStats();
                Assert.Equal(1, stats.TotalRegistered);
                Assert.Equal(0, stats.Running);   // never padded into the running count
                Assert.Equal(0, stats.Failed);    // disabled is NOT a failure
                Assert.Equal(1, stats.Disabled);  // surfaced honestly in its own bucket

                // And it must not appear in the unhealthy set that drives "needs attention".
                Assert.DoesNotContain(reg.GetUnhealthyMonitors(), m => m.Name == "OptionalX");
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Heartbeat_DoesNotResurrectADisabledMonitor()
        {
            var reg = NewRegistry(out var dir);
            try
            {
                reg.Register("OptionalX", MonitorCategory.ThreatIntel, null);
                reg.MarkDisabled("OptionalX", "off by config");

                // A blanket owned-monitor heartbeat loop must not fake liveness on a monitor
                // that is deliberately not running.
                reg.Heartbeat("OptionalX");

                Assert.Equal(0, reg.GetStats().Running);
                Assert.Equal(1, reg.GetStats().Disabled);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void GenericDisabledMonitor_CarriesTheMarkerAndAReason()
        {
            var m = new DisabledMonitor<EtwThreatIntelMonitor>(NullLogger<DisabledMonitor<EtwThreatIntelMonitor>>.Instance);
            Assert.IsAssignableFrom<IMonitor>(m);
            Assert.IsAssignableFrom<IDisabledMonitor>(m);
            Assert.Equal("EtwThreatIntelMonitor", m.Name);
            Assert.False(string.IsNullOrWhiteSpace(((IDisabledMonitor)m).DisabledReason));
        }

        private static void TryDelete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }
}
