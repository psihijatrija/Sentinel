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
            // State/progress tests do not emit detections or journal events. Avoid constructing
            // the response engine and Windows ACL-backed logger for an isolated registry test.
            return new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
        }

        [Fact]
        public void DisabledMonitor_IsReportedDisabled_NotRunning_NotFailed()
        {
            using var reg = NewRegistry(out var dir);
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
            using var reg = NewRegistry(out var dir);
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

        [Fact]
        public void StartupCompletionDoesNotBecomeFakeRunningAfterHeartbeat()
        {
            using var reg = NewRegistry(out var dir);
            try
            {
                reg.Register("OfflineLoader", MonitorCategory.ThreatIntel);
                reg.MarkCompleted("OfflineLoader", "Loaded offline bundle; no live feed.");
                reg.Heartbeat("OfflineLoader");
                reg.SupervisorHeartbeat("OfflineLoader");
                Assert.Equal(0, reg.GetStats().Running);
                Assert.Equal(1, reg.GetStats().Completed);
                Assert.Empty(reg.GetUnhealthyMonitors());
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void SupervisorLivenessCannotClearACollectionFailure()
        {
            using var reg = NewRegistry(out var dir);
            try
            {
                reg.Register("Dns", MonitorCategory.NetworkMonitoring);
                reg.MarkStarted("Dns");
                reg.ReportProgress("Dns", new SensorProgressSnapshot { State = "Failed", Error = "Access denied" });
                reg.SupervisorHeartbeat("Dns");
                Assert.Equal(1, reg.GetStats().Running);
                Assert.Equal(1, reg.GetStats().Unhealthy);
                Assert.Single(reg.GetUnhealthyMonitors());
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void WatchdogGracePreservesObservedHeartbeatEvidence()
        {
            using var reg = NewRegistry(out var dir);
            try
            {
                var old = DateTimeOffset.UtcNow.AddMinutes(-4);
                for (int i = 0; i < 4; i++)
                {
                    reg.Register("Stale" + i, MonitorCategory.SystemIntegrity);
                    reg.MarkStarted("Stale" + i);
                }
                foreach (var status in reg.GetAllStatuses()) status.LastHeartbeat = old;
                typeof(MonitorRegistry).GetMethod("WatchdogTick", System.Reflection.BindingFlags.Instance |
                    System.Reflection.BindingFlags.NonPublic)!.Invoke(reg, new object?[] { null });
                Assert.All(reg.GetAllStatuses(), status => Assert.Equal(old, status.LastHeartbeat));
                Assert.Equal(4, reg.GetStats().Unhealthy);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void VerifiedWorkerCanRecoverSchedulingTimeoutWithoutErasingCollectionError()
        {
            using var reg = NewRegistry(out var dir);
            try
            {
                reg.Register("Worker", MonitorCategory.SystemIntegrity);
                reg.MarkFailed("Worker", new InvalidOperationException("Heartbeat timeout (200s)"));
                reg.ReportProgress("Worker", new SensorProgressSnapshot { State = "Failed", Error = "Channel absent" });
                reg.SupervisorHeartbeat("Worker", workerVerified: true);
                Assert.Equal(1, reg.GetStats().Running);
                Assert.Equal(1, reg.GetStats().Unhealthy);
            }
            finally { TryDelete(dir); }
        }

        private static void TryDelete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }
}
