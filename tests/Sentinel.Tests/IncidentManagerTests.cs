using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class IncidentManagerTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly ProcessAncestryCache _ancestry;
        private readonly JsonlEventLogger _logger;
        private readonly IncidentManager _manager;

        public IncidentManagerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_inc_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _ancestry = new ProcessAncestryCache();
            _logger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            _manager = new IncidentManager(_ancestry, _logger, NullLogger<IncidentManager>.Instance);
        }

        public void Dispose()
        {
            _manager.Dispose();
            _logger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private DetectionEvent MakeDetection(int pid = 1000, string rule = "TestRule",
            double confidence = 0.80, DetectionTier tier = DetectionTier.Tier1Behavioral)
        {
            return new DetectionEvent
            {
                ProcessId = pid,
                ProcessName = "test.exe",
                RuleName = rule,
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>()
            };
        }

        [Fact]
        public void RegisterDetection_CreatesNewIncident()
        {
            var incident = _manager.RegisterDetection(MakeDetection());

            Assert.NotNull(incident);
            Assert.StartsWith("INC-", incident.Id);
            Assert.Equal(IncidentState.Open, incident.State);
            Assert.Single(incident.Detections);
        }

        [Fact]
        public void RegisterDetection_SamePid_GroupsIntoSameIncident()
        {
            var inc1 = _manager.RegisterDetection(MakeDetection(pid: 500, rule: "Rule1"));
            var inc2 = _manager.RegisterDetection(MakeDetection(pid: 500, rule: "Rule2"));

            Assert.Equal(inc1.Id, inc2.Id);
            Assert.Equal(2, inc1.Detections.Count);
        }

        [Fact]
        public void RegisterDetection_DifferentPids_CreatesSeparateIncidents()
        {
            var inc1 = _manager.RegisterDetection(MakeDetection(pid: 100));
            var inc2 = _manager.RegisterDetection(MakeDetection(pid: 200));

            Assert.NotEqual(inc1.Id, inc2.Id);
        }

        [Fact]
        public void RegisterDetection_TwoDetections_EscalatesToActive()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 300));
            Assert.Equal(IncidentState.Open, inc.State);

            _manager.RegisterDetection(MakeDetection(pid: 300, rule: "Rule2"));
            Assert.Equal(IncidentState.Active, inc.State);
        }

        [Fact]
        public void EscalateSeverity_HighConfidence_EscalatesToHigh()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 400, confidence: 0.85));
            Assert.True(inc.Severity >= IncidentSeverity.Medium);
        }

        [Fact]
        public void EscalateSeverity_ThreeTier1_BecomesCritical()
        {
            _manager.RegisterDetection(MakeDetection(pid: 500, rule: "R1", confidence: 0.80));
            _manager.RegisterDetection(MakeDetection(pid: 500, rule: "R2", confidence: 0.80));
            var inc = _manager.RegisterDetection(MakeDetection(pid: 500, rule: "R3", confidence: 0.80));

            Assert.Equal(IncidentSeverity.Critical, inc.Severity);
        }

        [Fact]
        public void MarkResponded_SetsRespondedState()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 600));
            _manager.MarkResponded(inc.Id, "KillProcessTree");

            Assert.Equal(IncidentState.Responded, inc.State);
            Assert.Equal("KillProcessTree", inc.ResponseAction);
            Assert.NotNull(inc.RespondedAt);
        }

        [Fact]
        public void MarkRespondedByPid_Works()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 700));
            _manager.MarkRespondedByPid(700, "Kill");

            Assert.Equal(IncidentState.Responded, inc.State);
        }

        [Fact]
        public void GetIncidentForPid_ReturnsCorrectIncident()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 800));
            var found = _manager.GetIncidentForPid(800);

            Assert.NotNull(found);
            Assert.Equal(inc.Id, found!.Id);
        }

        [Fact]
        public void GetIncidentForPid_ReturnsNull_ForUnknownPid()
        {
            var found = _manager.GetIncidentForPid(99999);
            Assert.Null(found);
        }

        [Fact]
        public void GetActiveIncidents_ExcludesClosed()
        {
            var inc = _manager.RegisterDetection(MakeDetection(pid: 900));
            _manager.MarkResponded(inc.Id, "Kill");

            // Force closed state
            inc.State = IncidentState.Closed;

            var active = _manager.GetActiveIncidents();
            Assert.DoesNotContain(active, i => i.Id == inc.Id);
        }

        [Fact]
        public void GetStats_ReportsCorrectly()
        {
            _manager.RegisterDetection(MakeDetection(pid: 1001));
            _manager.RegisterDetection(MakeDetection(pid: 1002));

            var stats = _manager.GetStats();
            Assert.Equal(2, stats.TotalCreated);
            Assert.Equal(2, stats.ActiveCount);
        }

        [Fact]
        public void Reinfection_GroupsByHash()
        {
            var d1 = MakeDetection(pid: 2000);
            d1.Metadata["SHA256"] = "aabbccdd";
            var inc1 = _manager.RegisterDetection(d1);

            var d2 = MakeDetection(pid: 2001);
            d2.Metadata["SHA256"] = "aabbccdd";
            var inc2 = _manager.RegisterDetection(d2);

            Assert.Equal(inc1.Id, inc2.Id);
            Assert.True(inc1.IsReinfection);
        }

        [Fact]
        public void Tier2Only_StaysLowSeverity()
        {
            var d = MakeDetection(pid: 3000, tier: DetectionTier.Tier2Indicator, confidence: 0.40);
            var inc = _manager.RegisterDetection(d);

            Assert.Equal(IncidentSeverity.Low, inc.Severity);
        }
    }
}
