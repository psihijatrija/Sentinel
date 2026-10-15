using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class IncidentRecoveryTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-recovery-" + Guid.NewGuid().ToString("N"));
        private readonly ProcessAncestryCache _ancestry = new();
        private readonly JsonlEventLogger _events;
        private string StatePath => Path.Combine(_directory, "state.json");

        public IncidentRecoveryTests()
        {
            Directory.CreateDirectory(_directory);
            _events = new JsonlEventLogger(Path.Combine(_directory, "events.jsonl"));
        }

        private IncidentManager Create(IIncidentStateStore? store = null) => new(_ancestry, _events,
            NullLogger<IncidentManager>.Instance, store ?? new IncidentStateStore(StatePath));
        private static DetectionEvent Detection(int pid) => new()
        {
            ProcessId = pid, RuleName = "Recovery test", Confidence = 0.5,
            Tier = DetectionTier.Tier2Indicator,
            Metadata = new Dictionary<string, string> { ["SHA256"] = "same-hash" }
        };

        [Fact]
        public void Restart_PreservesTimelineButDoesNotRestorePidOrHashAuthority()
        {
            string id;
            using (var first = Create())
            {
                var incident = first.RegisterDetection(Detection(12345));
                id = incident.Id;
                first.MarkResponded(id, "KillProcess");
            }
            using var second = Create();
            var recovered = Assert.Single(second.GetActiveIncidents());
            Assert.Equal(id, recovered.Id);
            Assert.True(recovered.RecoveredHistory);
            Assert.Equal("KillProcess", recovered.ResponseAction);
            Assert.Single(recovered.Detections);
            Assert.Null(second.GetIncidentForPid(12345));
            second.MarkRespondedByPid(12345, "must-not-replay");
            Assert.Equal("KillProcess", recovered.ResponseAction);
            var current = second.RegisterDetection(Detection(12345));
            Assert.NotEqual(id, current.Id);
            Assert.False(current.RecoveredHistory);
            Assert.Equal(2, second.GetStats().TotalCreated);
        }

        [Fact]
        public void CorruptState_IsRetainedAndDoesNotStopDetection()
        {
            File.WriteAllText(StatePath, "{truncated");
            using var manager = Create();
            Assert.True(manager.PersistenceDegraded);
            Assert.NotNull(manager.RegisterDetection(Detection(12345)));
            Assert.True(manager.PersistenceDegraded);
            Assert.Equal("{truncated", File.ReadAllText(StatePath));
        }

        [Fact]
        public void AtomicReplacement_RetainsLatestResponseAndLeavesNoTemporaryFiles()
        {
            using (var manager = Create())
            {
                var incident = manager.RegisterDetection(Detection(12345));
                manager.RegisterDetection(Detection(12345));
                manager.MarkResponded(incident.Id, "Quarantine");
            }
            var snapshot = new IncidentStateStore(StatePath).Load();
            var saved = Assert.Single(snapshot.Incidents);
            Assert.Equal(2, saved.Detections.Count);
            Assert.Equal(IncidentState.Responded, saved.State);
            Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
        }

        [Fact]
        public void UnsupportedSchema_IsNotSilentlyReplaced()
        {
            File.WriteAllText(StatePath, "{\"SchemaVersion\":99}");
            var store = new IncidentStateStore(StatePath);
            Assert.Throws<InvalidDataException>(() => store.Load());
            Assert.Throws<InvalidDataException>(() => store.Save(new IncidentStateSnapshot()));
            Assert.Contains("99", File.ReadAllText(StatePath));
        }

        [Fact]
        public void TimelineIsBoundedAndCallerMutationCannotRewriteHistory()
        {
            using var manager = new IncidentManager(_ancestry, _events, NullLogger<IncidentManager>.Instance);
            var detection = Detection(12345);
            var incident = manager.RegisterDetection(detection);
            detection.RuleName = "changed-after-registration";
            detection.Metadata["SHA256"] = "changed";
            for (int i = 1; i < 300; i++) manager.RegisterDetection(Detection(12345));
            Assert.Equal(300, incident.TotalDetectionCount);
            Assert.Equal(44, incident.OmittedDetectionCount);
            Assert.Equal(256, incident.Detections.Count);
            Assert.DoesNotContain(incident.Detections, d => d.DetectionEvent.RuleName == "changed-after-registration");
            Assert.All(incident.Detections, d => Assert.Equal("same-hash", d.DetectionEvent.Metadata["SHA256"]));
        }

        [Fact]
        public void ConcurrentFirstDetections_CreateOneIncidentAndPersistEveryDetection()
        {
            using var manager = Create();
            System.Threading.Tasks.Parallel.For(0, 20, _ => manager.RegisterDetection(Detection(12345)));
            Assert.Single(manager.GetActiveIncidents());
            var state = new IncidentStateStore(StatePath).Load();
            Assert.Equal(20, Assert.Single(state.Incidents).Detections.Count);
        }

        [Fact]
        public void OversizedCheckpointDoesNotReplaceLastValidState()
        {
            var store = new IncidentStateStore(StatePath);
            store.Save(new IncidentStateSnapshot());
            var large = new IncidentStateSnapshot
            {
                TotalCreated = 1,
                Incidents = new List<Incident> { new Incident { Id = "oversized", PrimaryProcessName = new string('x', 21 * 1024 * 1024) } }
            };
            Assert.Throws<InvalidDataException>(() => store.Save(large));
            Assert.Empty(store.Load().Incidents);
            Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
        }

        [Fact]
        public void InterruptedEvaluationSurvivesRestartForReviewWithoutRestoringAuthority()
        {
            using (var first = Create())
            {
                var incident = first.RegisterDetection(Detection(12345));
                first.BeginResponseEvaluation(12345, ResponseAction.KillProcessTree, incident.Id);
            }
            using var second = Create();
            var recovered = Assert.Single(second.GetActiveIncidents());
            Assert.Equal("Pending", recovered.ResponseEvaluation!.State);
            Assert.Null(recovered.ResponseEvaluation.CompletedUtc);
            Assert.True(recovered.RecoveredHistory);
            Assert.Null(second.GetIncidentForPid(12345));
        }

        [Fact]
        public async System.Threading.Tasks.Task ObservedResponseIsNotExecutedOrDeduplicatedAsASuccessfulKill()
        {
            using var manager = Create();
            using var bus = new ContextBus(NullLogger<ContextBus>.Instance);
            var engine = new AdvancedResponseEngine(new SentinelConfig(), new SentinelMetrics(), _events,
                new QuarantineManager(Path.Combine(_directory, "vault")));
            using var coordinator = new ResponseCoordinator(engine, manager, bus, _events, NullLogger<ResponseCoordinator>.Instance);
            var detection = Detection(12345);
            detection.AuthorizedResponse = ResponseAction.KillProcessTree;
            var incident = manager.RegisterDetection(detection);
            var first = await coordinator.ExecuteResponseAsync(detection, incidentId: incident.Id);
            var second = await coordinator.ExecuteResponseAsync(Detection(12345), incidentId: incident.Id);
            Assert.Equal(ResponseOutcome.Observed, first.Outcome);
            Assert.Equal(ResponseOutcome.Observed, second.Outcome);
            Assert.Equal(0, coordinator.GetStats().TotalExecuted);
            Assert.Equal(2, coordinator.GetStats().TotalObserved);
            Assert.NotEqual(IncidentState.Responded, incident.State);
        }

        public void Dispose()
        {
            _ancestry.Dispose();
            _events.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Directory.Delete(_directory, true);
        }
    }
}
