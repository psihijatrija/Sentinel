using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class ReliabilityImprovementsTests
    {
        [Fact]
        public void ProgressRequiresSuccessfulCollectionAndRecordsRecoveryGap()
        {
            var now = DateTimeOffset.UtcNow;
            var progress = new SensorProgress(TimeSpan.FromMinutes(1), () => now);
            Assert.Equal("Unknown", progress.Snapshot().State);
            progress.Succeeded(); // An empty collection cycle is still useful progress.
            Assert.Equal("Healthy", progress.Snapshot().State);
            now += TimeSpan.FromMinutes(2);
            Assert.Equal("Stale", progress.Snapshot().State);
            Assert.NotNull(progress.Snapshot().GapStarted);
            Assert.Null(progress.AcknowledgeRecovery());
            progress.Succeeded();
            Assert.NotNull(progress.AcknowledgeRecovery());
            Assert.Null(progress.AcknowledgeRecovery());
            progress.Failed("provider unavailable");
            Assert.Equal("Failed", progress.Snapshot().State);
        }

        [Fact]
        public void RecoveryRetainsGapEvenWhenSupervisorDidNotSampleStaleness()
        {
            var now = DateTimeOffset.UtcNow;
            var progress = new SensorProgress(TimeSpan.FromMinutes(1), () => now);
            progress.Succeeded();
            now += TimeSpan.FromMinutes(3);
            progress.Succeeded();
            Assert.NotNull(progress.AcknowledgeRecovery());
        }

        [Fact]
        public void LedgerDetectsModificationReorderingAndCheckpointTruncation()
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".jsonl");
            try
            {
                var ledger = new EvidenceLedger(path);
                ledger.Append(JsonSerializer.Serialize(new { Action = "Prepared" }));
                var checkpoint = ledger.Append(JsonSerializer.Serialize(new { Action = "Verified" }));
                var lines = File.ReadAllLines(path);
                Assert.Equal(2, EvidenceLedger.Verify(new StringReader(string.Join("\n", lines)), checkpoint).Sequence);
                Assert.Throws<InvalidDataException>(() => EvidenceLedger.Verify(new StringReader(lines[0]), checkpoint));
                Assert.Throws<InvalidDataException>(() => EvidenceLedger.Verify(new StringReader(string.Join("\n", Enumerable.Reverse(lines)))));
                Assert.Throws<InvalidDataException>(() => EvidenceLedger.Verify(new StringReader(string.Join("\n", lines).Replace("Verified", "Tampered"))));
                // Reopen across process lifetimes without losing the sequence.
                Assert.Equal(3, new EvidenceLedger(path).Append(JsonSerializer.Serialize(new { Action = "Restarted" })).Sequence);
            }
            finally { File.Delete(path); }
        }

        [Fact]
        public async Task ReplayUsesHistoricalTimeIsRepeatableAndCannotAuthorizeActions()
        {
            var time = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var signals = new[]
            {
                Signal("LSASS Credential Dump", time),
                Signal("C2 Beaconing Statistical", time.AddSeconds(2))
            };
            var replay = new DetectionReplay();
            var config = new WeightedCorrelationConfig { Threshold = 80 };
            var first = await replay.RunAsync(signals, config);
            var second = await replay.RunAsync(signals, config);
            Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
            Assert.Single(first.Composites);
            Assert.All(first.Composites, e => Assert.Equal(ResponseAction.LogOnly, e.AuthorizedResponse));
            Assert.Empty(signals[0].Metadata);
            Assert.True(config.EnableGraphBoost);
            signals[1].Timestamp = time.AddMinutes(3);
            Assert.Empty((await replay.RunAsync(signals, config)).Composites);
        }

        [Fact]
        public async Task NumericalScoreAloneCannotCreateTerminalAuthority()
        {
            var now = DateTime.UtcNow;
            var replay = new DetectionReplay();
            var report = await replay.RunAsync(new[]
            {
                Signal("DNS Anomaly", now), Signal("Persistence Scheduled Task", now.AddSeconds(1))
            }, new WeightedCorrelationConfig { Threshold = 1, MinDistinctCategories = 2 });
            Assert.Empty(report.Composites);
            Assert.Equal("MissingTerminalEvidence", report.Steps.Last().ScoreCard.Decision);
            Assert.DoesNotContain("(emit)", report.Steps.Last().ScoreCard.Explanation);
        }

        [Fact]
        public async Task ReplayComparisonRequiresMatchingEvidenceAndShowsChangedDecisions()
        {
            var time = DateTime.UtcNow;
            var events = new[] { Signal("LSASS Credential Dump", time), Signal("C2 Beaconing", time.AddSeconds(1)) };
            var replay = new DetectionReplay();
            var first = await replay.RunAsync(events, new WeightedCorrelationConfig { Threshold = 80 });
            var second = await replay.RunAsync(events, new WeightedCorrelationConfig { Threshold = 999 });
            var comparison = ReplayComparison.Compare(first, second);
            Assert.Equal(1, comparison.PreviousCompositeCount);
            Assert.Equal(0, comparison.CurrentCompositeCount);
            Assert.NotEmpty(comparison.ChangedStepIndexes);
            second.InputSha256 = "different evidence";
            Assert.Throws<ArgumentException>(() => ReplayComparison.Compare(first, second));
        }

        [Fact]
        public async Task CancelledReplayDoesNotProcessEvents()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DetectionReplay().RunAsync(
                new[] { Signal("C2 Beacon", DateTime.UtcNow) }, new WeightedCorrelationConfig(), cancellation.Token));
        }

        [Fact]
        public async Task SingleCategoryCannotBecomeCompositeEvenWithPermissiveConfiguration()
        {
            var report = await new DetectionReplay().RunAsync(new[] { Signal("LSASS Credential Dump", DateTime.UtcNow) },
                new WeightedCorrelationConfig { Threshold = 1, MinDistinctCategories = 1 });
            Assert.Empty(report.Composites);
            Assert.Equal("InsufficientCategories", report.Steps.Single().ScoreCard.Decision);
        }

        [Fact]
        public async Task ReplayDoesNotFeedPreviousWeightedOutputsBackIntoItsInputs()
        {
            var now = DateTime.UtcNow;
            var derived = Signal("Weighted Correlation: Multi-Signal Threat", now);
            derived.Metadata["WeightedCorrelation"] = "true";
            var report = await new DetectionReplay().RunAsync(new[] { derived }, new WeightedCorrelationConfig());
            Assert.Equal(1, report.SkippedDerivedCount);
            Assert.Equal(0, report.InputCount);
            Assert.Empty(report.Composites);
        }

        [Fact]
        public void ManifestVerifierRejectsTamperingTraversalAndEmptyManifests()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-pack-" + Guid.NewGuid());
            Directory.CreateDirectory(directory);
            try
            {
                var content = Encoding.UTF8.GetBytes("original evidence");
                File.WriteAllBytes(Path.Combine(directory, "event.txt"), content);
                using var sha = SHA256.Create();
                var hash = BitConverter.ToString(sha.ComputeHash(content)).Replace("-", "").ToLowerInvariant();
                var manifest = Path.Combine(directory, "MANIFEST.sha256");
                File.WriteAllText(manifest, hash + "  event.txt\n");
                var verifier = new EvidencePackVerifier();
                var result = verifier.Verify(directory);
                Assert.True(result.ContentHashesVerified);
                Assert.False(result.OriginAuthenticated);
                File.WriteAllText(Path.Combine(directory, "event.txt"), "modified evidence");
                Assert.Throws<InvalidDataException>(() => verifier.Verify(directory));
                File.WriteAllText(manifest, hash + "  ../outside.txt\n");
                Assert.Throws<InvalidDataException>(() => verifier.Verify(directory));
                File.WriteAllText(manifest, "# empty\n");
                Assert.Throws<InvalidDataException>(() => verifier.Verify(directory));
            }
            finally { Directory.Delete(directory, true); }
        }

        [Fact]
        public void RestoreNeverOverwritesAndRecoveryDoesNotMutateFiles()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-restore-" + Guid.NewGuid());
            Directory.CreateDirectory(directory);
            try
            {
                var vault = Path.Combine(directory, "sample.senq");
                var destination = Path.Combine(directory, "restored.txt");
                File.WriteAllText(vault, "encrypted original retained");
                var transaction = new RestoreTransaction();
                var record = transaction.Restore(vault, destination, Encoding.UTF8.GetBytes("restored content"));
                Assert.Equal("Verified", record.State);
                Assert.True(File.Exists(vault));
                var journal = Directory.GetFiles(directory, "*.json", SearchOption.AllDirectories).Single();
                Assert.True(transaction.Inspect(journal).DestinationMatches);
                Assert.Throws<IOException>(() => transaction.Restore(vault, destination, new byte[] { 1 }));
                Assert.Equal("restored content", File.ReadAllText(destination));
                File.WriteAllText(destination, "changed after restore");
                Assert.False(transaction.Inspect(journal).DestinationMatches);
                Assert.Equal("changed after restore", File.ReadAllText(destination));
                File.Delete(destination);
                Assert.False(transaction.Inspect(journal).DestinationMatches);
                Assert.False(File.Exists(destination));
            }
            finally { Directory.Delete(directory, true); }
        }

        [Fact]
        public void RedactedExportDoesNotLeakRawIdentifiersOrMutateOriginals()
        {
            var detection = Signal("C2 Beacon user-private.exe", DateTime.UtcNow);
            detection.Evidence = "private-user and private-path";
            detection.Reasoning = "private-reason";
            detection.Metadata["CommandLine"] = "private-argument";
            detection.ProcessName = "private-process";
            var export = new InvestigationExport().Redact(new[] { detection, detection });
            var json = JsonSerializer.Serialize(export);
            Assert.DoesNotContain("private", json);
            Assert.DoesNotContain("9001", json);
            Assert.Equal(export.Events[0].ProcessAlias, export.Events[1].ProcessAlias);
            Assert.Equal("private-argument", detection.Metadata["CommandLine"]);
            Assert.True(export.DerivedRedactedCopy);
        }

        [Fact]
        public async Task MonitorGroupDetectsBackgroundFailureAndRestartsWithoutDisposingInstance()
        {
            using var monitor = new RecoveringMonitor();
            using var group = new MonitorGroup(new MonitorGroupConfig
            {
                Name = "RecoveryFixture", StaggerDelay = TimeSpan.Zero,
                HealthCheckInterval = TimeSpan.FromMilliseconds(10), RestartCooldown = TimeSpan.Zero
            }, new IHostedService[] { monitor }, NullLogger.Instance);
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await group.StartAsync(stop.Token);
            var resumed = await Task.WhenAny(monitor.Recovered.Task, Task.Delay(TimeSpan.FromSeconds(4), stop.Token));
            Assert.Same(monitor.Recovered.Task, resumed);
            Assert.False(monitor.Disposed);
            await group.StopAsync(CancellationToken.None);
            Assert.True(monitor.Disposed);
        }

        [Fact]
        public async Task DeclaredStartupTaskThatCompletesIsNotRestartedForever()
        {
            using var monitor = new OptionalMonitor();
            using var group = new MonitorGroup(new MonitorGroupConfig
            {
                Name = "OptionalFixture", StaggerDelay = TimeSpan.Zero, RestartIndefinitely = true,
                HealthCheckInterval = TimeSpan.FromMilliseconds(10), RestartCooldown = TimeSpan.Zero
            }, new IHostedService[] { monitor }, NullLogger.Instance);
            await group.StartAsync(CancellationToken.None);
            var deadline = DateTime.UtcNow.AddSeconds(4);
            while ((monitor.Starts != 1 || group.RunningCount != 0) && DateTime.UtcNow < deadline)
                await Task.Delay(10);
            Assert.Equal(1, monitor.Starts);
            Assert.Equal(0, group.RunningCount);
            await group.StopAsync(CancellationToken.None);
        }

        private sealed class OptionalMonitor : BackgroundService, IMonitorStartupTask
        {
            public string CompletionDescription => "Test startup operation completed.";
            public int Starts;
            protected override Task ExecuteAsync(CancellationToken stoppingToken)
            {
                Interlocked.Increment(ref Starts);
                return Task.CompletedTask;
            }
        }

        [Fact]
        public void IntegrityHistorySeparatesObservedContextFromTrustAndSurvivesRestart()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-history-" + Guid.NewGuid());
            try
            {
                var previous = new HostIntegritySnapshot
                {
                    ObservedUtc = DateTimeOffset.UtcNow, NetworkContextId = "home"
                };
                previous.Network["adapter-hash"] = "gateway-dns-hash-before";
                previous.RootCertificates["LocalMachine:old-cert-hash"] = "Present";
                var history = new HostIntegrityHistory(directory);
                history.Save(previous);
                var restored = new HostIntegrityHistory(directory).Load();
                Assert.NotNull(restored);
                Assert.Equal("home", restored!.NetworkContextId);
                var current = new HostIntegritySnapshot
                {
                    ObservedUtc = previous.ObservedUtc.AddMinutes(2), NetworkContextId = "vpn"
                };
                current.Network["adapter-hash"] = "gateway-dns-hash-after";
                current.RootCertificates["LocalMachine:new-cert-hash"] = "Present";
                var changes = HostIntegrityHistory.Compare(restored, current);
                Assert.Equal(3, changes.Count);
                Assert.All(changes, change =>
                {
                    Assert.True(change.ContextChanged);
                    Assert.False(change.GrantsTrust);
                    Assert.StartsWith("Unknown", change.Attribution);
                });
                Assert.Contains(changes, c => c.Scope == "RootCertificate" && c.Change == "Removed");
                Assert.Contains(changes, c => c.Scope == "RootCertificate" && c.Change == "Added");
                Assert.All(HostIntegrityHistory.Compare(null, current), c => Assert.Equal("InitialObservation", c.Change));
                history.Save(current);
                Assert.Empty(HostIntegrityHistory.Compare(history.Load(), current));
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }

        [Fact]
        public void ModuleBaselineRetainsUnexplainedReviewAndLastValidCopyOnWriteFailure()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-module-baseline-" + Guid.NewGuid());
            try
            {
                var store = new ModuleBaselineStore(directory);
                var snapshot = new ModuleBaselineSnapshot();
                snapshot.ModulesFor("explorer").Add("accepted-module");
                snapshot.ModulesFor("explorer").Add("legacy-unexplained-module");
                snapshot.UnexplainedSince["legacy-unexplained-module"] = DateTime.UtcNow;
                Assert.False(snapshot.NeedsAttribution("explorer", "accepted-module"));
                Assert.True(snapshot.NeedsAttribution("explorer", "legacy-unexplained-module"));
                Assert.True(snapshot.NeedsAttribution("explorer", "new-module"));
                Assert.True(store.TrySave(snapshot));
                var restored = new ModuleBaselineStore(directory).Load();
                Assert.True(restored.NeedsAttribution("explorer", "legacy-unexplained-module"));
                Directory.CreateDirectory(store.BaselineFilePath + ".tmp");
                snapshot.ModulesFor("explorer").Add("must-not-replace-original");
                Assert.False(store.TrySave(snapshot));
                Assert.DoesNotContain("must-not-replace-original", new ModuleBaselineStore(directory).Load().ModulesFor("explorer"));
            }
            finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }

        [Fact]
        public void BoundedTelemetryQueueCountsActualEvictionsAndPreservesNewestContext()
        {
            int drops = 0;
            var queue = new TelemetryQueue(2, () => drops++);
            var first = new FusedTelemetryContext();
            var second = new FusedTelemetryContext();
            var third = new FusedTelemetryContext();
            Assert.True(queue.TryWrite(first));
            Assert.True(queue.TryWrite(second));
            Assert.Equal(0, drops);
            Assert.True(queue.TryWrite(third));
            Assert.Equal(1, drops);
            Assert.True(queue.OldestAgeMs >= 0);
            Assert.True(queue.Reader.TryRead(out var next));
            Assert.Same(second, next.Context);
            Assert.True(queue.Reader.TryRead(out next));
            Assert.Same(third, next.Context);
            Assert.Equal(0, queue.OldestAgeMs);
        }

        private sealed class RecoveringMonitor : BackgroundService
        {
            private int _starts;
            public bool Disposed { get; private set; }
            public TaskCompletionSource<bool> Recovered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
            protected override async Task ExecuteAsync(CancellationToken stoppingToken)
            {
                if (Interlocked.Increment(ref _starts) == 1)
                {
                    await Task.Yield();
                    throw new InvalidOperationException("Fixture sensor crashed.");
                }
                Recovered.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            public override void Dispose() { Disposed = true; base.Dispose(); }
        }

        private static DetectionEvent Signal(string name, DateTime timestamp) => new()
        {
            RuleName = name, Timestamp = timestamp, Confidence = 0.95, ProcessId = 9001, ProcessName = "fixture.exe"
        };
    }
}
