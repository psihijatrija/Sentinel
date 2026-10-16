using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class TelemetryReplayTests
    {
        private static readonly DateTime Time = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static TelemetryReplayRecord Process(string command, int seconds = 0) => TelemetryReplayRecord.FromEvent(new ProcessTelemetry
        {
            Timestamp = Time.AddSeconds(seconds), ProcessId = 12000, ProcessName = "fixture.exe",
            ParentProcessName = "fixture-parent.exe", ImagePath = "fixture.exe", CommandLine = command
        });

        [Fact]
        public async Task RecordedTelemetryRunsRealRulesAndRemainsDeterministicAndNonActionable()
        {
            var input = new[] { Process("vssadmin delete shadows /all /quiet"), Process("ordinary.exe --help", 1) };
            string original = JsonSerializer.Serialize(input);
            var replay = new TelemetryReplay();
            var first = await replay.RunAsync(input, new WeightedCorrelationConfig());
            var second = await replay.RunAsync(input, new WeightedCorrelationConfig());
            Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
            Assert.Equal(original, JsonSerializer.Serialize(input));
            Assert.Equal(8, first.RuleNames.Count);
            Assert.Equal(16, first.RuleEvaluationCount);
            Assert.Contains(first.Detections, d => d.Detection.RuleName == "RansomwareDetectionRule");
            Assert.All(first.Detections, d =>
            {
                Assert.Equal(Time, d.Detection.Timestamp);
                Assert.Equal(ResponseAction.LogOnly, d.Detection.AuthorizedResponse);
                Assert.Equal("true", d.Detection.Metadata["ReplayOnly"]);
            });
            Assert.All(first.Correlation.Composites.Concat(first.Correlation.BehavioralComposites), d => Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse));
            Assert.Empty(TelemetryReplayComparison.Compare(first, second).ChangedEventIndexes);
        }

        [Fact]
        public async Task ProductionDeduplicationSuppressesRepeatsAndRearmsInHistoricalTime()
        {
            var result = await new TelemetryReplay().RunAsync(new[]
            {
                Process("vssadmin delete shadows", 0), Process("vssadmin delete shadows", 1), Process("vssadmin delete shadows", 11)
            }, new WeightedCorrelationConfig());
            Assert.Equal(2, result.Detections.Count(d => d.Detection.RuleName == "RansomwareDetectionRule"));
            Assert.Equal(1, result.SuppressedDetectionCount);
        }

        [Fact]
        public async Task BenignRecordedWorkloadDoesNotInventDetections()
        {
            var result = await new TelemetryReplay().RunAsync(new[] { Process("fixture.exe --help"), Process("fixture.exe --version", 1) }, new WeightedCorrelationConfig());
            Assert.Empty(result.Detections);
            Assert.Equal(16, result.RuleEvaluationCount);
        }

        [Fact]
        public void SharedFeaturesUseTheHistoricalWindowAndActualTelemetryKinds()
        {
            var trigger = new ProcessTelemetry { Timestamp = Time, ProcessId = 100, ProcessName = "fixture" };
            var history = new TelemetryEvent[]
            {
                new NetworkTelemetry { Timestamp = Time.AddSeconds(-61) },
                new FileActivityTelemetry { Timestamp = Time.AddSeconds(-60), OperationType = "WRITE" },
                new ThreatIntelTelemetry { Timestamp = Time.AddSeconds(-1) }, trigger
            };
            var context = TelemetryContextBuilder.Build(trigger, history, Time);
            Assert.Equal(3, context.EventCount60s);
            Assert.False(context.HasNetworkActivity);
            Assert.True(context.HasFileWrites);
            Assert.True(context.HasSuspiciousAPIs);
        }

        [Theory]
        [InlineData("{\"ProcessId\":123}")]
        [InlineData("{\"Timestamp\":\"2020-01-01T00:00:00\",\"ProcessId\":123}")]
        [InlineData("{\"Timestamp\":\"2020-01-01T00:00:00Z\",\"ProcessId\":-1}")]
        public async Task MissingOrAmbiguousTimeAndInvalidIdentityAreRejected(string json)
        {
            using var data = JsonDocument.Parse(json);
            var input = new[] { new TelemetryReplayRecord { Kind = "Process", Data = data.RootElement.Clone() } };
            await Assert.ThrowsAsync<InvalidDataException>(() => new TelemetryReplay().RunAsync(input, new WeightedCorrelationConfig()));
        }

        [Fact]
        public async Task ComparisonFindsChangedRuleOutputsForTheSameRecordedEvidence()
        {
            var original = await new TelemetryReplay().RunAsync(new[] { Process("vssadmin delete shadows") }, new WeightedCorrelationConfig());
            var updated = JsonSerializer.Deserialize<TelemetryReplayReport>(JsonSerializer.Serialize(original))!;
            updated.RuleArtifactId = "fixture-new-build";
            updated.Detections[0].Detection.Reasoning = "Changed rule explanation";
            var comparison = TelemetryReplayComparison.Compare(original, updated);
            Assert.Equal(new[] { 0 }, comparison.ChangedEventIndexes);
            Assert.False(comparison.CorrelationOutputsChanged);
        }

        [Fact]
        public async Task DifferentRecordedInputsCannotBeComparedAndCancellationProducesNoPartialReport()
        {
            var replay = new TelemetryReplay();
            var first = await replay.RunAsync(new[] { Process("first") }, new WeightedCorrelationConfig());
            var second = await replay.RunAsync(new[] { Process("second") }, new WeightedCorrelationConfig());
            Assert.Throws<ArgumentException>(() => TelemetryReplayComparison.Compare(first, second));
            using var cancel = new CancellationTokenSource(); cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => replay.RunAsync(new[] { Process("first") }, new WeightedCorrelationConfig(), cancel.Token));
        }
    }
}
