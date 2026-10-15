using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class ReplayPipelineTests
    {
        private static DetectionEvent Signal(DateTime time, string rule, SignalType type) => new()
        {
            Timestamp = time, ProcessId = 12000, ProcessName = "recorded-process.exe",
            RuleName = rule, SignalType = type, Confidence = 0.95,
            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly
        };

        [Fact]
        public async Task HistoricalBehavioralReplay_IsDeterministicAndNeverAuthorizesActions()
        {
            var time = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var input = new[] { Signal(time, "Shadow copy destruction", SignalType.Ransomware),
                Signal(time.AddSeconds(1), "Mass file encryption", SignalType.Ransomware) };
            var replay = new DetectionReplay();
            var first = await replay.RunAsync(input, new WeightedCorrelationConfig(), includeBehavioral: true);
            var second = await replay.RunAsync(input, new WeightedCorrelationConfig(), includeBehavioral: true);
            Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
            var composite = Assert.Single(first.BehavioralComposites);
            Assert.Equal("Active Mass-Encryption Chain", composite.RuleName);
            Assert.Equal(time.AddSeconds(1), composite.Timestamp);
            Assert.Equal(ResponseAction.LogOnly, composite.AuthorizedResponse);
            Assert.All(first.Composites, c => Assert.Equal(ResponseAction.LogOnly, c.AuthorizedResponse));
            Assert.All(input, d => Assert.Equal(DetectionTier.Tier2Indicator, d.Tier));
        }

        [Fact]
        public async Task HistoricalSignalsOutsideWindow_DoNotFormBehavioralChain()
        {
            var time = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var input = new[] { Signal(time, "Shadow copy destruction", SignalType.Ransomware),
                Signal(time.AddMinutes(2), "Mass file encryption", SignalType.Ransomware) };
            var result = await new DetectionReplay().RunAsync(input, new WeightedCorrelationConfig(), includeBehavioral: true);
            Assert.Empty(result.BehavioralComposites);
        }

        [Fact]
        public async Task DifferentReplayScopes_AreNotComparable()
        {
            var input = new[] { Signal(DateTime.UtcNow, "Observation", SignalType.Generic) };
            var replay = new DetectionReplay();
            var weighted = await replay.RunAsync(input, new WeightedCorrelationConfig());
            var behavioral = await replay.RunAsync(input, new WeightedCorrelationConfig(), includeBehavioral: true);
            Assert.Throws<ArgumentException>(() => ReplayComparison.Compare(weighted, behavioral));
        }

        [Fact]
        public void PrivateExport_RemovesAbsoluteDateButPreservesIntervals()
        {
            var time = new DateTime(2026, 10, 15, 15, 20, 0, DateTimeKind.Utc);
            var input = new[] { Signal(time, "Private", SignalType.Generic),
                Signal(time.AddSeconds(17), "Private", SignalType.Generic) };
            var result = new InvestigationExport().Redact(input, relativeTime: true);
            Assert.True(result.RelativeTime);
            Assert.Equal(2000, result.Events[0].Timestamp.Year);
            Assert.Equal(TimeSpan.FromSeconds(17), result.Events[1].Timestamp - result.Events[0].Timestamp);
            Assert.DoesNotContain("2026", JsonSerializer.Serialize(result));
            Assert.Equal(time, input[0].Timestamp);
        }

        [Fact]
        public void RestoreInspection_RejectsNetworkDestinationBeforeReadingIt()
        {
            string path = Path.GetTempFileName();
            try
            {
                string id = Guid.NewGuid().ToString("N");
                var record = new RestoreTransactionRecord
                {
                    Id = id, VaultFile = "item.vault", State = "Prepared", Sha256 = new string('a', 64),
                    Destination = @"\\remote.invalid\share\file",
                    StagingPath = @"\\remote.invalid\share\file.sentinel-restore-" + id
                };
                File.WriteAllText(path, JsonSerializer.Serialize(record));
                Assert.Throws<InvalidDataException>(() => new RestoreTransaction().Inspect(path));
            }
            finally { File.Delete(path); }
        }

        [Fact]
        public void ProcessEvidenceCannotTargetANewerPidGenerationOrFutureEvent()
        {
            var now = new DateTime(2026, 10, 15, 15, 20, 0, DateTimeKind.Utc);
            Assert.False(ProcessIdentitySafety.EvidenceCanReferToGeneration(now.AddMinutes(-2), now.AddMinutes(-1), now));
            Assert.True(ProcessIdentitySafety.EvidenceCanReferToGeneration(now, now.AddMinutes(-1), now));
            Assert.False(ProcessIdentitySafety.EvidenceCanReferToGeneration(now.AddMinutes(1), now.AddMinutes(-1), now));
            Assert.False(ProcessIdentitySafety.EvidenceCanReferToGeneration(DateTime.SpecifyKind(now, DateTimeKind.Unspecified), now.AddMinutes(-1), now));
        }

        [Fact]
        public async Task IpcRequestReaderRejectsOversizedFramesAndHonorsCancellation()
        {
            using var oversized = new StringReader(new string('x', 65537));
            await Assert.ThrowsAsync<InvalidDataException>(() => ServiceAgentIpcHost.ReadBoundedRequestAsync(oversized, System.Threading.CancellationToken.None));
            using var valid = new StringReader("{\"op\":\"ping\"}\r\nignored");
            Assert.Equal("{\"op\":\"ping\"}", await ServiceAgentIpcHost.ReadBoundedRequestAsync(valid, System.Threading.CancellationToken.None));
            using var cancelled = new System.Threading.CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ServiceAgentIpcHost.ReadBoundedRequestAsync(valid, cancelled.Token));
        }

        [Theory]
        [InlineData("NUL")]
        [InlineData("CON.txt")]
        [InlineData("file:stream")]
        public void RestoreRefusesDeviceAndAlternateStreamDestinations(string filename)
        {
            string directory = Path.Combine(Path.GetTempPath(), "restore-path-" + Guid.NewGuid().ToString("N"));
            string destination = Path.Combine(directory, filename);
            Assert.Throws<InvalidDataException>(() => new RestoreTransaction().Restore(
                Path.Combine(directory, "item.vault"), destination, new byte[] { 1 }));
            Assert.False(Directory.Exists(directory));
        }

        [Theory]
        [InlineData("")]
        [InlineData("not xml")]
        [InlineData("<filters><item>")]
        [InlineData("<!DOCTYPE filters [<!ENTITY x SYSTEM 'file:///missing'>]><filters>&x;</filters>")]
        public void WfpSnapshot_InvalidOrExternalEntityInputIsRejected(string content)
        {
            Assert.ThrowsAny<Exception>(() => WfpIntegrityMonitor.ValidateSnapshot(content));
        }

        [Fact]
        public void WfpSnapshot_ValidEmptyInventoryIsAccepted()
        {
            WfpIntegrityMonitor.ValidateSnapshot("<?xml version=\"1.0\"?><wfpstate><filters /></wfpstate>");
        }
    }
}
