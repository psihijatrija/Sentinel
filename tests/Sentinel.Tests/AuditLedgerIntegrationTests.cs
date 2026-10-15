using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>Framework-host integration: execute on Windows, not the portable subset.</summary>
    public sealed class AuditLedgerIntegrationTests
    {
        [Fact]
        public async Task RecoveredLoggerRecordsAnExplicitEvidenceGap()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-audit-gap-" + Guid.NewGuid());
            Directory.CreateDirectory(directory);
            var blocked = Path.Combine(directory, "blocked");
            File.WriteAllText(blocked, "A file intentionally blocks the log directory in this fixture.");
            try
            {
                await using (var logger = new JsonlEventLogger(Path.Combine(blocked, "events.jsonl")))
                {
                    await logger.LogEventAsync("fixture", new { Missing = true });
                    Assert.Equal(1, logger.DroppedEvents);
                    File.Delete(blocked);
                    Directory.CreateDirectory(blocked);
                    await logger.LogAuditBeforeActionAsync("d1", "r1", "Fixture", ResponseAction.LogOnly,
                        0.5, "fixture.exe", 9001, "No action is executed");
                    var checkpoint = logger.GetAuditCheckpoint();
                    Assert.NotNull(checkpoint);
                    Assert.Equal(2, checkpoint!.Sequence);
                    using var stream = new FileStream(Path.Combine(blocked, checkpoint.File), FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(stream);
                    var contents = reader.ReadToEnd();
                    Assert.Contains("EVIDENCE_GAP", contents);
                    Assert.Equal(2, EvidenceLedger.Verify(new StringReader(contents)).Sequence);
                }
            }
            finally { Directory.Delete(directory, true); }
        }

        [Fact]
        public async Task PreActionAndOutcomeAreChainedAndCheckpointMatchesWrittenPrefix()
        {
            var directory = Path.Combine(Path.GetTempPath(), "sentinel-audit-integration-" + Guid.NewGuid());
            Directory.CreateDirectory(directory);
            try
            {
                await using (var logger = new JsonlEventLogger(Path.Combine(directory, "events.jsonl")))
                {
                    await logger.LogAuditBeforeActionAsync("d1", "r1", "Fixture", ResponseAction.KillProcess,
                        0.95, "fixture.exe", 9001, "Synthetic test only; no action is executed");
                    await logger.LogAuditActionOutcomeAsync("d1", ResponseAction.KillProcess, true);
                    logger.LogServiceStopExpected("fixture", 9001, "00:00:01");
                    Assert.False(logger.AuditIntegrityDegraded);
                    var checkpoint = logger.GetAuditCheckpoint();
                    Assert.NotNull(checkpoint);
                    using var stream = new FileStream(Path.Combine(directory, checkpoint!.File), FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(stream, Encoding.UTF8);
                    var verified = EvidenceLedger.Verify(reader, new LedgerCheckpoint
                    { Sequence = checkpoint.Sequence, Hash = checkpoint.Hash });
                    Assert.Equal(3, verified.Sequence);
                }
            }
            finally { Directory.Delete(directory, true); }
        }
    }
}
