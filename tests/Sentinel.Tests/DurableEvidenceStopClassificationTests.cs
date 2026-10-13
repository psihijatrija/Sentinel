using System;
using System.IO;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// B1 (durable evidence survival) - stop classification (R1/R3).
    /// Verifies ShutdownContext lifecycle signalling and the append-only audit records
    /// written by JsonlEventLogger for expected vs suspicious service stops.
    /// </summary>
    [Collection("ShutdownContextSerial")]
    public class DurableEvidenceStopClassificationTests : IDisposable
    {
        public DurableEvidenceStopClassificationTests()
        {
            ShutdownContext.ResetForTests();
        }

        public void Dispose()
        {
            ShutdownContext.ResetForTests();
        }

        [Fact]
        public void ShutdownContext_DefaultsToUnexpected()
        {
            Assert.False(ShutdownContext.IsExpected);
            Assert.Equal(ExpectedShutdownReason.None, ShutdownContext.Reason);
            Assert.Null(ShutdownContext.MarkedAtUtc);
        }

        [Fact]
        public void ShutdownContext_MarkExpected_SetsReason()
        {
            ShutdownContext.MarkExpected(ExpectedShutdownReason.ServiceControllerStop);

            Assert.True(ShutdownContext.IsExpected);
            Assert.Equal(ExpectedShutdownReason.ServiceControllerStop, ShutdownContext.Reason);
            Assert.NotNull(ShutdownContext.MarkedAtUtc);
        }

        [Fact]
        public void ShutdownContext_MarkExpected_None_IsIgnored()
        {
            ShutdownContext.MarkExpected(ExpectedShutdownReason.None);
            Assert.False(ShutdownContext.IsExpected);
        }

        [Fact]
        public void ShutdownContext_FirstReasonWins()
        {
            ShutdownContext.MarkExpected(ExpectedShutdownReason.SystemShutdown);
            ShutdownContext.MarkExpected(ExpectedShutdownReason.ServiceControllerStop);

            // First legitimate reason is preserved (not clobbered by a later teardown step).
            Assert.Equal(ExpectedShutdownReason.SystemShutdown, ShutdownContext.Reason);
        }

        [Fact]
        public void LogServiceStopSuspected_WritesAppendOnlyAuditRecord()
        {
            var (logger, tempDir) = MakeLogger();
            try
            {
                logger.LogServiceStopSuspected(
                    reason: "ProcessExit",
                    processId: 4242,
                    uptime: "00:10:00",
                    lastTick: DateTimeOffset.UtcNow,
                    classification: "no expected-shutdown signal recorded");

                var auditLine = ReadTodaysAudit(tempDir);
                Assert.Contains("SERVICE_STOP_SUSPECTED", auditLine);
                Assert.Contains("4242", auditLine);
                Assert.Contains("no expected-shutdown signal recorded", auditLine);
            }
            finally
            {
                CleanupLogger(logger, tempDir);
            }
        }

        [Fact]
        public void LogServiceStopExpected_WritesLifecycleAuditRecord()
        {
            var (logger, tempDir) = MakeLogger();
            try
            {
                logger.LogServiceStopExpected(
                    reason: "ProcessExit; expected=ServiceControllerStop",
                    processId: 4242,
                    uptime: "00:10:00");

                var auditLine = ReadTodaysAudit(tempDir);
                Assert.Contains("SERVICE_STOP_EXPECTED", auditLine);
                Assert.DoesNotContain("SERVICE_STOP_SUSPECTED", auditLine);
            }
            finally
            {
                CleanupLogger(logger, tempDir);
            }
        }

        [Fact]
        public void LogServiceStopSuspected_NeverThrows_WhenDisposed()
        {
            var (logger, tempDir) = MakeLogger();
            try
            {
                logger.DisposeAsync().AsTask().GetAwaiter().GetResult();

                // Exit-hook path must never throw even if the logger is torn down (NFR-2).
                var ex = Record.Exception(() => logger.LogServiceStopSuspected(
                    "ProcessExit", 1, "00:00:01", DateTimeOffset.UtcNow, "classification"));
                Assert.Null(ex);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        //  helpers 

        private static (JsonlEventLogger logger, string tempDir) MakeLogger()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "b1_stop_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            var logPath = Path.Combine(tempDir, "events.jsonl");
            return (new JsonlEventLogger(logPath), tempDir);
        }

        private static string ReadTodaysAudit(string tempDir)
        {
            var auditFile = Directory.GetFiles(tempDir, "audit-*.jsonl").FirstOrDefault();
            Assert.NotNull(auditFile);
            // File is opened with FileShare.Read - safe to read while the writer holds it.
            using var fs = new FileStream(auditFile!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sr = new StreamReader(fs);
            return sr.ReadToEnd();
        }

        private static void CleanupLogger(JsonlEventLogger logger, string tempDir)
        {
            try { logger.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
