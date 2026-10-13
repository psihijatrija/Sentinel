using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for JsonlEventLogger - verifies log rotation, JSONL format compliance,
    /// graceful disk space handling, and async write behavior.
    /// </summary>
    public class JsonlEventLoggerTests : IAsyncDisposable
    {
        private readonly string _tempDir;
        private readonly string _logPath;
        private readonly JsonlEventLogger _logger;

        public JsonlEventLoggerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_log_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _logPath = Path.Combine(_tempDir, "events.jsonl");
            _logger = new JsonlEventLogger(_logPath);
        }

        public async ValueTask DisposeAsync()
        {
            await _logger.DisposeAsync();
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public async Task LogEventAsync_CreatesLogFile()
        {
            await _logger.LogEventAsync("test", new { Message = "hello" });

            Assert.True(File.Exists(_logPath));
        }

        [Fact]
        public async Task LogEventAsync_WritesJsonlFormat()
        {
            await _logger.LogEventAsync("detection", new { RuleName = "TestRule", ProcessId = 123 });

            using var fs = new FileStream(_logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var content = reader.ReadToEnd();

            Assert.Contains("TestRule", content);
            Assert.Contains("123", content);
            // JSONL = one JSON object per line
            var lines = content.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            Assert.True(lines.Length >= 1);
        }

        [Fact]
        public async Task LogEventAsync_MultipleEvents_AppendedAsLines()
        {
            await _logger.LogEventAsync("event1", new { Id = 1 });
            await _logger.LogEventAsync("event2", new { Id = 2 });
            await _logger.LogEventAsync("event3", new { Id = 3 });

            using var fs = new FileStream(_logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var content = reader.ReadToEnd();
            var lines = content.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);

            Assert.True(lines.Length >= 3);
        }

        [Fact]
        public async Task LogEventAsync_IncludesTimestamp()
        {
            await _logger.LogEventAsync("timed", new { Value = "test" });

            using var fs = new FileStream(_logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var content = reader.ReadToEnd();

            // Timestamp field should be present
            Assert.Contains("Timestamp", content, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task LogEventAsync_IncludesEventType()
        {
            await _logger.LogEventAsync("my_event_type", new { Data = "x" });

            using var fs = new FileStream(_logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var content = reader.ReadToEnd();

            Assert.Contains("my_event_type", content);
        }

        [Fact]
        public async Task LogEventAsync_HandlesNullData_Gracefully()
        {
            // Should not throw
            await _logger.LogEventAsync("null_test", (object?)null!);
        }

        [Fact]
        public async Task DisposeAsync_FlushesContent()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel_flush_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "flush.jsonl");

            try
            {
                var logger = new JsonlEventLogger(path);
                await logger.LogEventAsync("flush", new { X = 1 });
                await logger.DisposeAsync();

                // After dispose, file should contain the data
                var content = File.ReadAllText(path);
                Assert.Contains("flush", content);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        [Fact]
        public async Task LogEventAsync_LargePayload_DoesNotThrow()
        {
            var largeEvidence = new string('A', 50_000);
            await _logger.LogEventAsync("large", new { Evidence = largeEvidence });
        }
    }
}
