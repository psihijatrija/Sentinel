using System;
using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class BehavioralBaselineServiceTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly SecureCacheStore _cache;
        private readonly BehavioralBaselineService _service;

        public BehavioralBaselineServiceTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_baseline_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _cache = new SecureCacheStore(_tempDir);
            _service = new BehavioralBaselineService(_cache, NullLogger<BehavioralBaselineService>.Instance);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void RecordProcess_MakesProcessEstablished_AfterThreshold()
        {
            // Need to record enough times to establish
            for (int i = 0; i < 15; i++)
            {
                _service.RecordProcess("notepad.exe", @"C:\Windows\System32\notepad.exe", 1, "explorer");
            }

            Assert.True(_service.IsEstablishedProcess("notepad.exe"));
        }

        [Fact]
        public void IsEstablishedProcess_ReturnsFalse_ForUnknown()
        {
            Assert.False(_service.IsEstablishedProcess("neverseen.exe"));
        }

        [Fact]
        public void RecordProcess_SingleTime_NotEstablished()
        {
            _service.RecordProcess("onetime.exe", @"C:\temp\onetime.exe", 1, "explorer");
            Assert.False(_service.IsEstablishedProcess("onetime.exe"));
        }

        [Fact]
        public void RecordNetworkConnection_TracksDestination()
        {
            _service.RecordProcess("chrome.exe", null, 1, "explorer");
            for (int i = 0; i < 10; i++)
            {
                _service.RecordNetworkConnection("chrome.exe", "142.250.80.46", 443);
            }

            Assert.True(_service.IsKnownNetworkDestination("chrome.exe", "142.250.80.46", 443));
        }

        [Fact]
        public void IsKnownNetworkDestination_ReturnsFalse_ForUnknown()
        {
            Assert.False(_service.IsKnownNetworkDestination("unknown.exe", "1.2.3.4", 80));
        }

        [Fact]
        public void IsKnownParentChild_TracksRelationship()
        {
            for (int i = 0; i < 10; i++)
            {
                _service.RecordProcess("cmd.exe", null, 1, "explorer");
            }

            Assert.True(_service.IsKnownParentChild("explorer", "cmd.exe"));
        }

        [Fact]
        public void IsKnownParentChild_ReturnsFalse_ForUnknown()
        {
            Assert.False(_service.IsKnownParentChild("unknown_parent", "unknown_child"));
        }

        [Fact]
        public void GetStatistics_ReturnsNonNull()
        {
            var stats = _service.GetStatistics();
            Assert.NotNull(stats);
        }

        [Fact]
        public void RecordDetectionForProcess_Tracks()
        {
            for (int i = 0; i < 10; i++)
                _service.RecordProcess("suspicious.exe", null, 1, "explorer");

            _service.RecordDetectionForProcess("suspicious.exe");
            // Should not throw, detection count is tracked internally
        }
    }
}
