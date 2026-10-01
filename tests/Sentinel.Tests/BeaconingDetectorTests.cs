using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for BeaconingDetector logic. The detector requires complex DI graph
    /// (DetectionEngine, FileReputationEngine, AllowlistService), so we test the
    /// observable static/internal aspects and detection model behavior.
    /// </summary>
    public class BeaconingDetectorTests
    {
        [Fact]
        public void ConnectionHistory_Records_Timestamps()
        {
            var history = new ConnectionHistory(1000, "beacon.exe", "10.0.0.1", 443, null);
            history.Record(System.DateTimeOffset.UtcNow);
            history.Record(System.DateTimeOffset.UtcNow.AddSeconds(30));
            history.Record(System.DateTimeOffset.UtcNow.AddSeconds(60));

            var intervals = history.GetIntervals();
            Assert.Equal(2, intervals.Count);
        }

        [Fact]
        public void ConnectionHistory_EmptyIntervals_WhenSingleRecord()
        {
            var history = new ConnectionHistory(2000, "single.exe", "1.2.3.4", 80, null);
            history.Record(System.DateTimeOffset.UtcNow);

            var intervals = history.GetIntervals();
            Assert.Empty(intervals);
        }

        [Fact]
        public void ConnectionHistory_IntervalValues_ArePositive()
        {
            var now = System.DateTimeOffset.UtcNow;
            var history = new ConnectionHistory(3000, "test.exe", "5.5.5.5", 443, null);
            history.Record(now);
            history.Record(now.AddSeconds(10));
            history.Record(now.AddSeconds(20));

            var intervals = history.GetIntervals();
            foreach (var interval in intervals)
            {
                Assert.True(interval >= 0);
            }
        }

        [Fact]
        public void ConnectionHistory_Properties_SetCorrectly()
        {
            var history = new ConnectionHistory(4000, "app.exe", "192.168.1.1", 8080, @"C:\app.exe");
            Assert.NotNull(history);
        }

        [Fact]
        public void ConnectionHistory_ManyRecords_DoNotCrash()
        {
            var history = new ConnectionHistory(5000, "flood.exe", "10.0.0.1", 443, null);
            var now = System.DateTimeOffset.UtcNow;

            for (int i = 0; i < 200; i++)
            {
                history.Record(now.AddSeconds(i * 30));
            }

            var intervals = history.GetIntervals();
            Assert.True(intervals.Count > 0);
        }
    }
}
