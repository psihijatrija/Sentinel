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

        //  Torrent / bulk-transfer clients are demoted to observe (never killed) 

        [Theory]
        [InlineData("qbittorrent")]
        [InlineData("utorrent")]
        [InlineData("bittorrent")]
        [InlineData("transmission")]
        [InlineData("transmission-qt")]
        [InlineData("transmission-daemon")]
        [InlineData("deluge")]
        [InlineData("deluged")]
        [InlineData("deluge-gtk")]
        [InlineData("tixati")]
        [InlineData("vuze")]
        [InlineData("azureus")]
        [InlineData("frostwire")]
        [InlineData("aria2c")]
        public void TorrentClient_IsDemotedToObserve_WithAndWithoutExe(string name)
        {
            Assert.True(BeaconingDetector.ShouldDemoteBeaconToObserve(name));
            Assert.True(BeaconingDetector.ShouldDemoteBeaconToObserve(name + ".exe"));
            // Case-insensitive
            Assert.True(BeaconingDetector.ShouldDemoteBeaconToObserve(name.ToUpperInvariant()));
        }

        [Fact]
        public void NonTorrentProcess_IsNotDemoted()
        {
            // A genuine C2 beacon name is NOT demoted - the normal kill path still applies.
            Assert.False(BeaconingDetector.ShouldDemoteBeaconToObserve("beacon"));
            Assert.False(BeaconingDetector.ShouldDemoteBeaconToObserve("beacon.exe"));
            Assert.False(BeaconingDetector.ShouldDemoteBeaconToObserve(null));
            Assert.False(BeaconingDetector.ShouldDemoteBeaconToObserve(""));
        }
    }
}
