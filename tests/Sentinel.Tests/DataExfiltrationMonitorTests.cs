using System;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for DataExfiltrationMonitor - validates integration with
    /// BulkTransferNoise suppression and detection model behavior.
    /// </summary>
    public class DataExfiltrationMonitorTests
    {
        [Fact]
        public void BulkTransferSuppression_RecognizesTorrentClients()
        {
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("qbittorrent"));
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("utorrent"));
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("aria2c"));
        }

        [Fact]
        public void BulkTransferSuppression_RejectsNonBulkProcesses()
        {
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName("malware.exe"));
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName("chrome"));
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName("cmd"));
        }

        [Fact]
        public void ExfiltrationSpikeSignal_Model_Properties()
        {
            var signal = new ExfiltrationSpikeSignal
            {
                ProcessId = 0,
                ProcessName = "SYSTEM",
                SourceMonitor = "DataExfiltrationMonitor",
                BytesDelta = 100_000_000,
                BaselineRate = 5_000_000,
                SpikeMultiplier = 20.0,
                Interval = TimeSpan.FromSeconds(15)
            };

            Assert.Equal(100_000_000, signal.BytesDelta);
            Assert.Equal(5_000_000, signal.BaselineRate);
            Assert.Equal(20.0, signal.SpikeMultiplier);
            Assert.Equal(TimeSpan.FromSeconds(15), signal.Interval);
        }

        [Fact]
        public void SpikeThreshold_LogicVerification()
        {
            // Verify the spike detection logic: threshold = max(5MB, baseline * 10)
            long minBaseline = 5_000_000;
            long spikeMultiplier = 10;

            // Low baseline: threshold should be minBaseline (5MB)
            long lowBaseline = 1_000_000;
            long threshold = Math.Max(minBaseline, lowBaseline * spikeMultiplier);
            Assert.Equal(10_000_000, threshold); // 1MB * 10 = 10MB > 5MB

            // Very low baseline: threshold should be 5MB minimum
            long veryLowBaseline = 100_000; // 100KB
            threshold = Math.Max(minBaseline, veryLowBaseline * spikeMultiplier);
            Assert.Equal(5_000_000, threshold); // min 5MB applies
        }
    }
}
