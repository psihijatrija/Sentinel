using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class BulkTransferNoiseTests
    {
        //  IsBulkTransferProcessName 

        [Theory]
        [InlineData("qbittorrent")]
        [InlineData("qbittorrent.exe")]
        [InlineData("utorrent")]
        [InlineData("utorrent.exe")]
        [InlineData("transmission-qt")]
        [InlineData("deluge")]
        [InlineData("tixati")]
        [InlineData("aria2c")]
        [InlineData("aria2c.exe")]
        [InlineData("sabnzbd")]
        [InlineData("nzbget")]
        [InlineData("freefileync")]
        public void IsBulkTransferProcessName_ReturnsTrue_ForKnownClients(string name)
        {
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName(name));
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("firefox")]
        [InlineData("notepad")]
        [InlineData("evil.exe")]
        [InlineData("cmd")]
        [InlineData("powershell")]
        [InlineData("explorer")]
        public void IsBulkTransferProcessName_ReturnsFalse_ForNonBulkProcesses(string name)
        {
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName(name));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void IsBulkTransferProcessName_ReturnsFalse_ForNullOrEmpty(string? name)
        {
            Assert.False(BulkTransferNoise.IsBulkTransferProcessName(name));
        }

        [Fact]
        public void IsBulkTransferProcessName_CaseInsensitive()
        {
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("QBitTorrent"));
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("UTORRENT"));
            Assert.True(BulkTransferNoise.IsBulkTransferProcessName("Aria2c.EXE"));
        }

        [Fact]
        public void ProcessNameStems_ContainsExpectedEntries()
        {
            Assert.Contains("qbittorrent", BulkTransferNoise.ProcessNameStems);
            Assert.Contains("steam", BulkTransferNoise.ProcessNameStems);
            Assert.Contains("aria2c", BulkTransferNoise.ProcessNameStems);
        }

        //  IsAnyBulkTransferProcessRunning 

        [Fact]
        public void IsAnyBulkTransferProcessRunning_DoesNotThrow()
        {
            // Should not throw regardless of what's running on the system
            BulkTransferNoise.IsAnyBulkTransferProcessRunning(out var matched);
            // matched may or may not be null depending on system state
        }

        [Fact]
        public void IsAnyBulkTransferProcessRunning_OverloadDoesNotThrow()
        {
            BulkTransferNoise.IsAnyBulkTransferProcessRunning();
        }
    }
}
