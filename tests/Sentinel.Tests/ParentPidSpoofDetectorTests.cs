using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ParentPidSpoofDetectorTests
    {
        //  ShouldDemotePpidToLogOnly 

        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe", false)]
        [InlineData("conhost.exe", @"C:\Windows\System32\conhost.exe", false)]
        public void ShouldDemotePpidToLogOnly_ReturnsTrue_ForConhost(string name, string path, bool selfSigned)
        {
            Assert.True(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(name, path, selfSigned));
        }

        [Theory]
        [InlineData("evil.exe", @"C:\Temp\evil.exe", false)]
        public void ShouldDemotePpidToLogOnly_ReturnsFalse_ForUnknown(string name, string path, bool selfSigned)
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(name, path, selfSigned));
        }

        //  IsStockWindowsConsoleHost 

        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe")]
        [InlineData("conhost.exe", @"C:\WINDOWS\system32\conhost.exe")]
        public void IsStockWindowsConsoleHost_ReturnsTrue_ForLegitConhost(string name, string path)
        {
            Assert.True(ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Theory]
        [InlineData("conhost", @"C:\Temp\conhost.exe")]
        [InlineData("cmd", @"C:\Windows\System32\cmd.exe")]
        [InlineData("conhost.exe", @"C:\Users\Desktop\conhost.exe")]
        public void IsStockWindowsConsoleHost_ReturnsFalse_ForFakeOrOther(string name, string? path)
        {
            Assert.False(ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Fact]
        public void ShouldDemotePpidToLogOnly_NullPath_ReturnsFalse()
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly("evil.exe", null, false));
        }

        [Fact]
        public void IsStockWindowsConsoleHost_EmptyName_ReturnsFalse()
        {
            Assert.False(ParentPidSpoofDetector.IsStockWindowsConsoleHost("", @"C:\Windows\System32\conhost.exe"));
        }
    }
}
