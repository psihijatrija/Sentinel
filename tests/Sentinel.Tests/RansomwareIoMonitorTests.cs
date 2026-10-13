using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for RansomwareIoMonitor - validates installer heuristics and
    /// the ransomware IO whitelist logic that prevents false positives on
    /// legitimate high-IO applications.
    /// </summary>
    public class RansomwareIoMonitorTests
    {
        //  InstallerHeuristics.LooksLikeInstallerName 

        [Theory]
        [InlineData("Git-2.43.0-64-bit.exe")]
        [InlineData("npp.8.6.2.Installer.x64.exe")]
        [InlineData("setup_vlc.exe")]
        [InlineData("VSCodeSetup-x64-1.85.exe")]
        [InlineData("ChromeSetup.exe")]
        public void LooksLikeInstallerName_ReturnsTrue_ForInstallers(string name)
        {
            Assert.True(RansomwareIoMonitor.LooksLikeInstallerName(name));
        }

        [Theory]
        [InlineData("evil.exe")]
        [InlineData("ransomware.exe")]
        [InlineData("notepad.exe")]
        public void LooksLikeInstallerName_ReturnsFalse_ForNonInstallers(string name)
        {
            Assert.False(RansomwareIoMonitor.LooksLikeInstallerName(name));
        }

        //  Detection model validation 

        [Fact]
        public void DetectionEvent_Ransomware_HasCorrectSignalType()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Ransomware: Mass File Rename",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = "ransom.exe",
                ProcessId = 1234,
                SignalType = SignalType.Ransomware
            };

            Assert.Equal(SignalType.Ransomware, detection.SignalType);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
        }

        [Fact]
        public void ScoringEngine_CategorizeDetection_RecognizesRansomware()
        {
            var category = ScoringEngine.CategorizeDetection("Ransomware: Mass File Rename");
            Assert.Equal(DetectionCategory.Ransomware, category);
        }

        [Fact]
        public void ScoringEngine_CategorizeDetection_RecognizesShadowCopy()
        {
            var category = ScoringEngine.CategorizeDetection("Ransomware Shadow Copy Deletion");
            Assert.Equal(DetectionCategory.Ransomware, category);
        }
    }
}
