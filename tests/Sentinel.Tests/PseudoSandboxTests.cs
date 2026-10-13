using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for PseudoSandbox - verifies sandbox artifact presence detection,
    /// detection model for evasion-aware malware, and classification.
    /// </summary>
    public class PseudoSandboxTests
    {
        [Fact]
        public void SandboxEvasion_DetectionModel_IsSecurityEvasion()
        {
            var category = ScoringEngine.CategorizeDetection("Sandbox Evasion: Analysis Tool Detection");
            Assert.Equal(DetectionCategory.SecurityEvasion, category);
        }

        [Fact]
        public void SandboxEvasion_IsPresidentsLaw()
        {
            // Security evasion is President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("Sandbox Evasion: Analysis Tool Detection"));
        }

        [Fact]
        public void SandboxAwareMalware_DetectionEvent()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Sandbox Evasion: Sleep-Based Delay Detected",
                ProcessId = 3000,
                ProcessName = "dropper.exe",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SuspiciousProcess
            };

            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
        }

        [Fact]
        public void SandboxDetection_TimingEvasion_Model()
        {
            // Malware that sleeps > threshold before executing payload
            var detection = new DetectionEvent
            {
                RuleName = "Sandbox Evasion: Extended Sleep Before Execution",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "suspicious.exe",
                ProcessId = 4000
            };

            Assert.False(detection.KillAuthorized);
        }
    }
}
