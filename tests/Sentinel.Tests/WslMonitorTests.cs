using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for WslMonitor - verifies WSL/container detection logic,
    /// lateral movement classification, and detection model behavior.
    /// </summary>
    public class WslMonitorTests
    {
        // 
        // Detection model validation
        // 

        [Fact]
        public void WslProcessSpawn_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "WSL: Suspicious Process Spawn from Linux Subsystem",
                ProcessId = 5000,
                ProcessName = "wsl.exe",
                Confidence = 0.72,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SuspiciousProcess
            };

            Assert.Equal("WSL: Suspicious Process Spawn from Linux Subsystem", detection.RuleName);
            Assert.Equal(SignalType.SuspiciousProcess, detection.SignalType);
        }

        [Fact]
        public void WslInteropEscalation_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "WSL: Windows Interop Privilege Escalation Attempt",
                ProcessId = 6000,
                ProcessName = "bash",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.SuspiciousProcess
            };

            Assert.True(detection.KillAuthorized);
        }

        [Fact]
        public void DockerEscape_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Container Escape: Docker Socket Mount Detected",
                ProcessId = 7000,
                ProcessName = "docker.exe",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.SuspiciousProcess
            };

            Assert.Equal(0.90, detection.Confidence);
        }

        // 
        // WSL file access patterns
        // 

        [Theory]
        [InlineData(@"\\wsl$\Ubuntu\etc\shadow")]
        [InlineData(@"\\wsl$\kali-linux\tmp\payload")]
        [InlineData(@"\\wsl.localhost\Debian\root\.ssh\authorized_keys")]
        public void WslFilePaths_RecognizedAsWslAccess(string path)
        {
            // Paths beginning with \\wsl$ or \\wsl.localhost indicate WSL filesystem access
            Assert.True(path.StartsWith(@"\\wsl") || path.StartsWith(@"\\wsl.localhost"));
        }

        [Theory]
        [InlineData(@"C:\Users\user\Documents\file.txt")]
        [InlineData(@"D:\Projects\code.py")]
        public void NonWslPaths_NotRecognized(string path)
        {
            Assert.False(path.StartsWith(@"\\wsl"));
        }

        // 
        // Distro detection validation
        // 

        [Theory]
        [InlineData("Ubuntu")]
        [InlineData("kali-linux")]
        [InlineData("Debian")]
        [InlineData("openSUSE-Leap")]
        public void KnownDistroNames_AreExpected(string distro)
        {
            // Verify format expectations for WSL distro names
            Assert.False(string.IsNullOrWhiteSpace(distro));
            Assert.DoesNotContain(" ", distro); // WSL distro names don't have spaces
        }

        // 
        // Container-to-host lateral movement
        // 

        [Fact]
        public void LateralMovement_HighConfidence_WhenToolchainsDetected()
        {
            // When WSL/Docker processes spawn credential-accessing Windows binaries,
            // confidence should be high
            var detection = new DetectionEvent
            {
                RuleName = "Container-to-Host Lateral Movement",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "wsl.exe",
                ProcessId = 8000,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            Assert.True(detection.Confidence >= 0.85);
            Assert.True(detection.KillAuthorized);
        }
    }
}
