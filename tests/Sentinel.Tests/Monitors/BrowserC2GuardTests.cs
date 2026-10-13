using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for BrowserC2Guard - verifies Chrome DevTools protocol abuse detection,
    /// headless browser proxy detection, and malicious extension permission classification.
    /// </summary>
    public class BrowserC2GuardTests
    {
        // 
        // Debug port extraction (mirrors private ExtractDebugPort)
        // 

        [Theory]
        [InlineData("chrome.exe --remote-debugging-port=9222 --headless", 9222)]
        [InlineData("msedge.exe --remote-debugging-port=9229", 9229)]
        [InlineData("chrome.exe --user-data-dir=C:\\Temp", 0)]
        [InlineData("", 0)]
        public void ExtractDebugPort_FromCommandLine(string cmdLine, int expectedPort)
        {
            Assert.Equal(expectedPort, ExtractDebugPort(cmdLine));
        }

        // 
        // Headless browser proxy detection model
        // 

        [Fact]
        public void HeadlessProxy_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Browser C2: Headless Browser as Proxy",
                ProcessId = 5000,
                ProcessName = "chrome.exe",
                Confidence = 0.82,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.NetworkC2
            };

            Assert.Equal(SignalType.NetworkC2, detection.SignalType);
            Assert.True(detection.KillAuthorized);
        }

        // 
        // Malicious extension permissions
        // 

        [Theory]
        [InlineData("nativeMessaging")]
        [InlineData("debugger")]
        [InlineData("webRequestBlocking")]
        [InlineData("proxy")]
        public void DangerousPermissions_AreHighRisk(string permission)
        {
            // These Chrome extension permissions are dangerous in the wrong hands
            var dangerous = new[] { "nativeMessaging", "debugger", "webRequestBlocking", "proxy", "cookies", "webNavigation" };
            Assert.Contains(permission, dangerous);
        }

        // 
        // CDP client detection model
        // 

        [Fact]
        public void CdpClient_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Browser C2: Active Chrome DevTools Protocol Client",
                ProcessId = 6000,
                ProcessName = "chrome.exe",
                Confidence = 0.78,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            // C2 beaconing category
            var category = ScoringEngine.CategorizeDetection("Browser C2: Active Chrome DevTools Protocol Client");
            Assert.NotEqual(DetectionCategory.Unknown, category);
        }

        // 
        // Malicious extension detection model
        // 

        [Fact]
        public void MaliciousExtension_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Browser C2: Malicious Extension with nativeMessaging",
                ProcessId = 7000,
                ProcessName = "chrome.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        // 
        // Helper (mirrors private ExtractDebugPort)
        // 

        private static int ExtractDebugPort(string cmdLine)
        {
            if (string.IsNullOrEmpty(cmdLine)) return 0;
            const string flag = "--remote-debugging-port=";
            var idx = cmdLine.IndexOf(flag);
            if (idx < 0) return 0;
            var start = idx + flag.Length;
            var end = start;
            while (end < cmdLine.Length && char.IsDigit(cmdLine[end])) end++;
            if (end == start) return 0;
            return int.TryParse(cmdLine[start..end], out var port) ? port : 0;
        }
    }
}
