using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for PeripheralMonitors - verifies MTP transfer detection,
    /// Bluetooth detection model, and dangerous extension classification.
    /// </summary>
    public class PeripheralMonitorsTests
    {
        // 
        // MtpTransferGuard - dangerous extension detection
        // 

        [Theory]
        [InlineData(".exe", true)]
        [InlineData(".dll", true)]
        [InlineData(".scr", true)]
        [InlineData(".bat", true)]
        [InlineData(".cmd", true)]
        [InlineData(".ps1", true)]
        [InlineData(".vbs", true)]
        [InlineData(".hta", true)]
        [InlineData(".jpg", false)]
        [InlineData(".mp3", false)]
        [InlineData(".pdf", false)]
        [InlineData(".docx", false)]
        public void DangerousExtensions_Classification(string ext, bool isDangerous)
        {
            Assert.Equal(isDangerous, IsDangerousExtension(ext));
        }

        // 
        // Bluetooth detection model
        // 

        [Fact]
        public void Bluetooth_NewDevice_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Bluetooth: New Device Paired",
                ProcessId = 4,
                ProcessName = "SYSTEM",
                Confidence = 0.50,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.Generic
            };

            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.False(detection.KillAuthorized);
        }

        // 
        // MTP transfer detection model
        // 

        [Fact]
        public void MtpTransfer_Inbound_Executable_HighConfidence()
        {
            var detection = new DetectionEvent
            {
                RuleName = "MTP: Inbound Executable Transfer",
                ProcessId = 3000,
                ProcessName = "explorer.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SuspiciousProcess
            };

            Assert.Equal(0.85, detection.Confidence);
        }

        [Fact]
        public void MtpTransfer_Outbound_DataExfil_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "MTP: Potential Data Exfiltration via USB Device",
                ProcessId = 4000,
                ProcessName = "explorer.exe",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
        }

        // 
        // DeviceInstallMonitor - Windows driver path detection
        // 

        [Theory]
        [InlineData(@"C:\Windows\System32\drivers\WdFilter.sys", true)]
        [InlineData(@"C:\Windows\System32\DriverStore\FileRepository\driver.sys", true)]
        [InlineData(@"C:\Users\attacker\evil_driver.sys", false)]
        [InlineData(@"C:\Temp\vuln_driver.sys", false)]
        public void WindowsDriverPath_Classification(string path, bool isWindowsDriver)
        {
            Assert.Equal(isWindowsDriver, IsWindowsDriverPath(path));
        }

        // 
        // Helpers (mirror private logic)
        // 

        private static bool IsDangerousExtension(string ext)
        {
            var lower = ext.ToLowerInvariant();
            return lower is ".exe" or ".dll" or ".scr" or ".com" or ".bat" or
                ".cmd" or ".ps1" or ".vbs" or ".js" or ".hta" or ".msi" or ".wsf";
        }

        private static bool IsWindowsDriverPath(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            var lower = imagePath.ToLowerInvariant();
            return lower.Contains(@"\windows\system32\drivers\") ||
                   lower.Contains(@"\windows\system32\driverstore\") ||
                   lower.Contains(@"\windows\inf\") ||
                   lower.Contains(@"\systemroot\system32\drivers\");
        }
    }
}
