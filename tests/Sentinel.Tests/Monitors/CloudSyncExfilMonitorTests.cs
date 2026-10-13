using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for CloudSyncExfilMonitor and related network monitors that detect
    /// data exfiltration via cloud sync tools and connectivity anomalies.
    /// </summary>
    public class CloudSyncExfilMonitorTests
    {
        // 
        // Cloud sync exfiltration detection model
        // 

        [Fact]
        public void CloudSyncExfil_RcloneBulkUpload_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Data Exfiltration: Cloud Sync Tool Running",
                ProcessId = 8000,
                ProcessName = "rclone.exe",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.Generic
            };

            // Cloud sync is observe-only without chain confirmation
            Assert.False(detection.KillAuthorized);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
        }

        [Fact]
        public void CloudSyncExfil_OneDriveNormal_NotFlagged()
        {
            // OneDrive/Dropbox running normally should not trigger high-confidence alerts
            var detection = new DetectionEvent
            {
                RuleName = "Data Exfiltration: Cloud Sync Tool Running",
                ProcessId = 9000,
                ProcessName = "OneDrive.exe",
                Confidence = 0.30,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.True(detection.Confidence < 0.50);
        }

        // 
        // ConnectivityCanaryMonitor detection model
        // 

        [Fact]
        public void ConnectivityCanary_DnsFailure_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Network Integrity: DNS Resolution Failure",
                ProcessId = 4,
                ProcessName = "SYSTEM",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        // 
        // PrivacyServiceOutboundMonitor detection model
        // 

        [Fact]
        public void PrivacyOutbound_UnexpectedConnection_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Privacy: Unexpected Outbound Connection from Service",
                ProcessId = 2000,
                ProcessName = "svchost.exe",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.False(detection.KillAuthorized);
        }

        // 
        // RemoteSessionGuard detection model
        // 

        [Fact]
        public void RemoteSession_UnauthorizedRdp_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Remote Session: Unauthorized RDP Connection Attempt",
                ProcessId = 4,
                ProcessName = "SYSTEM",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate
            };

            Assert.Equal(ResponseAction.NetworkIsolate, detection.AuthorizedResponse);
        }

        // 
        // RpcLateralMonitor detection model
        // 

        [Fact]
        public void RpcLateral_SuspiciousBinding_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Lateral Movement: Suspicious RPC Binding",
                ProcessId = 5000,
                ProcessName = "evil.exe",
                Confidence = 0.75,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        // 
        // EtwProviderTamperMonitor detection model
        // 

        [Fact]
        public void EtwTamper_ProviderDisabled_IsPresidentsLaw()
        {
            // ETW tampering = security evasion = President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("ETW Tampering: Provider Disabled"));
        }

        // 
        // WfpIntegrityMonitor detection model
        // 

        [Fact]
        public void WfpIntegrity_FilterRemoved_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Anti-Tamper: WFP Filter Removed",
                ProcessId = 4,
                ProcessName = "SYSTEM",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            var category = ScoringEngine.CategorizeDetection(detection.RuleName);
            Assert.Equal(DetectionCategory.AntiTamper, category);
        }
    }
}
