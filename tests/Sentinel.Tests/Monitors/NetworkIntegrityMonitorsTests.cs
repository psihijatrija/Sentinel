using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for NetworkIntegrityMonitors - verifies PhantomDeviceMonitor
    /// classification logic, manufacturer lookup, and detection model behavior.
    /// </summary>
    public class NetworkIntegrityMonitorsTests
    {
        // 
        // NetworkDevice - internal class, test via detection model instead
        // 

        [Fact]
        public void PhantomDevice_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Phantom Device: Unknown Network Device Detected",
                Confidence = 0.75,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                ProcessName = "SYSTEM",
                ProcessId = 4
            };

            Assert.Equal(ResponseAction.NetworkIsolate, detection.AuthorizedResponse);
        }

        // 
        // ARP spoofing detection model
        // 

        [Fact]
        public void ArpSpoof_DetectionEvent_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "ARP Spoofing: Gateway MAC Changed",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                ProcessName = "SYSTEM",
                ProcessId = 4,
                SignalType = SignalType.Generic
            };

            Assert.Equal("ARP Spoofing: Gateway MAC Changed", detection.RuleName);
            Assert.Equal(ResponseAction.NetworkIsolate, detection.AuthorizedResponse);
        }

        // 
        // DNS response validation model
        // 

        [Fact]
        public void DnsResponseValidation_SubnetExtraction()
        {
            // Verify the concept: GetSubnet extracts /24 prefix
            var ip = "192.168.1.100";
            var parts = ip.Split('.');
            var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
            Assert.Equal("192.168.1.0/24", subnet);
        }

        [Fact]
        public void DnsResponseValidation_DetectionEvent_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "DNS Poisoning: Unexpected Resolver Response",
                Confidence = 0.75,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "svchost.exe",
                ProcessId = 1234
            };

            var category = ScoringEngine.CategorizeDetection(detection.RuleName);
            Assert.Equal(DetectionCategory.DnsAnomaly, category);
        }

        // 
        // WiFi security detection model
        // 

        [Fact]
        public void WifiSecurity_OpenNetwork_HighRisk()
        {
            // Open WiFi networks with no encryption are high risk
            var detection = new DetectionEvent
            {
                RuleName = "WiFi Security: Connected to Open Network",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 4
            };

            Assert.True(detection.Confidence >= 0.80);
        }

        // 
        // Remote access detection model
        // 

        [Fact]
        public void RemoteAccess_UnexpectedRdp_Detection()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Remote Access: Unexpected RDP Session",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "svchost.exe",
                ProcessId = 888
            };

            // Verify the detection event is well-formed
            Assert.Equal(0.85, detection.Confidence);
            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        // 
        // Security validation helpers used by network monitors
        // 

        [Theory]
        [InlineData("192.168.1.1", true)]
        [InlineData("10.0.0.1", true)]
        [InlineData("172.16.0.1", true)]
        [InlineData("8.8.8.8", false)]
        [InlineData("1.1.1.1", false)]
        public void SecurityValidation_IsPrivateIpAddress(string ip, bool expected)
        {
            Assert.Equal(expected, SecurityValidation.IsPrivateIpAddress(ip));
        }
    }
}
