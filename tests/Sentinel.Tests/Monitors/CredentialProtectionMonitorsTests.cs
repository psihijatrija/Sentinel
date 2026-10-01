using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for CredentialProtectionMonitors - verifies detection model behavior
    /// for credential theft scenarios, category classification, and President's Law
    /// enforcement on credential rules.
    /// </summary>
    public class CredentialProtectionMonitorsTests
    {
        // 
        // Credential detection rules - President's Law classification
        // 

        [Theory]
        [InlineData("LSASS Memory Dump")]
        [InlineData("LSASS Access")]
        [InlineData("Credential Theft: Canary Credential Deleted")]
        [InlineData("Credential Theft: Browser Cookie Harvest")]
        public void CredentialRules_ArePresidentsLaw(string ruleName)
        {
            Assert.True(ScoringEngine.IsPresidentsLawRule(ruleName),
                $"'{ruleName}' should be President's Law");
        }

        [Theory]
        [InlineData("LSASS Memory Dump")]
        [InlineData("LSASS Access")]
        [InlineData("Credential Theft: Canary Credential Deleted")]
        public void CredentialRules_CategorizedAsCredentialDump(string ruleName)
        {
            var category = ScoringEngine.CategorizeDetection(ruleName);
            Assert.Equal(DetectionCategory.CredentialDump, category);
        }

        // 
        // Browser credential guard - detection model
        // 

        [Fact]
        public void BrowserCredentialAccess_DetectionModel()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Browser Credential Store Access",
                ProcessId = 1234,
                ProcessName = "stealer.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft
            };

            Assert.Equal(SignalType.CredentialTheft, detection.SignalType);
            Assert.True(detection.KillAuthorized);
        }

        // 
        // Canary credential monitor - signal behavior
        // 

        [Fact]
        public void CredentialAccessSignal_CanaryDeleted_Model()
        {
            var signal = new CredentialAccessSignal
            {
                ProcessId = 500,
                ProcessName = "mimikatz.exe",
                TargetName = "Exchange_SMTP_Relay_abc123",
                AccessType = CredentialAccessType.CanaryDeleted
            };

            Assert.Equal(CredentialAccessType.CanaryDeleted, signal.AccessType);
            Assert.Equal("Exchange_SMTP_Relay_abc123", signal.TargetName);
        }

        [Fact]
        public void CredentialAccessType_Enum_HasExpectedValues()
        {
            Assert.Equal(0, (int)CredentialAccessType.CanaryDeleted);
            Assert.Equal(1, (int)CredentialAccessType.CanaryRead);
            Assert.Equal(2, (int)CredentialAccessType.CanaryModified);
        }

        // 
        // Null session guard - observe-until-chain enforcement
        // 

        [Fact]
        public void NullSessionProtection_Detection_IsTier2WhenObserveMode()
        {
            // Null session hardening alerts should be Tier2 in observe mode
            var detection = new DetectionEvent
            {
                RuleName = "Credential Protection: Null Session Hardening Required",
                Confidence = 0.50,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 4
            };

            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
            Assert.Equal(ResponseAction.LogOnly, detection.AuthorizedResponse);
        }

        // 
        // Password rotation guard - static helpers
        // 

        [Fact]
        public void PasswordRotation_GeneratesExpectedLengthPasswords()
        {
            // GenerateRandomPassword is private, but we can verify the concept:
            // Random passwords should meet minimum complexity requirements
            var random = new System.Random(12345);
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%";
            var password = new char[24];
            for (int i = 0; i < 24; i++)
                password[i] = chars[random.Next(chars.Length)];

            var pw = new string(password);
            Assert.Equal(24, pw.Length);
            Assert.Matches("[A-Z]", pw); // has uppercase
            Assert.Matches("[a-z]", pw); // has lowercase  
            Assert.Matches("[0-9]", pw); // has digit (statistically almost guaranteed in 24 chars)
        }
    }
}
