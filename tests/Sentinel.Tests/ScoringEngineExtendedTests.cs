using System;
using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Extended tests for ScoringEngine covering categorization, President's Law,
    /// scoring adjustments, and process state tracking.
    /// </summary>
    public class ScoringEngineExtendedTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly SecureCacheStore _cache;
        private readonly AllowlistService _allowlist;
        private readonly SafeProcessExemptionRegistry _exemptions;
        private readonly ScoringEngine _engine;

        public ScoringEngineExtendedTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_score_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
            _cache = new SecureCacheStore(Path.Combine(_tempDir, "cache"));
            _allowlist = new AllowlistService(_cache, NullLogger<AllowlistService>.Instance);
            _exemptions = new SafeProcessExemptionRegistry();
            _engine = new ScoringEngine(_allowlist, _exemptions, NullLogger<ScoringEngine>.Instance);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        #region President's Law Classification

        [Theory]
        [InlineData("LsassAccessRule")]
        [InlineData("RansomwareDetectionRule")]
        [InlineData("ReverseShellRule")]
        [InlineData("ThreatIntelInjectionRule")]
        [InlineData("PrivilegeEscalationRule")]
        public void IsPresidentsLaw_True_ForCriticalRules(string ruleName)
        {
            Assert.True(ScoringEngine.IsPresidentsLawRule(ruleName));
        }

        [Theory]
        [InlineData("UnsignedBinaryRule")]
        [InlineData("CampaignIocRule")]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("SomeRandomRule")]
        public void IsPresidentsLaw_False_ForNonCriticalRules(string? ruleName)
        {
            Assert.False(ScoringEngine.IsPresidentsLawRule(ruleName));
        }

        #endregion

        #region Detection Categorization

        [Theory]
        [InlineData("LsassAccessRule", DetectionCategory.CredentialDump)]
        [InlineData("RansomwareDetectionRule", DetectionCategory.Ransomware)]
        [InlineData("ReverseShellRule", DetectionCategory.ReverseShell)]
        [InlineData("ThreatIntelInjectionRule", DetectionCategory.ProcessInjection)]
        [InlineData("PrivilegeEscalationRule", DetectionCategory.PrivilegeEscalation)]
        [InlineData("AttackToolsRule", DetectionCategory.SecurityEvasion)]
        [InlineData("ClickFixDetectionRule", DetectionCategory.ReverseShell)]
        [InlineData("NpmSupplyChainRule", DetectionCategory.SecurityEvasion)]
        [InlineData("ChromeRemoteDebuggingRule", DetectionCategory.CredentialDump)]
        [InlineData("DllSideloadingDetectionRule", DetectionCategory.ProcessInjection)]
        public void CategorizeDetection_ReturnsCorrectCategory(string ruleName, DetectionCategory expected)
        {
            var category = ScoringEngine.CategorizeDetection(ruleName);
            Assert.Equal(expected, category);
        }

        [Theory]
        [InlineData("ETW Tampering: Provider Disabled", DetectionCategory.SecurityEvasion)]
        [InlineData("process etw bypass", DetectionCategory.SecurityEvasion)]
        [InlineData("Self-Protection: Unexpected ETW Patch", DetectionCategory.SecurityEvasion)]
        [InlineData("Network UDP: LOLBin Datagram", DetectionCategory.NetworkAnomaly)]
        [InlineData("Network ICMP: Redirect Inbound", DetectionCategory.NetworkAnomaly)]
        [InlineData("Covert Mesh: Userspace Overlay Tool", DetectionCategory.NetworkAnomaly)]
        public void CategorizeDetection_EtwToken_DoesNotEatNetworkRules(string ruleName, DetectionCategory expected)
        {
            Assert.Equal(expected, ScoringEngine.CategorizeDetection(ruleName));
        }

        [Fact]
        public void ContainsEtwToken_SkipsLettersInsideNetwork()
        {
            Assert.False(ScoringEngine.ContainsEtwToken("network udp: lolbin datagram"));
            Assert.True(ScoringEngine.ContainsEtwToken("etw tampering: provider disabled"));
            Assert.True(ScoringEngine.ContainsEtwToken("process etw bypass"));
            Assert.True(ScoringEngine.ContainsEtwToken("anti-tamper: etw session disabled"));
        }

        #endregion

        #region Scoring Logic

        [Fact]
        public void Score_HighConfidence_Tier1_ProducesHighScore()
        {
            var detection = new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 1234,
                ProcessName = "evil.exe",
                SignalType = SignalType.LsassAccess
            };
            var score = _engine.Score(detection);
            Assert.True(score.Score >= 80);
            Assert.True(score.RequiresAction);
        }

        [Fact]
        public void Score_LowConfidence_Tier2_ProducesLowScore()
        {
            var detection = new DetectionEvent
            {
                RuleName = "UnsignedBinaryRule",
                Confidence = 0.40,
                Tier = DetectionTier.Tier2Indicator,
                ProcessId = 5678,
                ProcessName = "unknown.exe",
                SignalType = SignalType.SuspiciousProcess
            };
            var score = _engine.Score(detection);
            Assert.True(score.Score < 80);
        }

        [Fact]
        public void Score_Corroboration_IncreasesThreatLevel()
        {
            // First detection for this PID
            var det1 = new DetectionEvent
            {
                RuleName = "ReverseShellRule",
                Confidence = 0.70,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 9999,
                ProcessName = "implant.exe",
                SignalType = SignalType.ReverseShell
            };
            _engine.Score(det1);

            // Second detection, different category, same PID
            var det2 = new DetectionEvent
            {
                RuleName = "ThreatIntelInjectionRule",
                Confidence = 0.70,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 9999,
                ProcessName = "implant.exe",
                SignalType = SignalType.ProcessInjection
            };
            var score2 = _engine.Score(det2);
            // Corroboration should boost the score
            Assert.True(score2.Score >= 70);
        }

        [Fact]
        public void Score_ProcessProfile_TracksCategories()
        {
            var det = new DetectionEvent
            {
                RuleName = "RansomwareDetectionRule",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 7777,
                ProcessName = "locker.exe",
                SignalType = SignalType.Ransomware
            };
            _engine.Score(det);
            var profile = _engine.GetProcessProfile(7777);
            Assert.NotNull(profile);
        }

        #endregion

        #region Cleanup

        [Fact]
        public void Cleanup_DoesNotThrow()
        {
            _engine.Score(new DetectionEvent
            {
                RuleName = "Test",
                Confidence = 0.5,
                ProcessId = 1,
                ProcessName = "t.exe",
                SignalType = SignalType.Generic
            });
            _engine.Cleanup(); // Should not throw
        }

        #endregion
    }
}
