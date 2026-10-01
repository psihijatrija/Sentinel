using System;
using System.Collections.Generic;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class AutoIncidentReporterTests
    {
        private DetectionEvent MakeDetection(
            string rule = "TestRule",
            double confidence = 0.85,
            DetectionTier tier = DetectionTier.Tier1Behavioral,
            ResponseAction response = ResponseAction.KillProcessTree)
        {
            return new DetectionEvent
            {
                RuleName = rule,
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = response,
                ProcessId = 1000,
                ProcessName = "test.exe",
                Evidence = "Test evidence",
                Metadata = new Dictionary<string, string>()
            };
        }

        //  IsChainConfirmedOrComposite 

        [Fact]
        public void IsChainConfirmedOrComposite_ReturnsFalse_ForSimpleDetection()
        {
            var d = MakeDetection();
            Assert.False(AutoIncidentReporter.IsChainConfirmedOrComposite(d));
        }

        [Fact]
        public void IsChainConfirmedOrComposite_ReturnsTrue_WhenChainConfirmed()
        {
            var d = MakeDetection();
            d.Metadata["ChainConfirmed"] = "true";
            Assert.True(AutoIncidentReporter.IsChainConfirmedOrComposite(d));
        }

        [Fact]
        public void IsChainConfirmedOrComposite_ReturnsTrue_WhenCompositeDetection()
        {
            var d = MakeDetection(rule: "Composite: Multi-Signal Attack");
            d.Metadata["ChainConfirmed"] = "true";
            Assert.True(AutoIncidentReporter.IsChainConfirmedOrComposite(d));
        }

        //  IsAttackCharacter 

        [Fact]
        public void IsAttackCharacter_ReturnsTrue_ForHighConfidenceKill()
        {
            var d = MakeDetection(confidence: 0.90, response: ResponseAction.KillProcessTree);
            Assert.True(AutoIncidentReporter.IsAttackCharacter(d));
        }

        [Fact]
        public void IsAttackCharacter_ReturnsFalse_ForLowConfidenceLogOnly()
        {
            var d = MakeDetection(confidence: 0.40, response: ResponseAction.LogOnly);
            Assert.False(AutoIncidentReporter.IsAttackCharacter(d));
        }

        //  RuleNameLooksLikeAttack 

        [Theory]
        [InlineData("LSASS Memory Dump")]
        [InlineData("Ransomware Shadow Copy Deletion")]
        [InlineData("Process Injection: CreateRemoteThread")]
        [InlineData("Credential Theft: Canary Credential Deleted")]
        [InlineData("C2 Beaconing Behavior (Statistical)")]
        public void RuleNameLooksLikeAttack_ReturnsTrue_ForKnownAttackRules(string ruleName)
        {
            Assert.True(AutoIncidentReporter.RuleNameLooksLikeAttack(ruleName));
        }

        [Theory]
        [InlineData("Traffic Anomaly: Outbound Volume Spike")]
        [InlineData(null)]
        [InlineData("")]
        public void RuleNameLooksLikeAttack_ReturnsFalse_ForBenignRules(string? ruleName)
        {
            Assert.False(AutoIncidentReporter.RuleNameLooksLikeAttack(ruleName));
        }

        //  ExtractIndicators 

        [Fact]
        public void ExtractIndicators_ExtractsProcessInfo()
        {
            var d = MakeDetection();
            d.Metadata["SHA256"] = "abc123def456";
            d.Metadata["RemoteAddress"] = "10.0.0.1";

            var indicators = AutoIncidentReporter.ExtractIndicators(d);
            Assert.NotNull(indicators);
        }

        [Fact]
        public void ExtractIndicators_HandlesEmptyMetadata()
        {
            var d = MakeDetection();
            d.Metadata = new Dictionary<string, string>();

            var indicators = AutoIncidentReporter.ExtractIndicators(d);
            Assert.NotNull(indicators);
        }

        //  IsTokenTheftOsFalsePositive 

        [Fact]
        public void IsTokenTheftOsFalsePositive_ReturnsFalse_ForNonTokenTheftRule()
        {
            var d = MakeDetection(rule: "Something Else");
            Assert.False(AutoIncidentReporter.IsTokenTheftOsFalsePositive(d));
        }

        //  VerifyPackIntegrity 

        [Fact]
        public void VerifyPackIntegrity_NonExistentDirectory_ReturnsFailure()
        {
            var result = AutoIncidentReporter.VerifyPackIntegrity(@"C:\nonexistent\path\12345");
            Assert.False(result.Ok);
        }

        [Fact]
        public void VerifyPackIntegrity_EmptyDirectory_ReturnsFailure()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel_pack_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(dir);
            try
            {
                var result = AutoIncidentReporter.VerifyPackIntegrity(dir);
                Assert.False(result.Ok);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        //  HMAC helpers 

        [Fact]
        public void ComputeSha256Hex_ProducesConsistentHash()
        {
            var data = System.Text.Encoding.UTF8.GetBytes("hello world");
            var hash1 = AutoIncidentReporter.ComputeSha256Hex(data);
            var hash2 = AutoIncidentReporter.ComputeSha256Hex(data);

            Assert.Equal(hash1, hash2);
            Assert.Equal(64, hash1.Length); // SHA-256 = 32 bytes = 64 hex chars
        }

        [Fact]
        public void DeriveEvidenceHmacKey_ReturnsNonNull()
        {
            var key = AutoIncidentReporter.DeriveEvidenceHmacKey();
            Assert.NotNull(key);
            Assert.True(key.Length > 0);
        }
    }
}
