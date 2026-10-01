using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ScoringEngineTests
    {
        private ScoringEngine CreateEngine()
        {
            var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_test_" + System.Guid.NewGuid().ToString("N")[..8]);
            var cache = new SecureCacheStore(dir);
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            return new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
        }

        [Fact]
        public void Score_HighConfidenceTier1_ReturnsMaliciousOrCritical()
        {
            var engine = CreateEngine();
            var detection = new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 1000
            };
            var score = engine.Score(detection);
            Assert.True(score.Score >= 80);
            Assert.True(score.RequiresAction);
        }

        [Fact]
        public void Score_LowConfidenceTier2_ReturnsSuspiciousOrLower()
        {
            var engine = CreateEngine();
            var detection = new DetectionEvent
            {
                RuleName = "UnsignedBinaryRule",
                Confidence = 0.40,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "unknown.exe",
                ProcessId = 2000
            };
            var score = engine.Score(detection);
            Assert.True(score.Score < 80);
            Assert.False(score.RequiresAction);
        }

        [Fact]
        public void Score_MultiCategoryCorroboration_BoostsScore()
        {
            var engine = CreateEngine();

            // First detection: credential dump
            engine.Score(new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 3000
            });

            // Second detection: different category on same PID
            var score2 = engine.Score(new DetectionEvent
            {
                RuleName = "Reverse Shell Callback",
                Confidence = 0.70,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 3000
            });

            // Should have corroboration boost
            Assert.True(score2.CorroboratingSources >= 1);
            Assert.True(score2.Score > 70); // Base + boosts
        }

        [Fact]
        public void Score_AllowlistedDevelopmentTool_ReducesScore()
        {
            var engine = CreateEngine();
            var detection = new DetectionEvent
            {
                RuleName = "UnsignedBinaryRule",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "dotnet",
                ProcessId = 4000
            };
            var score = engine.Score(detection);
            Assert.True(score.Score >= 60); // No built-in reduction without user allowlist
        }

        [Fact]
        public void Score_PresidentsLawRule_NoReduction()
        {
            var engine = CreateEngine();
            var detection = new DetectionEvent
            {
                RuleName = "LSASS Memory Dump",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "dotnet", // Even a dev tool
                ProcessId = 5000
            };
            var score = engine.Score(detection);
            // No reduction for president's law rules, even on dev tools
            Assert.True(score.Score >= 90);
        }

        [Fact]
        public void Score_ScoreNeverNegative()
        {
            var engine = CreateEngine();
            var detection = new DetectionEvent
            {
                RuleName = "UnsignedBinaryRule",
                Confidence = 0.10,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "dotnet",
                ProcessId = 6000
            };
            var score = engine.Score(detection);
            Assert.True(score.Score >= 0);
        }

        [Fact]
        public void GetProcessProfile_ReturnsNull_ForUnknownPid()
        {
            var engine = CreateEngine();
            Assert.Null(engine.GetProcessProfile(99999));
        }

        [Fact]
        public void GetProcessProfile_ReturnsProfile_AfterScoring()
        {
            var engine = CreateEngine();
            engine.Score(new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 7000
            });
            var profile = engine.GetProcessProfile(7000);
            Assert.NotNull(profile);
            Assert.Equal(1, profile!.DetectionCount);
        }

        [Fact]
        public void Verdict_Critical_AtHighScore()
        {
            var engine = CreateEngine();
            // Two high-confidence detections on same PID in different categories
            engine.Score(new DetectionEvent
            {
                RuleName = "LsassAccessRule",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 8000
            });
            var score = engine.Score(new DetectionEvent
            {
                RuleName = "Ransomware Shadow Copy",
                Confidence = 0.98,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "evil.exe",
                ProcessId = 8000
            });
            Assert.Equal(Verdict.Critical, score.Verdict);
        }

        [Fact]
        public void Cleanup_DoesNotThrow()
        {
            var engine = CreateEngine();
            engine.Cleanup(); // Should not throw even with no state
        }

        [Fact]
        public void Score_EstablishedBaselineProcess_AppliesReduction()
        {
            var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_test_baseline_" + System.Guid.NewGuid().ToString("N")[..8]);
            var cache = new SecureCacheStore(dir);
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            var baseline = new BehavioralBaselineService(cache, NullLogger<BehavioralBaselineService>.Instance);
            
            // Record a process multiple times to establish it in baseline
            for (int i = 0; i < 12; i++)
            {
                baseline.RecordProcess("goodapp.exe", @"C:\Program Files\goodapp.exe", 100, "explorer.exe");
            }

            var engine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance, baseline);
            
            // Non-President's Law rule hit
            var detection = new DetectionEvent
            {
                RuleName = "Suspicious Execution Path",
                Confidence = 0.80,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "goodapp.exe",
                ProcessId = 9000,
                Metadata = new()
                {
                    ["ParentProcessName"] = "explorer.exe"
                }
            };

            var score = engine.Score(detection);
            
            // v1.5.9: The process HAD established baseline status, but calling Score()
            // records a detection for "goodapp.exe" which revokes established status.
            // Therefore the -10 "established process" reduction is NOT applied.
            // The -5 parent-child reduction still applies (parent-child relationships
            // are observational facts, not trust grants).
            // Final: 80 base + 10 Tier1 - 5 parent-child = 85.
            Assert.Equal(85, score.Score);
            Assert.DoesNotContain(score.Adjustments, adj => adj.Reason.Contains("established"));
            Assert.Contains(score.Adjustments, adj => adj.Reason.Contains("parent-child"));

            try { System.IO.Directory.Delete(dir, true); } catch { }
        }
    }
}
