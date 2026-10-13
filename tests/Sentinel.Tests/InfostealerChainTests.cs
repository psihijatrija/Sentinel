using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.6.x coverage: general-case infostealer credential-file access and the
    /// collect->package->exfil chain (SensitiveFileAccessMonitor +
    /// "Infostealer: Credential Access + Outbound" / "Data Staging + Exfiltration").
    ///
    /// Enforces the observe-until-chain contract for the new signals:
    ///   - The raw file-read / archive-staging legs are Tier2 + LogOnly and NEVER solo-kill.
    ///   - Kill authority arrives ONLY via the correlated composite (read/staging + outbound).
    /// </summary>
    [Collection("ResponsePolicy")]
    public class InfostealerChainTests
    {
        public InfostealerChainTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static DetectionEvent SensitiveRead(int pid = 4242) => new()
        {
            RuleName = "Sensitive File Access: Browser Credential Store",
            Evidence = "Non-owning process 'evil.exe' (PID 4242) accessed browser login/cookie store 'C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'",
            Reasoning = "test",
            Confidence = 0.6,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic,
            ProcessId = pid,
            ProcessName = "evil.exe",
            Metadata = new Dictionary<string, string> { ["SensitiveFileAccess"] = "true", ["SensitiveKind"] = "Browser Credential Store" },
        };

        private static DetectionEvent ArchiveStaging(int pid = 4242) => new()
        {
            RuleName = "Data Staging: Archive of User Documents",
            Evidence = "Process 'evil.exe' (PID 4242) created archive 'C:\\Users\\x\\Documents\\loot.zip' (2048KB) over a user document tree",
            Reasoning = "test",
            Confidence = 0.55,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic,
            ProcessId = pid,
            ProcessName = "evil.exe",
            Metadata = new Dictionary<string, string> { ["ArchiveStaging"] = "true" },
        };

        private static DetectionEvent NetworkC2(int pid = 4242) => new()
        {
            RuleName = "C2 Beaconing Behavior (Statistical)",
            Confidence = 0.88,
            Tier = DetectionTier.Tier1Behavioral,
            SignalType = SignalType.NetworkC2,
            ProcessId = pid,
            ProcessName = "evil.exe",
            Timestamp = DateTime.UtcNow,
        };

        // 
        //  (2) Tier2 / observe-only contract for the raw signals - never solo-escalate
        // 

        [Fact]
        public void SensitiveFileRead_IsTier2_AfterTierLaw()
        {
            var d = SensitiveRead();
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        [Fact]
        public void SensitiveFileRead_NeverSoloKills()
        {
            var d = SensitiveRead();
            // Not a terminal family on its own (Generic + non-terminal rule name).
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
            // v2.9.4: observe-until-chain removed as a settable mode; the classification safety
            // properties above (non-terminal, not kill-grade, not attack-class) are what keep this
            // raw file-read leg from ever soloing a kill.
        }

        [Fact]
        public void ArchiveStaging_IsTier2_AndNeverSoloKills()
        {
            var d = ArchiveStaging();
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);

            // Even though the rule name matches an "Exfil" terminal fragment, Exfil is
            // terminal-but-not-solo-kill-grade, and confidence is below MinTier1Confidence,
            // so it can never authorize a destructive response alone.
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
            // v2.9.4: observe-until-chain removed as a settable mode; the classification safety
            // properties above (not kill-grade, not attack-class) keep this archive-staging leg
            // from ever soloing a kill.
        }

        // 
        //  (1) Composites fire and return Tier1Behavioral
        // 

        [Fact]
        public async Task InfostealerChain_CredentialAccessPlusOutbound_FiresTier1()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(SensitiveRead());
            await engine.RegisterSignalAsync(NetworkC2());

            Assert.NotNull(composite);
            Assert.Equal("Infostealer: Credential Access + Outbound", composite!.RuleName);
            Assert.Equal(0.95, composite.Confidence);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
            Assert.True(composite.KillAuthorized);
            Assert.Equal("true", composite.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.True(ResponsePolicy.IsNukeComposite(composite));
        }

        [Fact]
        public async Task DataStagingChain_ArchivePlusOutbound_FiresTier1()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(ArchiveStaging());
            await engine.RegisterSignalAsync(NetworkC2());

            Assert.NotNull(composite);
            Assert.Equal("Data Staging + Exfiltration", composite!.RuleName);
            Assert.Equal(0.93, composite.Confidence);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
            Assert.True(composite.KillAuthorized);
            Assert.True(ResponsePolicy.IsNukeComposite(composite));
        }

        [Fact]
        public async Task SensitiveRead_Alone_DoesNotFireComposite()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // A single credential-read leg with no outbound must not produce a composite.
            await engine.RegisterSignalAsync(SensitiveRead());

            Assert.Null(composite);
        }

        // 
        //  (3) Tier2 log-only contract holds through the response engine
        // 

        [Fact]
        public async Task RawSensitiveRead_WithActiveResponse_StaysLogOnly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_infostealer_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                // ActiveResponse on, ObserveUntilChain off (lab path) - even so a Tier2 observe
                // signal that isn't chain-confirmed must produce LOG, never a destructive action.
                var config = new SentinelConfig { ActiveResponse = true, ObserveUntilChain = false };
                var metrics = new SentinelMetrics();
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var quarantine = new QuarantineManager(tempDir);
                var engine = new AdvancedResponseEngine(config, metrics, logger, quarantine);

                var d = SensitiveRead(pid: 4242);
                await engine.HandleAsync(d);
                await logger.DisposeAsync();

                bool foundLogOnly = false;
                bool foundDestructive = false;
                foreach (var line in File.ReadAllLines(logPath))
                {
                    if (line.Contains("\"ActionTaken\":\"LOG\"")) foundLogOnly = true;
                    if (line.Contains("\"ActionTaken\":\"KILL") ||
                        line.Contains("QUARANTINE") ||
                        line.Contains("NETWORK_ISOLATE"))
                        foundDestructive = true;
                }

                Assert.False(foundDestructive, "Tier2 sensitive-file-read must never trigger a destructive action.");
                Assert.True(foundLogOnly, "Expected LOG action for the Tier2 observe signal.");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        // 
        //  (4) Weighted correlation category mapping
        // 

        [Fact]
        public void WeightedCategory_SensitiveRead_MapsToCredential()
        {
            Assert.Equal("Credential", WeightedCorrelationEngine.MapWeightCategory(SensitiveRead()));
        }

        [Fact]
        public void WeightedCategory_ArchiveStaging_MapsToExfil()
        {
            Assert.Equal("Exfil", WeightedCorrelationEngine.MapWeightCategory(ArchiveStaging()));
        }
    }
}
