using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class InfostealerChainTests
    {
        public InfostealerChainTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static readonly long Birth = DateTime.UtcNow.AddHours(-1).ToFileTimeUtc();

        private static DetectionEvent SensitiveRead(int pid = 4242) => new()
        {
            RuleName = "Sensitive File Access: ETW Credential Store Read",
            Evidence = "Non-owning process 'evil.exe' (PID 4242) accessed browser login/cookie store 'C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'",
            Reasoning = "test",
            Confidence = 0.6,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic,
            ProcessId = pid,
            ProcessName = "evil.exe",
            Metadata = new Dictionary<string, string> { ["SensitiveFileAccess"] = "true", ["SensitiveKind"] = "Browser Credential Store", ["AccessSource"] = "KernelFileRead", ["ProcessCreationTime"] = Birth.ToString() },
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
        }

        // 
        //  (1) Composites fire and return Tier1Behavioral
        // 

        [Fact]
        public async Task InfostealerChain_CredentialAccessPlusOutbound_FiresTier1()
        {
            var engine = new BehavioralCorrelationEngine(_ => null, _ => Birth);
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

        [Theory]
        [InlineData("watcher")]
        [InlineData("ordinary-relay")]
        [InlineData("reused-pid")]
        [InlineData("unknown-lifetime")]
        [InlineData("different-pid")]
        [InlineData("expired")]
        [InlineData("future")]
        [InlineData("weak-network")]
        [InlineData("consultant-read")]
        [InlineData("consultant-network")]
        [InlineData("network-before-birth")]
        [InlineData("identity-denied")]
        public async Task AmbiguousInstallerOrRelayEvidenceDoesNotCompleteTheftChain(string scenario)
        {
            var read = SensitiveRead(); var remote = NetworkC2();
            long live = Birth;
            switch (scenario)
            {
                case "watcher": read.Metadata!["AccessSource"] = "FileSystemWatcher"; break;
                case "ordinary-relay": remote.Tier = DetectionTier.Tier2Indicator; remote.Confidence = 0.6; break;
                case "reused-pid": live++; break;
                case "unknown-lifetime": read.Metadata!.Remove("ProcessCreationTime"); break;
                case "different-pid": remote.ProcessId++; break;
                case "expired": read.Timestamp = DateTime.UtcNow.AddMinutes(-2); break;
                case "future": read.Timestamp = DateTime.UtcNow.AddMinutes(1); break;
                case "consultant-read": read.Metadata!["ConsultantSignal"] = "true"; break;
                case "consultant-network": remote.Metadata = new Dictionary<string, string> { ["ConsultantSignal"] = "true" }; break;
                case "network-before-birth": live = DateTime.UtcNow.AddSeconds(-1).ToFileTimeUtc(); read.Metadata!["ProcessCreationTime"] = live.ToString(); remote.Timestamp = DateTime.UtcNow.AddSeconds(-2); break;
                case "weak-network": remote.Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" }; break;
            }
            var engine = new BehavioralCorrelationEngine(_ => null, _ => scenario == "identity-denied"
                ? throw new System.ComponentModel.Win32Exception(5) : live);
            var emitted = new List<DetectionEvent>();
            engine.Initialize(e => { emitted.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(read);
            await engine.RegisterSignalAsync(remote);
            Assert.Empty(emitted);
        }

        [Theory]
        [InlineData("setup.exe")]
        [InlineData("renpy.exe")]
        [InlineData("python.exe")]
        public async Task ConfirmedReverseShellAndCredentialReadCompleteChainRegardlessOfInstallerName(string name)
        {
            var read = SensitiveRead(); var remote = NetworkC2();
            read.ProcessName = remote.ProcessName = name;
            remote.SignalType = SignalType.ReverseShell;
            remote.RuleName = "Reverse Shell: Raw Socket I/O Redirect";
            var engine = new BehavioralCorrelationEngine(_ => null, _ => Birth);
            var emitted = new List<DetectionEvent>();
            engine.Initialize(e => { emitted.Add(e); return Task.CompletedTask; });
            await engine.RegisterSignalAsync(remote);
            await engine.RegisterSignalAsync(read);
            var result = Assert.Single(emitted);
            Assert.Equal("Infostealer: Credential Access + Outbound", result.RuleName);
            ResponsePolicy.EnforceDispatchPolicy(result);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public async Task DataStagingChain_ArchivePlusOutbound_FiresTier1()
        {
            var engine = new BehavioralCorrelationEngine(_ => null, _ => Birth);
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
            var engine = new BehavioralCorrelationEngine(_ => null, _ => Birth);
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
                var config = new SentinelConfig { ActiveResponse = true };
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
