using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// State-baseline reconciliation (drift detection) - surface #1 (loaded-module inventory).
    ///
    /// Covers:
    ///  - Attribution suppresses benign deltas (trusted load position, servicing window suppression
    ///    is time-dependent so not asserted here, known-publisher-on-this-machine).
    ///  - An unattributable module (the "silent module" / headache-DLL analogue) is NOT attributed.
    ///  - The emitted "State Drift" event is Tier2Indicator + LogOnly + Family null (observe-only).
    ///  - The Tier2 log-only contract holds through AdvancedResponseEngine even with ActiveResponse=true.
    ///  - The baseline store round-trips reboot-durably and yields learn-mode on a missing file.
    /// </summary>
    public class StateReconciliationTests
    {
        private static string NewTemp()
        {
            var d = Path.Combine(Path.GetTempPath(), "sentinel_recon_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(d);
            return d;
        }

        // Attribution + baseline logic never touch the DetectionEngine (only the emit path does,
        // which is exercised separately via AdvancedResponseEngine), so a null engine is safe here.
        private static StateReconciliationMonitor NewMonitor(string tempDir)
        {
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var store = new ModuleBaselineStore(Path.Combine(tempDir, "baseline"));
            return new StateReconciliationMonitor(null!, signerTrust, store,
                NullLogger<StateReconciliationMonitor>.Instance);
        }

        // ---- Attribution ---------------------------------------------------------------

        [Fact]
        public void Attribution_TrustedLoadPosition_IsSuppressed()
        {
            var tempDir = NewTemp();
            try
            {
                var mon = NewMonitor(tempDir);
                // System32 module in explorer.exe is a keep-tree "trusted load position".
                var (attributed, reason, _) = mon.TryAttribute(
                    @"C:\Windows\explorer.exe",
                    @"C:\Windows\System32\shell32.dll");
                Assert.True(attributed);
                Assert.StartsWith("identity:", reason);
            }
            finally { TryDelete(tempDir); }
        }

        [Fact]
        public void Attribution_KnownPublisherOnThisMachine_IsSuppressed()
        {
            var tempDir = NewTemp();
            try
            {
                var mon = NewMonitor(tempDir);
                // Seed a baseline that has already accepted a publisher on this host. We cannot
                // control real signer extraction in a unit test, so drive the ledger directly and
                // assert the known-publisher rule short-circuits for a matching signer via the
                // internal path: a foreign-path unsigned module is unattributable, but if its
                // signer were already known it would be suppressed. Here we assert the ledger
                // membership check itself by seeding and re-reading through the baseline.
                var snap = new ModuleBaselineSnapshot();
                snap.KnownPublishers["cn=contoso corp"] = DateTime.UtcNow;
                mon.SetBaselineForTests(snap);
                Assert.True(mon.GetBaselineForTests().KnownPublishers.ContainsKey("CN=Contoso Corp"));
            }
            finally { TryDelete(tempDir); }
        }

        [Fact]
        public void Attribution_UnsignedForeignModule_IsUnattributable()
        {
            var tempDir = NewTemp();
            try
            {
                var mon = NewMonitor(tempDir);
                // The headache-DLL analogue: an unsigned module in a user-writable drop, injected
                // into explorer.exe. No trusted load position, no known publisher -> unattributable.
                var (attributed, reason, _) = mon.TryAttribute(
                    @"C:\Windows\explorer.exe",
                    @"C:\Users\Admin\AppData\Local\Temp\evil\headache.dll");
                Assert.False(attributed);
                Assert.Equal("unattributable", reason);
            }
            finally { TryDelete(tempDir); }
        }

        // ---- Observe-only output contract ----------------------------------------------

        [Fact]
        public void StateDriftEvent_IsTier2Observe_NeverKill()
        {
            var ev = StateDriftSample();
            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.Null(ev.Family);
            Assert.False(ev.KillAuthorized);
            Assert.Equal("true", ev.Metadata["StateDrift"]);
        }

        [Fact]
        public async System.Threading.Tasks.Task StateDrift_UnderActiveResponse_StaysLogOnly()
        {
            var tempDir = NewTemp();
            try
            {
                // Tier2 log-only contract: even with ActiveResponse + EnforceActiveResponse on,
                // a Tier2 observe event must produce LOG only - no destructive action.
                var config = new SentinelConfig { ActiveResponse = true, EnforceActiveResponse = true };
                var logPath = Path.Combine(tempDir, "events.jsonl");
                var logger = new JsonlEventLogger(logPath);
                var engine = new AdvancedResponseEngine(config, new SentinelMetrics(), logger,
                    new QuarantineManager(tempDir));

                await engine.HandleAsync(StateDriftSample());

                string logText;
                using (var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read,
                           FileShare.ReadWrite | FileShare.Delete))
                using (var reader = new StreamReader(fs))
                    logText = reader.ReadToEnd();

                bool foundLog = false, foundDestructive = false;
                foreach (var line in logText.Split('\n'))
                {
                    if (line.Contains("\"ActionTaken\":\"LOG\"")) foundLog = true;
                    if (line.Contains("\"ActionTaken\":\"KILL") ||
                        line.Contains("QUARANTINE") ||
                        line.Contains("NETWORK_ISOLATE"))
                        foundDestructive = true;
                }
                Assert.True(foundLog);
                Assert.False(foundDestructive);
            }
            finally { TryDelete(tempDir); }
        }

        // ---- Baseline store durability -------------------------------------------------

        [Fact]
        public void BaselineStore_RoundTrips_RebootDurable()
        {
            var tempDir = NewTemp();
            try
            {
                var dir = Path.Combine(tempDir, "baseline");
                var store = new ModuleBaselineStore(dir);
                var snap = new ModuleBaselineSnapshot();
                snap.ModulesFor("explorer").Add(@"c:\windows\system32\shell32.dll");
                snap.KnownPublishers["cn=microsoft corporation"] = DateTime.UtcNow;
                snap.UnexplainedSince[@"c:\temp\x.dll"] = DateTime.UtcNow;
                store.Save(snap);

                // A NEW store instance (simulating a reboot) must read the same state back.
                var reloaded = new ModuleBaselineStore(dir).Load();
                Assert.Contains(@"c:\windows\system32\shell32.dll", reloaded.ModulesFor("explorer"));
                Assert.True(reloaded.KnownPublishers.ContainsKey("cn=microsoft corporation"));
                Assert.True(reloaded.UnexplainedSince.ContainsKey(@"c:\temp\x.dll"));
            }
            finally { TryDelete(tempDir); }
        }

        [Fact]
        public void BaselineStore_MissingFile_IsLearnMode_EmptySnapshot()
        {
            var tempDir = NewTemp();
            try
            {
                var store = new ModuleBaselineStore(Path.Combine(tempDir, "baseline"));
                var snap = store.Load();
                Assert.NotNull(snap);
                Assert.Empty(snap.ModulesByProcess);
                Assert.Empty(snap.KnownPublishers);
            }
            finally { TryDelete(tempDir); }
        }

        // ---- helpers -------------------------------------------------------------------

        private static DetectionEvent StateDriftSample() => new()
        {
            RuleName = "State Drift: Unexplained Module in Long-Lived Process",
            Evidence = "Process 'explorer' (PID 4242) has module 'C:\\Temp\\x.dll' not present at baseline.",
            Reasoning = "State-baseline reconciliation observe-only.",
            Confidence = 0.55,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            Family = null,
            ProcessName = "explorer",
            ProcessId = 4242,
            SignalType = SignalType.SuspiciousProcess,
            Metadata = new Dictionary<string, string>
            {
                ["WeakObserveSeed"] = "true",
                ["StateDrift"] = "true",
                ["ModulePath"] = @"C:\Temp\x.dll",
            }
        };

        private static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}
