using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for TrustedHostModuleIntegrityMonitor - the registry-driven DLL-load-point
    /// integrity monitor (audio APOs + print monitors + print processors).
    ///
    /// Registry/signature reads are abstracted behind an injected IRegisteredModuleSource and
    /// SignerTrustService.AddTestOverride, so the trust decision and the Tier2/LogOnly contract
    /// are proven deterministically with no elevation, network, or machine-registry dependence.
    /// </summary>
    public class TrustedHostModuleIntegrityMonitorTests
    {
        // ---- (a) Pure classifier: signature + location only, fail-closed ----

        // ClassifyModule is a pure path + signature function (never name). The module source only
        // ever hands it a path that already exists on disk, so these cases use representative
        // paths to pin each branch: user-writable locations, OS-trusted locations, unsigned
        // elsewhere, and the fail-closed null/empty case.
        [Theory]
        [InlineData(@"C:\Users\bob\AppData\Local\Temp\evil.dll", false, ModuleVerdict.UserWritablePath)]
        [InlineData(@"C:\ProgramData\x\evil.dll", false, ModuleVerdict.UserWritablePath)]
        [InlineData(@"C:\Users\bob\Downloads\evil.dll", true, ModuleVerdict.UserWritablePath)]   // user-writable even if signed
        [InlineData(@"C:\Windows\System32\drivers\etc\..\..\apo.dll", false, ModuleVerdict.Trusted)] // keep-tree, location exonerates
        [InlineData(@"C:\Windows\System32\newapo.dll", true, ModuleVerdict.Trusted)]              // signed + keep-tree
        [InlineData(@"D:\third\party\lib\mod.dll", false, ModuleVerdict.Unsigned)]                // unsigned, non-OS, non-user-writable
        [InlineData(@"D:\third\party\lib\mod.dll", true, ModuleVerdict.Trusted)]                  // signature exonerates
        [InlineData(null, false, ModuleVerdict.Unresolved)]
        [InlineData("", false, ModuleVerdict.Unresolved)]
        public void ClassifyModule_IsSignatureAndLocationOnly(
            string? path, bool isSigned, ModuleVerdict expected)
        {
            Assert.Equal(expected, TrustedHostModuleIntegrityMonitor.ClassifyModule(path, isSigned));
        }

        [Fact]
        public void ClassifyModule_UnsignedButOsTrustedLocation_IsTrusted()
        {
            // A System32 DLL path is in an OS keep-tree, so location alone exonerates even when
            // isSigned is false (no signature check performed in the classifier - pure location).
            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string kernel32 = Path.Combine(system32, "kernel32.dll");

            Assert.Equal(ModuleVerdict.Trusted,
                TrustedHostModuleIntegrityMonitor.ClassifyModule(kernel32, isSigned: false));
        }

        // ---- (b) Factory contract: Tier2Indicator + LogOnly, never Tier1 / kill ----

        public static IEnumerable<object[]> FlaggedVerdicts()
        {
            yield return new object[] { ModuleVerdict.Unsigned };
            yield return new object[] { ModuleVerdict.UserWritablePath };
            yield return new object[] { ModuleVerdict.Unresolved };
        }

        [Theory]
        [MemberData(nameof(FlaggedVerdicts))]
        public void BuildModuleEvent_IsTier2Indicator_LogOnly_Unattributed(ModuleVerdict verdict)
        {
            var m = new RegisteredModule("AudioAPO",
                @"HKLM\...\FxProperties\Value", @"C:\Users\x\evil.dll", @"C:\Users\x\evil.dll");

            var ev = TrustedHostModuleIntegrityMonitor.BuildModuleEvent(m, verdict, signed: false, signer: null);

            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.NotEqual(DetectionTier.Tier1Behavioral, ev.Tier);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.False(ev.KillAuthorized);
            Assert.Equal(0, ev.ProcessId);
            Assert.Equal("SYSTEM", ev.ProcessName);
        }

        // ---- (c) Tier law keeps it Tier2 + LogOnly ----

        [Theory]
        [MemberData(nameof(FlaggedVerdicts))]
        public void TierLaw_KeepsEvent_Tier2AndLogOnly(ModuleVerdict verdict)
        {
            var m = new RegisteredModule("PrintMonitor",
                @"HKLM\...\Monitors\Evil\Driver", "evil.dll", @"C:\Users\x\evil.dll");
            var ev = TrustedHostModuleIntegrityMonitor.BuildModuleEvent(m, verdict, signed: false, signer: null);

            ResponsePolicy.ApplyTierLaw(ev);

            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.False(ev.KillAuthorized);
        }

        [Fact]
        public async Task Tier2_StaysLogOnly_ThroughResponseEngine_WithActiveResponse()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_thm_engine_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var engine = CreateMinimalEngine(tempDir, activeResponse: true);

                var m = new RegisteredModule("AudioAPO",
                    @"HKLM\...\FxProperties\APO", @"C:\Users\x\evil.dll", @"C:\Users\x\evil.dll");
                var ev = TrustedHostModuleIntegrityMonitor.BuildModuleEvent(m, ModuleVerdict.Unsigned, false, null);
                Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);

                await engine.EmitAsync(ev);

                Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
                Assert.False(ev.KillAuthorized);

                engine.Stop();
            }
            finally { TryDeleteDir(tempDir); }
        }

        // ---- (d)/(e) Deterministic monitor pass via a fake module source ----

        [Fact]
        public async Task ScanAsync_UnsignedNewModule_EmitsExactlyOneTier2Event()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_thm_scan_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            // Put the "unsigned" DLL under a non-OS-trusted, non-temp dir so classification lands
            // on Unsigned (not UserWritablePath) - either way it must emit; the point is >=1 event.
            string dllPath = Path.Combine(tempDir, "payload.dll");
            File.WriteAllText(dllPath, "x");

            try
            {
                var recorder = new RecordingDetectionEngine(tempDir);
                var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
                signerTrust.AddTestOverride(dllPath, isSigned: false, signer: "");

                var source = new FakeModuleSource(new[]
                {
                    new RegisteredModule("PrintMonitor", @"HKLM\...\Monitors\Evil\Driver", "payload.dll", dllPath)
                });

                var monitor = new TrustedHostModuleIntegrityMonitor(
                    recorder.Engine, signerTrust,
                    NullLogger<TrustedHostModuleIntegrityMonitor>.Instance, source);

                await monitor.ScanAsync(CancellationToken.None);

                Assert.Single(recorder.Events);
                var ev = recorder.Events[0];
                Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
                Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);

                // Second pass must not re-emit (dedup).
                await monitor.ScanAsync(CancellationToken.None);
                Assert.Single(recorder.Events);

                recorder.Engine.Stop();
            }
            finally { TryDeleteDir(tempDir); }
        }

        [Fact]
        public async Task ScanAsync_SignedModuleInOsTrustedLocation_DoesNotEmit()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_thm_signed_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);

            // Use a real System32 DLL path (OS-trusted keep-tree). Signed override makes the
            // signature path also pass; either anchor exonerates.
            string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string kernel32 = Path.Combine(system32, "kernel32.dll");
            if (!File.Exists(kernel32)) return; // no System32 - skip

            try
            {
                var recorder = new RecordingDetectionEngine(tempDir);
                var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
                signerTrust.AddTestOverride(kernel32, isSigned: true, signer: "Microsoft Windows");

                var source = new FakeModuleSource(new[]
                {
                    new RegisteredModule("AudioAPO", @"HKLM\...\FxProperties\APO", "kernel32.dll", kernel32)
                });

                var monitor = new TrustedHostModuleIntegrityMonitor(
                    recorder.Engine, signerTrust,
                    NullLogger<TrustedHostModuleIntegrityMonitor>.Instance, source);

                await monitor.ScanAsync(CancellationToken.None);

                Assert.Empty(recorder.Events);

                recorder.Engine.Stop();
            }
            finally { TryDeleteDir(tempDir); }
        }

        // ---- helpers ----

        private sealed class FakeModuleSource : IRegisteredModuleSource
        {
            private readonly IReadOnlyList<RegisteredModule> _modules;
            public FakeModuleSource(IReadOnlyList<RegisteredModule> modules) => _modules = modules;
            public IReadOnlyList<RegisteredModule> GetRegisteredModules(ILogger logger, CancellationToken ct) => _modules;
        }

        /// <summary>
        /// Wraps a real minimal DetectionEngine and recovers the events it wrote by reading the
        /// JSONL log the engine persists. Simpler and dependency-light: capture via the log file.
        /// </summary>
        private sealed class RecordingDetectionEngine
        {
            public DetectionEngine Engine { get; }
            private readonly string _logPath;

            public RecordingDetectionEngine(string tempDir)
            {
                _logPath = Path.Combine(tempDir, "events.jsonl");
                Engine = BuildEngine(tempDir, _logPath, activeResponse: false);
            }

            // The engine persists each detection to events.jsonl wrapped as { type, timestamp, data }.
            // We re-read that log and recover the DetectionEvent payloads emitted by this monitor,
            // keeping the test deterministic without a mock framework.
            public List<DetectionEvent> Events => ReadEvents();

            // The engine keeps events.jsonl open for append with FileShare.ReadWrite|Delete, so the
            // reader MUST request the same sharing (a plain File.ReadAllLines uses FileShare.Read and
            // throws "file is in use"). This also honours the constraint that file reads use
            // FileShare.ReadWrite | FileShare.Delete.
            private static string[] ReadLinesShared(string path)
            {
                if (!File.Exists(path)) return Array.Empty<string>();
                var lines = new List<string>();
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs);
                string? line;
                while ((line = reader.ReadLine()) != null) lines.Add(line);
                return lines.ToArray();
            }

            private List<DetectionEvent> ReadEvents()
            {
                var list = new List<DetectionEvent>();

                string[] lines;
                try { lines = ReadLinesShared(_logPath); }
                catch { return list; }

                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        using var doc = System.Text.Json.JsonDocument.Parse(line);
                        // Payload may be at the root (RuleName present) or nested under "data".
                        var root = doc.RootElement;
                        System.Text.Json.JsonElement payload = root;
                        if (root.ValueKind == System.Text.Json.JsonValueKind.Object &&
                            root.TryGetProperty("data", out var dataEl) &&
                            dataEl.ValueKind == System.Text.Json.JsonValueKind.Object)
                        {
                            payload = dataEl;
                        }

                        if (payload.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                        if (!payload.TryGetProperty("RuleName", out var ruleEl)) continue;
                        if (ruleEl.GetString() != "Trusted Host Module: Suspicious Registered DLL") continue;

                        var ev = System.Text.Json.JsonSerializer.Deserialize<DetectionEvent>(payload.GetRawText());
                        if (ev != null) list.Add(ev);
                    }
                    catch { /* skip non-matching lines */ }
                }
                return list;
            }
        }

        private static DetectionEngine CreateMinimalEngine(string tempDir, bool activeResponse)
            => BuildEngine(tempDir, Path.Combine(tempDir, "events.jsonl"), activeResponse);

        private static DetectionEngine BuildEngine(string tempDir, string logPath, bool activeResponse)
        {
            var cache = new SecureCacheStore(tempDir);
            var metrics = new SentinelMetrics();
            var logger = new JsonlEventLogger(logPath);
            var config = new SentinelConfig { ActiveResponse = activeResponse, ObserveUntilChain = false };
            var allowlist = new AllowlistService(cache, NullLogger<AllowlistService>.Instance);
            var responseEngine = new AdvancedResponseEngine(config, metrics, logger, new QuarantineManager(tempDir));
            var iocScanner = new IoCScanner(cache);
            var reputationService = new HashReputationService(cache, new ThreatReportingConfig(), NullLogger<HashReputationService>.Instance);
            var correlationEngine = new BehavioralCorrelationEngine();
            var scoringEngine = new ScoringEngine(allowlist, new SafeProcessExemptionRegistry(), NullLogger<ScoringEngine>.Instance);
            var signerTrust = new SignerTrustService(NullLogger<SignerTrustService>.Instance);
            var fileReputationEngine = new FileReputationEngine(reputationService, signerTrust, cache, NullLogger<FileReputationEngine>.Instance);

            return new DetectionEngine(
                new List<IDetectionRule>(),
                metrics,
                logger,
                responseEngine,
                iocScanner,
                reputationService,
                fileReputationEngine,
                correlationEngine,
                scoringEngine,
                NullLogger<DetectionEngine>.Instance
            );
        }

        private static void TryDeleteDir(string dir)
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}
