using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for InputIntegrityGuard - the behavioral synthetic-input-injection,
    /// keylogger/replay-heuristic, and clipboard write-replace monitor that replaced
    /// the name-based PhantomKeystrokeGuard.
    ///
    /// The low-level hooks and clipboard listener require real OS input and a message
    /// pump, which a unit test cannot drive without elevation. So the detection-event
    /// construction is exposed via internal pure factories and tested directly, proving
    /// the Tier2Indicator + LogOnly + unattributed-ProcessId contract. A separate test
    /// runs the ApplyTierLaw gate (the law enforced in the response path) and a lifecycle
    /// test proves the BackgroundService starts and stops cleanly without crashing.
    /// </summary>
    public class InputIntegrityGuardTests
    {
        public static IEnumerable<object[]> AllFactoryEvents()
        {
            yield return new object[] { InputIntegrityGuard.BuildInjectedEvent("keyboard", 40, 40) };
            yield return new object[] { InputIntegrityGuard.BuildInjectedEvent("mouse", 40, 40) };
            yield return new object[] { InputIntegrityGuard.BuildKeyloggerHeuristicEvent(500) };
            yield return new object[] { InputIntegrityGuard.BuildClipBankerEvent(120) };
        }

        [Theory]
        [MemberData(nameof(AllFactoryEvents))]
        public void AllSignals_AreTier2Indicator_NotTier1(DetectionEvent ev)
        {
            // Core contract: these are weak input heuristics, never kill-grade.
            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.NotEqual(DetectionTier.Tier1Behavioral, ev.Tier);
        }

        [Theory]
        [MemberData(nameof(AllFactoryEvents))]
        public void AllSignals_AreLogOnly_AndNotKillAuthorized(DetectionEvent ev)
        {
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.False(ev.KillAuthorized);
        }

        [Theory]
        [MemberData(nameof(AllFactoryEvents))]
        public void AllSignals_DoNotFakeAttribution(DetectionEvent ev)
        {
            // Windows does not attribute the source process of injected input or clipboard
            // writes from userland, so the monitor must report ProcessId 0 / unknown rather
            // than faking it.
            Assert.Equal(0, ev.ProcessId);
            Assert.Equal("unknown", ev.ProcessName);
            Assert.Equal(SignalType.PhantomKeystroke, ev.SignalType);
        }

        [Theory]
        [MemberData(nameof(AllFactoryEvents))]
        public void TierLaw_KeepsSignals_Tier2AndLogOnly(DetectionEvent ev)
        {
            // The response path runs ApplyTierLaw. A Tier2 weak-observe signal must stay
            // Tier2 + LogOnly after the law runs - it can never be promoted to a kill.
            ResponsePolicy.ApplyTierLaw(ev);

            Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);
            Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
            Assert.False(ev.KillAuthorized);
        }

        [Fact]
        public async Task Tier2_StaysLogOnly_ThroughResponseEngine_WithActiveResponse()
        {
            // The docs/constraints.md contract: a Tier2 detection, even with ActiveResponse
            // enabled, must still resolve to LogOnly. Drive one injected-burst event through
            // the real DetectionEngine/AdvancedResponseEngine wiring (mock-less, no live system
            // access) and confirm the engine never escalates it.
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_input_integrity_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var engine = CreateMinimalEngine(tempDir, activeResponse: true);

                var ev = InputIntegrityGuard.BuildInjectedEvent("keyboard", 99, 99);
                Assert.Equal(DetectionTier.Tier2Indicator, ev.Tier);

                // Emitting must not throw and must not escalate the event's authorized response.
                await engine.EmitAsync(ev);

                Assert.Equal(ResponseAction.LogOnly, ev.AuthorizedResponse);
                Assert.False(ev.KillAuthorized);

                engine.Stop();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task Guard_Lifecycle_StartsAndStopsCleanly()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_input_integrity_life_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var engine = CreateMinimalEngine(tempDir, activeResponse: false);
                var guard = new InputIntegrityGuard(engine, NullLogger<InputIntegrityGuard>.Instance);

                // BackgroundService.StartAsync kicks off ExecuteAsync (installs hooks on a
                // dedicated message-pump thread). Give it a brief moment, then stop.
                await guard.StartAsync(CancellationToken.None);
                await Task.Delay(200);
                await guard.StopAsync(CancellationToken.None);

                engine.Stop();
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        private static DetectionEngine CreateMinimalEngine(string tempDir, bool activeResponse)
        {
            var cache = new SecureCacheStore(tempDir);
            var metrics = new SentinelMetrics();
            var logPath = Path.Combine(tempDir, "events.jsonl");
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
    }
}
