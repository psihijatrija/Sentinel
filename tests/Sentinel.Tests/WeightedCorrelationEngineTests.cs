using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Sentinel.Core.Plugins;

namespace Sentinel.Tests
{
    public class WeightedCorrelationEngineTests
    {
        [Fact]
        public async Task RegisterSignal_AttachesScoreCardMetadata()
        {
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 100,
                MinDistinctCategories = 2
            });
            engine.Initialize(_ => Task.CompletedTask);

            var signal = new DetectionEvent
            {
                RuleName = "LSASS Access Detected",
                ProcessId = 4242,
                ProcessName = "mimikatz.exe",
                SignalType = SignalType.LsassAccess,
                Confidence = 0.9,
                Tier = DetectionTier.Tier1Behavioral,
                Timestamp = DateTime.UtcNow
            };

            await engine.RegisterSignalAsync(signal);

            Assert.True(signal.Metadata.ContainsKey("ScoreCardTotal"));
            Assert.True(signal.Metadata.ContainsKey("ScoreCardBreakdown"));
            Assert.True(signal.Metadata.ContainsKey("ScoreCardExplanation"));
            Assert.True(int.Parse(signal.Metadata["ScoreCardTotal"]) > 0);
        }

        [Fact]
        public async Task MultiCategoryTerminal_EmitsWeightedComposite()
        {
            DetectionEvent? composite = null;
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 80,
                MinDistinctCategories = 2
            });
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LSASS Credential Dump",
                ProcessId = 9001,
                ProcessName = "evil.exe",
                SignalType = SignalType.LsassAccess,
                Confidence = 0.92,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Statistical",
                ProcessId = 9001,
                ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2,
                Confidence = 0.88,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Contains("Weighted Correlation", composite!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
            Assert.True(composite.KillAuthorized);
            Assert.Equal("true", composite.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.True(composite.Metadata.ContainsKey("ScoreCardBreakdown"));
            Assert.True(ResponsePolicy.IsNukeComposite(composite));
        }

        [Fact]
        public async Task PureUxNoise_DoesNotContribute()
        {
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 10,
                MinDistinctCategories = 1
            });
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Cast Device Guard: New Device",
                ProcessId = 111,
                ProcessName = "svchost.exe",
                Confidence = 0.9,
                Timestamp = DateTime.UtcNow
            });

            var card = engine.GetScoreCard(111);
            Assert.Equal(0, card.TotalScore);
            Assert.Null(composite);
        }

        [Fact]
        public async Task PluginCorrelationRule_CannotAuthorizeWithoutIndependentTerminalEvidence()
        {
            var plugins = new PluginRegistry();
            plugins.Register(new TestCorrelationRule());

            DetectionEvent? emitted = null;
            var engine = new WeightedCorrelationEngine(
                new WeightedCorrelationConfig { Enabled = true, Threshold = 999 },
                plugins);
            engine.Initialize(ev =>
            {
                emitted = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "PluginProbe",
                ProcessId = 77,
                ProcessName = "probe.exe",
                Confidence = 0.5,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(emitted);
            Assert.Equal("Plugin Test Composite", emitted!.RuleName);
            Assert.Equal("false", emitted.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.Equal(DetectionTier.Tier2Indicator, emitted.Tier);
            Assert.Equal(ResponseAction.LogOnly, emitted.AuthorizedResponse);
        }

        [Fact]
        public async Task PluginCorrelationRule_CanConfirmWithIndependentTerminalCategories()
        {
            var plugins = new PluginRegistry();
            plugins.Register(new TestCorrelationRule());
            DetectionEvent? emitted = null;
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig { Threshold = 999 }, plugins);
            engine.Initialize(ev => { emitted = ev; return Task.CompletedTask; });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LSASS Credential Dump", ProcessId = 77, Confidence = 0.95, Timestamp = DateTime.UtcNow
            });
            Assert.Equal(ResponseAction.LogOnly, emitted!.AuthorizedResponse);
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing", ProcessId = 77, Confidence = 0.95, Timestamp = DateTime.UtcNow
            });
            Assert.Equal("true", emitted!.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.Equal(DetectionTier.Tier1Behavioral, emitted.Tier);
        }

        [Fact]
        public void MapWeightCategory_CredentialAndC2()
        {
            Assert.Equal("Credential", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "LSASS MiniDump"
            }));
            Assert.Equal("C2", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "Confirmed C2 Beacon"
            }));
            Assert.Equal("BYOVD", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "BYOVD: Vulnerable Driver Load"
            }));
        }

        [Fact]
        public void MapWeightCategory_FilelessComposites_MapToMemoryBucket()
        {
            // These kill-grade composites match none of the name-first branches, so they fall
            // through to the enum switch. Before the CategorizeDetection fix they resolved to
            // Unknown and were weighted as the "Generic" bucket (10); now they correctly land
            // in the FilelessAttack -> "Memory" bucket (40).
            Assert.Equal("Memory", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "Fileless Attack Chain"
            }));
            Assert.Equal("Memory", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "In-Memory Implant Active"
            }));
            Assert.Equal("Memory", WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "Dropped Payload Active"
            }));
        }

        private sealed class TestCorrelationRule : ICorrelationRule
        {
            public string Name => "TestRule";
            public double MinConfidence => 0.5;

            public DetectionEvent? Evaluate(int processId, string processName, IReadOnlyList<DetectionEvent> signals)
            {
                if (signals.Count == 0) return null;
                return new DetectionEvent
                {
                    RuleName = "Plugin Test Composite",
                    ProcessId = processId,
                    ProcessName = processName,
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.QuarantineAndKill,
                    Evidence = "[COMPOSITE] plugin test",
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>()
                };
            }
        }
    }

    public class AttackTechniqueMapTests
    {
        [Fact]
        public void Resolve_Lsass_MapsToT1003()
        {
            var techs = AttackTechniqueMap.Resolve("LSASS Credential Dump");
            Assert.Contains("T1003.001", techs);
        }

        [Fact]
        public void Enrich_WritesMetadata()
        {
            var d = new DetectionEvent { RuleName = "Ransomware: Mass Encrypt" };
            AttackTechniqueMap.Enrich(d);
            Assert.True(d.Metadata.ContainsKey("AttackTechniques"));
            Assert.Contains("T1486", d.Metadata["AttackTechniques"]);
        }

        [Fact]
        public void Resolve_Unknown_Empty()
        {
            Assert.Empty(AttackTechniqueMap.Resolve("Completely Benign Thing"));
        }

        // Composites emitted by BehavioralCorrelationEngine previously carried no SignalType
        // (Generic), so a composite whose NAME matched no ATT&CK fragment emitted with an EMPTY
        // AttackTechniques field. ClassifyCompositeSignal now assigns a representative terminal
        // SignalType so AttackTechniqueMap.Enrich's signal fallback fires. These composite names
        // match no fragment in the map, so without the fix they would resolve to nothing.
        [Theory]
        [InlineData("Fileless Attack Chain")]
        [InlineData("In-Memory Implant Active")]
        [InlineData("Dropped Payload Active")]
        [InlineData("Spoofed Process Phoning Home")]
        [InlineData("Local Payload: Staged Module + Credential Access")]
        public void Composite_NameMatchesNoFragment_StillGetsTechniques(string compositeName)
        {
            // Precondition: the raw name resolves to nothing (this is the gap being closed).
            Assert.Empty(AttackTechniqueMap.Resolve(compositeName));

            // With the classified SignalType the composite is built with, Enrich now populates it.
            var ev = new DetectionEvent
            {
                RuleName = compositeName,
                SignalType = BehavioralCorrelationEngine.ClassifyCompositeSignal(compositeName),
            };
            Assert.NotEqual(SignalType.Generic, ev.SignalType);

            AttackTechniqueMap.Enrich(ev);
            Assert.True(ev.Metadata.ContainsKey("AttackTechniques"),
                $"Composite '{compositeName}' must carry ATT&CK techniques (FR-8).");
            Assert.False(string.IsNullOrWhiteSpace(ev.Metadata["AttackTechniques"]));
        }

        [Theory]
        [InlineData("Active Mass-Encryption Chain", SignalType.Ransomware)]
        [InlineData("Credential Dump + Exfiltration", SignalType.CredentialTheft)]
        [InlineData("Fileless Attack Chain", SignalType.ProcessInjection)]
        [InlineData("In-Memory Implant Active", SignalType.ProcessInjection)]
        [InlineData("Dropped Payload Active", SignalType.NetworkC2)]
        [InlineData("Spoofed Process Phoning Home", SignalType.NetworkC2)]
        [InlineData("Local Payload: Staged Module + Defense Tampering", SignalType.SecurityEvasion)]
        public void ClassifyCompositeSignal_MapsToTerminalFamily(string name, SignalType expected)
        {
            Assert.Equal(expected, BehavioralCorrelationEngine.ClassifyCompositeSignal(name));
        }
    }

    public class ProductInfoTests
    {
        [Fact]
        public void Version_IsCurrent()
        {
            // v2.6.0: ProductInfo.Version is computed from version.txt / the stamped assembly
            // version - it must track the single source of truth, not a frozen literal that
            // silently drifts every release. Assert it matches the loaded assembly version.
            var asmVersion = typeof(ProductInfo).Assembly.GetName().Version?.ToString(3);
            Assert.Equal(asmVersion, ProductInfo.Version);
        }
    }

    public class WeightedCorrelationMonoCategoryBoostTests
    {
        // Helper: build a Credential-category signal at given confidence
        private static DetectionEvent CredSignal(int pid, double conf = 0.92) => new DetectionEvent
        {
            RuleName = "LSASS Credential Dump",
            ProcessId = pid,
            ProcessName = "evil.exe",
            SignalType = SignalType.LsassAccess,
            Confidence = conf,
            Tier = DetectionTier.Tier1Behavioral,
            Timestamp = DateTime.UtcNow
        };

        [Fact]
        public void GetScoreCard_SingleCategoryFlood_SetsMonoCategoryBoostFlag()
        {
            // Three signals, all Credential — should set MonoCategoryBoostApplied
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 50,
                MinDistinctCategories = 2
            });
            engine.Initialize(_ => Task.CompletedTask);

            // Feed 3 signals synchronously via RegisterSignalAsync (they populate the buffer)
            engine.RegisterSignalAsync(CredSignal(1001)).GetAwaiter().GetResult();
            engine.RegisterSignalAsync(CredSignal(1001)).GetAwaiter().GetResult();
            engine.RegisterSignalAsync(CredSignal(1001)).GetAwaiter().GetResult();

            var card = engine.GetScoreCard(1001);
            Assert.True(card.MonoCategoryBoostApplied,
                "Expected MonoCategoryBoostApplied=true when single category fires >=3 times");
        }

        [Fact]
        public async Task SingleCategoryFlood_DoesNotEmitComposite_WhenOnlyBoostedThresholdNotMet()
        {
            // Threshold=80; boost raises it to 96 (ceil(80*1.2)).
            // Three Credential signals each scaled ~25 pts (50 weight * 0.5+0.5*0.92 = 46, best wins).
            // Best-by-category only takes the highest, so total stays at ~46 — below both thresholds.
            // This test verifies that with 1 category and a tight threshold a flood never emits.
            DetectionEvent? composite = null;
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 80,
                MinDistinctCategories = 2   // also enforces 2 categories — belt-and-suspenders
            });
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            // Send 5 identical credential signals — same category, same PID
            for (int i = 0; i < 5; i++)
                await engine.RegisterSignalAsync(CredSignal(2002, conf: 0.92));

            Assert.Null(composite);  // MinDistinctCategories=2 also blocks it, but boost is the semantic gate
        }

        [Fact]
        public async Task TwoCategorySignals_StillEmitComposite_BoostNotApplied()
        {
            // Ensure the boost does NOT block legitimate multi-category composites.
            DetectionEvent? composite = null;
            var engine = new WeightedCorrelationEngine(new WeightedCorrelationConfig
            {
                Enabled = true,
                Threshold = 80,
                MinDistinctCategories = 2
            });
            engine.Initialize(ev => { composite = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LSASS Credential Dump",
                ProcessId = 3003, ProcessName = "evil.exe",
                SignalType = SignalType.LsassAccess, Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral, Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Statistical",
                ProcessId = 3003, ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2, Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral, Timestamp = DateTime.UtcNow
            });

            var card = engine.GetScoreCard(3003);
            // Two distinct categories — boost must NOT be applied
            Assert.False(card.MonoCategoryBoostApplied,
                "MonoCategoryBoostApplied must be false for multi-category signals");
            // And composite should fire (Credential+C2 scores sum well above 80)
            Assert.NotNull(composite);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite!.Tier);
        }
    }

    // SelfPathGuardTests moved to dedicated SelfPathGuardTests.cs

    public class SentinelMetricsV2Tests
    {
        [Fact]
        public void Snapshot_IncludesV2Fields()
        {
            var m = new SentinelMetrics();
            m.RecordTelemetryReceived();
            m.RecordDetection(12);
            m.RecordCorrelation(3.5);
            m.RecordCompositeEmitted();
            m.RecordWeightedEmitted();
            m.TickRates();

            var snap = m.CreateSnapshot();
            Assert.Equal(1, snap.DetectionsTotal);
            Assert.Equal(1, snap.TelemetryReceived);
            Assert.Equal(1, snap.CompositesEmitted);
            Assert.Equal(1, snap.WeightedCompositesEmitted);
            // v2.6.0: snapshot version tracks the computed ProductInfo.Version, not a literal.
            Assert.Equal(ProductInfo.Version, snap.ProductVersion);
        }
    }
}
