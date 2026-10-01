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
        public async Task PluginCorrelationRule_CanEmit()
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
            Assert.Equal("true", emitted.Metadata[ResponsePolicy.ChainConfirmedKey]);
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
