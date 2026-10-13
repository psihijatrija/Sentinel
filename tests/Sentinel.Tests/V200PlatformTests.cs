using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Sentinel.Core.Plugins;

namespace Sentinel.Tests
{
    public class EventGraphDiversityTests
    {
        [Fact]
        public void GetProcessDiversity_CountsEndpointsAndFiles()
        {
            var g = new EventGraph();
            g.AddEdge("PID_42_evil", "ENDPOINT_1.2.3.4_443", "CONNECTED");
            g.AddEdge("PID_42_evil", "ENDPOINT_5.6.7.8_80", "CONNECTED");
            g.AddEdge("PID_42_evil", "FILE_C:\\temp\\a.bin", "WROTE");

            var d = g.GetProcessDiversity(42, "evil");
            Assert.True(d.EdgeCount >= 3);
            Assert.Equal(2, d.DistinctEndpoints);
            Assert.Equal(1, d.DistinctFiles);
            Assert.True(d.WeightBoost > 0);
        }
    }

    public class RulePackLoaderTests
    {
        [Fact]
        public async Task FragmentRule_EmitsWhenAllFragmentsPresent()
        {
            var plugins = new PluginRegistry();
            var loader = new RulePackLoader(plugins, new Microsoft.Extensions.Logging.Abstractions.NullLogger<RulePackLoader>());
            loader.LoadPackForTest(new RulePackFile
            {
                Name = "unit",
                Rules = new List<RulePackCorrelationRule>
                {
                    new RulePackCorrelationRule
                    {
                        Name = "CredBeacon",
                        MinSignals = 2,
                        RequiredFragments = new List<string> { "LSASS", "Beacon" },
                        Confidence = 0.93,
                        Evidence = "test"
                    }
                }
            });

            Assert.Equal(1, plugins.CorrelationRules.Count);

            DetectionEvent? hit = null;
            var engine = new WeightedCorrelationEngine(
                new WeightedCorrelationConfig { Enabled = true, Threshold = 999 },
                plugins);
            engine.Initialize(ev => { hit = ev; return Task.CompletedTask; });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LSASS Access",
                ProcessId = 55,
                ProcessName = "x.exe",
                Confidence = 0.9,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing",
                ProcessId = 55,
                ProcessName = "x.exe",
                Confidence = 0.9,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(hit);
            Assert.Contains("Rule Pack", hit!.RuleName);
            Assert.True(ResponsePolicy.IsNukeComposite(hit));
        }
    }

    public class WeightedGraphBoostTests
    {
        [Fact]
        public async Task GraphBoost_IncreasesScoreCard()
        {
            var graph = new EventGraph();
            for (int i = 0; i < 5; i++)
                graph.AddEdge("PID_7_p", $"ENDPOINT_{i}_443", "CONNECTED");

            var engine = new WeightedCorrelationEngine(
                new WeightedCorrelationConfig
                {
                    Enabled = true,
                    Threshold = 10000, // never emit
                    EnableGraphBoost = true
                },
                eventGraph: graph);

            engine.Initialize(_ => Task.CompletedTask);

            var signal = new DetectionEvent
            {
                RuleName = "LSASS Dump",
                ProcessId = 7,
                ProcessName = "p",
                Confidence = 0.9,
                SignalType = SignalType.LsassAccess,
                Timestamp = DateTime.UtcNow
            };
            await engine.RegisterSignalAsync(signal);

            Assert.True(signal.Metadata.ContainsKey("ScoreCardTotal"));
            var total = int.Parse(signal.Metadata["ScoreCardTotal"]);
            Assert.True(total > 40); // credential weight + graph boost
            Assert.Contains("GraphDiversity", signal.Metadata.GetValueOrDefault("ScoreCardBreakdown", ""));
        }
    }

    public class ServiceAgentIpcCryptoTests
    {
        [Fact]
        public void SignAndVerify_RoundTrip()
        {
            var token = new byte[32];
            for (int i = 0; i < 32; i++) token[i] = (byte)i;
            var payload = ServiceAgentIpc.BuildAuthPayload(123, "nonceabc", "ping", "");
            var sig = ServiceAgentIpc.Sign(token, payload);
            Assert.True(ServiceAgentIpc.Verify(token, payload, sig));
            Assert.False(ServiceAgentIpc.Verify(token, payload, "00" + sig.Substring(2)));
        }

        [Fact]
        public void TimestampFreshness_Window()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Assert.True(ServiceAgentIpc.IsTimestampFresh(now));
            Assert.False(ServiceAgentIpc.IsTimestampFresh(now - 3600));
        }
    }

    public class PluginRegistryTests
    {
        [Fact]
        public void Register_CountsTotal()
        {
            var reg = new PluginRegistry();
            reg.Register(new FragmentCorrelationRule(new RulePackCorrelationRule
            {
                Name = "a",
                RequiredFragments = new List<string> { "X" }
            }, "p"));
            Assert.Equal(1, reg.TotalCount);
            Assert.Single(reg.CorrelationRules);
        }
    }
}
