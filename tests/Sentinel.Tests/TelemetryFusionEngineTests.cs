using System;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class TelemetryFusionEngineTests : IAsyncDisposable
    {
        private readonly EventGraph _eventGraph;
        private readonly TelemetryFusionEngine _engine;

        public TelemetryFusionEngineTests()
        {
            _eventGraph = new EventGraph();
            _engine = new TelemetryFusionEngine(_eventGraph);
        }

        public async ValueTask DisposeAsync() => await _engine.DisposeAsync();

        [Fact]
        public void FeedEvent_ReturnsContextWithCorrectPid()
        {
            var evt = new ProcessTelemetry
            {
                ProcessId = 1234,
                ProcessName = "test.exe",
                ParentProcessId = 5678,
                ParentProcessName = "parent.exe",
                Timestamp = DateTime.UtcNow
            };

            var context = _engine.FeedEvent(evt);

            Assert.Equal(1234, context.ProcessId);
            Assert.Equal("test.exe", context.ProcessName);
            Assert.NotNull(context.TriggeringEvent);
        }

        [Fact]
        public void FeedEvent_NetworkTelemetry_SetsHasNetworkActivity()
        {
            var netEvt = new NetworkTelemetry
            {
                ProcessId = 100,
                ProcessName = "net.exe",
                RemoteAddress = "1.2.3.4",
                RemotePort = 443,
                Timestamp = DateTime.UtcNow
            };

            var context = _engine.FeedEvent(netEvt);
            Assert.True(context.HasNetworkActivity);
        }

        [Fact]
        public void FeedEvent_FileWriteTelemetry_SetsHasFileWrites()
        {
            var fileEvt = new FileActivityTelemetry
            {
                ProcessId = 200,
                ProcessName = "writer.exe",
                FilePath = @"C:\test.txt",
                OperationType = "WRITE",
                Timestamp = DateTime.UtcNow
            };

            var context = _engine.FeedEvent(fileEvt);
            Assert.True(context.HasFileWrites);
        }

        [Fact]
        public void FeedEvent_ThreatIntelTelemetry_SetsHasSuspiciousAPIs()
        {
            var tiEvt = new ThreatIntelTelemetry
            {
                ProcessId = 300,
                ProcessName = "evil.exe",
                Timestamp = DateTime.UtcNow
            };

            var context = _engine.FeedEvent(tiEvt);
            Assert.True(context.HasSuspiciousAPIs);
        }

        [Fact]
        public void FeedEvent_MultipleEvents_IncrementsEventCount()
        {
            for (int i = 0; i < 5; i++)
            {
                _engine.FeedEvent(new ProcessTelemetry
                {
                    ProcessId = 400,
                    ProcessName = "multi.exe",
                    Timestamp = DateTime.UtcNow
                });
            }

            var context = _engine.FeedEvent(new ProcessTelemetry
            {
                ProcessId = 400,
                ProcessName = "multi.exe",
                Timestamp = DateTime.UtcNow
            });

            Assert.True(context.EventCount60s >= 5);
        }

        [Fact]
        public void FeedEvent_DifferentPids_IndependentChains()
        {
            _engine.FeedEvent(new ProcessTelemetry { ProcessId = 1, ProcessName = "a.exe", Timestamp = DateTime.UtcNow });
            _engine.FeedEvent(new ProcessTelemetry { ProcessId = 1, ProcessName = "a.exe", Timestamp = DateTime.UtcNow });
            _engine.FeedEvent(new ProcessTelemetry { ProcessId = 1, ProcessName = "a.exe", Timestamp = DateTime.UtcNow });

            var ctx2 = _engine.FeedEvent(new ProcessTelemetry { ProcessId = 2, ProcessName = "b.exe", Timestamp = DateTime.UtcNow });

            Assert.Equal(1, ctx2.EventCount60s);
        }

        [Fact]
        public void FeedEvent_AddsNodesAndEdgesToEventGraph()
        {
            _engine.FeedEvent(new ProcessTelemetry
            {
                ProcessId = 500,
                ProcessName = "child.exe",
                ParentProcessId = 499,
                ParentProcessName = "parent.exe",
                Timestamp = DateTime.UtcNow
            });

            // EventGraph should have the process node with edges
            var edges = _eventGraph.GetProcessEdges("PID_499_parent.exe");
            Assert.NotNull(edges);
            Assert.True(edges.Count > 0);
        }

        [Fact]
        public void FeedEvent_BoundedChain_DoesNotGrowUnbounded()
        {
            // Feed 600 events (max is 500 per chain) - should not crash
            for (int i = 0; i < 600; i++)
            {
                _engine.FeedEvent(new ProcessTelemetry
                {
                    ProcessId = 600,
                    ProcessName = "flood.exe",
                    Timestamp = DateTime.UtcNow
                });
            }

            var context = _engine.FeedEvent(new ProcessTelemetry
            {
                ProcessId = 600,
                ProcessName = "flood.exe",
                Timestamp = DateTime.UtcNow
            });

            // Should still work, count is bounded to recent window events
            Assert.True(context.EventCount60s > 0);
        }
    }
}
