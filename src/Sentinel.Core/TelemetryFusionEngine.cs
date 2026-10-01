using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class TelemetryFusionEngine : IAsyncDisposable
    {
        private readonly EventGraph _eventGraph;
        private readonly ConcurrentDictionary<int, List<TelemetryEvent>> _processChains = new();
        private readonly System.Threading.Timer _cleanupTimer;

        // 500/chain resists FIFO erasure. Retention 2 min - BuildContext scores 60s only.
        private const int MaxEventsPerChain = 500;
        private static readonly TimeSpan ChainRetention = TimeSpan.FromMinutes(2);

        public TelemetryFusionEngine(EventGraph eventGraph)
        {
            _eventGraph = eventGraph;
            _cleanupTimer = new System.Threading.Timer(CleanupStaleChains, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        public FusedTelemetryContext FeedEvent(TelemetryEvent telemetryEvent)
        {
            var pid = telemetryEvent.ProcessId;
            var chain = _processChains.GetOrAdd(pid, _ => new List<TelemetryEvent>());

            lock (chain)
            {
                chain.Add(telemetryEvent);
                if (chain.Count > MaxEventsPerChain)
                {
                    chain.RemoveAt(0);
                }
            }

            // Update EventGraph
            var procKey = $"PID_{pid}_{telemetryEvent.ProcessName}";
            _eventGraph.AddNode(procKey, "PROCESS", new Dictionary<string, string>
            {
                { "PID", pid.ToString() },
                { "Name", telemetryEvent.ProcessName }
            });

            if (telemetryEvent is ProcessTelemetry pt)
            {
                var parentKey = $"PID_{pt.ParentProcessId}_{pt.ParentProcessName}";
                _eventGraph.AddEdge(parentKey, procKey, "SPAWNED");
            }
            else if (telemetryEvent is NetworkTelemetry nt)
            {
                var endpointKey = $"ENDPOINT_{nt.RemoteAddress}_{nt.RemotePort}";
                _eventGraph.AddEdge(procKey, endpointKey, "CONNECTED");
            }
            else if (telemetryEvent is FileActivityTelemetry ft)
            {
                var fileKey = $"FILE_{ft.FilePath}";
                _eventGraph.AddEdge(procKey, fileKey, "WROTE");
            }

            // Produce Fused Context
            return BuildContext(pid, telemetryEvent);
        }

        private FusedTelemetryContext BuildContext(int pid, TelemetryEvent triggeringEvent)
        {
            var context = new FusedTelemetryContext
            {
                TriggeringEvent = triggeringEvent,
                ProcessId = pid,
                ProcessName = triggeringEvent.ProcessName
            };

            if (_processChains.TryGetValue(pid, out var chain))
            {
                lock (chain)
                {
                    int count = 0;
                    bool hasNet = false;
                    bool hasFile = false;
                    bool hasApi = false;
                    var cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(60);

                    foreach (var e in chain)
                    {
                        if (e.Timestamp >= cutoff)
                        {
                            count++;
                            if (e is NetworkTelemetry) hasNet = true;
                            else if (e is FileActivityTelemetry fat && fat.OperationType == "WRITE") hasFile = true;
                            else if (e is ThreatIntelTelemetry) hasApi = true;
                        }
                    }

                    context.EventCount60s = count;
                    context.HasNetworkActivity = hasNet;
                    context.HasFileWrites = hasFile;
                    context.HasSuspiciousAPIs = hasApi;
                }
            }

            return context;
        }

        private void CleanupStaleChains(object? state)
        {
            var cutoff = DateTime.UtcNow - ChainRetention;
            foreach (var key in _processChains.Keys)
            {
                if (_processChains.TryGetValue(key, out var chain))
                {
                    lock (chain)
                    {
                        chain.RemoveAll(e => e.Timestamp < cutoff);
                        if (chain.Count == 0)
                        {
                            _processChains.TryRemove(key, out _);
                        }
                    }
                }
            }
            _eventGraph.Prune(ChainRetention);
        }

        public ValueTask DisposeAsync()
        {
            _cleanupTimer.Dispose();
            GC.SuppressFinalize(this);
            return default(ValueTask);
        }
    }

    public class FusedTelemetryContext
    {
        public TelemetryEvent TriggeringEvent { get; set; } = null!;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int EventCount60s { get; set; }
        public bool HasNetworkActivity { get; set; }
        public bool HasFileWrites { get; set; }
        public bool HasSuspiciousAPIs { get; set; }
    }
}
