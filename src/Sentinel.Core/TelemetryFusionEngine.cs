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

        // Reflexive-loop guard. Sentinel runs as SYSTEM and continuously scans other
        // processes (OpenProcess / ReadProcessMemory / handle enumeration) and writes its
        // own logs, quarantine, and diagnostics. If that self-generated activity is fed
        // back into the fusion pipeline it becomes a self-amplifying A->B->A loop that keeps
        // every bounded buffer saturated and drives allocation churn (one FusedTelemetryContext
        // per event) - the real cause of runaway RAM, not an unbounded map. The response engine
        // already self-excludes, but that runs AFTER ingestion/accumulation. We exclude our own
        // PID here, at the single ingestion choke point, mirroring the proven `owningPid == myPid`
        // filter used by the network scanners (NetworkMonitor et al). PID is constant for the
        // process lifetime, so it is cached once rather than resolved per event on the hot path.
        private static readonly int SelfPid = System.Net48Environment.ProcessId;

        // Upper bound on distinct per-PID chains. The per-chain FIFO (500) and the 15s/2min
        // cleanup bound each chain and drop empties, but nothing bounds the NUMBER of chains
        // between cleanups. A burst of distinct PIDs could spike RAM in that window; this cap
        // sheds the least-recently-touched chains on insert so a burst cannot run away.
        private const int MaxTrackedPids = 8000;

        public TelemetryFusionEngine(EventGraph eventGraph)
        {
            _eventGraph = eventGraph;
            _cleanupTimer = new System.Threading.Timer(CleanupStaleChains, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
        }

        public FusedTelemetryContext FeedEvent(TelemetryEvent telemetryEvent)
        {
            var pid = telemetryEvent.ProcessId;

            // Drop Sentinel's own activity before it enters any accumulator. We still return a
            // valid (empty) context so callers that forward it to the detection engine do not
            // NRE; it simply carries no event history and will not promote anything.
            if (pid == SelfPid && SelfPid > 0)
            {
                return new FusedTelemetryContext
                {
                    TriggeringEvent = telemetryEvent,
                    ProcessId = pid,
                    ProcessName = telemetryEvent.ProcessName
                };
            }

            // Shed excess chains on insert so a burst of distinct PIDs cannot spike RAM between
            // the 15s cleanup passes. Only applies when adding a brand-new PID.
            if (!_processChains.ContainsKey(pid) && _processChains.Count >= MaxTrackedPids)
            {
                EvictOldestChain();
            }

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

        // Evicts the chain whose most-recent event is oldest. Used as an insert-time safety
        // valve when the number of tracked PIDs exceeds MaxTrackedPids, so a burst cannot
        // outrun the periodic cleanup. O(n) over keys, but only runs at the cap boundary.
        private void EvictOldestChain()
        {
            int oldestPid = 0;
            DateTime oldest = DateTime.MaxValue;

            foreach (var kvp in _processChains)
            {
                DateTime last;
                lock (kvp.Value)
                {
                    last = kvp.Value.Count > 0 ? kvp.Value[kvp.Value.Count - 1].Timestamp : DateTime.MinValue;
                }
                if (last < oldest)
                {
                    oldest = last;
                    oldestPid = kvp.Key;
                }
            }

            if (oldestPid != 0)
            {
                _processChains.TryRemove(oldestPid, out _);
            }
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
