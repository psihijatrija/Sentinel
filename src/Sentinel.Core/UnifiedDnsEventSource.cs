using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public interface IRealtimeDnsTelemetry
    {
        bool IsDnsProviderActive { get; }
        event Action<string>? DnsQueryObserved;
    }

    public interface IDnsEventSourceDiagnostics
    {
        string CollectionMode { get; }
        long DroppedQueries { get; }
        bool LastReadHadLoss { get; }
    }

    /// <summary>Uses the existing real-time provider without requiring the Event Log service.
    /// Falls back to structured log reads if the ETW consumer/provider is unavailable.</summary>
    public sealed class UnifiedDnsEventSource : IDnsEventSource, IDnsEventSourceDiagnostics, IDisposable
    {
        private const int Capacity = 4096;
        private readonly IRealtimeDnsTelemetry _telemetry;
        private readonly IDnsEventLogSource _fallback;
        private readonly ILogger<UnifiedDnsEventSource> _logger;
        private readonly ConcurrentQueue<DnsQueryRecord> _queries = new();
        private int _queued;
        private long _sequence;
        private long _dropped;
        private long _reportedDrops;
        private bool _fallbackReady;
        private bool _mayEnableChannel;
        private volatile bool _disposed;
        public bool LastReadHadLoss { get; private set; }
        public string CollectionMode { get; private set; } = "Not initialized";
        public long DroppedQueries => Interlocked.Read(ref _dropped);

        public UnifiedDnsEventSource(IRealtimeDnsTelemetry telemetry,
            IDnsEventLogSource fallback, ILogger<UnifiedDnsEventSource> logger)
        {
            _telemetry = telemetry;
            _fallback = fallback;
            _logger = logger;
            _telemetry.DnsQueryObserved += Enqueue;
        }

        public void Initialize(bool mayEnableChannel)
        {
            _mayEnableChannel = mayEnableChannel;
            SelectSource();
        }

        private bool SelectSource()
        {
            bool realtime = _telemetry.IsDnsProviderActive;
            var mode = realtime ? "Real-time DNS ETW" : "DNS Operational event-log fallback";
            if (!realtime && !_fallbackReady)
            {
                _fallback.Initialize(_mayEnableChannel);
                _fallbackReady = true;
            }
            if (CollectionMode != mode)
            {
                if (CollectionMode != "Not initialized")
                    _logger.LogWarning("DNS source changed from {Before} to {After}; a transition coverage gap cannot be ruled out", CollectionMode, mode);
                else _logger.LogInformation("DNS collection source: {Mode}", mode);
            }
            CollectionMode = mode;
            return realtime;
        }

        private void Enqueue(string queryName)
        {
            if (_disposed) return;
            if (Interlocked.Increment(ref _queued) > Capacity)
            {
                Interlocked.Decrement(ref _queued);
                Interlocked.Increment(ref _dropped);
                return;
            }
            _queries.Enqueue(new DnsQueryRecord { RecordId = Interlocked.Increment(ref _sequence), Domain = queryName });
        }

        public IReadOnlyList<DnsQueryRecord> ReadQueries(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            bool realtime = SelectSource();
            var dropped = DroppedQueries;
            LastReadHadLoss = dropped != _reportedDrops;
            _reportedDrops = dropped;
            if (!realtime)
            {
                // Do not replay previously queued events alongside the same event-log history.
                while (_queries.TryDequeue(out _))
                {
                    Interlocked.Decrement(ref _queued);
                    Interlocked.Increment(ref _dropped);
                    LastReadHadLoss = true;
                }
                _reportedDrops = DroppedQueries;
                return _fallback.ReadQueries(ct);
            }
            var records = new List<DnsQueryRecord>();
            while (records.Count < Capacity && _queries.TryDequeue(out var record))
            {
                Interlocked.Decrement(ref _queued);
                records.Add(record);
            }
            // A later fallback should start at that transition, not replay stale history.
            _fallbackReady = false;
            return records;
        }

        public void Dispose()
        {
            _disposed = true;
            _telemetry.DnsQueryObserved -= Enqueue;
        }
    }
}
