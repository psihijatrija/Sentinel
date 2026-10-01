using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Thread-safe pub/sub bus for cross-monitor enrichment signals.
    ///
    /// This is the nervous system of the EDR - monitors publish enrichment signals
    /// (not detections - those flow through DetectionEngine) and other monitors
    /// subscribe to consume context that helps them make better decisions.
    ///
    /// Design principles:
    ///   - Non-blocking publish (bounded channel drops oldest on overflow)
    ///   - Subscribers receive only signal types they registered for
    ///   - No monitor waits on another monitor - pure async fire-and-forget enrichment
    ///   - Backpressure monitoring: tracks drops, queue depths, consumer lag
    ///   - Signal TTL: stale signals are discarded by consumers
    ///
    /// Signal flow (enrichment, not detection):
    ///   BeaconingDetector -> publishes NetworkC2Signal -> consumed by GhostProcessMonitor
    ///   GhostProcessMonitor -> publishes GhostProcessSignal -> consumed by BeaconingDetector
    ///   FileReputationEngine -> publishes FileVerdictSignal -> consumed by AppNetworkPolicyMonitor
    ///   DnsQueryMonitor -> publishes DnsAnomalySignal -> consumed by GhostProcessMonitor
    ///   EtwThreatIntelMonitor -> publishes InjectionSignal -> consumed by ChainTracer
    ///
    /// This is NOT for detections (those go through DetectionEngine -> SentinelOrchestrator).
    /// This is for enrichment context that helps monitors make better decisions.
    /// </summary>
    public sealed class ContextBus : IDisposable
    {
        private readonly ILogger<ContextBus> _logger;
        private readonly ConcurrentDictionary<Type, List<SubscriptionInfo>> _subscriptions = new();
        private readonly Channel<EnrichmentSignal> _publishChannel;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _dispatchTask;

        // Metrics
        private long _totalPublished;
        private long _totalDelivered;
        private long _totalDropped;
        private long _totalExpired;

        // Per-PID signal cache for queries (bounded, LRU-evicted)
        private readonly ConcurrentDictionary<int, BoundedSignalCache> _pidSignalCache = new();
        private const int MaxCachedPids = 5000;
        private const int MaxSignalsPerPid = 20;

        // Backpressure
        private const int ChannelCapacity = 10_000;
        private static readonly TimeSpan DefaultSignalTtl = TimeSpan.FromMinutes(5);

        public ContextBus(ILogger<ContextBus> logger)
        {
            _logger = logger;

            _publishChannel = Channel.CreateBounded<EnrichmentSignal>(
                new BoundedChannelOptions(ChannelCapacity)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleWriter = false,
                    SingleReader = true
                });

            _dispatchTask = Task.Run(DispatchLoopAsync);
        }

        // 
        // Publishing
        // 

        /// <summary>
        /// Publishes an enrichment signal to all subscribers of its type.
        /// Non-blocking. Returns immediately. If the channel is full, the oldest
        /// signal is dropped (bounded channel backpressure).
        /// </summary>
        public void Publish(EnrichmentSignal signal)
        {
            if (signal == null) return;

            Interlocked.Increment(ref _totalPublished);

            if (!_publishChannel.Writer.TryWrite(signal))
            {
                Interlocked.Increment(ref _totalDropped);
            }

            // Cache for synchronous queries
            CacheSignal(signal);
        }

        /// <summary>
        /// Publishes an enrichment signal asynchronously (awaits channel space).
        /// Use this only when backpressure feedback is needed.
        /// </summary>
        public async ValueTask PublishAsync(EnrichmentSignal signal, CancellationToken ct = default)
        {
            if (signal == null) return;

            Interlocked.Increment(ref _totalPublished);
            await _publishChannel.Writer.WriteAsync(signal, ct);
            CacheSignal(signal);
        }

        // 
        // Subscribing
        // 

        /// <summary>
        /// Subscribes a handler to a specific enrichment signal type.
        /// The handler is invoked asynchronously for each published signal of that type.
        /// Returns a disposable subscription that can be used to unsubscribe.
        /// </summary>
        public IDisposable Subscribe<TSignal>(Func<TSignal, Task> handler, string subscriberName)
            where TSignal : EnrichmentSignal
        {
            var type = typeof(TSignal);
            var subscription = new SubscriptionInfo
            {
                SubscriberName = subscriberName,
                SignalType = type,
                Handler = async (signal) =>
                {
                    if (signal is TSignal typed)
                        await handler(typed);
                },
                RegisteredAt = DateTimeOffset.UtcNow
            };

            var list = _subscriptions.GetOrAdd(type, _ => new List<SubscriptionInfo>());
            lock (list)
            {
                list.Add(subscription);
            }

            _logger.LogDebug("[ContextBus] {Subscriber} subscribed to {SignalType}",
                subscriberName, type.Name);

            return new Unsubscriber(() =>
            {
                lock (list) { list.Remove(subscription); }
            });
        }

        /// <summary>
        /// Subscribes a synchronous handler (for monitors that don't need async processing).
        /// </summary>
        public IDisposable Subscribe<TSignal>(Action<TSignal> handler, string subscriberName)
            where TSignal : EnrichmentSignal
        {
            return Subscribe<TSignal>(signal =>
            {
                handler(signal);
                return Task.CompletedTask;
            }, subscriberName);
        }

        // 
        // Synchronous Queries (for monitors that need immediate context)
        // 

        /// <summary>
        /// Queries the signal cache for recent signals of a specific type for a PID.
        /// Used by monitors that need immediate context without waiting for pub/sub delivery.
        /// </summary>
        public IReadOnlyList<TSignal> Query<TSignal>(int pid) where TSignal : EnrichmentSignal
        {
            if (_pidSignalCache.TryGetValue(pid, out var cache))
            {
                return cache.Get<TSignal>();
            }
            return Array.Empty<TSignal>();
        }

        /// <summary>
        /// Queries for the most recent signal of a type for a PID, or null.
        /// </summary>
        public TSignal? QueryLatest<TSignal>(int pid) where TSignal : EnrichmentSignal
        {
            return Query<TSignal>(pid).LastOrDefault();
        }

        /// <summary>
        /// Checks if any signal of the given type exists for a PID (fast existence check).
        /// </summary>
        public bool HasSignal<TSignal>(int pid) where TSignal : EnrichmentSignal
        {
            if (_pidSignalCache.TryGetValue(pid, out var cache))
            {
                return cache.Has<TSignal>();
            }
            return false;
        }

        // 
        // Metrics
        // 

        public ContextBusStats GetStats() => new()
        {
            TotalPublished = Interlocked.Read(ref _totalPublished),
            TotalDelivered = Interlocked.Read(ref _totalDelivered),
            TotalDropped = Interlocked.Read(ref _totalDropped),
            TotalExpired = Interlocked.Read(ref _totalExpired),
            PendingInChannel = _publishChannel.Reader.Count,
            SubscriptionCount = _subscriptions.Values.Sum(l => { lock (l) { return l.Count; } }),
            CachedPids = _pidSignalCache.Count,
            ChannelCapacity = ChannelCapacity
        };

        // 
        // Internal Dispatch Loop
        // 

        private async Task DispatchLoopAsync()
        {
            try
            {
                var reader = _publishChannel.Reader;
                while (await reader.WaitToReadAsync(_cts.Token))
                {
                    while (reader.TryRead(out var signal))
                    {
                        try
                        {
                            // Check TTL
                            if (signal.IsExpired)
                            {
                                Interlocked.Increment(ref _totalExpired);
                                continue;
                            }

                            // Dispatch to subscribers of this exact type
                            var signalType = signal.GetType();
                            if (_subscriptions.TryGetValue(signalType, out var subscribers))
                            {
                                List<SubscriptionInfo> snapshot;
                                lock (subscribers) { snapshot = new List<SubscriptionInfo>(subscribers); }

                                foreach (var sub in snapshot)
                                {
                                    try
                                    {
                                        await sub.Handler(signal);
                                        Interlocked.Increment(ref _totalDelivered);
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogDebug(ex,
                                            "[ContextBus] Handler error in {Subscriber} for {Signal}",
                                            sub.SubscriberName, signalType.Name);
                                    }
                                }
                            }

                            // Also dispatch to base type subscribers (EnrichmentSignal catch-all)
                            if (signalType != typeof(EnrichmentSignal) &&
                                _subscriptions.TryGetValue(typeof(EnrichmentSignal), out var baseSubscribers))
                            {
                                List<SubscriptionInfo> snapshot;
                                lock (baseSubscribers) { snapshot = new List<SubscriptionInfo>(baseSubscribers); }

                                foreach (var sub in snapshot)
                                {
                                    try
                                    {
                                        await sub.Handler(signal);
                                        Interlocked.Increment(ref _totalDelivered);
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger.LogDebug(ex,
                                            "[ContextBus] Base handler error in {Subscriber}",
                                            sub.SubscriberName);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "[ContextBus] Dispatch error");
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { } // CTS disposed during shutdown
            catch (Exception ex)
            {
                _logger.LogError(ex, "[ContextBus] Critical dispatch loop failure");
            }
        }

        // 
        // Signal Cache (for synchronous queries)
        // 

        private void CacheSignal(EnrichmentSignal signal)
        {
            if (signal.ProcessId <= 0) return;

            // Evict if too many PIDs cached
            if (_pidSignalCache.Count >= MaxCachedPids && !_pidSignalCache.ContainsKey(signal.ProcessId))
            {
                // Remove oldest entry
                var oldest = _pidSignalCache
                    .OrderBy(kv => kv.Value.LastAccess)
                    .FirstOrDefault();
                if (oldest.Value != null)
                    _pidSignalCache.TryRemove(oldest.Key, out _);
            }

            var cache = _pidSignalCache.GetOrAdd(signal.ProcessId, _ => new BoundedSignalCache(MaxSignalsPerPid));
            cache.Add(signal);
        }

        /// <summary>
        /// Prunes expired signals from the cache. Called periodically by the orchestrator.
        /// </summary>
        public void PruneExpiredCache()
        {
            foreach (var (pid, cache) in _pidSignalCache)
            {
                cache.PruneExpired();
                if (cache.IsEmpty)
                    _pidSignalCache.TryRemove(pid, out _);
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                if (!_cts.IsCancellationRequested)
                    _cts.Cancel();
            }
            catch { }
            try { _publishChannel.Writer.TryComplete(); } catch { }
            try { _dispatchTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
            try { _cts.Dispose(); } catch { }
        }

        private volatile bool _disposed;

        // 
        // Internal Types
        // 

        private sealed class SubscriptionInfo
        {
            public string SubscriberName { get; set; } = string.Empty;
            public Type SignalType { get; set; } = typeof(EnrichmentSignal);
            public Func<EnrichmentSignal, Task> Handler { get; set; } = null!;
            public DateTimeOffset RegisteredAt { get; set; }
        }

        private sealed class Unsubscriber : IDisposable
        {
            private readonly Action _unsubscribe;
            public Unsubscriber(Action unsubscribe) => _unsubscribe = unsubscribe;
            public void Dispose() => _unsubscribe();
        }
    }

    // 
    // Bounded Signal Cache (per-PID, for synchronous queries)
    // 

    internal sealed class BoundedSignalCache
    {
        private readonly List<EnrichmentSignal> _signals;
        private readonly int _maxSize;
        private readonly object _lock = new();

        public DateTimeOffset LastAccess { get; private set; } = DateTimeOffset.UtcNow;
        public bool IsEmpty { get { lock (_lock) { return _signals.Count == 0; } } }

        public BoundedSignalCache(int maxSize)
        {
            _maxSize = maxSize;
            _signals = new List<EnrichmentSignal>(maxSize);
        }

        public void Add(EnrichmentSignal signal)
        {
            lock (_lock)
            {
                if (_signals.Count >= _maxSize)
                    _signals.RemoveAt(0);
                _signals.Add(signal);
                LastAccess = DateTimeOffset.UtcNow;
            }
        }

        public IReadOnlyList<TSignal> Get<TSignal>() where TSignal : EnrichmentSignal
        {
            lock (_lock)
            {
                LastAccess = DateTimeOffset.UtcNow;
                return _signals.OfType<TSignal>()
                    .Where(s => !s.IsExpired)
                    .ToList();
            }
        }

        public bool Has<TSignal>() where TSignal : EnrichmentSignal
        {
            lock (_lock)
            {
                LastAccess = DateTimeOffset.UtcNow;
                return _signals.Any(s => s is TSignal && !s.IsExpired);
            }
        }

        public void PruneExpired()
        {
            lock (_lock)
            {
                _signals.RemoveAll(s => s.IsExpired);
            }
        }
    }

    // 
    // Stats
    // 

    public sealed class ContextBusStats
    {
        public long TotalPublished { get; set; }
        public long TotalDelivered { get; set; }
        public long TotalDropped { get; set; }
        public long TotalExpired { get; set; }
        public int PendingInChannel { get; set; }
        public int SubscriptionCount { get; set; }
        public int CachedPids { get; set; }
        public int ChannelCapacity { get; set; }
        public double DropRate => TotalPublished > 0 ? (double)TotalDropped / TotalPublished : 0;
    }
}
