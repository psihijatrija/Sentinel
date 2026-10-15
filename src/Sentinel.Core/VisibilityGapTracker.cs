using System;

namespace Sentinel.Core
{
    /// <summary>Bounded coordination hint. It never supplies trust or response authority.</summary>
    public sealed class VisibilityGapTracker
    {
        private readonly object _gate = new();
        private VisibilityGap? _latest;
        public void Report(string source, string reason)
        {
            lock (_gate) _latest = new VisibilityGap
            {
                Generation = (_latest?.Generation ?? 0) + 1,
                ObservedUtc = DateTimeOffset.UtcNow, Source = source, Reason = reason
            };
        }
        public VisibilityGap? Snapshot()
        {
            lock (_gate) return _latest == null ? null : new VisibilityGap
            {
                Generation = _latest.Generation, ObservedUtc = _latest.ObservedUtc,
                Source = _latest.Source, Reason = _latest.Reason
            };
        }
    }

    public sealed class VisibilityGap
    {
        public long Generation { get; set; }
        public DateTimeOffset ObservedUtc { get; set; }
        public string Source { get; set; } = "";
        public string Reason { get; set; } = "";
    }

    public sealed class EtwHealthSnapshot
    {
        public DateTimeOffset SampledUtc { get; set; }
        public bool SessionPresent { get; set; }
        public bool QuerySucceeded { get; set; }
        public bool ConsumerAlive { get; set; }
        public long EventsProcessed { get; set; }
        public long DispatchDrops { get; set; }
        public long NativeEventsLost { get; set; }
        public long NativeBuffersLost { get; set; }
        public string? Error { get; set; }
        public System.Collections.Generic.Dictionary<string, uint> ProviderStatus { get; set; } = new();
    }
}
