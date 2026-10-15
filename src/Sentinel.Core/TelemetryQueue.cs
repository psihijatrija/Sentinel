using System;
using System.Diagnostics;
using System.Threading.Channels;

namespace Sentinel.Core
{
    /// <summary>Bounded queue with exact eviction accounting and monotonic queue age.</summary>
    public sealed class TelemetryQueue
    {
        private readonly Channel<QueuedTelemetry> _channel;
        public TelemetryQueue(int capacity, Action onDropped)
        {
            _channel = Channel.CreateBounded<QueuedTelemetry>(new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true, SingleWriter = false
            }, _ => onDropped());
        }
        public ChannelReader<QueuedTelemetry> Reader => _channel.Reader;
        public bool TryWrite(FusedTelemetryContext context) => _channel.Writer.TryWrite(new QueuedTelemetry(context));
        public double OldestAgeMs => Reader.TryPeek(out var item) ? item.AgeMs : 0;
    }

    public sealed class QueuedTelemetry
    {
        private readonly long _enqueuedAt = Stopwatch.GetTimestamp();
        public QueuedTelemetry(FusedTelemetryContext context) => Context = context;
        public FusedTelemetryContext Context { get; }
        public double AgeMs => Math.Max(0, (Stopwatch.GetTimestamp() - _enqueuedAt) * 1000.0 / Stopwatch.Frequency);
    }

    public sealed class TelemetryPipelineSnapshot
    {
        public string State { get; set; } = "Unknown";
        public int NormalQueueDepth { get; set; }
        public int PriorityQueueDepth { get; set; }
        public double OldestQueuedAgeMs { get; set; }
        public DateTime? LastProcessedUtc { get; set; }
    }
}
