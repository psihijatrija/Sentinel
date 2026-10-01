using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// Pipeline performance metrics. v2.0 expands counters for Ops dashboard:
    /// events/sec, drops, correlation latency, monitor health hooks.
    /// </summary>
    public class SentinelMetrics
    {
        private readonly ConcurrentQueue<double> _detectionLatencies = new();
        private readonly ConcurrentQueue<double> _responseLatencies = new();
        private readonly ConcurrentQueue<double> _correlationLatencies = new();

        private long _falsePositivesCount;
        private long _detectionsCount;
        private long _responsesCount;
        private long _telemetryReceived;
        private long _telemetryDropped;
        private long _compositesEmitted;
        private long _weightedEmitted;
        private long _chainConfirmed;

        // Rate windows
        private long _detectionsPrev;
        private long _telemetryPrev;
        private DateTime _rateWindowStart = DateTime.UtcNow;
        private double _detectionsPerSecond;
        private double _telemetryPerSecond;

        public void RecordDetection(double latencyMs)
        {
            Interlocked.Increment(ref _detectionsCount);
            _detectionLatencies.Enqueue(latencyMs);
            TrimQueue(_detectionLatencies);
        }

        public void RecordResponse(double latencyMs)
        {
            Interlocked.Increment(ref _responsesCount);
            _responseLatencies.Enqueue(latencyMs);
            TrimQueue(_responseLatencies);
        }

        public void RecordCorrelation(double latencyMs)
        {
            _correlationLatencies.Enqueue(latencyMs);
            TrimQueue(_correlationLatencies);
        }

        public void RecordFalsePositive() => Interlocked.Increment(ref _falsePositivesCount);

        public void RecordTelemetryReceived() => Interlocked.Increment(ref _telemetryReceived);

        public void RecordTelemetryDropped() => Interlocked.Increment(ref _telemetryDropped);

        public void RecordCompositeEmitted() => Interlocked.Increment(ref _compositesEmitted);

        public void RecordWeightedEmitted() => Interlocked.Increment(ref _weightedEmitted);

        public void RecordChainConfirmed() => Interlocked.Increment(ref _chainConfirmed);

        /// <summary>Recompute rolling events/sec (call from publisher every ~10s).</summary>
        public void TickRates()
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _rateWindowStart).TotalSeconds;
            if (elapsed < 1) return;

            long det = Interlocked.Read(ref _detectionsCount);
            long tel = Interlocked.Read(ref _telemetryReceived);
            _detectionsPerSecond = (det - _detectionsPrev) / elapsed;
            _telemetryPerSecond = (tel - _telemetryPrev) / elapsed;
            _detectionsPrev = det;
            _telemetryPrev = tel;
            _rateWindowStart = now;
        }

        public (double p50, double p90, double p95, double p99) GetDetectionLatencyPercentiles()
            => CalculatePercentiles(_detectionLatencies.ToList());

        public (double p50, double p90, double p95, double p99) GetResponseLatencyPercentiles()
            => CalculatePercentiles(_responseLatencies.ToList());

        public (double p50, double p90, double p95, double p99) GetCorrelationLatencyPercentiles()
            => CalculatePercentiles(_correlationLatencies.ToList());

        public int GetDetectionsCount() => (int)Interlocked.Read(ref _detectionsCount);
        public int GetResponsesCount() => (int)Interlocked.Read(ref _responsesCount);
        public int GetFalsePositivesCount() => (int)Interlocked.Read(ref _falsePositivesCount);

        public OpsMetricsSnapshot CreateSnapshot()
        {
            var det = GetDetectionLatencyPercentiles();
            var resp = GetResponseLatencyPercentiles();
            var corr = GetCorrelationLatencyPercentiles();

            return new OpsMetricsSnapshot
            {
                TimestampUtc = DateTime.UtcNow,
                DetectionsTotal = Interlocked.Read(ref _detectionsCount),
                ResponsesTotal = Interlocked.Read(ref _responsesCount),
                FalsePositivesTotal = Interlocked.Read(ref _falsePositivesCount),
                TelemetryReceived = Interlocked.Read(ref _telemetryReceived),
                TelemetryDropped = Interlocked.Read(ref _telemetryDropped),
                CompositesEmitted = Interlocked.Read(ref _compositesEmitted),
                WeightedCompositesEmitted = Interlocked.Read(ref _weightedEmitted),
                ChainConfirmed = Interlocked.Read(ref _chainConfirmed),
                DetectionsPerSecond = Math.Round(_detectionsPerSecond, 2),
                TelemetryPerSecond = Math.Round(_telemetryPerSecond, 2),
                DetectionLatencyMsP50 = det.p50,
                DetectionLatencyMsP95 = det.p95,
                ResponseLatencyMsP50 = resp.p50,
                ResponseLatencyMsP95 = resp.p95,
                CorrelationLatencyMsP50 = corr.p50,
                CorrelationLatencyMsP95 = corr.p95,
            };
        }

        private static void TrimQueue(ConcurrentQueue<double> queue)
        {
            while (queue.Count > 1000)
                queue.TryDequeue(out _);
        }

        private static (double p50, double p90, double p95, double p99) CalculatePercentiles(List<double> values)
        {
            if (values.Count == 0) return (0, 0, 0, 0);
            values.Sort();
            return (
                GetPercentile(values, 0.50),
                GetPercentile(values, 0.90),
                GetPercentile(values, 0.95),
                GetPercentile(values, 0.99));
        }

        private static double GetPercentile(List<double> sortedValues, double percentile)
        {
            int idx = (int)Math.Ceiling(percentile * sortedValues.Count) - 1;
            idx = Math.Max(0, Math.Min(sortedValues.Count - 1, idx));
            return sortedValues[idx];
        }
    }

    /// <summary>Serializable ops snapshot written to ProgramData\Sentinel\ops_metrics.json.</summary>
    public sealed class OpsMetricsSnapshot
    {
        public DateTime TimestampUtc { get; set; }
        public string ProductVersion { get; set; } = ProductInfo.Version;
        public long DetectionsTotal { get; set; }
        public long ResponsesTotal { get; set; }
        public long FalsePositivesTotal { get; set; }
        public long TelemetryReceived { get; set; }
        public long TelemetryDropped { get; set; }
        public long CompositesEmitted { get; set; }
        public long WeightedCompositesEmitted { get; set; }
        public long ChainConfirmed { get; set; }
        public double DetectionsPerSecond { get; set; }
        public double TelemetryPerSecond { get; set; }
        public double DetectionLatencyMsP50 { get; set; }
        public double DetectionLatencyMsP95 { get; set; }
        public double ResponseLatencyMsP50 { get; set; }
        public double ResponseLatencyMsP95 { get; set; }
        public double CorrelationLatencyMsP50 { get; set; }
        public double CorrelationLatencyMsP95 { get; set; }
        public int RegisteredMonitors { get; set; }
        public int RunningMonitors { get; set; }
        public int PluginCount { get; set; }
        public bool WeightedCorrelationEnabled { get; set; }
        public int WeightedThreshold { get; set; }
    }
}
