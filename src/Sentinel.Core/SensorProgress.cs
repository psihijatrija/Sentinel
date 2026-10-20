using System;

namespace Sentinel.Core
{
    /// <summary>A successful collection cycle, including an empty one, proves progress.
    /// A supervisor tick or an absence of detections does not.</summary>
    public sealed class SensorProgress
    {
        private readonly object _gate = new();
        private readonly Func<DateTimeOffset> _utcNow;
        private readonly TimeSpan _maximumSilence;
        private DateTimeOffset? _lastSuccess;
        private DateTimeOffset? _gapStarted;
        private long _cycles;
        private long _observations;
        public string Scope { get; set; } = "Collection progress only; does not prove complete telemetry coverage";
        private string? _error;

        public SensorProgress(TimeSpan maximumSilence, Func<DateTimeOffset>? utcNow = null)
        {
            if (maximumSilence <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumSilence));
            _maximumSilence = maximumSilence;
            _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        }

        public void Succeeded(long observations = 0)
        {
            lock (_gate)
            {
                var now = _utcNow();
                if (_lastSuccess.HasValue && now - _lastSuccess.Value > _maximumSilence)
                    _gapStarted ??= _lastSuccess.Value + _maximumSilence;
                _lastSuccess = now; _cycles++; _observations += observations; _error = null;
            }
        }

        public void Failed(string error)
        {
            lock (_gate) { _gapStarted ??= _utcNow(); _error = error; }
        }

        public SensorProgressSnapshot Snapshot()
        {
            lock (_gate)
            {
                var now = _utcNow();
                bool stale = _lastSuccess.HasValue && now - _lastSuccess.Value > _maximumSilence;
                if (stale) _gapStarted ??= _lastSuccess!.Value + _maximumSilence;
                return new SensorProgressSnapshot
                {
                    State = _error != null ? "Failed" : stale ? "Stale" : _lastSuccess.HasValue ? "Healthy" : "Unknown",
                    LastSuccess = _lastSuccess, SuccessfulCycles = _cycles, Observations = _observations, Scope = Scope, Error = _error,
                    GapStarted = _gapStarted, MaximumSilenceSeconds = _maximumSilence.TotalSeconds
                };
            }
        }

        /// <summary>Consume a recovered coverage gap only after a successful reconciliation.</summary>
        public DateTimeOffset? AcknowledgeRecovery()
        {
            lock (_gate)
            {
                if (_error != null || !_lastSuccess.HasValue || _utcNow() - _lastSuccess.Value > _maximumSilence)
                    return null;
                var gap = _gapStarted;
                _gapStarted = null;
                return gap;
            }
        }
    }

    public interface ISensorProgressSource { SensorProgress Progress { get; } }

    public sealed class SensorProgressSnapshot
    {
        public string State { get; set; } = "Unknown";
        public string Scope { get; set; } = "Collection progress only; does not prove complete telemetry coverage";
        public DateTimeOffset? LastSuccess { get; set; }
        public long SuccessfulCycles { get; set; }
        public long Observations { get; set; }
        public double MaximumSilenceSeconds { get; set; }
        public DateTimeOffset? GapStarted { get; set; }
        public string? Error { get; set; }
    }
}
