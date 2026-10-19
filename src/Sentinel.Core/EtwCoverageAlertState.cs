using System;

namespace Sentinel.Core
{
    /// <summary>Changes alert immediately; continuing loss produces bounded reminders, not an incident per poll.</summary>
    internal sealed class EtwCoverageAlertState
    {
        private string? _reason;
        private DateTimeOffset _lastAlert;
        private DateTimeOffset? _healthySince;
        internal bool IsDegraded => _reason != null;
        internal bool Observe(string? reason, DateTimeOffset now)
        {
            if (reason == null)
            {
                _healthySince ??= now;
                if (now - _healthySince.Value >= TimeSpan.FromSeconds(30)) _reason = null;
                return false;
            }
            _healthySince = null;
            bool emit = !string.Equals(_reason, reason, StringComparison.Ordinal) || now - _lastAlert >= TimeSpan.FromMinutes(5);
            _reason = reason;
            if (emit) _lastAlert = now;
            return emit;
        }
    }
}
