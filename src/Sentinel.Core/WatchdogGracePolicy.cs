using System;

namespace Sentinel.Core
{
    internal sealed class WatchdogGracePolicy
    {
        private DateTimeOffset _lastTick;
        private bool _deferred;
        public WatchdogGracePolicy(DateTimeOffset now) => _lastTick = now;
        public bool ShouldDefer(DateTimeOffset now, TimeSpan criticalTimeout, int running, int stale)
        {
            bool delayed = now - _lastTick > criticalTimeout;
            _lastTick = now;
            if (stale == 0) { _deferred = false; return false; }
            if (_deferred) return false;
            if (!delayed && !(running >= 4 && stale > running / 2.0)) return false;
            _deferred = true;
            return true;
        }
    }
}
