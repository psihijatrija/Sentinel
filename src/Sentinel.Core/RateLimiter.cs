using System;

namespace Sentinel.Core
{
    public class RateLimiter
    {
        private readonly int _limit;
        private readonly TimeSpan _window;
        private readonly object _lock = new();
        private int _count;
        private DateTime _windowStart;

        public RateLimiter(int limit, TimeSpan window)
        {
            _limit = limit;
            _window = window;
            _windowStart = DateTime.UtcNow;
        }

        public bool AllowRequest()
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                if (now - _windowStart >= _window)
                {
                    _count = 0;
                    _windowStart = now;
                }

                if (_count < _limit)
                {
                    _count++;
                    return true;
                }
                return false;
            }
        }
    }

    public class BurstRateLimiter
    {
        private readonly double _limitPerSecond;
        private readonly double _maxBurst;
        private readonly object _lock = new();
        private double _tokens;
        private DateTime _lastRefill;

        public BurstRateLimiter(double limitPerSecond, double maxBurst)
        {
            _limitPerSecond = limitPerSecond;
            _maxBurst = maxBurst;
            _tokens = maxBurst;
            _lastRefill = DateTime.UtcNow;
        }

        public bool AllowRequest()
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                var elapsed = (now - _lastRefill).TotalSeconds;
                _lastRefill = now;

                _tokens = Math.Min(_maxBurst, _tokens + elapsed * _limitPerSecond);

                if (_tokens >= 1.0)
                {
                    _tokens -= 1.0;
                    return true;
                }
                return false;
            }
        }
    }
}
