using System;
using System.Collections.Concurrent;

namespace Sentinel.Core
{
    internal static class DetectionDeduplication
    {
        // ConcurrentDictionary factory delegates can execute repeatedly and outside its lock.
        // Only successful compare/exchange operations confer ownership of a detection slot.
        internal static bool TryClaim<TKey>(ConcurrentDictionary<TKey, DateTime> cache,
            TKey key, DateTime now, TimeSpan window) where TKey : notnull
        {
            while (true)
            {
                if (cache.TryGetValue(key, out var previous))
                {
                    if (now - previous < window) return false;
                    if (cache.TryUpdate(key, now, previous)) return true;
                }
                else if (cache.TryAdd(key, now)) return true;
            }
        }
    }
}
