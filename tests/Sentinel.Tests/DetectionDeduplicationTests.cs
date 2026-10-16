using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class DetectionDeduplicationTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void SimultaneousClaimsHaveOneWinner(bool expired)
        {
            var cache = new ConcurrentDictionary<string, DateTime>();
            var now = new DateTime(2026, 10, 16, 0, 0, 0, DateTimeKind.Utc);
            if (expired) cache["same-rule-and-process"] = now.AddMinutes(-1);
            int winners = 0;
            Parallel.For(0, 10000, _ =>
            {
                if (DetectionDeduplication.TryClaim(cache, "same-rule-and-process", now, TimeSpan.FromSeconds(10)))
                    Interlocked.Increment(ref winners);
            });
            Assert.Equal(1, winners);
        }

        [Fact]
        public void WindowsAreIndependentAndRearmAtTheirBoundary()
        {
            var cache = new ConcurrentDictionary<string, DateTime>();
            var now = new DateTime(2026, 10, 16, 0, 0, 0, DateTimeKind.Utc);
            var window = TimeSpan.FromSeconds(10);
            Assert.True(DetectionDeduplication.TryClaim(cache, "first", now, window));
            Assert.True(DetectionDeduplication.TryClaim(cache, "second", now, window));
            Assert.False(DetectionDeduplication.TryClaim(cache, "first", now.AddSeconds(9), window));
            Assert.True(DetectionDeduplication.TryClaim(cache, "first", now.AddSeconds(10), window));
            Assert.False(DetectionDeduplication.TryClaim(cache, "first", now, window));
        }
    }
}
