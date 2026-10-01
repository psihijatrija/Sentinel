using System;
using System.Threading;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class RateLimiterTests
    {
        //  RateLimiter (fixed window) 

        [Fact]
        public void RateLimiter_AllowsUpToLimit()
        {
            var limiter = new RateLimiter(5, TimeSpan.FromSeconds(60));

            for (int i = 0; i < 5; i++)
                Assert.True(limiter.AllowRequest());

            Assert.False(limiter.AllowRequest());
        }

        [Fact]
        public void RateLimiter_ResetsAfterWindow()
        {
            var limiter = new RateLimiter(2, TimeSpan.FromMilliseconds(50));

            Assert.True(limiter.AllowRequest());
            Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());

            Thread.Sleep(100); // wait for window to expire

            Assert.True(limiter.AllowRequest());
        }

        [Fact]
        public void RateLimiter_LimitOne_AllowsSingleRequest()
        {
            var limiter = new RateLimiter(1, TimeSpan.FromMinutes(1));
            Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());
        }

        [Fact]
        public void RateLimiter_HighLimit_AllowsMany()
        {
            var limiter = new RateLimiter(1000, TimeSpan.FromMinutes(1));
            for (int i = 0; i < 1000; i++)
                Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());
        }

        //  BurstRateLimiter (token bucket) 

        [Fact]
        public void BurstRateLimiter_AllowsInitialBurst()
        {
            var limiter = new BurstRateLimiter(1.0, 5.0); // 1/sec, burst of 5

            for (int i = 0; i < 5; i++)
                Assert.True(limiter.AllowRequest());

            Assert.False(limiter.AllowRequest());
        }

        [Fact]
        public void BurstRateLimiter_RefillsOverTime()
        {
            var limiter = new BurstRateLimiter(100.0, 3.0); // 100/sec, burst of 3

            // Consume all tokens
            Assert.True(limiter.AllowRequest());
            Assert.True(limiter.AllowRequest());
            Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());

            // Wait for refill (100/sec = 1 token per 10ms)
            Thread.Sleep(50);

            // Should have at least 1 token refilled
            Assert.True(limiter.AllowRequest());
        }

        [Fact]
        public void BurstRateLimiter_NeverExceedsMaxBurst()
        {
            var limiter = new BurstRateLimiter(1000.0, 3.0); // fast refill, burst 3

            Thread.Sleep(100); // let tokens accumulate well beyond max

            // Should still only allow burst amount
            int allowed = 0;
            for (int i = 0; i < 10; i++)
            {
                if (limiter.AllowRequest()) allowed++;
            }
            Assert.True(allowed <= 4); // 3 initial + maybe 1 refill during iteration
        }

        [Fact]
        public void BurstRateLimiter_ZeroRate_OnlyAllowsBurst()
        {
            var limiter = new BurstRateLimiter(0.0, 2.0);

            Assert.True(limiter.AllowRequest());
            Assert.True(limiter.AllowRequest());
            Assert.False(limiter.AllowRequest());

            Thread.Sleep(50);
            Assert.False(limiter.AllowRequest()); // no refill at 0 rate
        }
    }
}
