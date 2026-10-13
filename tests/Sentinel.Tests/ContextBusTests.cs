using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ContextBusTests : IDisposable
    {
        private readonly ContextBus _bus;

        public ContextBusTests()
        {
            _bus = new ContextBus(NullLogger<ContextBus>.Instance);
        }

        public void Dispose() => _bus.Dispose();

        //  Publish / Subscribe 

        [Fact]
        public async Task Publish_DeliversToSubscriber()
        {
            var received = new List<NetworkC2Signal>();
            _bus.Subscribe<NetworkC2Signal>(s => { received.Add(s); return Task.CompletedTask; }, "test");

            _bus.Publish(new NetworkC2Signal
            {
                ProcessId = 100,
                ProcessName = "evil.exe",
                RemoteAddress = "10.0.0.1",
                RemotePort = 443
            });

            await Task.Delay(200); // allow dispatch loop
            Assert.Single(received);
            Assert.Equal("10.0.0.1", received[0].RemoteAddress);
        }

        [Fact]
        public async Task Publish_DoesNotDeliverToWrongType()
        {
            var received = new List<GhostProcessSignal>();
            _bus.Subscribe<GhostProcessSignal>(s => { received.Add(s); return Task.CompletedTask; }, "test");

            _bus.Publish(new NetworkC2Signal { ProcessId = 1, ProcessName = "x" });

            await Task.Delay(200);
            Assert.Empty(received);
        }

        [Fact]
        public async Task Subscribe_Sync_Works()
        {
            var received = new List<FileVerdictSignal>();
            _bus.Subscribe<FileVerdictSignal>(s => received.Add(s), "sync-sub");

            _bus.Publish(new FileVerdictSignal
            {
                ProcessId = 50,
                ProcessName = "scanner",
                FilePath = @"C:\test.exe",
                Sha256 = "abc123"
            });

            await Task.Delay(200);
            Assert.Single(received);
            Assert.Equal(@"C:\test.exe", received[0].FilePath);
        }

        [Fact]
        public async Task Unsubscribe_StopsDelivery()
        {
            var received = new List<NetworkC2Signal>();
            var sub = _bus.Subscribe<NetworkC2Signal>(s => { received.Add(s); return Task.CompletedTask; }, "test");

            sub.Dispose(); // unsubscribe

            _bus.Publish(new NetworkC2Signal { ProcessId = 1, ProcessName = "x" });
            await Task.Delay(200);
            Assert.Empty(received);
        }

        //  Query Cache 

        [Fact]
        public void Query_ReturnsPublishedSignals()
        {
            _bus.Publish(new NetworkC2Signal { ProcessId = 42, ProcessName = "test", RemoteAddress = "1.2.3.4" });
            _bus.Publish(new NetworkC2Signal { ProcessId = 42, ProcessName = "test", RemoteAddress = "5.6.7.8" });

            var results = _bus.Query<NetworkC2Signal>(42);
            Assert.Equal(2, results.Count);
        }

        [Fact]
        public void Query_ReturnsEmpty_ForUnknownPid()
        {
            var results = _bus.Query<NetworkC2Signal>(99999);
            Assert.Empty(results);
        }

        [Fact]
        public void QueryLatest_ReturnsLastSignal()
        {
            _bus.Publish(new NetworkC2Signal { ProcessId = 10, ProcessName = "a", RemoteAddress = "first" });
            _bus.Publish(new NetworkC2Signal { ProcessId = 10, ProcessName = "a", RemoteAddress = "second" });

            var latest = _bus.QueryLatest<NetworkC2Signal>(10);
            Assert.NotNull(latest);
            Assert.Equal("second", latest.RemoteAddress);
        }

        [Fact]
        public void HasSignal_ReturnsTrue_WhenExists()
        {
            _bus.Publish(new GhostProcessSignal { ProcessId = 77, ProcessName = "ghost" });
            Assert.True(_bus.HasSignal<GhostProcessSignal>(77));
        }

        [Fact]
        public void HasSignal_ReturnsFalse_WhenNotExists()
        {
            Assert.False(_bus.HasSignal<GhostProcessSignal>(88));
        }

        [Fact]
        public void Query_DoesNotCacheZeroPid()
        {
            _bus.Publish(new NetworkC2Signal { ProcessId = 0, ProcessName = "sys" });
            var results = _bus.Query<NetworkC2Signal>(0);
            Assert.Empty(results);
        }

        //  Stats 

        [Fact]
        public void GetStats_TracksPublished()
        {
            _bus.Publish(new NetworkC2Signal { ProcessId = 1, ProcessName = "x" });
            _bus.Publish(new NetworkC2Signal { ProcessId = 2, ProcessName = "y" });

            var stats = _bus.GetStats();
            Assert.Equal(2, stats.TotalPublished);
        }

        //  Pruning 

        [Fact]
        public void PruneExpiredCache_RemovesExpiredSignals()
        {
            // Publish a signal with very short TTL
            var signal = new NetworkC2Signal
            {
                ProcessId = 55,
                ProcessName = "short",
                Ttl = TimeSpan.FromMilliseconds(1)
            };
            _bus.Publish(signal);

            Thread.Sleep(50); // let it expire

            _bus.PruneExpiredCache();
            Assert.False(_bus.HasSignal<NetworkC2Signal>(55));
        }

        //  Null safety 

        [Fact]
        public void Publish_NullSignal_DoesNotThrow()
        {
            _bus.Publish(null!);
            Assert.Equal(0, _bus.GetStats().TotalPublished);
        }
    }
}
