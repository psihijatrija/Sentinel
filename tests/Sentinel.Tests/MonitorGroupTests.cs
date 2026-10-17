using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class MonitorGroupTests
    {
        private sealed class FakeMonitor : BackgroundService
        {
            public bool Started { get; private set; }
            public bool Stopped { get; private set; }
            private readonly TaskCompletionSource<bool> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public Task StartedSignal => _started.Task;
            private readonly bool _shouldFail;

            public FakeMonitor(bool shouldFail = false) => _shouldFail = shouldFail;

            public override Task StartAsync(CancellationToken ct)
            {
                if (_shouldFail) throw new InvalidOperationException("Simulated failure");
                Started = true;
                var start = base.StartAsync(ct);
                _started.TrySetResult(true);
                return start;
            }

            public override Task StopAsync(CancellationToken ct)
            {
                Stopped = true;
                return base.StopAsync(ct);
            }

            protected override Task ExecuteAsync(CancellationToken stoppingToken) => Task.CompletedTask;
        }

        [Fact]
        public void MonitorGroup_ReportsCorrectCount()
        {
            var monitors = new IHostedService[] { new FakeMonitor(), new FakeMonitor(), new FakeMonitor() };
            var config = new MonitorGroupConfig { Name = "TestGroup" };
            using var group = new MonitorGroup(config, monitors, NullLogger.Instance);

            Assert.Equal("TestGroup", group.GroupName);
            Assert.Equal(3, group.MonitorCount);
            Assert.Equal(0, group.RunningCount);
        }

        [Fact]
        public async Task MonitorGroup_StartsAllMonitors()
        {
            var m1 = new FakeMonitor();
            var m2 = new FakeMonitor();
            var monitors = new IHostedService[] { m1, m2 };
            var config = new MonitorGroupConfig
            {
                Name = "StartTest",
                StaggerDelay = TimeSpan.FromMilliseconds(10),
                HealthCheckInterval = TimeSpan.FromHours(1) // don't health check during test
            };
            using var group = new MonitorGroup(config, monitors, NullLogger.Instance);

            using var cts = new CancellationTokenSource();
            try
            {
                await group.StartAsync(cts.Token);
                await AwaitStartup(Task.WhenAll(m1.StartedSignal, m2.StartedSignal));
                Assert.True(m1.Started);
                Assert.True(m2.Started);
            }
            finally
            {
                cts.Cancel();
                await group.StopAsync(CancellationToken.None);
            }
            Assert.True(m1.Stopped);
            Assert.True(m2.Stopped);
        }

        [Fact]
        public async Task MonitorGroup_HandlesFailedMonitorGracefully()
        {
            var good = new FakeMonitor();
            var bad = new FakeMonitor(shouldFail: true);
            var monitors = new IHostedService[] { bad, good };
            var config = new MonitorGroupConfig
            {
                Name = "FailTest",
                StaggerDelay = TimeSpan.FromMilliseconds(10),
                HealthCheckInterval = TimeSpan.FromHours(1)
            };
            using var group = new MonitorGroup(config, monitors, NullLogger.Instance);

            using var cts = new CancellationTokenSource();
            try
            {
                await group.StartAsync(cts.Token);
                await AwaitStartup(good.StartedSignal);
                // A failed monitor cannot prevent the remaining monitor from starting.
                Assert.True(good.Started);
            }
            finally
            {
                cts.Cancel();
                await group.StopAsync(CancellationToken.None);
            }
            Assert.True(good.Stopped);
        }

        private static async Task AwaitStartup(Task startup)
        {
            using var timeout = new CancellationTokenSource();
            var deadline = Task.Delay(TimeSpan.FromSeconds(30), timeout.Token);
            try
            {
                Assert.Same(startup, await Task.WhenAny(startup, deadline));
                await startup;
            }
            finally { timeout.Cancel(); }
        }

        [Fact]
        public void MonitorGroupConfig_DefaultValues()
        {
            var config = new MonitorGroupConfig();
            Assert.Equal("Unnamed", config.Name);
            Assert.Equal(TimeSpan.Zero, config.StartDelay);
            Assert.Equal(TimeSpan.FromMilliseconds(200), config.StaggerDelay);
            Assert.Equal(3, config.MaxRestartAttempts);
            Assert.Equal(TimeSpan.FromSeconds(10), config.RestartCooldown);
            Assert.Equal(TimeSpan.FromSeconds(30), config.HealthCheckInterval);
            Assert.False(config.RestartIndefinitely);
        }
    }
}
