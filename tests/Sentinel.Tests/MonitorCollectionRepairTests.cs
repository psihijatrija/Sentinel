using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class MonitorCollectionRepairTests
    {
        [Theory]
        [InlineData("QueryName", ".", ".")]
        [InlineData("QueryName", "WWW.Example.COM.", "www.example.com")]
        [InlineData("QueryName", "_ldap._tcp.example.com", "_ldap._tcp.example.com")]
        [InlineData("QueryName", "DNS query for example.com", null)]
        [InlineData("QueryName", "a..example.com", null)]
        [InlineData("Message", "example.com", null)]
        [InlineData("QueryName", "https://example.com", null)]
        public void DnsUsesNamedEventDataRatherThanLocalizedDescription(string field, string value, string? expected)
        {
            var xml = $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData><Data Name='{field}'>{value}</Data></EventData><RenderingInfo><Message>Translated DNS message</Message></RenderingInfo></Event>";
            Assert.Equal(expected, WindowsDnsEventSource.ParseQueryName(xml));
        }

        [Fact]
        public void DnsXmlRejectsDocumentEntities()
        {
            Assert.Throws<XmlException>(() => WindowsDnsEventSource.ParseQueryName(
                "<!DOCTYPE Event [<!ENTITY name SYSTEM 'file:///does-not-exist'>]><Event>&name;</Event>"));
        }

        [Fact]
        public void PersistentMassStalenessCannotReceiveUnlimitedGrace()
        {
            var now = DateTimeOffset.UtcNow;
            var policy = new WatchdogGracePolicy(now);
            Assert.True(policy.ShouldDefer(now.AddSeconds(30), TimeSpan.FromMinutes(3), 136, 100));
            for (int i = 2; i < 20; i++)
                Assert.False(policy.ShouldDefer(now.AddSeconds(30 * i), TimeSpan.FromMinutes(3), 136, 100));
        }

        [Fact]
        public void EvenRepeatedTimerStallsOnlyDeferOnceUntilRecovery()
        {
            var now = DateTimeOffset.UtcNow;
            var policy = new WatchdogGracePolicy(now);
            Assert.True(policy.ShouldDefer(now.AddMinutes(4), TimeSpan.FromMinutes(3), 3, 3));
            Assert.False(policy.ShouldDefer(now.AddMinutes(8), TimeSpan.FromMinutes(3), 3, 3));
            Assert.False(policy.ShouldDefer(now.AddMinutes(9), TimeSpan.FromMinutes(3), 3, 0));
            Assert.True(policy.ShouldDefer(now.AddMinutes(13), TimeSpan.FromMinutes(3), 3, 3));
        }

        [Fact]
        public async Task DnsReadFailureIsVisibleWhileWorkerRunsAndSuccessfulReadRecovers()
        {
            var source = new SequencedSource();
            var monitor = new DnsQueryMonitor(null!, new SentinelConfig { DnsPollIntervalSeconds = 1 },
                NullLogger<DnsQueryMonitor>.Instance, source);
            try
            {
                await monitor.StartAsync(CancellationToken.None);
                await Until(() => monitor.Progress.Snapshot().State == "Failed");
                Assert.True(monitor.IsWorkerRunning);
                Assert.Contains("No cache fallback", monitor.Progress.Snapshot().Error);
                source.Recover = true;
                await Until(() => monitor.QueriesProcessed == 1);
                Assert.Equal("Healthy", monitor.Progress.Snapshot().State);
                Assert.Equal(1, source.Initializations); // no cursor reset/replay on transient failures
            }
            finally { await monitor.StopAsync(); monitor.Dispose(); }
        }

        [Fact]
        public async Task EmptySuccessfulDnsReadProvesCollectionCycleButNotQueryArrival()
        {
            var source = new SequencedSource { Recover = true, Empty = true };
            var monitor = new DnsQueryMonitor(null!, new SentinelConfig { DnsPollIntervalSeconds = 1 },
                NullLogger<DnsQueryMonitor>.Instance, source);
            try
            {
                await monitor.StartAsync(CancellationToken.None);
                await Until(() => monitor.Progress.Snapshot().SuccessfulCycles > 0);
                Assert.Equal(0, monitor.QueriesProcessed);
                Assert.Equal("Healthy", monitor.Progress.Snapshot().State);
            }
            finally { await monitor.StopAsync(); monitor.Dispose(); }
        }

        [Fact]
        public async Task FileWatcherLifetimeContinuesAfterInitialWalkCompletes()
        {
            using var stop = new CancellationTokenSource();
            int checks = 0;
            var lifetime = FileVerdictScanner.SuperviseWatchersAsync(Task.CompletedTask, () => checks++, stop.Token);
            Assert.Equal(1, checks);
            Assert.False(lifetime.IsCompleted);
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lifetime);
        }

        [Fact]
        public async Task FileWatcherFailureFaultsWorkerForGroupRecovery()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => FileVerdictScanner.SuperviseWatchersAsync(
                Task.CompletedTask, () => throw new InvalidOperationException("Watcher overflow"), CancellationToken.None));
        }

        [Fact]
        public async Task InitialWalkFailureCannotBeLostInFireAndForgetTask()
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => FileVerdictScanner.SuperviseWatchersAsync(
                Task.FromException(new InvalidOperationException("Walk failed")), () => { }, CancellationToken.None));
        }

        [Fact]
        public async Task OnlyDeclaredStartupTasksMayFinishWithoutBeingRestarted()
        {
            var once = new Initializer();
            using var group = new MonitorGroup(new MonitorGroupConfig
            {
                StaggerDelay = TimeSpan.Zero, HealthCheckInterval = TimeSpan.FromMilliseconds(10)
            }, new Microsoft.Extensions.Hosting.IHostedService[] { once }, NullLogger.Instance);
            await group.StartAsync(CancellationToken.None);
            try
            {
                await Until(() => group.RunningCount == 0);
                Assert.Equal(1, once.Starts);
            }
            finally { await group.StopAsync(CancellationToken.None); }
        }

        [Fact]
        public async Task UnsupportedWorkerExitIsAnExplicitGapRatherThanCompletedStartupOrRestartLoop()
        {
            using var registry = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            var worker = new UnsupportedWorker();
            using var group = new MonitorGroup(new MonitorGroupConfig
            {
                StaggerDelay = TimeSpan.Zero, HealthCheckInterval = TimeSpan.FromMilliseconds(10), RestartIndefinitely = true
            }, new Microsoft.Extensions.Hosting.IHostedService[] { worker }, NullLogger.Instance, registry);
            await group.StartAsync(CancellationToken.None);
            try
            {
                await Until(() => registry.GetUnhealthyMonitors().Count == 1);
                Assert.Equal(MonitorState.Unavailable, registry.GetAllStatuses()[0].State);
                Assert.Equal(0, registry.GetStats().Completed);
                Assert.Equal(1, worker.Starts);
            }
            finally { await group.StopAsync(CancellationToken.None); }
        }

        private sealed class UnsupportedWorker : Microsoft.Extensions.Hosting.BackgroundService
        {
            public int Starts;
            protected override Task ExecuteAsync(CancellationToken ct) { Interlocked.Increment(ref Starts); return Task.CompletedTask; }
        }

        private sealed class Initializer : Microsoft.Extensions.Hosting.BackgroundService, IMonitorStartupTask
        {
            public int Starts;
            public string CompletionDescription => "Offline initialization complete, not continuous telemetry.";
            protected override Task ExecuteAsync(CancellationToken ct) { Interlocked.Increment(ref Starts); return Task.CompletedTask; }
        }

        private static async Task Until(Func<bool> condition)
        {
            var deadline = DateTime.UtcNow.AddSeconds(8);
            while (!condition())
            {
                Assert.True(DateTime.UtcNow < deadline, "Worker did not reach expected state before timeout.");
                await Task.Delay(10);
            }
        }

        private sealed class SequencedSource : IDnsEventSource
        {
            public volatile bool Recover;
            public bool Empty;
            public int Initializations;
            private bool _delivered;
            public void Initialize(bool mayEnableChannel) => Initializations++;
            public IReadOnlyList<DnsQueryRecord> ReadQueries(CancellationToken ct)
            {
                ct.ThrowIfCancellationRequested();
                if (!Recover) throw new UnauthorizedAccessException("Simulated missing Windows channel access.");
                if (Empty || _delivered) return Array.Empty<DnsQueryRecord>();
                _delivered = true;
                // Trusted domain avoids any detection side effect: this tests the collection path.
                return new[] { new DnsQueryRecord { RecordId = 17, Domain = "microsoft.com" } };
            }
        }
    }
}
