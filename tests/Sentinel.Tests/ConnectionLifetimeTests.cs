using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ConnectionLifetimeTests
    {
        private const int Pid = 987654;
        private static PersistentConnectionMonitor.ActiveConnection Connection(long created) => new()
        { Pid = Pid, Created = created, ProcessName = "fixture", RemoteIp = "192.0.2.1", RemotePort = 443 };

        [Fact]
        public void ReusedPidCannotInheritPersistentConnectionAgeOrRecentDrop()
        {
            var now = DateTime.UtcNow; long live = now.AddHours(-1).ToFileTimeUtc();
            using var monitor = new PersistentConnectionMonitor(null!, NullLogger<PersistentConnectionMonitor>.Instance,
                _ => live, utcNow: () => now);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
            now = now.AddMinutes(6);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
            live = now.ToFileTimeUtc();
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection>(), now);
            Assert.False(monitor.HasRecentDrop(Pid));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RecentDropRequiresQueryableMatchingLifetime(bool unavailable)
        {
            var now = DateTime.UtcNow; long live = now.AddHours(-1).ToFileTimeUtc();
            using var monitor = new PersistentConnectionMonitor(null!, NullLogger<PersistentConnectionMonitor>.Instance,
                _ => live, utcNow: () => now);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
            now = now.AddMinutes(6);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
            monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection>(), now);
            Assert.True(monitor.HasRecentDrop(Pid));
            live = unavailable ? 0 : live + 1;
            Assert.False(monitor.HasRecentDrop(Pid));
            monitor.RecordDnsQuery(Pid, "fixture.invalid");
        }

        [Fact]
        public void DnsBurstCountersCannotCarryAcrossProcessLifetimes()
        {
            var now = DateTime.UtcNow; long live = now.AddHours(-1).ToFileTimeUtc();
            using var monitor = new PersistentConnectionMonitor(null!, NullLogger<PersistentConnectionMonitor>.Instance,
                _ => live, utcNow: () => now);
            for (int generation = 0; generation < 2; generation++)
            {
                monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
                now = now.AddMinutes(6);
                monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection> { Connection(live) }, now);
                monitor.TrackConnections(new List<PersistentConnectionMonitor.ActiveConnection>(), now);
                for (int i = 0; i < 9; i++) monitor.RecordDnsQuery(Pid, "fixture.invalid");
                live = now.AddSeconds(1).ToFileTimeUtc(); now = now.AddSeconds(2);
            }
            // With a PID-only counter the second generation reaches ten and attempts
            // emission through the intentionally absent engine. Nine per lifetime cannot.
        }
    }
}
