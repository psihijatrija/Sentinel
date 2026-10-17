using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class DisposableDnsFactAttribute : FactAttribute
    {
        public DisposableDnsFactAttribute()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT ||
                Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
                !Guid.TryParse(Environment.GetEnvironmentVariable("SENTINEL_DNS_SMOKE_ADAPTER_ID"), out _))
                Skip = "Live DNS mutation requires the guarded disposable hosted-runner wrapper.";
        }
    }

    public class DnsRepairWindowsSmokeTests
    {
        // This fixture owns only its temporary transaction files. It exercises the actual
        // native backend/audit/transaction service, not the production SYSTEM-only journal ACL.
        private sealed class FixtureJournal : IDnsRepairJournal
        {
            private readonly string _path;
            public FixtureJournal(string path) => _path = path;
            public IReadOnlyList<DnsRepairRecord> ReadAll() => Directory.GetFiles(_path, "*.json")
                .Select(p => JsonSerializer.Deserialize<DnsRepairRecord>(File.ReadAllText(p))!).ToArray();
            public void Save(DnsRepairRecord record)
            {
                string path = Path.Combine(_path, record.Id + ".json");
                string temp = path + ".tmp";
                byte[] data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
                using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { file.Write(data, 0, data.Length); file.Flush(true); }
                if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
            }
        }
        private sealed class CancelAfterFirstSet : IDnsConfigurationBackend
        {
            private readonly IDnsConfigurationBackend _inner;
            private readonly CancellationTokenSource _cancellation;
            private bool _cancelled;
            public CancelAfterFirstSet(IDnsConfigurationBackend inner, CancellationTokenSource cancellation)
            { _inner = inner; _cancellation = cancellation; }
            public IReadOnlyList<DnsAdapterState> Inspect() => _inner.Inspect();
            public bool FlushCache() => _inner.FlushCache();
            public void SetServers(string id, AddressFamily family, string servers)
            {
                _inner.SetServers(id, family, servers);
                if (!_cancelled) { _cancelled = true; _cancellation.Cancel(); }
            }
        }
        private static DnsRepairRequest Request(DnsAdapterState state, string transaction = "") => new()
        { AdapterId = state.Id, ExpectedFingerprint = state.Fingerprint, Profile = "Quad9", TransactionId = transaction };
        private static void RequireOriginal(DnsAdapterState before, DnsAdapterState after)
        {
            Assert.True(DnsRepairService.SameServers(DnsRepairService.Servers(before.Ipv4Static), DnsRepairService.Servers(after.Ipv4Static)));
            Assert.True(DnsRepairService.SameServers(DnsRepairService.Servers(before.Ipv6Static), DnsRepairService.Servers(after.Ipv6Static)));
            Assert.True(new HashSet<string>(before.EffectiveServers).SetEquals(after.EffectiveServers));
        }

        [DisposableDnsFact]
        [Trait("Category", "DisposableDns")]
        public async Task NativeRepairAutomaticRestoreCancellationAndRestartRecovery()
        {
            using var identity = WindowsIdentity.GetCurrent();
            Assert.True(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator));
            string adapterId = Environment.GetEnvironmentVariable("SENTINEL_DNS_SMOKE_ADAPTER_ID")!;
            string directory = Path.Combine(Path.GetTempPath(), "SentinelDnsSmoke_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var backend = new WindowsDnsConfigurationBackend();
            DnsAdapterState Read() => backend.Inspect().Single(a => DnsRepairService.SameAdapter(a.Id, adapterId));
            var original = Read();
            Assert.True(original.Eligible);
            await using var logger = new JsonlEventLogger(Path.Combine(directory, "events.jsonl"));
            var audit = new DnsRepairAudit(logger);
            var journal = new FixtureJournal(directory);
            var service = new DnsRepairService(backend, journal, audit);
            var repair = await service.ExecuteAsync(Request(original), false, default);
            Assert.True(repair.Status == "Verified", JsonSerializer.Serialize(repair));
            var restored = await service.ExecuteAsync(Request(Read(), repair.TransactionId), true, default);
            Assert.True(restored.Status == "Verified", JsonSerializer.Serialize(restored));
            RequireOriginal(original, Read());

            using var cancel = new CancellationTokenSource();
            var cancelled = await new DnsRepairService(new CancelAfterFirstSet(backend, cancel), journal, audit)
                .ExecuteAsync(Request(Read()), false, cancel.Token);
            Assert.Equal("Failed", cancelled.Status);
            Assert.True(cancelled.RollbackVerified, JsonSerializer.Serialize(cancelled));
            RequireOriginal(original, Read());

            // Durable intent followed by one family mutation models a crash before the second
            // family/commit. A new service and journal instance must recover from disk alone.
            var profile = DnsRepairService.Profile("Quad9");
            var target = JsonSerializer.Deserialize<DnsAdapterState>(JsonSerializer.Serialize(original))!;
            target.Ipv4Static = profile.V4; target.Ipv6Static = profile.V6;
            target.EffectiveServers = (target.SupportsIpv4 ? DnsRepairService.Servers(profile.V4) : Array.Empty<string>())
                .Concat(target.SupportsIpv6 ? DnsRepairService.Servers(profile.V6) : Array.Empty<string>()).ToArray();
            var pending = new DnsRepairRecord { Id = Guid.NewGuid().ToString("N"), CreatedAt = DateTimeOffset.UtcNow,
                Profile = "Quad9", Before = original, PendingFrom = original, PendingTarget = target };
            journal.Save(pending);
            await audit.WriteBeforeAsync(pending, "FixtureInterruptedRepair", default);
            backend.SetServers(original.Id, original.SupportsIpv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6,
                original.SupportsIpv4 ? profile.V4 : profile.V6);
            var restarted = new DnsRepairService(backend, new FixtureJournal(directory), audit);
            var recovered = await restarted.ExecuteAsync(Request(Read(), pending.Id), false, default, recover: true);
            Assert.True(recovered.Status == "Verified", JsonSerializer.Serialize(recovered));
            RequireOriginal(original, Read());
            Assert.Equal("Recovered", journal.ReadAll().Single(r => r.Id == pending.Id).Phase);
        }
    }
}
