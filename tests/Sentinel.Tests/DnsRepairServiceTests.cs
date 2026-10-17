using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class DnsRepairServiceTests
    {
        private sealed class Backend : IDnsConfigurationBackend
        {
            public DnsAdapterState State = new()
            {
                Id = Guid.NewGuid().ToString("B"), Name = "Fixture adapter", Eligible = true,
                SupportsIpv4 = true, SupportsIpv6 = true, EffectiveServers = new[] { "192.168.1.1", "fd00::1" }
            };
            public int Sets, Flushes, FailSetAt;
            public bool ExtraResolver, FailFlush, FailRollback;
            public Action<int>? AfterSet;
            public List<string> Order = new();
            public IReadOnlyList<DnsAdapterState> Inspect() => new[] { Copy(State) };
            public void SetServers(string id, AddressFamily family, string servers)
            {
                Order.Add("set");
                Sets++;
                if (Sets == FailSetAt || FailRollback && Sets > 2) throw new InvalidOperationException("Native fixture denial");
                if (family == AddressFamily.InterNetwork) State.Ipv4Static = servers;
                else State.Ipv6Static = servers;
                State.EffectiveServers = (State.SupportsIpv4 ? Values(State.Ipv4Static, "192.168.1.1") : Array.Empty<string>())
                    .Concat(State.SupportsIpv6 ? Values(State.Ipv6Static, "fd00::1") : Array.Empty<string>()).ToArray();
                if (ExtraResolver && State.Ipv4Static.Length > 0) State.EffectiveServers = State.EffectiveServers.Concat(new[] { "203.0.113.10" }).ToArray();
                AfterSet?.Invoke(Sets);
            }
            public bool FlushCache() { Flushes++; return !FailFlush || Flushes > 1; }
            private static string[] Values(string value, string automatic) => value.Length == 0 ? new[] { automatic } : DnsRepairService.Servers(value);
        }
        private sealed class Journal : IDnsRepairJournal
        {
            public List<DnsRepairRecord> Records = new();
            public int Saves, FailAt;
            public List<string> Order = new();
            public IReadOnlyList<DnsRepairRecord> ReadAll() => Records.Select(Copy).ToArray();
            public void Save(DnsRepairRecord record)
            {
                Order.Add("journal");
                if (++Saves == FailAt) throw new InvalidOperationException("Snapshot storage unavailable");
                Records.RemoveAll(r => r.Id == record.Id); Records.Add(Copy(record));
            }
        }
        private sealed class Audit : IDnsRepairAudit
        {
            public bool FailBefore, FailResult;
            public List<string> Order = new();
            public Task WriteBeforeAsync(DnsRepairRecord record, string operation, CancellationToken ct)
            { Order.Add("audit"); if (FailBefore) throw new InvalidOperationException("Audit unavailable"); return Task.CompletedTask; }
            public Task WriteResultAsync(DnsRepairReceipt receipt, CancellationToken ct)
            { if (FailResult) throw new InvalidOperationException("Final audit unavailable"); return Task.CompletedTask; }
        }
        private static T Copy<T>(T source) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(source))!;
        private static DnsRepairService Service(Backend backend, Journal journal, Audit audit) => new(backend, journal, audit, TimeSpan.Zero);
        private static DnsRepairRequest Request(Backend backend, string profile = "Quad9") => new()
        { AdapterId = backend.State.Id, Profile = profile, ExpectedFingerprint = backend.State.Fingerprint };

        [Fact]
        public async Task RepairPersistsAndAuditsBeforeMutatingBothFamiliesAndVerifiesReadback()
        {
            var b = new Backend(); var j = new Journal(); var a = new Audit();
            var order = new List<string>(); b.Order = j.Order = a.Order = order;
            var result = await Service(b, j, a).ExecuteAsync(Request(b), false, default);
            Assert.Equal("Verified", result.Status);
            Assert.True(result.ConfigurationVerified); Assert.True(result.CacheFlushed);
            Assert.Equal(new[] { "journal", "audit", "set", "set", "journal" }, order);
            Assert.Contains("9.9.9.9", b.State.EffectiveServers); Assert.Contains("2620:fe::fe", b.State.EffectiveServers);
            Assert.Equal("Verified", Assert.Single(j.Records).Phase);
        }
        [Theory]
        [InlineData(true)] [InlineData(false)]
        public async Task MissingSnapshotOrAuditRefusesWithoutMutation(bool snapshotFails)
        {
            var b = new Backend(); var j = new Journal { FailAt = snapshotFails ? 1 : 0 }; var a = new Audit { FailBefore = !snapshotFails };
            var result = await Service(b, j, a).ExecuteAsync(Request(b), false, default);
            Assert.Equal("Refused", result.Status); Assert.Equal(0, b.Sets);
        }
        [Theory]
        [InlineData("invalid")] [InlineData("stale")] [InlineData("managed")] [InlineData("unsupported")] [InlineData("profile")] [InlineData("incomplete")]
        public async Task InvalidScopeAndStalePreviewNeverMutate(string scenario)
        {
            var b = new Backend(); var request = Request(b);
            if (scenario == "invalid") request.AdapterId = "not-a-guid";
            if (scenario == "stale") b.State.Ipv4Static = "192.0.2.1";
            if (scenario == "managed") b.State.PolicyManaged = true;
            if (scenario == "unsupported") b.State.Eligible = false;
            if (scenario == "profile") request.Profile = "arbitrary-address";
            if (scenario == "incomplete") b.State.InspectionComplete = false;
            var result = await Service(b, new Journal(), new Audit()).ExecuteAsync(request, false, default);
            Assert.Equal("Refused", result.Status); Assert.Equal(0, b.Sets);
        }
        [Theory]
        [InlineData("native")] [InlineData("readback")] [InlineData("cache")] [InlineData("commit")]
        public async Task IncompleteRepairRollsBackInsteadOfReportingSuccess(string failure)
        {
            var b = new Backend { FailSetAt = failure == "native" ? 2 : 0,
                ExtraResolver = failure == "readback", FailFlush = failure == "cache" };
            var j = new Journal { FailAt = failure == "commit" ? 2 : 0 };
            string before = b.State.Fingerprint;
            var result = await Service(b, j, new Audit()).ExecuteAsync(Request(b), false, default);
            Assert.Equal("Failed", result.Status); Assert.True(result.RollbackVerified);
            Assert.False(result.ConfigurationVerified); Assert.Equal(before, b.State.Fingerprint);
            Assert.Equal("RolledBack", Assert.Single(j.Records).Phase);
        }
        [Fact]
        public async Task FailedRollbackRemainsExplicitlyPartial()
        {
            var b = new Backend { ExtraResolver = true, FailRollback = true };
            var result = await Service(b, new Journal(), new Audit()).ExecuteAsync(Request(b), false, default);
            Assert.Equal("PartiallyCompleted", result.Status); Assert.False(result.RollbackVerified);
        }
        [Fact]
        public async Task ExplicitRestorePreservesAutomaticDnsModeAndItsObservedServers()
        {
            var b = new Backend(); var j = new Journal(); var service = Service(b, j, new Audit());
            string before = b.State.Fingerprint;
            var repair = await service.ExecuteAsync(Request(b), false, default);
            var request = Request(b); request.TransactionId = repair.TransactionId;
            var restore = await service.ExecuteAsync(request, true, default);
            Assert.Equal("Verified", restore.Status); Assert.Equal(before, b.State.Fingerprint);
            Assert.Equal("Restored", Assert.Single(j.Records).Phase);
        }
        [Fact]
        public async Task RestoreCannotOverwriteNewerConfigurationOrAnotherAdapter()
        {
            var b = new Backend(); var j = new Journal(); var service = Service(b, j, new Audit());
            var repair = await service.ExecuteAsync(Request(b), false, default);
            b.State.Ipv4Static = "192.0.2.53";
            var request = Request(b); request.TransactionId = repair.TransactionId;
            int calls = b.Sets;
            var restore = await service.ExecuteAsync(request, true, default);
            Assert.Equal("Refused", restore.Status); Assert.Equal(calls, b.Sets);
            request = Request(b); request.TransactionId = Guid.NewGuid().ToString("N");
            Assert.Equal("Refused", (await service.ExecuteAsync(request, true, default)).Status);
        }
        [Fact]
        public async Task CancellationAfterMutationRestoresWithAnIndependentRollbackBudget()
        {
            var b = new Backend(); using var cts = new CancellationTokenSource();
            b.AfterSet = count => { if (count == 1) cts.Cancel(); };
            var result = await Service(b, new Journal(), new Audit()).ExecuteAsync(Request(b), false, cts.Token);
            Assert.Equal("Failed", result.Status); Assert.True(result.RollbackVerified);
        }
        [Fact]
        public async Task FinalAuditFailureCannotClaimFullyVerifiedOperation()
        {
            var b = new Backend();
            var result = await Service(b, new Journal(), new Audit { FailResult = true }).ExecuteAsync(Request(b), false, default);
            Assert.Equal("PartiallyCompleted", result.Status); Assert.Contains("Final audit", result.Detail);
        }
        [Fact]
        public async Task ConcurrentApprovalsCannotReuseTheSamePreview()
        {
            var b = new Backend(); var service = Service(b, new Journal(), new Audit());
            var request = Request(b);
            var results = await Task.WhenAll(service.ExecuteAsync(request, false, default), service.ExecuteAsync(request, false, default));
            Assert.Single(results, r => r.Status == "Verified"); Assert.Single(results, r => r.Status == "Refused");
        }
        [Fact]
        public void FingerprintDetectsDhcpIpv6AndResolverPriorityChanges()
        {
            var b = new Backend(); string original = b.State.Fingerprint;
            b.State.EffectiveServers = new[] { "192.168.1.1", "fd00::2" };
            Assert.NotEqual(original, b.State.Fingerprint);
            string changed = b.State.Fingerprint;
            b.State.EffectiveServers = Enumerable.Reverse(b.State.EffectiveServers).ToArray();
            Assert.NotEqual(changed, b.State.Fingerprint);
        }
        [Fact]
        public async Task RestoreAuditRefusalRetainsTheUsableRollbackSnapshot()
        {
            var b = new Backend(); var j = new Journal(); var a = new Audit(); var service = Service(b, j, a);
            var repair = await service.ExecuteAsync(Request(b), false, default);
            var request = Request(b); request.TransactionId = repair.TransactionId;
            a.FailBefore = true;
            int writes = b.Sets;
            Assert.Equal("Refused", (await service.ExecuteAsync(request, true, default)).Status);
            Assert.Equal(writes, b.Sets);
            Assert.Equal("Verified", Assert.Single(j.Records).Phase);
        }

        [Fact]
        public async Task InspectionReportsDriftAgainstExplicitlyApprovedConfiguration()
        {
            var b = new Backend(); var service = Service(b, new Journal(), new Audit());
            await service.ExecuteAsync(Request(b), false, default);
            using var clean = JsonDocument.Parse(JsonSerializer.Serialize(service.Inspect()));
            Assert.True(clean.RootElement.GetProperty("Adapters")[0].GetProperty("ApprovedConfigurationMatches").GetBoolean());
            b.State.EffectiveServers = new[] { "203.0.113.53" };
            using var drift = JsonDocument.Parse(JsonSerializer.Serialize(service.Inspect()));
            Assert.False(drift.RootElement.GetProperty("Adapters")[0].GetProperty("ApprovedConfigurationMatches").GetBoolean());
            Assert.Equal(2, b.Sets); // inspection never remediates on its own
        }

        [Fact]
        public async Task Ipv6OnlyAdapterIsNotSilentlySkipped()
        {
            var b = new Backend(); b.State.SupportsIpv4 = false; b.State.EffectiveServers = new[] { "fd00::1" };
            var result = await Service(b, new Journal(), new Audit()).ExecuteAsync(Request(b), false, default);
            Assert.Equal("Verified", result.Status); Assert.Equal(1, b.Sets); Assert.Contains("2620:fe::fe", b.State.EffectiveServers);
        }
    }
}
