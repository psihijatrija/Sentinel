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
            public Action? OnBefore;
            public List<string> Order = new();
            public Task WriteBeforeAsync(DnsRepairRecord record, string operation, CancellationToken ct)
            { Order.Add("audit"); OnBefore?.Invoke(); if (FailBefore) throw new InvalidOperationException("Audit unavailable"); return Task.CompletedTask; }
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
        public async Task ConfigurationChangeDuringDurablePreparationRefusesBeforeMutation()
        {
            var b = new Backend(); var j = new Journal();
            var result = await Service(b, j, new Audit { OnBefore = () => b.State.Ipv4Static = "203.0.113.53" })
                .ExecuteAsync(Request(b), false, default);
            Assert.Equal("Refused", result.Status); Assert.Equal(0, b.Sets);
            Assert.Equal("203.0.113.53", b.State.Ipv4Static);
        }

        private static async Task<DnsRepairRecord> Prepared(Backend backend, Journal journal)
        {
            var receipt = await Service(backend, journal, new Audit { FailBefore = true }).ExecuteAsync(Request(backend), false, default);
            Assert.Equal("Refused", receipt.Status);
            return Assert.Single(journal.Records);
        }

        [Theory]
        [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)]
        public async Task FreshServiceRecoversEachInterruptedFamilyCombinationToTheOriginalSnapshot(int changed)
        {
            var b = new Backend(); var j = new Journal(); string before = b.State.Fingerprint;
            var pending = await Prepared(b, j);
            if ((changed & 1) != 0) b.SetServers(b.State.Id, AddressFamily.InterNetwork, pending.PendingTarget!.Ipv4Static);
            if ((changed & 2) != 0) b.SetServers(b.State.Id, AddressFamily.InterNetworkV6, pending.PendingTarget!.Ipv6Static);
            var request = Request(b); request.TransactionId = pending.Id;
            var restarted = Service(b, j, new Audit());
            using var inspection = JsonDocument.Parse(JsonSerializer.Serialize(restarted.Inspect()));
            Assert.True(inspection.RootElement.GetProperty("Transactions")[0].GetProperty("RecoveryAvailable").GetBoolean());
            var result = await restarted.ExecuteAsync(request, false, default, recover: true);
            Assert.Equal("Recover", result.Operation); Assert.Equal("Verified", result.Status);
            Assert.Equal(before, b.State.Fingerprint);
            Assert.Equal("Recovered", Assert.Single(j.Records).Phase);
            Assert.Equal("Verified", (await restarted.ExecuteAsync(Request(b), false, default)).Status);
        }

        [Theory]
        [InlineData("RestorePrepared")] [InlineData("RecoveryPrepared")]
        [InlineData("RecoveryRequired")] [InlineData("RollbackFailed")]
        public async Task RecoveryHandlesInterruptedRestoreAndRollbackPhases(string phase)
        {
            var b = new Backend(); var j = new Journal(); string original = b.State.Fingerprint;
            await Service(b, j, new Audit()).ExecuteAsync(Request(b), false, default);
            var record = Assert.Single(j.Records);
            record.Phase = phase; record.PendingFrom = Copy(b.State); record.PendingTarget = Copy(record.Before);
            b.SetServers(b.State.Id, AddressFamily.InterNetwork, record.Before.Ipv4Static);
            var request = Request(b); request.TransactionId = record.Id;
            var result = await Service(b, j, new Audit()).ExecuteAsync(request, false, default, recover: true);
            Assert.Equal("Verified", result.Status); Assert.Equal(original, b.State.Fingerprint);
        }

        [Theory]
        [InlineData("unrelated")] [InlineData("legacy")] [InlineData("protocol")]
        [InlineData("newer")] [InlineData("stale")] [InlineData("wrong-snapshot")]
        public async Task RecoveryRefusesUnexplainedOrUnapprovedStateWithoutMutation(string scenario)
        {
            var b = new Backend(); var j = new Journal(); var record = await Prepared(b, j);
            var request = Request(b); request.TransactionId = record.Id;
            if (scenario == "unrelated") b.State.Ipv4Static = "203.0.113.53";
            if (scenario == "legacy") record.PendingTarget = null;
            if (scenario == "protocol") b.State.SupportsIpv6 = false;
            if (scenario == "newer") j.Records.Add(new DnsRepairRecord { Id = Guid.NewGuid().ToString("N"),
                CreatedAt = record.CreatedAt.AddSeconds(1), Before = Copy(b.State), Phase = "Verified" });
            if (scenario == "wrong-snapshot") request.TransactionId = Guid.NewGuid().ToString("N");
            if (scenario != "stale") request.ExpectedFingerprint = b.State.Fingerprint;
            else b.State.EffectiveServers = new[] { "192.0.2.53" };
            var result = await Service(b, j, new Audit()).ExecuteAsync(request, false, default, recover: true);
            Assert.Equal("Refused", result.Status); Assert.Equal(0, b.Sets);
        }

        [Fact]
        public async Task PendingTransactionBlocksNewRepairAndCannotBeUsedAsOrdinaryRestore()
        {
            var b = new Backend(); var j = new Journal(); var pending = await Prepared(b, j);
            var service = Service(b, j, new Audit()); var request = Request(b); request.TransactionId = pending.Id;
            Assert.Equal("Refused", (await service.ExecuteAsync(request, false, default)).Status);
            Assert.Equal("Refused", (await service.ExecuteAsync(request, true, default)).Status);
            Assert.Equal(0, b.Sets);
        }

        [Fact]
        public async Task FailedRecoveryRollsBackToFreshlyApprovedStateAndRetainsOriginalRecoveryTarget()
        {
            var b = new Backend(); var j = new Journal(); var pending = await Prepared(b, j);
            b.SetServers(b.State.Id, AddressFamily.InterNetwork, pending.PendingTarget!.Ipv4Static);
            string interrupted = b.State.Fingerprint;
            b.FailSetAt = b.Sets + 2;
            var request = Request(b); request.TransactionId = pending.Id;
            var failed = await Service(b, j, new Audit()).ExecuteAsync(request, false, default, recover: true);
            Assert.Equal("Failed", failed.Status); Assert.True(failed.RollbackVerified);
            Assert.Equal(interrupted, b.State.Fingerprint);
            Assert.Equal("RecoveryRequired", Assert.Single(j.Records).Phase);
            Assert.Empty(Assert.Single(j.Records).Before.Ipv4Static);
            var retried = await Service(b, j, new Audit()).ExecuteAsync(RequestForRecovery(b, pending.Id), false, default, recover: true);
            Assert.Equal("Verified", retried.Status); Assert.Empty(b.State.Ipv4Static); Assert.Empty(b.State.Ipv6Static);
        }

        private static DnsRepairRequest RequestForRecovery(Backend backend, string id)
        { var request = Request(backend); request.TransactionId = id; return request; }

        [Fact]
        public async Task RecoveryAuditRefusalKeepsThePendingTransactionAndNeverMutates()
        {
            var b = new Backend(); var j = new Journal(); var pending = await Prepared(b, j);
            var result = await Service(b, j, new Audit { FailBefore = true }).ExecuteAsync(
                RequestForRecovery(b, pending.Id), false, default, recover: true);
            Assert.Equal("Refused", result.Status); Assert.Equal("Prepared", Assert.Single(j.Records).Phase);
            Assert.Equal(0, b.Sets);
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
