using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public sealed class FirewallIsolationTransactionTests : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "sentinel-firewall-" + Guid.NewGuid().ToString("N"));
        private readonly FakeStore _store = new();
        private FirewallIsolationTransaction Create() => new(_store, _directory);
        private string Journal(FirewallIsolationRecord record) => Path.Combine(_directory, record.Id + ".firewall.json");
        public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

        [Fact]
        public void WriteAheadReadbackAndExplicitRollbackAreRepeatable()
        {
            var transaction = Create();
            _store.BeforeAdd = () =>
            {
                string path = Directory.GetFiles(_directory, "*.firewall.json").Single();
                Assert.Equal("Applying", transaction.Inspect(path).State);
            };
            var applied = transaction.Apply("203.0.113.10", "fixture-authorized-chain");
            Assert.Equal("Verified", applied.State);
            Assert.Equal(2, _store.Rules.Count);
            _store.BeforeAdd = null;
            // A fresh service object may inspect and explicitly roll back retained state.
            Assert.Equal("Verified", Create().Inspect(Journal(applied)).State);
            Assert.Equal("RolledBack", Create().Rollback(Journal(applied)).State);
            Assert.Empty(_store.Rules);
            Assert.Equal("RolledBack", Create().Rollback(Journal(applied)).State);
        }

        [Fact]
        public void PartialFailureIsRetainedAndNeverAutomaticallyReplayedOrRemoved()
        {
            _store.FailOnAdd = 2;
            var record = Create().Apply("203.0.113.10", "fixture");
            Assert.Equal("Failed", record.State);
            Assert.Single(_store.Rules);
            Assert.Equal("Failed", Create().Inspect(Journal(record)).State);
            Assert.Single(_store.Rules);
            Assert.Equal("RolledBack", Create().Rollback(Journal(record)).State);
            Assert.Empty(_store.Rules);
        }

        [Fact]
        public void InterruptedRollbackCanResumeExplicitlyWithoutRecreatingRemovedRules()
        {
            var record = Create().Apply("203.0.113.10", "fixture");
            _store.FailOnRemove = 2;
            Assert.Equal("RollbackFailed", Create().Rollback(Journal(record)).State);
            Assert.Single(_store.Rules);
            _store.FailOnRemove = 0;
            Assert.Equal("RolledBack", Create().Rollback(Journal(record)).State);
            Assert.Empty(_store.Rules);
        }

        [Fact]
        public void JournalPathCannotEscapeTheConfiguredRecoveryDirectory()
        {
            string path = Path.Combine(Path.GetTempPath(), "foreign-" + Guid.NewGuid().ToString("N") + ".firewall.json");
            Assert.Throws<InvalidDataException>(() => Create().Inspect(path));
            Assert.Empty(_store.Rules);
        }

        [Fact]
        public void ChangedOrDuplicatedRulesPreventRollbackBeforeAnyRemoval()
        {
            var record = Create().Apply("203.0.113.10", "fixture");
            _store.Rules[1].Enabled = false;
            Assert.Throws<InvalidOperationException>(() => Create().Rollback(Journal(record)));
            Assert.Equal(2, _store.Rules.Count);
            _store.Rules[1].Enabled = true;
            _store.Rules.Add(Clone(_store.Rules[0]));
            Assert.Throws<InvalidOperationException>(() => Create().Rollback(Journal(record)));
            Assert.Equal(3, _store.Rules.Count);
        }

        [Fact]
        public void ReadbackMismatchCannotBecomeVerified()
        {
            _store.CorruptAdd = true;
            var record = Create().Apply("203.0.113.10", "fixture");
            Assert.Equal("Failed", record.State);
            Assert.Throws<InvalidOperationException>(() => Create().Rollback(Journal(record)));
        }

        [Fact]
        public void EditedJournalCannotAuthorizeRemovalOfAnUnrelatedRule()
        {
            var record = Create().Apply("203.0.113.10", "fixture");
            record.Rules[0].Name = "foreign-rule";
            File.WriteAllText(Journal(record), JsonSerializer.Serialize(record));
            Assert.Throws<InvalidDataException>(() => Create().Rollback(Journal(record)));
            Assert.Equal(2, _store.Rules.Count);
        }

        [Theory]
        [InlineData("127.0.0.1")]
        [InlineData("::1")]
        [InlineData("::ffff:10.0.0.1")]
        [InlineData("192.168.1.1")]
        [InlineData("fc00::1")]
        [InlineData("224.0.0.1")]
        [InlineData("invalid")]
        public void InvalidOrLocalTargetsNeverWriteOrMutate(string target)
        {
            Assert.Throws<ArgumentException>(() => Create().Apply(target, "fixture"));
            Assert.False(Directory.Exists(_directory));
            Assert.Empty(_store.Rules);
        }

        [Fact]
        public void CancellationBeforeApplicationNeverCreatesAJournalOrRules()
        {
            using var cancel = new CancellationTokenSource(); cancel.Cancel();
            Assert.Throws<OperationCanceledException>(() => Create().Apply("203.0.113.10", "fixture", cancel.Token));
            Assert.False(Directory.Exists(_directory));
            Assert.Empty(_store.Rules);
        }

        [Fact]
        public void RepeatedTargetsReuseVerifiedRulesAcrossServiceRestartWithoutGrowingHistory()
        {
            var first = Create().Apply("203.0.113.10", "first");
            var repeated = Create().Apply("203.0.113.10", "second");
            Assert.Equal(first.Id, repeated.Id);
            Assert.Equal(2, _store.Rules.Count);
            Assert.Single(Directory.GetFiles(_directory, "*.firewall.json"));
            Create().Rollback(Journal(first));
            var renewed = Create().Apply("203.0.113.10", "new-authorization");
            Assert.NotEqual(first.Id, renewed.Id);
            Assert.Equal(2, _store.Rules.Count);
        }

        [Fact]
        public void ExistingRulesArePreservedAndEachTransactionHasIndependentNames()
        {
            _store.Rules.Add(new FirewallIsolationRule { Name = "user-rule", RemoteAddress = "203.0.113.10" });
            var first = Create().Apply("203.0.113.10", "first");
            var second = Create().Apply("203.0.113.11", "second");
            Assert.Equal(5, _store.Rules.Count);
            Create().Rollback(Journal(first));
            Assert.Equal(3, _store.Rules.Count);
            Assert.Contains(_store.Rules, r => r.Name == "user-rule");
            Assert.All(second.Rules, r => Assert.Contains(_store.Rules, actual => actual.Name == r.Name));
        }
        private static FirewallIsolationRule Clone(FirewallIsolationRule rule) =>
            JsonSerializer.Deserialize<FirewallIsolationRule>(JsonSerializer.Serialize(rule))!;
        private sealed class FakeStore : IFirewallIsolationStore
        {
            public readonly List<FirewallIsolationRule> Rules = new();
            public Action? BeforeAdd;
            public int FailOnAdd;
            public int FailOnRemove;
            private int _removes;
            public bool CorruptAdd;
            private int _adds;
            public IReadOnlyList<FirewallIsolationRule> Find(string name) => Rules.Where(r => r.Name == name).Select(Clone).ToArray();
            public void Add(FirewallIsolationRule rule)
            {
                BeforeAdd?.Invoke();
                if (++_adds == FailOnAdd) throw new IOException("fixture");
                var copy = Clone(rule);
                if (CorruptAdd) copy.Direction = 42;
                Rules.Add(copy);
            }
            public void Remove(string name)
            {
                if (++_removes == FailOnRemove) throw new IOException("fixture rollback failure");
                Rules.RemoveAll(r => r.Name == name);
            }
        }
    }
}
