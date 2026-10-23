using System;
using System.Collections.Generic;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class InjectedVictimResponseTests
    {
        private sealed class Target : IProcessTreeTarget
        {
            public int ProcessId { get; set; }
            public long CreationTime { get; set; }
            public bool CanTerminate { get; set; } = true;
            public bool HasExited { get; private set; }
            public int Attempts { get; private set; }
            public bool TerminateAndWait(int milliseconds) { Attempts++; return HasExited = true; }
            public void Dispose() { }
        }

        private sealed class Operations : IProcessTreeOperations
        {
            internal readonly Dictionary<int, Target> Targets = new();
            internal int Opens;
            public IProcessTreeTarget? Open(int pid) { Opens++; return Targets.TryGetValue(pid, out var target) ? target : null; }
            public IReadOnlyList<ProcessTreeEntry> Snapshot() => new[]
            {
                new ProcessTreeEntry(5151, 0), new ProcessTreeEntry(4242, 5151), new ProcessTreeEntry(4243, 4242)
            };
        }

        private static DetectionEvent Composite(long created) => new()
        {
            RuleName = "Credential Theft: Unbacked PE + Store Read", ProcessId = 4242,
            Evidence = "[COMPOSITE] memory-inspected PE and lifetime-matched store read",
            Tier = DetectionTier.Tier1Behavioral, Confidence = 0.95,
            AuthorizedResponse = ResponseAction.QuarantineAndKill, SignalType = SignalType.CredentialTheft,
            Metadata = new Dictionary<string, string>
            {
                [ResponsePolicy.ChainConfirmedKey] = "true", [ResponsePolicy.TerminalOutcomeKey] = "Composite",
                ["ContainmentScope"] = "InjectedVictim", ["ProcessCreationTime"] = created.ToString()
            }
        };

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void PinnedVictimContainmentLeavesParentAloneAndRejectsReplacementProcess(bool reusedPid)
        {
            long created = DateTime.UtcNow.AddHours(-1).ToFileTimeUtc();
            var ops = new Operations();
            ops.Targets[5151] = new Target { ProcessId = 5151, CreationTime = created - 100 };
            ops.Targets[4242] = new Target { ProcessId = 4242, CreationTime = created + (reusedPid ? 1 : 0) };
            ops.Targets[4243] = new Target { ProcessId = 4243, CreationTime = created + 100 };
            var result = InjectedVictimResponse.Execute(Composite(created), ops);
            Assert.Equal(!reusedPid, result.Success);
            Assert.Equal(0, ops.Targets[5151].Attempts);
            Assert.Equal(reusedPid ? 0 : 1, ops.Targets[4242].Attempts);
            Assert.Equal(reusedPid ? 0 : 1, ops.Targets[4243].Attempts);
        }

        [Theory]
        [InlineData("tier2")]
        [InlineData("missing-birth")]
        [InlineData("bad-birth")]
        [InlineData("missing-scope")]
        [InlineData("unconfirmed")]
        [InlineData("log-only")]
        [InlineData("expired")]
        public void MissingAuthorityOrIdentityNeverOpensAProcess(string scenario)
        {
            var ev = Composite(DateTime.UtcNow.AddHours(-1).ToFileTimeUtc());
            if (scenario == "tier2") ev.Tier = DetectionTier.Tier2Indicator;
            if (scenario == "missing-birth") ev.Metadata!.Remove("ProcessCreationTime");
            if (scenario == "bad-birth") ev.Metadata!["ProcessCreationTime"] = "not-a-time";
            if (scenario == "missing-scope") ev.Metadata!.Remove("ContainmentScope");
            if (scenario == "unconfirmed") ev.Metadata!.Remove(ResponsePolicy.ChainConfirmedKey);
            if (scenario == "log-only") ev.AuthorizedResponse = ResponseAction.LogOnly;
            if (scenario == "expired") ev.Timestamp = DateTime.UtcNow.AddMinutes(-1);
            var ops = new Operations();
            var result = InjectedVictimResponse.Execute(ev, ops);
            Assert.False(result.Success);
            Assert.Contains(4242, result.RefusedProcessIds);
            Assert.Equal(0, ops.Opens);
        }
    }
}
