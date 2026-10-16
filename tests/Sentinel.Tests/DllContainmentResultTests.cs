using System.Text.Json;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class DllContainmentResultTests
    {
        [Fact]
        public void FailedContainmentCannotBeReportedAsSuccessEvenWithQuarantine()
        {
            var result = new DllUnloadResult { Containment = new ProcessTreeTerminationResult { RootExited = true } };
            result.RecordFileOutcome("bad.dll", DllFileOutcome.Quarantined);
            Assert.False(result.HostContained);
            Assert.False(result.Success);
            Assert.Contains("HostContained=False", result.ContainmentSummary);
        }

        [Fact]
        public void DetectedModuleAloneIsNeverCountedAsQuarantined()
        {
            var result = new DllUnloadResult();
            result.DetectedDlls.Add("bad.dll");
            Assert.Empty(result.QuarantinedDlls);
            Assert.False(result.Success);
            Assert.False(result.CreateExecutionReceipt().VerifiesRequestedAction);
        }

        [Theory]
        [InlineData(DllFileOutcome.Deferred)]
        [InlineData(DllFileOutcome.Failed)]
        public void IncompleteFileRemediationRemainsVisibleAfterHostExited(DllFileOutcome outcome)
        {
            var result = new DllUnloadResult
            {
                Containment = new ProcessTreeTerminationResult { RootExited = true, DiscoveryComplete = true }
            };
            result.RecordFileOutcome("bad.dll", outcome);
            Assert.True(result.HostContained);
            Assert.False(result.Success);
            Assert.Empty(result.QuarantinedDlls);
            var metadata = result.CreateContainmentMetadata("host.exe");
            using var files = JsonDocument.Parse(metadata[outcome == DllFileOutcome.Deferred ? "DeferredDlls" : "FailedDlls"]);
            Assert.Equal("bad.dll", files.RootElement[0].GetString());
        }

        [Fact]
        public void AlreadyAbsentFileIsNotDescribedAsQuarantined()
        {
            var result = new DllUnloadResult();
            result.RecordFileOutcome("gone.dll", DllFileOutcome.AlreadyAbsent);
            Assert.True(result.Success);
            Assert.Single(result.AbsentDlls);
            Assert.Empty(result.QuarantinedDlls);
            Assert.False(result.HostContained); // disk-only remediation never implies a process kill
        }

        [Fact]
        public void VerifiedContainmentAndAllFilesRemovedReportsSuccess()
        {
            var result = new DllUnloadResult
            {
                ProcessId = 1234,
                Containment = new ProcessTreeTerminationResult { RootProcessId = 1234, RootExited = true, DiscoveryComplete = true }
            };
            result.RecordFileOutcome("bad.dll", DllFileOutcome.Quarantined);
            Assert.True(result.Success);
            Assert.True(result.HostContained);
            Assert.Single(result.QuarantinedDlls);
            Assert.True(result.CreateExecutionReceipt().VerifiesRequestedAction);
        }

        [Fact]
        public void RetriedFileOutcomeReplacesDeferredStateWithoutDoubleCounting()
        {
            var result = new DllUnloadResult();
            result.RecordFileOutcome("BAD.dll", DllFileOutcome.Deferred);
            result.RecordFileOutcome("bad.dll", DllFileOutcome.Quarantined);
            Assert.Single(result.QuarantinedDlls);
            Assert.Empty(result.DeferredDlls);
            Assert.True(result.Success);
        }
    }
}
