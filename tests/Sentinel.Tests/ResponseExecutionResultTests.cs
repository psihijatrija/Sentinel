using System;
using System.IO;
using System.Text.Json;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ResponseExecutionResultTests
    {
        [Fact]
        public void EmptyResultCannotClaimAnActionExecuted()
        {
            var result = new ResponseExecutionResult();
            Assert.Equal(ResponseExecutionStatus.NotRequested, result.Status);
            result.RequestedAction = "KillProcessTree";
            Assert.Equal(ResponseExecutionStatus.Refused, result.Status);
            Assert.False(result.VerifiesRequestedAction);
        }

        [Theory]
        [InlineData(ResponseExecutionStatus.Attempted)]
        [InlineData(ResponseExecutionStatus.Refused)]
        [InlineData(ResponseExecutionStatus.Failed)]
        [InlineData(ResponseExecutionStatus.PartiallyCompleted)]
        public void UnverifiedEffectNeverBecomesCompletionReceipt(ResponseExecutionStatus status)
        {
            var result = Receipt();
            result.Add("ProcessTree", "123", status, "Unverified fixture.");
            Assert.Equal(status, result.Status);
            Assert.False(result.VerifiesRequestedAction);
        }

        [Fact]
        public void MixedEffectsReportPartialCompletion()
        {
            var result = Receipt();
            result.Add("ProcessTree", "123", ResponseExecutionStatus.Verified, "Exited.");
            result.Add("Quarantine", "bad.dll", ResponseExecutionStatus.Failed, "Access denied.");
            Assert.Equal(ResponseExecutionStatus.PartiallyCompleted, result.Status);
            Assert.False(result.VerifiesRequestedAction);
        }

        [Fact]
        public void UnrelatedVerifiedCleanupCannotSatisfyAProcessTerminationRequest()
        {
            var result = Receipt();
            result.Add("DnsCacheCleanup", "resolver", ResponseExecutionStatus.Verified, "Cache flushed.");
            Assert.Equal(ResponseExecutionStatus.PartiallyCompleted, result.Status);
            Assert.False(result.VerifiesRequestedAction);
        }

        [Fact]
        public void VerifiedEffectsNeedMatchingActionAndCompletedReceipt()
        {
            var result = Receipt();
            result.Add("ProcessTree", "123", ResponseExecutionStatus.Verified, "Exited.");
            result.CompletedAt = null;
            Assert.False(result.VerifiesRequestedAction);
            Assert.Equal(ResponseExecutionStatus.Attempted, result.Status);
            result.CompletedAt = DateTimeOffset.UtcNow;
            result.EffectiveAction = "DismountVolume";
            Assert.False(result.VerifiesRequestedAction);
            Assert.Equal(ResponseExecutionStatus.PartiallyCompleted, result.Status);
            result.EffectiveAction = result.RequestedAction;
            Assert.True(result.VerifiesRequestedAction);
        }

        [Fact]
        public void RootExitWithoutDescendantVerificationRemainsPartial()
        {
            var result = Receipt();
            result.AddProcessTree(new ProcessTreeTerminationResult { RootProcessId = 123, RootExited = true });
            Assert.Equal(ResponseExecutionStatus.PartiallyCompleted, result.Status);
            Assert.False(result.VerifiesRequestedAction);
        }

        [Fact]
        public void NativeRefusalDoesNotBecomeSuccessfulProcessContainment()
        {
            var tree = new ProcessTreeTerminationResult { RootProcessId = 123 };
            tree.RefusedProcessIds.Add(123);
            var result = Receipt();
            result.AddProcessTree(tree);
            Assert.Equal(ResponseExecutionStatus.Refused, result.Status);
        }

        [Fact]
        public void SerializationUsesExplicitReadableOutcomeAndEffectStatuses()
        {
            var result = Receipt();
            result.Add("ProcessTree", "123", ResponseExecutionStatus.Failed, "Denied.");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(result));
            Assert.Equal("Failed", json.RootElement.GetProperty("Status").GetString());
            Assert.Equal("Failed", json.RootElement.GetProperty("Effects")[0].GetProperty("Status").GetString());
            Assert.False(json.RootElement.GetProperty("VerifiesRequestedAction").GetBoolean());
        }

        [Fact]
        public void VaultCopyWithoutSourceRemovalIsOnlyAttempted()
        {
            WithFiles((source, vault) =>
            {
                File.WriteAllText(source, "fixture");
                File.WriteAllText(vault, "fixture vault");
                Assert.Equal(ResponseExecutionStatus.Attempted, ResponseVerification.Quarantine(source, vault).Status);
            });
        }

        [Fact]
        public void SourceAbsenceWithoutVaultReceiptIsNotVerifiedQuarantine()
        {
            WithFiles((source, vault) =>
            {
                Assert.Equal(ResponseExecutionStatus.Failed, ResponseVerification.Quarantine(source, vault).Status);
                Assert.Equal(ResponseExecutionStatus.Refused, ResponseVerification.Quarantine(source, null).Status);
            });
        }

        [Fact]
        public void QuarantineRequiresBothVaultPresenceAndSourceAbsence()
        {
            WithFiles((source, vault) =>
            {
                File.WriteAllText(vault, "fixture vault");
                Assert.Equal(ResponseExecutionStatus.Verified, ResponseVerification.Quarantine(source, vault).Status);
            });
        }

        [Fact]
        public void FileReadBackErrorsAreNotTreatedAsSourceAbsence()
        {
            WithFiles((source, vault) =>
            {
                File.WriteAllText(vault, "fixture vault");
                Assert.Equal(ResponseExecutionStatus.Failed, ResponseVerification.Quarantine("invalid\0path", vault).Status);
            });
        }

        [Fact]
        public void DirectoryCannotStandInForAVaultFile()
        {
            WithFiles((source, vault) =>
            {
                Directory.CreateDirectory(vault);
                Assert.Equal(ResponseExecutionStatus.Failed, ResponseVerification.Quarantine(source, vault).Status);
            });
        }

        [Theory]
        [InlineData(123, ResponseExecutionStatus.Verified, true)]
        [InlineData(124, ResponseExecutionStatus.Verified, false)]
        [InlineData(123, ResponseExecutionStatus.PartiallyCompleted, false)]
        public void ReinfectionTrackingRequiresVerifiedExitOfTheActualTarget(int pid, ResponseExecutionStatus status, bool expected)
        {
            var result = Receipt();
            result.Add("ProcessTree", pid.ToString(), status, "Fixture outcome.");
            Assert.Equal(expected, result.HasVerifiedProcessExit(123));
        }

        private static ResponseExecutionResult Receipt() => new()
        {
            ProcessId = 123, RequestedAction = "KillProcessTree", EffectiveAction = "KillProcessTree",
            CompletedAt = DateTimeOffset.UtcNow
        };
        private static void WithFiles(Action<string, string> action)
        {
            string directory = Path.Combine(Path.GetTempPath(), "SentinelReceipt_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try { action(Path.Combine(directory, "source.dll"), Path.Combine(directory, "vault.bin")); }
            finally { Directory.Delete(directory, true); }
        }
    }
}
