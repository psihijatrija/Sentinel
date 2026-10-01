using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for ResponseCoordinator data models and logic that doesn't require
    /// the full DI graph (AdvancedResponseEngine needs complex wiring).
    /// </summary>
    public class ResponseCoordinatorTests
    {
        [Fact]
        public void ResponseOutcome_Enum_HasExpectedValues()
        {
            Assert.Equal(0, (int)ResponseOutcome.Executed);
            Assert.True(Enum.IsDefined(typeof(ResponseOutcome), ResponseOutcome.Deduplicated));
            Assert.True(Enum.IsDefined(typeof(ResponseOutcome), ResponseOutcome.DeferredForChainTrace));
            Assert.True(Enum.IsDefined(typeof(ResponseOutcome), ResponseOutcome.LockTimeout));
            Assert.True(Enum.IsDefined(typeof(ResponseOutcome), ResponseOutcome.Failed));
        }

        [Fact]
        public void ResponseResult_Properties_SetCorrectly()
        {
            var result = new ResponseResult
            {
                ProcessId = 1234,
                ProcessName = "test.exe",
                RequestedAction = ResponseAction.KillProcessTree,
                Outcome = ResponseOutcome.Executed,
                Reason = "ChainConfirmed",
                ExecutedAt = DateTimeOffset.UtcNow
            };

            Assert.Equal(1234, result.ProcessId);
            Assert.Equal("test.exe", result.ProcessName);
            Assert.Equal(ResponseAction.KillProcessTree, result.RequestedAction);
            Assert.Equal(ResponseOutcome.Executed, result.Outcome);
            Assert.NotNull(result.ExecutedAt);
        }

        [Fact]
        public void ResponseResult_Defaults()
        {
            var result = new ResponseResult();
            Assert.Equal(0, result.ProcessId);
            Assert.Equal(string.Empty, result.ProcessName);
            Assert.Null(result.Reason);
            Assert.Null(result.ExecutedAt);
        }

        [Fact]
        public void ResponseCoordinatorStats_Properties_DefaultToZero()
        {
            var stats = new ResponseCoordinatorStats();
            Assert.Equal(0, stats.TotalExecuted);
            Assert.Equal(0, stats.TotalDeduplicated);
            Assert.Equal(0, stats.TotalDeferred);
            Assert.Equal(0, stats.TotalFailed);
            Assert.Equal(0, stats.ActiveLocks);
            Assert.Equal(0, stats.ActiveChainTraceHolds);
        }

        [Fact]
        public void ResponseAction_KillProcessTree_HasHigherValue_ThanLogOnly()
        {
            // Verify enum ordering used for deduplication escalation logic
            Assert.True(ResponseAction.KillProcessTree > ResponseAction.LogOnly);
        }

        [Fact]
        public void ResponseAction_QuarantineAndKill_Exists()
        {
            Assert.True(Enum.IsDefined(typeof(ResponseAction), ResponseAction.QuarantineAndKill));
        }

        [Fact]
        public void ResponseAction_NetworkIsolate_Exists()
        {
            Assert.True(Enum.IsDefined(typeof(ResponseAction), ResponseAction.NetworkIsolate));
        }
    }
}
