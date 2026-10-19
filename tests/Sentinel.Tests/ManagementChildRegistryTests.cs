using System;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ManagementChildRegistryTests
    {
        [Fact]
        public void ChildAttribution_RequiresSignatureExactImageAndLiveLifetime()
        {
            var time = DateTime.UtcNow;
            (DateTime Start, string Path)? current = (time, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
            var registry = new ManagementChildRegistry(_ => current);
            string path = current.Value.Path;
            Assert.False(registry.RegisterIdentity(123, time, path, path, false));
            Assert.False(registry.IsCurrentChild(123));
            Assert.False(registry.RegisterIdentity(123, time, @"C:\Temp\powershell.exe", path, true));
            Assert.False(registry.RegisterIdentity(123, DateTime.MinValue, path, path, true));
            Assert.True(registry.RegisterIdentity(123, time, path, path, true));
            Assert.True(registry.IsCurrentChild(123));
            current = (time.AddSeconds(1), path); // PID reused by the same executable.
            Assert.False(registry.IsCurrentChild(123));
            current = (time, path);
            Assert.False(registry.IsCurrentChild(123)); // Stale registration was removed.
            Assert.True(registry.RegisterIdentity(123, time, path, path, true));
            current = null;
            Assert.False(registry.IsCurrentChild(123));
        }

        [Theory]
        [InlineData("ReverseShellRule")]
        [InlineData("AttackToolsRule")]
        [InlineData("Dropped Payload Active")]
        public void BehavioralSignals_NeverReceiveManagementCoalescing(string rule)
        {
            Assert.False(ManagementChildRegistry.IsRoutineObservation(new DetectionEvent
            { RuleName = rule, Tier = DetectionTier.Tier1Behavioral, AuthorizedResponse = ResponseAction.KillProcessTree, Confidence = 0.99 }));
        }

        [Theory]
        [InlineData("PowerShell: Encoded Command Observation")]
        [InlineData("File Reputation: Suspicious Binary Executed")]
        [InlineData("Named Pipe: High-Entropy Name (Non-System Owner)")]
        public void OnlyWeakLogOnlyObservations_CanBeCoalesced(string rule)
        {
            var detection = new DetectionEvent { RuleName = rule, Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly, Confidence = 0.55 };
            Assert.True(ManagementChildRegistry.IsRoutineObservation(detection));
            detection.Confidence = 0.9;
            Assert.False(ManagementChildRegistry.IsRoutineObservation(detection));
            detection.Confidence = 0.55;
            detection.AuthorizedResponse = ResponseAction.QuarantineAndKill;
            Assert.False(ManagementChildRegistry.IsRoutineObservation(detection));
        }
    }
}
