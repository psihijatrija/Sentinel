using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class V175FeatureTests
    {
        [Theory]
        [InlineData(0, "Services", RemoteSessionGuard.WtsConnectState.WTSActive, 1u, false)]
        [InlineData(1, "Console", RemoteSessionGuard.WtsConnectState.WTSActive, 1u, false)]
        [InlineData(2, "rdp-tcp#0", RemoteSessionGuard.WtsConnectState.WTSActive, 1u, true)]
        [InlineData(3, "rdp-tcp#1", RemoteSessionGuard.WtsConnectState.WTSDisconnected, 1u, true)]
        [InlineData(4, "rdp-tcp", RemoteSessionGuard.WtsConnectState.WTSListen, 1u, false)]
        [InlineData(5, "Console", RemoteSessionGuard.WtsConnectState.WTSActive, 5u, false)] // is console session id
        [InlineData(6, "ica-tcp#2", RemoteSessionGuard.WtsConnectState.WTSConnected, 1u, true)]
        [InlineData(7, "rdp-tcp#9", RemoteSessionGuard.WtsConnectState.WTSInit, 1u, false)]
        public void RemoteSessionGuard_ShouldTerminateSession_ClassifiesCorrectly(
            int sessionId,
            string station,
            RemoteSessionGuard.WtsConnectState state,
            uint consoleId,
            bool expected)
        {
            Assert.Equal(expected, RemoteSessionGuard.ShouldTerminateSession(sessionId, station, state, consoleId));
        }

        [Fact]
        public void HardeningModule_AsrRules_HasExpectedBlockListSize()
        {
            // High-value rules; excludes prevalence + "advanced ransomware" (blocks Inno TEMP extract)
            Assert.True(HardeningModule.AsrRules.Length >= 12);
            Assert.Contains(HardeningModule.AsrRules, r => r.Guid == "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"); // LSASS
            Assert.Contains(HardeningModule.AsrRules, r => r.Guid == "56a863a9-875e-4185-98a7-b882c64b5ce5"); // vulnerable drivers
            Assert.DoesNotContain(HardeningModule.AsrRules, r => r.Guid == "01443614-cd74-433a-b99e-2ecdc07bfc25"); // prevalence
            Assert.DoesNotContain(HardeningModule.AsrRules, r => r.Guid == "c1db55ab-c21a-4637-bb3f-a12568109d35");
            Assert.Contains(HardeningModule.AsrRulesNeverBlock, g => g == "c1db55ab-c21a-4637-bb3f-a12568109d35");
        }

        [Fact]
        public void HardeningModule_AsrRules_AllGuidsAreUnique()
        {
            var guids = HardeningModule.AsrRules.Select(r => r.Guid).ToList();
            Assert.Equal(guids.Count, guids.Distinct().Count());
        }

        [Fact]
        public void HardeningModule_ApplyAsrRules_DoesNotThrow()
        {
            // May no-op without admin; must never throw
            HardeningModule.ApplyAsrRules();
            HardeningModule.ReapplyAsrRules();
            _ = HardeningModule.IsAsrPolicyIntact();
        }

        [Fact]
        public void HardeningModule_ReleaseUserWorkSurface_DoesNotThrow()
        {
            // ReleaseUserWorkSurface still exists for upgrade cleanup; must never throw.
            var ex = Record.Exception(() => HardeningModule.ReleaseUserWorkSurface());
            Assert.Null(ex);
            ex = Record.Exception(() => HardeningModule.ApplyOrFail());
            Assert.Null(ex);
        }

        [Fact]
        public void HardeningModule_ApplyCredentialAndBrowserHardening_DoesNotThrow()
        {
            HardeningModule.ApplyCredentialHardening();
            HardeningModule.ApplyBrowserHardening();
        }
    }
}
