using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// FEAT-001 1B: the pure signed-vs-unsigned mitigation decision. BlockNonMicrosoftBinaries
    /// is only added on an Authenticode-signed build; the baseline mitigations are always present.
    /// </summary>
    public class SelfMitigationPlanTests
    {
        [Fact]
        public void Unsigned_ExcludesBlockNonMicrosoftBinaries()
        {
            var plan = HardeningModule.GetSelfMitigationPlan(processImageIsAuthenticodeSigned: false);
            Assert.False(plan.HasFlag(HardeningModule.SelfMitigation.BlockNonMicrosoftBinaries));
        }

        [Fact]
        public void Unsigned_IncludesBaselineMitigations()
        {
            var plan = HardeningModule.GetSelfMitigationPlan(processImageIsAuthenticodeSigned: false);
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.DepPermanent));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.StrictHandleCheck));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ExtensionPointDisable));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ControlFlowGuard));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadNoRemoteImages));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadNoLowMandatoryLabelImages));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadPreferSystem32Images));
        }

        [Fact]
        public void Signed_IncludesBlockNonMicrosoftBinaries()
        {
            var plan = HardeningModule.GetSelfMitigationPlan(processImageIsAuthenticodeSigned: true);
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.BlockNonMicrosoftBinaries));
        }

        [Fact]
        public void Signed_StillIncludesBaselineMitigations()
        {
            var plan = HardeningModule.GetSelfMitigationPlan(processImageIsAuthenticodeSigned: true);
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.DepPermanent));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.StrictHandleCheck));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ExtensionPointDisable));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ControlFlowGuard));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadNoRemoteImages));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadNoLowMandatoryLabelImages));
            Assert.True(plan.HasFlag(HardeningModule.SelfMitigation.ImageLoadPreferSystem32Images));
        }
    }
}
