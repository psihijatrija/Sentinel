using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.5.5+: Hardening is always-on. These tests verify the always-on semantics
    /// that replaced the old work-first / observe-only defaults.
    /// </summary>
    public class ProductPostureTests
    {
        [Fact]
        public void Default_Config_HardeningIsAlwaysOn()
        {
            var c = new SentinelConfig();
            // v2.5.5: RestrictivePortHardening is always true.
            Assert.True(c.RestrictivePortHardening);
            // v2.9.4: armed-by-default posture
            Assert.False(c.ObserveUntilChain);
            Assert.True(c.SilentObserve);
            Assert.False(c.AutoDisableFailedUsbEnumeration);
            Assert.True(c.ThreatIntelProactiveFirewall);
            Assert.True(c.BlockFcmPushChannel);
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(c));
            Assert.True(ProductPosture.ModuleIdentityUnloadAlwaysOn);
        }

        [Fact]
        public void TryProactiveHostLockdown_AlwaysSucceeds()
        {
            // v2.5.5: hardening is always-on - denyReason is always empty.
            Assert.True(ProductPosture.TryProactiveHostLockdown(new SentinelConfig(), out var reason));
            Assert.Equal("", reason);
        }

        [Fact]
        public void TryProactiveHostLockdown_AlwaysSucceeds_WithNullConfig()
        {
            Assert.True(ProductPosture.TryProactiveHostLockdown(null, out var reason));
            Assert.Equal("", reason);
        }

        [Fact]
        public void HardeningModule_Default_ApplyOrFail_DoesNotThrow()
        {
            // v2.5.5: ApplyOrFail always runs the hardening trio - must not throw.
            var ex = Record.Exception(() =>
            {
                HardeningModule.ApplyOrFail();
            });
            Assert.Null(ex);
        }

        [Fact]
        public void AllowsProactiveHostLockdown_AlwaysTrue()
        {
            // v2.5.5: always returns true regardless of config.
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(null));
            Assert.True(ProductPosture.AllowsProactiveHostLockdown(new SentinelConfig()));
        }
    }
}
