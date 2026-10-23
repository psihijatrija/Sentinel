using System;
using System.Linq;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ProtectionPostureTests
    {
        [Fact]
        public void VbsAndConfiguredCredentialGuardDoNotProveRuntimeIsolation()
        {
            var checks = ProtectionPosture.DeviceGuard(2U, new uint[] { 1, 2 }, Array.Empty<uint>());
            Assert.Equal("ObservedActive", checks.Single(c => c.Name == "Virtualization-based security").State);
            Assert.Equal("ContextDependent", checks.Single(c => c.Name == ProtectionPosture.CredentialGuard).State);
            Assert.Equal("ConfiguredNotRunning", checks.Single(c => c.Name == ProtectionPosture.MemoryIntegrity).State);
        }

        [Fact]
        public void ActualRunningServicesAreEvaluatedIndependentlyAndExplainPersonalAccountScope()
        {
            var checks = ProtectionPosture.DeviceGuard(2U, new uint[] { 1, 2 }, new uint[] { 1 });
            var guard = checks.Single(c => c.Name == ProtectionPosture.CredentialGuard);
            Assert.Equal("ObservedActive", guard.State);
            Assert.Contains("personal Microsoft-account", guard.Detail);
            Assert.Contains("browser cookies", guard.Detail);
            Assert.Equal("ConfiguredNotRunning", checks.Single(c => c.Name == ProtectionPosture.MemoryIntegrity).State);
        }

        [Theory]
        [InlineData(0U)]
        [InlineData(1U)]
        public void ContradictoryRunningServicesWithoutRunningVbsRemainUnknown(uint state)
            => Assert.Equal("Unknown", ProtectionPosture.DeviceGuard(state, new uint[] { 1 }, new uint[] { 1 })
                .Single(c => c.Name == ProtectionPosture.CredentialGuard).State);

        [Fact]
        public void MalformedMissingAndFutureValuesCannotBecomeActiveProtection()
        {
            foreach (object? services in new object?[] { null, "1", new int[] { 1 }, new uint[] { 99 }, new uint[] { 0, 1 } })
            {
                var checks = ProtectionPosture.DeviceGuard(2U, new uint[] { 1, 2 }, services);
                Assert.All(checks.Where(c => c.Name != "Virtualization-based security"), c => Assert.Equal("Unknown", c.State));
            }
            Assert.All(ProtectionPosture.DeviceGuard("2", null, new uint[] { 1, 2 }), c => Assert.Equal("Unknown", c.State));
        }

        [Theory]
        [InlineData(4U, "ObservedActive")]
        [InlineData(0U, "ObservedActive")]
        [InlineData(0xfffffffeU, "NeedsReview")]
        [InlineData(0xffffffffU, "Unknown")]
        public void LsassProtectionLevelsDoNotUseRegistryConfigurationAsRuntimeProof(uint level, string state)
            => Assert.Equal(state, ProtectionPosture.Lsass(level).State);

        [Fact]
        public void UnqueryableLsassRemainsUnknown() => Assert.Equal("Unknown", ProtectionPosture.Lsass(null).State);

        [Fact]
        public void InactiveCredentialGuardIsContextualRatherThanAPersonalComputerFailure()
        {
            var runtime = ProtectionPosture.DeviceGuard(0U, new uint[] { 0 }, new uint[] { 0 })
                .Single(c => c.Name == ProtectionPosture.CredentialGuard);
            Assert.Equal("ContextDependent", runtime.State);
            Assert.Contains("local-account", runtime.Detail);
            var configuration = SecurityAuditService.Evaluate(new AuditPolicy("Credential Guard", "key", "value", 1,
                scope: ProtectionPosture.CredentialScope), new AuditRegistryReading { Available = true, Value = 0 });
            Assert.Equal("ContextDependent", configuration.State);
        }
    }
}
