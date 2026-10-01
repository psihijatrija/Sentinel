using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the compile-time-safe RuleCategoryRegistry that maps
    /// rule class names to DetectionCategory via [RuleCategory] attributes.
    /// </summary>
    public class RuleCategoryRegistryTests
    {
        [Theory]
        [InlineData("LsassAccessRule", DetectionCategory.CredentialDump)]
        [InlineData("RansomwareDetectionRule", DetectionCategory.Ransomware)]
        [InlineData("ReverseShellRule", DetectionCategory.ReverseShell)]
        [InlineData("ThreatIntelInjectionRule", DetectionCategory.ProcessInjection)]
        [InlineData("PrivilegeEscalationRule", DetectionCategory.PrivilegeEscalation)]
        [InlineData("AttackToolsRule", DetectionCategory.SecurityEvasion)]
        [InlineData("CampaignIocRule", DetectionCategory.CampaignIoC)]
        [InlineData("UnsignedBinaryRule", DetectionCategory.UnsignedBinary)]
        [InlineData("VerdictGateRule", DetectionCategory.AntiTamper)]
        [InlineData("ClickFixDetectionRule", DetectionCategory.ReverseShell)]
        [InlineData("NpmSupplyChainRule", DetectionCategory.SecurityEvasion)]
        [InlineData("ChromeRemoteDebuggingRule", DetectionCategory.CredentialDump)]
        [InlineData("DllSideloadingDetectionRule", DetectionCategory.ProcessInjection)]
        public void RuleCategoryRegistry_ResolvesAllKnownRules(string ruleName, DetectionCategory expected)
        {
            var category = RuleCategoryRegistry.Resolve(ruleName);
            Assert.NotNull(category);
            Assert.Equal(expected, category!.Value);
        }

        [Theory]
        [InlineData("UnknownRule")]
        [InlineData("")]
        [InlineData(null)]
        public void RuleCategoryRegistry_ReturnsNull_ForUnknownRules(string? ruleName)
        {
            var category = RuleCategoryRegistry.Resolve(ruleName);
            Assert.Null(category);
        }

        [Fact]
        public void RuleCategoryRegistry_AllRulesHaveAttribute()
        {
            // Verify that all known detection rules have been registered
            var knownRules = new[]
            {
                "LsassAccessRule", "RansomwareDetectionRule", "ReverseShellRule",
                "ThreatIntelInjectionRule", "PrivilegeEscalationRule", "AttackToolsRule",
                "CampaignIocRule", "UnsignedBinaryRule", "VerdictGateRule",
                "ClickFixDetectionRule", "NpmSupplyChainRule",
                "ChromeRemoteDebuggingRule", "DllSideloadingDetectionRule"
            };
            foreach (var rule in knownRules)
            {
                Assert.NotNull(RuleCategoryRegistry.Resolve(rule));
            }
        }
    }
}
