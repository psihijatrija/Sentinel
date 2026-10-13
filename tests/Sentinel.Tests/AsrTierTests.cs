using System;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// FEAT-001 1A: audit-first ASR tier invariants. These assert the GUID set is well-formed
    /// and that installer-safety / Safe-Mode-reboot GUIDs are never enforced.
    /// </summary>
    public class AsrTierTests
    {
        // The install-safety GUID that must never be forced to Block.
        private const string InstallerSafetyGuid = "c1db55ab-c21a-4637-bb3f-a12568109d35";

        // "Block process creations originating from PSExec and WMI commands" has a safe-mode-reboot
        // sibling; the canonical ASR "safe mode reboot" rule GUID must appear in neither array.
        private const string SafeModeRebootGuid = "33ddedf1-c6e0-47cb-833e-de6133960387";

        [Fact]
        public void AuditRules_AreDisjointFromBlockRules()
        {
            var block = HardeningModule.AsrRules.Select(r => r.Guid).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var (guid, _) in HardeningModule.AsrRulesAudit)
            {
                Assert.DoesNotContain(guid, block, StringComparer.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void InstallerSafetyGuid_IsInNeitherBlockNorAudit()
        {
            Assert.DoesNotContain(HardeningModule.AsrRules.Select(r => r.Guid),
                g => string.Equals(g, InstallerSafetyGuid, StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(HardeningModule.AsrRulesAudit.Select(r => r.Guid),
                g => string.Equals(g, InstallerSafetyGuid, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void SafeModeRebootGuid_IsInNeitherBlockNorAudit()
        {
            Assert.DoesNotContain(HardeningModule.AsrRules.Select(r => r.Guid),
                g => string.Equals(g, SafeModeRebootGuid, StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(HardeningModule.AsrRulesAudit.Select(r => r.Guid),
                g => string.Equals(g, SafeModeRebootGuid, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void InstallerSafetyGuid_StaysInNeverBlock()
        {
            Assert.Contains(HardeningModule.AsrRulesNeverBlock,
                g => string.Equals(g, InstallerSafetyGuid, StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void AuditRules_ContainOnlyTheThreeConfirmedGuids()
        {
            var expected = new[]
            {
                "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
                "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
                "01443614-cd74-433a-b99e-2ecdc07bfc25",
            };
            var actual = HardeningModule.AsrRulesAudit.Select(r => r.Guid).ToArray();
            Assert.Equal(expected.OrderBy(x => x), actual.OrderBy(x => x));
        }
    }
}
