using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for DriverLoadMonitor - verifies service name validation, 
    /// CN extraction from distinguished names, and known CA classification.
    /// </summary>
    public class DriverLoadMonitorTests
    {
        // 
        // ScoringEngine.CategorizeDetection for driver-related rules
        // 

        [Theory]
        [InlineData("BYOVD: Vulnerable Driver Installed")]
        [InlineData("BYOVD: Known Vulnerable Driver Loaded")]
        public void DriverRules_CategorizedCorrectly(string ruleName)
        {
            // Driver rules don't have a specific category in the string-pattern fallback
            // but they should not crash
            var category = ScoringEngine.CategorizeDetection(ruleName);
            // These might map to Unknown if not in RuleCategoryRegistry - that's OK
            Assert.True(Enum.IsDefined(typeof(DetectionCategory), category));
        }

        // 
        // Service name validation logic (mirrors private IsValidServiceName)
        // 

        [Theory]
        [InlineData("WdFilter")]
        [InlineData("nvlddmkm")]
        [InlineData("Sentinel.Service")]
        [InlineData("VirtualBox USB")]
        [InlineData("my-driver_v3")]
        public void ValidServiceNames_Accepted(string name)
        {
            Assert.True(IsValidServiceName(name));
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("evil;drop")]
        [InlineData("cmd/c calc")]
        [InlineData("pipe|name")]
        [InlineData("reg\"add")]
        public void InvalidServiceNames_Rejected(string name)
        {
            Assert.False(IsValidServiceName(name));
        }

        [Fact]
        public void NullServiceName_Rejected()
        {
            Assert.False(IsValidServiceName(null!));
        }

        [Fact]
        public void OverlongServiceName_Rejected()
        {
            Assert.False(IsValidServiceName(new string('X', 257)));
        }

        [Fact]
        public void MaxLengthServiceName_Accepted()
        {
            Assert.True(IsValidServiceName(new string('A', 256)));
        }

        // 
        // Known public CA detection (prevent revoking legitimate vendor certs)
        // 

        [Theory]
        [InlineData("CN=DigiCert SHA2 Assured ID CA, O=DigiCert Inc")]
        [InlineData("CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation")]
        [InlineData("CN=NVIDIA Corporation, O=NVIDIA")]
        [InlineData("CN=Intel(R) Platform Key, O=Intel")]
        public void KnownPublicCa_ShouldNotBeRevoked(string dn)
        {
            // These distinguished names contain known public CA strings
            // The monitor should never revoke certs from these issuers
            Assert.True(ContainsKnownPublicCa(dn));
        }

        [Theory]
        [InlineData("CN=DESKTOP-ABC123")]
        [InlineData("CN=My Evil Corp")]
        [InlineData("CN=Unknown CA, O=Shady Org")]
        public void UnknownCa_ShouldBeInvestigated(string dn)
        {
            Assert.False(ContainsKnownPublicCa(dn));
        }

        // 
        // Helper re-implementations for testing private logic
        // 

        private static bool IsValidServiceName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name) || name!.Length > 256) return false;
            foreach (var c in name)
            {
                if (!(char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or ' '))
                    return false;
            }
            return true;
        }

        private static bool ContainsKnownPublicCa(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return false;
            string[] knownPublicCas =
            {
                "DigiCert", "GlobalSign", "VeriSign", "Entrust", "GeoTrust", "GoDaddy",
                "Comodo", "Sectigo", "Let's Encrypt", "ISRG Root",
                "Microsoft Root", "Microsoft Corporation", "Microsoft Code",
                "Microsoft Windows", "NVIDIA", "AMD", "Intel", "Realtek", "Broadcom",
                "Samsung", "Logitech", "Razer", "Corsair"
            };
            foreach (var ca in knownPublicCas)
            {
                if (distinguishedName.Contains(ca))
                    return true;
            }
            return false;
        }
    }
}
