using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the thumbprint-keyed certificate distrust list.
    ///
    /// The list is the authoritative, non-attacker-controllable identity anchor for the cert
    /// scan + remediation path: StartCom (globally distrusted CA).
    ///
    /// v3.1.3: The three Microsoft ECC roots previously seeded from Registry\Certificates.reg
    /// were removed - they are active, CTL-vouched Microsoft roots (Windows Update / Store TLS /
    /// Authenticode time-stamping). Having them on the distrust list caused RootStoreGuard to
    /// move them to Disallowed on startup, breaking Microsoft Store downloads.
    /// A certificate's Subject/Issuer strings are attacker-controlled, so detection keys on the
    /// SHA-1 thumbprint only.
    /// </summary>
    public class CertDistrustListTests
    {
        private const string StartCom = "3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F";
        // Removed in v3.1.3 - active Microsoft roots, never should have been on the list.
        private const string MsTimeStampRoot2014 = "0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8";
        private const string MsEccTsRoot2018 = "31F9FC8BA3805986B721EA7295C65B3A44534274";
        private const string MsEccProductRoot2018 = "06F1AA330B927B753A40E68CDF22E34BCBEF3352";

        [Fact]
        public void IsDistrusted_StartCom_ReturnsTrue()
        {
            Assert.True(CertDistrustList.IsDistrusted(StartCom));
            Assert.NotNull(CertDistrustList.GetLabel(StartCom));
        }

        [Theory]
        [InlineData(MsTimeStampRoot2014)]
        [InlineData(MsEccTsRoot2018)]
        [InlineData(MsEccProductRoot2018)]
        public void IsDistrusted_MicrosoftEccRoots_ReturnsFalse_RemovedInV313(string thumbprint)
        {
            // These three active Microsoft roots were removed from the distrust list in v3.1.3
            // because RootStoreGuard was moving them to Disallowed on startup, breaking Store TLS.
            Assert.False(CertDistrustList.IsDistrusted(thumbprint));
            Assert.Null(CertDistrustList.GetLabel(thumbprint));
        }

        [Fact]
        public void IsDistrusted_IsCaseAndSeparatorInsensitive()
        {
            Assert.True(CertDistrustList.IsDistrusted(StartCom.ToLowerInvariant()));
            Assert.True(CertDistrustList.IsDistrusted("3e:2b:f7:f2:03:1b:96:f3:8c:e6:c4:d8:a8:5d:3e:2d:58:47:6a:0f"));
            Assert.True(CertDistrustList.IsDistrusted("3E 2B F7 F2 03 1B 96 F3 8C E6 C4 D8 A8 5D 3E 2D 58 47 6A 0F"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("deadbeef")]
        [InlineData("1234567890123456789012345678901234567890")] // valid shape, not on list
        public void IsDistrusted_UnknownOrEmpty_ReturnsFalse(string? thumbprint)
        {
            Assert.False(CertDistrustList.IsDistrusted(thumbprint));
            Assert.Null(CertDistrustList.GetLabel(thumbprint));
        }

        [Fact]
        public void Normalize_StripsSeparatorsAndUppercases()
        {
            Assert.Equal(StartCom, CertDistrustList.Normalize("3e:2b f7-f2\t031b96f38ce6c4d8a85d3e2d58476a0f"));
            Assert.Equal(string.Empty, CertDistrustList.Normalize(null));
            Assert.Equal(string.Empty, CertDistrustList.Normalize("   "));
        }

        [Fact]
        public void List_ContainsExactlyOneSeedThumbprint()
        {
            // v3.1.3: list is down to StartCom only.
            Assert.Equal(1, CertDistrustList.Count);
            Assert.Contains(StartCom, CertDistrustList.Thumbprints);
        }
    }
}
