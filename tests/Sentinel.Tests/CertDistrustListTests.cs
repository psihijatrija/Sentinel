using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the thumbprint-keyed certificate distrust list.
    ///
    /// The list is the authoritative, non-attacker-controllable identity anchor for the cert
    /// scan + remediation path: StartCom (globally distrusted CA) plus the three roots that
    /// Registry\Certificates.reg (and an independent Zemana AntiLogger scan) flag for deletion.
    /// A certificate's Subject/Issuer strings are attacker-controlled, so detection keys on the
    /// SHA-1 thumbprint only.
    /// </summary>
    public class CertDistrustListTests
    {
        // The four seed thumbprints the feature must cover.
        private const string StartCom = "3E20F7F203189673EC6DC4D8AE5D3ED35847EADF";
        private const string MsTimeStampRoot2014 = "0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8";
        private const string MsEccTsRoot2018 = "31F9FC8BA3805986B721EA7295C65B3A44534274";
        private const string MsEccProductRoot2018 = "06F1AA330B927B753A40E68CDF22E34BCBEF3352";

        [Theory]
        [InlineData(StartCom)]
        [InlineData(MsTimeStampRoot2014)]
        [InlineData(MsEccTsRoot2018)]
        [InlineData(MsEccProductRoot2018)]
        public void IsDistrusted_SeedThumbprints_ReturnsTrue(string thumbprint)
        {
            Assert.True(CertDistrustList.IsDistrusted(thumbprint));
            Assert.NotNull(CertDistrustList.GetLabel(thumbprint));
        }

        [Fact]
        public void IsDistrusted_IsCaseAndSeparatorInsensitive()
        {
            // Lowercase, with spaces and colons - all must normalize to the same entry.
            Assert.True(CertDistrustList.IsDistrusted(StartCom.ToLowerInvariant()));
            Assert.True(CertDistrustList.IsDistrusted("31 F9 FC 8B A3 80 59 86 B7 21 EA 72 95 C6 5B 3A 44 53 42 74"));
            Assert.True(CertDistrustList.IsDistrusted("06:F1:AA:33:0B:92:7B:75:3A:40:E6:8C:DF:22:E3:4B:CB:EF:33:52"));
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
            Assert.Equal(StartCom, CertDistrustList.Normalize("3e:20 f7-f2\t03189673ec6dc4d8ae5d3ed35847eadf"));
            Assert.Equal(string.Empty, CertDistrustList.Normalize(null));
            Assert.Equal(string.Empty, CertDistrustList.Normalize("   "));
        }

        [Fact]
        public void List_ContainsExactlyTheFourSeedThumbprints()
        {
            var expected = new[] { StartCom, MsTimeStampRoot2014, MsEccTsRoot2018, MsEccProductRoot2018 }
                .OrderBy(x => x).ToArray();
            var actual = CertDistrustList.Thumbprints.OrderBy(x => x).ToArray();

            Assert.Equal(4, CertDistrustList.Count);
            Assert.Equal(expected, actual);
        }
    }
}
