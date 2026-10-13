using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the HijackThis-derived detections brought into Sentinel:
    ///  - WinsockLspIntegrityMonitor static helpers (catalog parsing, signer, entry format)
    ///  - PublicDnsResolvers allowlist (NetworkInterfaceGuard DNS-confidence tuning)
    ///  - LolbinCanonicalPaths location-anomaly signal
    ///
    /// The monitor itself is an observe-only BackgroundService (AuthorizedResponse = LogOnly,
    /// Tier1Behavioral, no host mutation) so there is no active-response or posture-gate
    /// contract to assert; these tests cover the classification logic that drives it.
    /// </summary>
    public class WinsockLspIntegrityMonitorTests
    {
        // ---- Catalog entry name formatting (zero-padded to 12 digits) ----

        [Theory]
        [InlineData(1, "000000000001")]
        [InlineData(12, "000000000012")]
        [InlineData(1234, "000000001234")]
        public void FormatCatalogEntry_ZeroPadsTo12(int index, string expected)
        {
            Assert.Equal(expected, WinsockLspIntegrityMonitor.FormatCatalogEntry(index));
        }

        // ---- Microsoft signer classification ----

        [Theory]
        [InlineData("Microsoft Windows", true)]
        [InlineData("Microsoft Corporation", true)]
        [InlineData("microsoft corporation", true)]
        [InlineData("Contoso VPN Inc", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsMicrosoftSigner_MatchesMicrosoftOnly(string? signer, bool expected)
        {
            Assert.Equal(expected, WinsockLspIntegrityMonitor.IsMicrosoftSigner(signer));
        }

        // ---- PackedCatalogItem path extraction ----

        [Fact]
        public void ExtractPath_FindsEmbeddedDllPath()
        {
            // Simulate a WSAPROTOCOL_INFOW-style blob: some leading bytes, then a NUL-terminated
            // Unicode provider path, then trailing protocol-name text.
            var blob = new byte[16]; // arbitrary leading header bytes
            var path = Encoding.Unicode.GetBytes(@"C:\Windows\System32\mswsock.dll" + "\0");
            var trailer = Encoding.Unicode.GetBytes("MSAFD Tcpip [TCP/IP]\0");

            var buf = new byte[blob.Length + path.Length + trailer.Length];
            System.Buffer.BlockCopy(blob, 0, buf, 0, blob.Length);
            System.Buffer.BlockCopy(path, 0, buf, blob.Length, path.Length);
            System.Buffer.BlockCopy(trailer, 0, buf, blob.Length + path.Length, trailer.Length);

            var result = WinsockLspIntegrityMonitor.ExtractPathFromPackedCatalogItem(buf);
            Assert.Equal(@"C:\Windows\System32\mswsock.dll", result);
        }

        [Fact]
        public void ExtractPath_ExpandsEnvironmentVarPath()
        {
            var bytes = Encoding.Unicode.GetBytes(@"%SystemRoot%\System32\mswsock.dll" + "\0");
            var result = WinsockLspIntegrityMonitor.ExtractPathFromPackedCatalogItem(bytes);
            Assert.NotNull(result);
            Assert.EndsWith(@"\System32\mswsock.dll", result!);
            Assert.DoesNotContain("%", result!); // expanded
        }

        [Fact]
        public void ExtractPath_NoDllReturnsNull()
        {
            var bytes = Encoding.Unicode.GetBytes("MSAFD Tcpip [TCP/IP]\0some other text\0");
            Assert.Null(WinsockLspIntegrityMonitor.ExtractPathFromPackedCatalogItem(bytes));
        }

        [Fact]
        public void ExtractPath_NullOrTinyReturnsNull()
        {
            Assert.Null(WinsockLspIntegrityMonitor.ExtractPathFromPackedCatalogItem(null));
            Assert.Null(WinsockLspIntegrityMonitor.ExtractPathFromPackedCatalogItem(new byte[] { 1, 2 }));
        }

        // ---- Tier1 rule contracts (constraint 1: rule fires + Tier1Behavioral) ----
        //
        // This monitor introduces THREE Tier1 rules and ZERO Tier2 rules, so constraints (2)
        // Tier2Indicator and (3) Tier2 log-only are not applicable. It performs NO host mutation
        // (LogOnly only, never edits the Winsock catalog), so constraint (4) posture-gate /
        // default-deny is not applicable. The three tests below prove each rule fires and returns
        // Tier1Behavioral with an observe-only (LogOnly) response.

        [Fact]
        public void MissingProviderRule_FiresTier1LogOnly()
        {
            var e = WinsockLspIntegrityMonitor.BuildMissingProviderEvent("Protocol", @"C:\gone\evil.dll");
            Assert.Equal("Network: Winsock LSP Provider Missing", e.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, e.Tier);
            Assert.Equal(ResponseAction.LogOnly, e.AuthorizedResponse);
            Assert.False(e.KillAuthorized);
            Assert.Equal("Missing", e.Metadata["Condition"]);
            Assert.Equal("Protocol", e.Metadata["Catalog"]);
        }

        [Theory]
        [InlineData(true, "Contoso VPN", 0.50)]  // signed, non-Microsoft -> lower confidence
        [InlineData(false, null, 0.68)]          // unsigned -> higher confidence
        public void NonMicrosoftProviderRule_FiresTier1LogOnly(bool signed, string? signer, double expectedConfidence)
        {
            var e = WinsockLspIntegrityMonitor.BuildNonMicrosoftProviderEvent(
                "NameSpace", @"C:\Program Files\Vendor\lsp.dll", signed, signer);
            Assert.Equal("Network: Non-Microsoft Winsock LSP Provider", e.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, e.Tier);
            Assert.Equal(ResponseAction.LogOnly, e.AuthorizedResponse);
            Assert.False(e.KillAuthorized);
            Assert.Equal(expectedConfidence, e.Confidence);
            Assert.Equal(signed.ToString(), e.Metadata["Signed"]);
        }

        [Fact]
        public void ChainGapRule_FiresTier1LogOnly()
        {
            var e = WinsockLspIntegrityMonitor.BuildChainGapEvent("Protocol", 3, 7);
            Assert.Equal("Network: Winsock LSP Chain Gap", e.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, e.Tier);
            Assert.Equal(ResponseAction.LogOnly, e.AuthorizedResponse);
            Assert.False(e.KillAuthorized);
            Assert.Equal("3", e.Metadata["MissingIndex"]);
            Assert.Equal("7", e.Metadata["DeclaredCount"]);
        }
    }

    public class PublicDnsResolversTests
    {
        [Theory]
        [InlineData("1.1.1.1", true)]
        [InlineData("8.8.8.8", true)]
        [InlineData("9.9.9.9", true)]
        [InlineData("208.67.222.222", true)]
        [InlineData("2606:4700:4700::1111", true)]
        [InlineData("203.0.113.66", false)]   // TEST-NET-3, not a known resolver
        [InlineData("10.6.6.6", false)]        // attacker-style private hijack target
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsKnownPublicResolver_ClassifiesCorrectly(string? ip, bool expected)
        {
            Assert.Equal(expected, PublicDnsResolvers.IsKnownPublicResolver(ip));
        }

        [Theory]
        [InlineData("1.1.1.1,1.0.0.1", true)]
        [InlineData("8.8.8.8 8.8.4.4", true)]
        [InlineData("9.9.9.9;149.112.112.112", true)]
        [InlineData("1.1.1.1,203.0.113.66", false)]  // one unknown taints the whole set
        [InlineData("203.0.113.66", false)]
        [InlineData("", false)]
        [InlineData("   ", false)]
        [InlineData(null, false)]
        public void AllKnownPublicResolvers_RequiresEveryServerKnown(string? list, bool expected)
        {
            Assert.Equal(expected, PublicDnsResolvers.AllKnownPublicResolvers(list));
        }
    }

    public class LolbinCanonicalPathsTests
    {
        [Theory]
        [InlineData("rundll32.exe", true)]
        [InlineData("rundll32", true)]         // name without extension
        [InlineData("PowerShell.exe", true)]   // case-insensitive
        [InlineData("notepad.exe", false)]     // not an anchored LOLBin
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsAnchoredLolbin_ClassifiesKnownBinaries(string? name, bool expected)
        {
            Assert.Equal(expected, LolbinCanonicalPaths.IsAnchoredLolbin(name));
        }

        [Theory]
        // Canonical locations - NOT flagged
        [InlineData("rundll32.exe", @"C:\Windows\System32\rundll32.exe", false)]
        [InlineData("rundll32.exe", @"C:\Windows\SysWOW64\rundll32.exe", false)]
        [InlineData("wmic.exe", @"C:\Windows\System32\wbem\wmic.exe", false)]
        [InlineData("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", false)]
        [InlineData("cmd.exe", @"D:\Windows\System32\cmd.exe", false)] // non-C: install tolerated
        // Masquerade locations - FLAGGED
        [InlineData("rundll32.exe", @"C:\Users\bob\AppData\Local\Temp\rundll32.exe", true)]
        [InlineData("powershell.exe", @"C:\Windows\Temp\powershell.exe", true)]
        [InlineData("regsvr32.exe", @"C:\ProgramData\regsvr32.exe", true)]
        [InlineData("wmic.exe", @"C:\Windows\System32\wmic.exe", true)] // wmic outside wbem
        // Missing data - NOT flagged (fail-open, never fabricate a signal)
        [InlineData("rundll32.exe", "", false)]
        [InlineData("rundll32.exe", null, false)]
        // Unknown binary - NOT flagged
        [InlineData("notepad.exe", @"C:\Users\bob\Downloads\notepad.exe", false)]
        public void IsLolbinFromNonCanonicalPath_DetectsMasquerade(string? name, string? path, bool expected)
        {
            Assert.Equal(expected, LolbinCanonicalPaths.IsLolbinFromNonCanonicalPath(name, path));
        }
    }
}
