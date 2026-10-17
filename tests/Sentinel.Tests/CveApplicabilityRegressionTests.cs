using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class CveApplicabilityRegressionTests
    {
        [Theory]
        [InlineData("Google", "Pixel", "Google Chrome", "chrome")]
        [InlineData("Cisco", "Identity Services Engine", "", "services")]
        [InlineData("TeamViewer", "Desktop", "", "StoreDesktopExtension")]
        [InlineData("Vendor", "Client", "Other Client", "OtherClient")]
        public void UnrelatedAssetCannotEstablishProductApplicability(string vendor, string product, string installed, string process)
        {
            var match = CveCoverageHeuristics.ClassifyKevForWorkstation("CVE-2026-0001", vendor, product,
                new[] { installed }, new[] { process });
            Assert.False(match.Matched);
            Assert.False(match.DeployProcessRules);
        }

        [Fact]
        public void DistinctiveInstalledProductAndKnownProcessAliasStillMatch()
        {
            Assert.True(CveCoverageHeuristics.ClassifyKevForWorkstation("CVE-2026-0001", "Microsoft", "SharePoint Server",
                new[] { "Microsoft SharePoint Server 2019" }, Array.Empty<string>()).Matched);
            Assert.True(CveCoverageHeuristics.ClassifyKevForWorkstation("CVE-2026-0001", "Google", "Chrome",
                Array.Empty<string>(), new[] { "chrome.exe" }).Matched);
        }
    }
}
