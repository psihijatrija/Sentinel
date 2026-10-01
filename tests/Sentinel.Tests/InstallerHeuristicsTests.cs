using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Comprehensive tests for InstallerHeuristics static utility.
    /// Covers installer name detection, extractor patterns, and prefetch basenames.
    /// </summary>
    public class InstallerHeuristicsTests
    {
        #region LooksLikeInstallerName

        [Theory]
        [InlineData("ChromeSetup", null)]
        [InlineData("VSCodeUserSetup-x64-1.90.0", null)]
        [InlineData("Git-2.47.0-64-bit", null)]
        [InlineData("python-3.12.0-amd64", null)]
        [InlineData("node-v20.11.0-x64", null)]
        [InlineData("SentinelSetup-1.6.5", null)]
        [InlineData("dotnet-sdk-8.0.100-win-x64", null)]
        [InlineData("vcredist_x64", null)]
        [InlineData("WindowsDesktop-Runtime-8.0.0-win-x64", null)]
        [InlineData("BraveSetup", null)]
        [InlineData("FirefoxInstaller", null)]
        [InlineData("DockerDesktopInstaller", null)]
        [InlineData("unins000", null)]
        [InlineData("msiexec", null)]
        [InlineData("jdk-21_windows-x64", null)]
        public void LooksLikeInstallerName_True(string name, string? path)
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName(name, path));
        }

        [Theory]
        [InlineData("notepad", null)]
        [InlineData("malware", null)]
        [InlineData("svchost", null)]
        [InlineData("explorer", null)]
        [InlineData("evil", null)]
        [InlineData("payload", null)]
        [InlineData("", null)]
        public void LooksLikeInstallerName_False(string name, string? path)
        {
            Assert.False(InstallerHeuristics.LooksLikeInstallerName(name, path));
        }

        [Fact]
        public void LooksLikeInstallerName_UsesImagePath_WhenNameEmpty()
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName("", @"C:\Temp\ChromeSetup.exe"));
        }

        [Fact]
        public void LooksLikeInstallerName_Null_ReturnsFalse()
        {
            Assert.False(InstallerHeuristics.LooksLikeInstallerName(null, null));
        }

        [Theory]
        [InlineData("app-1.2.3-x64")]
        [InlineData("tool-5.0.0-amd64")]
        [InlineData("product-2.1.0-64-bit")]
        public void LooksLikeInstallerName_VersionWithArch_Matches(string name)
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName(name, null));
        }

        [Theory]
        [InlineData("app-1.2.3")]
        public void LooksLikeInstallerName_VersionWithoutArch_NoMatch(string name)
        {
            // Version pattern requires architecture indicator
            Assert.False(InstallerHeuristics.LooksLikeInstallerName(name, null));
        }

        #endregion

        #region IsInstallerExtractor

        [Theory]
        [InlineData("innosetup-7.0.2-x64.tmp", null)]
        [InlineData("is-ABC12.tmp", null)]
        [InlineData("issetup", null)]
        [InlineData("setup.tmp", null)]
        public void IsInstallerExtractor_True(string name, string? path)
        {
            Assert.True(InstallerHeuristics.IsInstallerExtractor(name, path));
        }

        [Theory]
        [InlineData(null, @"C:\Users\Admin\AppData\Local\Temp\is-ABCDE\setup.exe")]
        [InlineData(null, @"C:\Temp\nst12345\app.exe")]
        [InlineData(null, @"C:\Temp\nsm45678\helper.dll")]
        [InlineData(null, @"C:\Temp\7zS1234\extract.exe")]
        public void IsInstallerExtractor_ByPath_True(string? name, string path)
        {
            Assert.True(InstallerHeuristics.IsInstallerExtractor(name, path));
        }

        [Theory]
        [InlineData("chrome.exe", null)]
        [InlineData("notepad.exe", null)]
        [InlineData("svchost.exe", null)]
        public void IsInstallerExtractor_False(string name, string? path)
        {
            Assert.False(InstallerHeuristics.IsInstallerExtractor(name, path));
        }

        #endregion

        #region IsBenignEphemeralPrefetchName

        [Theory]
        [InlineData("GIT-2.47.0-64-BIT.EXE")]
        [InlineData("INNOSETUP-7.0.2-X64.TMP")]
        [InlineData("DOTNET-SDK-8.0.EXE")]
        [InlineData("CHROMESETUP.EXE")]
        [InlineData("VCREDIST_X64.EXE")]
        [InlineData("SENTINELSETUP-1.6.0.EXE")]
        [InlineData("FINALIZER.EXE")]
        [InlineData("GOOGLEUPDATE.EXE")]
        public void IsBenignEphemeralPrefetchName_True(string stem)
        {
            Assert.True(InstallerHeuristics.IsBenignEphemeralPrefetchName(stem));
        }

        [Theory]
        [InlineData("MALWARE.EXE")]
        [InlineData("PAYLOAD.EXE")]
        [InlineData("SVCHOST.EXE")]
        [InlineData("")]
        [InlineData(null)]
        public void IsBenignEphemeralPrefetchName_False(string? stem)
        {
            Assert.False(InstallerHeuristics.IsBenignEphemeralPrefetchName(stem));
        }

        #endregion

        #region IsLikelyInstallerPath (v1.8.1 RT-LOW-2)

        [Theory]
        [InlineData(@"C:\Users\Alice\Downloads\ChromeSetup.exe")]
        [InlineData(@"C:\Users\Alice\Desktop\Git-2.47.0-64-bit.exe")]
        [InlineData(@"C:\Program Files\Git\bin\git.exe")]
        [InlineData(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")]
        [InlineData(@"C:\Windows\Installer\foo.msi")]
        [InlineData(@"C:\Users\Alice\AppData\Local\Temp\is-ABCDE\innosetup-7.0.2-x64.tmp")]
        public void IsLikelyInstallerPath_True(string path)
        {
            Assert.True(InstallerHeuristics.IsLikelyInstallerPath(path));
        }

        [Theory]
        [InlineData(@"C:\Users\Alice\AppData\Roaming\ChromeSetup.exe")]
        [InlineData(@"C:\Users\Alice\AppData\Local\Temp\ChromeSetup.exe")]
        [InlineData(@"C:\Users\Alice\AppData\Local\Programs\evil\setup.exe")]
        [InlineData(null)]
        [InlineData("")]
        public void IsLikelyInstallerPath_False(string? path)
        {
            Assert.False(InstallerHeuristics.IsLikelyInstallerPath(path));
        }

        #endregion
    }
}
