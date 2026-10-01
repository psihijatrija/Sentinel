using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Production FPs from 2026-07-25/26 ProgramData logs:
    /// - PPID kill on innosetup -> quarantine Git
    /// - Raw Disk kill on explorer / taskhostw
    /// - Ephemeral "self-delete" on GIT / INNOSETUP / DOTNET installers
    /// </summary>
    public class InstallerFalsePositiveTests
    {
        [Theory]
        [InlineData("Git-2.47.0-64-bit", true)]
        [InlineData("Git-2.47.0-64-bit.exe", true)]
        [InlineData("Git-64-bit", true)]
        [InlineData("ChromeSetup", true)]
        [InlineData("VSCodeUserSetup-x64-1.85.0", true)]
        [InlineData("node-v22.11.0-x64", true)]
        [InlineData("python-3.12.0-amd64", true)]
        [InlineData("windowsdesktop-runtime-8.0.11-win-x64", true)]
        [InlineData("vcredist_x64", true)]
        [InlineData("dxsetup", true)]
        [InlineData("DXSETUP.exe", true)]
        [InlineData("setup", true)]
        [InlineData("SentinelSetup-1.6.1", true)]
        [InlineData("evil-payload", false)]
        [InlineData("ransomware", false)]
        public void LooksLikeInstallerName_RecognizesOfficialPatterns(string name, bool expected)
        {
            Assert.Equal(expected, InstallerHeuristics.LooksLikeInstallerName(name));
        }

        [Theory]
        [InlineData("dxsetup", null, true)]
        [InlineData("DXSETUP", @"C:\Steam\steamapps\common\Game\_CommonRedist\DirectX\DXSETUP.exe", true)]
        [InlineData("vcredist_x64", null, true)]
        [InlineData("evil", @"C:\Temp\evil.exe", false)]
        [InlineData("unknown", @"C:\WINDOWS\System32\d3dx9_43.dll", true)]
        public void IsDirectXOrRuntimeRedist_RecognizesSteamAndRedist(string name, string? path, bool expected)
        {
            Assert.Equal(expected, InstallerHeuristics.IsDirectXOrRuntimeRedist(name, path));
        }

        [Fact]
        public void LooksLikeInstallerName_UsesImagePathFilename()
        {
            Assert.True(InstallerHeuristics.LooksLikeInstallerName(
                "unknown",
                @"C:\Users\Alice\Downloads\Git-2.47.0-64-bit.exe"));
        }

        [Theory]
        [InlineData("innosetup-7.0.2-x64.tmp", null, true)]
        [InlineData("innosetup-7.0.2-x64", @"C:\Users\Alice\AppData\Local\Temp\is-ABCDE\innosetup-7.0.2-x64.tmp", true)]
        [InlineData("is-ABC12", null, true)]
        [InlineData("iside", null, true)]
        [InlineData("malware", @"C:\Temp\evil.exe", false)]
        public void IsInstallerExtractor_RecognizesInnoSetup(string name, string? path, bool expected)
        {
            Assert.Equal(expected, InstallerHeuristics.IsInstallerExtractor(name, path));
        }

        [Theory]
        [InlineData("GIT-2.55.0.3-64-BIT.TMP-DB7614B1.pf", true)]
        [InlineData("INNOSETUP-7.0.2-X64.EXE-3A0B0377.pf", true)]
        [InlineData("DOTNET-SDK-10.0.302-WIN-X64.E-6144FD27.pf", true)]
        [InlineData("FINALIZER.EXE-0D302E77.pf", true)]
        [InlineData("ISIDE.EXE-CFE5E665.pf", true)]
        [InlineData("MALWARE.EXE-AABBCCDD.pf", false)]
        public void IsBenignEphemeralPrefetchName_SuppressesInstallerNoise(string prefetch, bool expected)
        {
            Assert.Equal(expected, InstallerHeuristics.IsBenignEphemeralPrefetchName(prefetch));
        }

        [Theory]
        [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome", true)]
        [InlineData(@"C:\Users\Alice\AppData\Local\Temp\chrome.exe", "chrome", false)]
        public void IsLegitimateBrowserHost_PathRules(string path, string name, bool expected)
        {
            Assert.Equal(expected, ChainTracer.IsLegitimateBrowserHost(path, name));
        }

        /// <summary>
        /// Production FP 2026-08-01: WinReducerEX110 -> System32\conhost PPID race -> chain kill.
        /// Stock console hosts and OS paths must demote to LogOnly (no KillProcess).
        /// </summary>
        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe", true)]
        [InlineData("conhost.exe", @"C:\Windows\SysWOW64\conhost.exe", true)]
        [InlineData("conhost", null, true)]
        [InlineData("conhost", "", true)]
        [InlineData("conhost", @"C:\Users\Alice\AppData\Local\Temp\conhost.exe", false)]
        [InlineData("WinReducerEX110_x64", @"D:\WinReducerEX110\WinReducerEX110_x64.exe", false)]
        [InlineData("openconsole", @"C:\Windows\System32\OpenConsole.exe", true)]
        public void IsStockWindowsConsoleHost_WinReducerConhostFp(string name, string? path, bool expected)
        {
            Assert.Equal(expected, ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe", false, true)]
        [InlineData("conhost", null, false, true)]
        [InlineData("evil", @"C:\Temp\evil.exe", false, false)]
        [InlineData("evil", @"C:\Temp\evil.exe", true, true)] // signed -> demote
        [InlineData("payload", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", false, true)] // OS path
        public void ShouldDemotePpidToLogOnly_WinReducerCase(string name, string? path, bool selfSigned, bool expected)
        {
            Assert.Equal(expected, ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(name, path, selfSigned));
        }
    }
}
