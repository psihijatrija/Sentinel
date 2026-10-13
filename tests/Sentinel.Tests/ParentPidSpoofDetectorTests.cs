using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ParentPidSpoofDetectorTests
    {
        //  ShouldDemotePpidToLogOnly 

        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe", false)]
        [InlineData("conhost.exe", @"C:\Windows\System32\conhost.exe", false)]
        public void ShouldDemotePpidToLogOnly_ReturnsTrue_ForConhost(string name, string path, bool selfSigned)
        {
            Assert.True(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(name, path, selfSigned));
        }

        [Theory]
        [InlineData("evil.exe", @"C:\Temp\evil.exe", false)]
        public void ShouldDemotePpidToLogOnly_ReturnsFalse_ForUnknown(string name, string path, bool selfSigned)
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(name, path, selfSigned));
        }

        //  IsStockWindowsConsoleHost 

        [Theory]
        [InlineData("conhost", @"C:\Windows\System32\conhost.exe")]
        [InlineData("conhost.exe", @"C:\WINDOWS\system32\conhost.exe")]
        public void IsStockWindowsConsoleHost_ReturnsTrue_ForLegitConhost(string name, string path)
        {
            Assert.True(ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Theory]
        [InlineData("conhost", @"C:\Temp\conhost.exe")]
        [InlineData("cmd", @"C:\Windows\System32\cmd.exe")]
        [InlineData("conhost.exe", @"C:\Users\Desktop\conhost.exe")]
        public void IsStockWindowsConsoleHost_ReturnsFalse_ForFakeOrOther(string name, string? path)
        {
            Assert.False(ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Fact]
        public void ShouldDemotePpidToLogOnly_NullPath_ReturnsFalse()
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly("evil.exe", null, false));
        }

        //  Transient-race fix (2.9.9): allowlisted dev tool with unresolved image path 

        // An allowlisted dev tool (gh / git-remote-https) whose image path could not be resolved
        // in the scan race window must be demoted to LogOnly, never KillProcess.
        [Theory]
        [InlineData("gh", null)]
        [InlineData("gh", "")]
        [InlineData("git-remote-https", null)]
        [InlineData("chrome", null)]
        public void ShouldDemotePpidToLogOnly_ReturnsTrue_ForAllowlistedNameWithUnresolvedPath(string name, string? path)
        {
            Assert.True(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(
                name, path, selfSigned: false, allowlistedDevTool: true));
        }

        // A non-allowlisted, unsigned process with the same mismatch is NOT demoted - it still
        // yields KillProcess / Tier1. The transient-race flag only applies to allowlisted names.
        [Theory]
        [InlineData("evil", null)]
        [InlineData("evil.exe", "")]
        public void ShouldDemotePpidToLogOnly_ReturnsFalse_ForNonAllowlistedUnresolvedPath(string name, string? path)
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(
                name, path, selfSigned: false, allowlistedDevTool: false));
        }

        // The allowlisted-dev-tool name demotes the kill ONLY while the image path is
        // unresolved (the transient race window). Once a path DID resolve to an untrusted,
        // unsigned location like C:\Temp\gh.exe, the name alone is NOT enough: the method falls
        // through to the selfSigned / stock-console-host / OS-critical-path checks and the kill
        // stands. A filename never self-authorizes trust on a kill path.
        [Fact]
        public void ShouldDemotePpidToLogOnly_AllowlistedDevTool_ResolvedUntrustedPath_DoesNotDemote()
        {
            Assert.False(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(
                "gh", @"C:\Temp\gh.exe", selfSigned: false, allowlistedDevTool: true));
        }

        // A validly-signed real tool whose path resolved is still demoted - via the selfSigned
        // branch, not via its name. This proves the tightening does not break the legitimate
        // signed tool whose top-of-scan signed-skip raced.
        [Fact]
        public void ShouldDemotePpidToLogOnly_AllowlistedDevTool_ResolvedSignedPath_Demotes()
        {
            Assert.True(ParentPidSpoofDetector.ShouldDemotePpidToLogOnly(
                "gh", @"C:\Program Files\GitHub CLI\gh.exe", selfSigned: true, allowlistedDevTool: true));
        }

        [Fact]
        public void IsStockWindowsConsoleHost_EmptyName_ReturnsFalse()
        {
            Assert.False(ParentPidSpoofDetector.IsStockWindowsConsoleHost("", @"C:\Windows\System32\conhost.exe"));
        }
    }
}
