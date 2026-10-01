using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.5.3: skip the real civilian, never the costume.
    /// discord.exe in Temp is not Discord. C:\Users\attacker\epic games\ is not Epic.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class CivilianIdentityTests
    {
        [Fact]
        public void RealDiscordPath_IsCommsIdentity()
        {
            Assert.True(UserlandProtocolHeuristics.IsKnownCommsIdentity(
                "discord", @"C:\Users\x\AppData\Local\Discord\app.exe"));
        }

        [Fact]
        public void DiscordInTemp_IsNotCommsIdentity()
        {
            Assert.False(UserlandProtocolHeuristics.IsKnownCommsIdentity(
                "discord", @"C:\Users\x\AppData\Local\Temp\discord.exe"));
            Assert.False(UserlandProtocolHeuristics.ShouldSkipWorkSurface(
                "discord", @"C:\Users\x\Downloads\discord.exe"));
        }

        [Fact]
        public void DiscordNameAlone_DoesNotSkip()
        {
            Assert.True(UserlandProtocolHeuristics.IsKnownCommsProcess("discord"));
            Assert.False(UserlandProtocolHeuristics.IsKnownCommsIdentity("discord", null));
            Assert.False(UserlandProtocolHeuristics.ShouldSkipWorkSurface("discord", null));
        }

        [Fact]
        public void ImpostorDiscord_Temp_IsCovertMesh()
        {
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "discord",
                @"C:\Users\x\Downloads\discord.exe",
                nonAmbientUdpBinds: 8, hasStunPort: true, hasHttps: true, meshDnsRecently: true);
            Assert.NotEqual(UserlandProtocolHeuristics.CovertMeshKind.None, k);
        }

        [Fact]
        public void ImpostorDiscord_Temp_IsWebhook()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "discord", @"C:\Users\x\Temp\discord.exe",
                hasHttps: true, dedicatedDnsRecently: false, commsDnsRecently: false, urlInContent: true);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.UrlInContent, k);
        }

        [Fact]
        public void RealChrome_StillSkippedForWebhook()
        {
            var k = UserlandProtocolHeuristics.ClassifyWebhook(
                "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                hasHttps: true, dedicatedDnsRecently: true, commsDnsRecently: true, urlInContent: true);
            Assert.Equal(UserlandProtocolHeuristics.WebhookKind.None, k);
        }

        [Fact]
        public void TailscaleInProgramFiles_IsVpnIdentity()
        {
            Assert.True(UserlandProtocolHeuristics.IsVpnOrIkeIdentity(
                "tailscale", @"C:\Program Files\Tailscale\tailscale.exe"));
        }

        [Fact]
        public void TailscaleInTemp_IsNotVpnIdentity()
        {
            Assert.False(UserlandProtocolHeuristics.IsVpnOrIkeIdentity(
                "tailscale", @"C:\Temp\tailscale.exe"));
        }

        [Fact]
        public void SvchostInTemp_IsNotSystem()
        {
            Assert.False(SecurityValidation.IsWindowsSystemImage(@"C:\Temp\svchost.exe"));
            Assert.False(UserlandProtocolHeuristics.IsVpnOrIkeIdentity(
                "svchost", @"C:\Temp\svchost.exe"));
            var k = UserlandProtocolHeuristics.ClassifyCovertMesh(
                "svchost", @"C:\Temp\svchost.exe",
                nonAmbientUdpBinds: 4, hasStunPort: false, hasHttps: true, meshDnsRecently: true);
            Assert.NotEqual(UserlandProtocolHeuristics.CovertMeshKind.None, k);
        }

        [Fact]
        public void AttackerEpicGamesFolder_IsNotGamePath()
        {
            Assert.False(SecurityValidation.IsGameOrAntiCheatPath(
                @"C:\Users\attacker\epic games\malware.exe"));
        }

        [Fact]
        public void SteamLibrary_IsStillGamePath()
        {
            Assert.True(SecurityValidation.IsGameOrAntiCheatPath(
                @"D:\SteamLibrary\steamapps\common\Game\game.exe"));
        }

        [Fact]
        public void SteamExeInTemp_IsNotGameProtected()
        {
            var d = new DetectionEvent
            {
                RuleName = "Network Indicator: Classic Malware Port",
                ProcessName = "steam",
                ProcessId = 4242,
                Confidence = 0.90,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Tier = DetectionTier.Tier1Behavioral,
            };
            Assert.False(AlwaysOnPolicies.ApplyGameProtection(d, @"C:\Temp\steam.exe"));
            Assert.Equal(ResponseAction.KillProcessTree, d.AuthorizedResponse);
        }

        [Fact]
        public void FakeOverlay_IsNotCivilian()
        {
            Assert.False(ClickjackingGuard.IsVerifiedOverlayCivilian(
                "FakeOverlay", @"C:\Temp\FakeOverlay.exe"));
            Assert.False(ClickjackingGuard.IsVerifiedOverlayCivilian(
                "Discord", @"C:\Temp\discord.exe"));
            Assert.True(ClickjackingGuard.IsVerifiedOverlayCivilian(
                "Discord", @"C:\Users\x\AppData\Local\Discord\app.exe"));
        }

        [Fact]
        public void NameContainingOverlay_IsNotAFreePass()
        {
            Assert.False(ClickjackingGuard.IsVerifiedOverlayCivilian(
                "NotAnOverlay", @"C:\Temp\payload.exe"));
        }
    }
}
