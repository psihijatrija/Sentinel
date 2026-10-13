using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Microsoft.Extensions.Hosting;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.2.0 red-team remediations: dashboard auth, game-path reputation skip,
    /// ChainTracer system-path, President's Law scope.
    /// </summary>
    public class V220SecurityHardeningTests
    {
        [Fact]
        public void ProductInfo_Version_Is220()
        {
            // v2.6.0: version is computed from version.txt / stamped assembly version.
            var asmVersion = typeof(ProductInfo).Assembly.GetName().Version?.ToString(3);
            Assert.Equal(asmVersion, ProductInfo.Version);
        }

        [Fact]
        public void DashboardAuth_RejectsRefererAsProofOfOrigin()
        {
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess("http://localhost:19845/"));
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess("http://localhost:19845.evil.test/"));
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess(null));
        }

        [Fact]
        public void DashboardAuth_RequiresMatchingBearer()
        {
            const string secret = "test-bearer-token-value-ok";
            Assert.False(LoopbackDashboardAuth.Authenticate(null, null, secret));
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer wrong", null, secret));
            Assert.True(LoopbackDashboardAuth.Authenticate("Bearer " + secret, null, secret));
            Assert.True(LoopbackDashboardAuth.Authenticate(null, secret, secret));
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer " + secret, null, "other"));
        }

        [Fact]
        public void DashboardAuth_IgnoresEmptyExpected()
        {
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer x", null, ""));
        }

        [Fact]
        public void GameReputationSkip_RejectsUserProfileSubstring()
        {
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\AppData\Roaming\steamapps\common\payload.exe"));
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\AppData\Roaming\ubisoft\cheat.exe"));
            Assert.False(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Users\Player\Desktop\vanguard\evil.exe"));
        }

        [Fact]
        public void GameReputationSkip_AllowsProgramFilesAndXbox()
        {
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Program Files (x86)\Steam\steamapps\common\Game\game.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\XboxGames\SomeGame\Content\game.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"C:\Program Files\WindowsApps\Microsoft.GamingApp_1.0\XboxPcApp.exe"));
            Assert.True(SecurityValidation.ShouldSkipReputationForGamePath(
                @"D:\SteamLibrary\steamapps\common\Game\game.exe"));
        }

        [Fact]
        public void ChainTracer_DoesNotTreatWindowsTempAsSystem()
        {
            var winTemp = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", "dropper.exe");
            Assert.False(ChainTracer.IsSystemBinary(winTemp, "dropper"));

            var sys32 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "svchost.exe");
            Assert.True(ChainTracer.IsSystemBinary(sys32, "svchost"));
        }

        [Fact]
        public void PresidentsLaw_DoesNotIncludeDnsOrNetworkAnomaly()
        {
            Assert.False(ScoringEngine.IsPresidentsLawRule("DNS Tunnel: Unusual Query Volume"));
            Assert.False(ScoringEngine.IsPresidentsLawRule("ARP Spoof Detected"));
            Assert.True(ScoringEngine.IsPresidentsLawRule("LSASS Memory Access"));
        }

        [Fact]
        public void EncryptedConfigStore_RoundTripWithHmacEnvelope()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-v220-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var path = Path.Combine(dir, "config.enc");
                var store = new EncryptedConfigStore(customPath: path);
                store.SetOverride("RestrictivePortHardening", "true");
                Assert.True(store.Save());

                var bytes = File.ReadAllBytes(path);
                Assert.True(bytes.Length > 5);
                Assert.Equal((byte)'S', bytes[0]);
                Assert.Equal((byte)'C', bytes[1]);
                Assert.Equal((byte)'F', bytes[2]);
                Assert.Equal((byte)'G', bytes[3]);
                Assert.Equal((byte)'2', bytes[4]);

                var reloaded = new EncryptedConfigStore(customPath: path);
                Assert.Equal("true", reloaded.GetOverride("RestrictivePortHardening"));
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        [Fact]
        public void HoneypotDlls_LiveInDedicatedSubdirectory()
        {
            Assert.Equal("honeypot", HoneypotDllMonitor.HoneypotSubdir);
            Assert.False(string.Equals(HoneypotDllMonitor.HoneypotSubdir, ".", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain("..", HoneypotDllMonitor.HoneypotSubdir);
        }

        [Fact]
        public void V217Monitors_AreBackgroundServices()
        {
            Assert.True(typeof(BackgroundService).IsAssignableFrom(typeof(HoneypotDllMonitor)));
            Assert.True(typeof(BackgroundService).IsAssignableFrom(typeof(EdrKillerDetectionMonitor)));
            Assert.True(typeof(BackgroundService).IsAssignableFrom(typeof(DecoyPipeMonitor)));
            Assert.True(typeof(BackgroundService).IsAssignableFrom(typeof(KernelModuleAuditMonitor)));
            Assert.True(typeof(BackgroundService).IsAssignableFrom(typeof(TokenPrivilegeAuditMonitor)));
        }

        [Fact]
        public void GSecurityInf_DoesNotWeakenPasswordsOrAuditOrFips()
        {
            // v2.3.6+: GSecurity.inf ships as a plain file under HardeningResources
            // (not an embedded resource - that dropper pattern tripped AV heuristics).
            var bases = new[]
            {
                AppContext.BaseDirectory,
                AppDomain.CurrentDomain.BaseDirectory,
                Path.GetDirectoryName(typeof(HardeningModule).Assembly.Location),
                Path.GetDirectoryName(typeof(V220SecurityHardeningTests).Assembly.Location),
            }.Where(d => !string.IsNullOrWhiteSpace(d)).Distinct(StringComparer.OrdinalIgnoreCase);

            var candidates = new List<string>();
            foreach (var root in bases)
            {
                candidates.Add(Path.Combine(root!, "HardeningResources", "GSecurity.inf"));
                candidates.Add(Path.Combine(root!, "GSecurity.inf"));
            }
            // Source-tree fallback when running from bin/ without Content copy
            candidates.Add(Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "..", "src", "Sentinel.Core", "HardeningResources", "GSecurity.inf")));

            string? path = candidates.FirstOrDefault(File.Exists);
            Assert.False(string.IsNullOrEmpty(path),
                "GSecurity.inf missing - tried: " + string.Join(" | ", candidates));

            var bytes = File.ReadAllBytes(path!);
            var inf = bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE
                ? Encoding.Unicode.GetString(bytes)
                : Encoding.UTF8.GetString(bytes);

            Assert.False(string.IsNullOrWhiteSpace(inf), "GSecurity.inf is empty");
            Assert.DoesNotContain("MinimumPasswordLength = 0", inf);
            Assert.Contains("MinimumPasswordLength = 12", inf);
            Assert.DoesNotContain("PasswordComplexity = 0", inf);
            Assert.Contains("AuditLogonEvents = 3", inf);
            Assert.DoesNotContain(@"FIPSAlgorithmPolicy\Enabled=4,0", inf);
        }

        [Fact]
        public void DriverHashBlocklist_HasNoCorruptTriedEntries()
        {
            var field = typeof(DriverLoadMonitor).GetField(
                "VulnerableDriverHashes", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(field);
            var hashes = field!.GetValue(null) as HashSet<string>;
            Assert.NotNull(hashes);
            Assert.DoesNotContain(hashes!, h =>
                h.IndexOf("tried", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        [Fact]
        public void UserProfilePath_IsNeverAReputationSkip()
        {
            Assert.True(SecurityValidation.IsUserProfileOrStagingPath(
                @"C:\Users\Player\AppData\Roaming\steamapps\common\x.exe"));
            Assert.False(SecurityValidation.IsUserProfileOrStagingPath(
                @"C:\Program Files (x86)\Steam\steamapps\common\Game\game.exe"));
        }
    }
}
