using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.8.0 - TokenTheft OS false-positive suppressions + evidence pack gates.
    /// </summary>
    public class V180FeatureTests
    {
        [Theory]
        [InlineData("Memory Compression")]
        [InlineData("memory compression")]
        [InlineData("Registry")]
        [InlineData("Secure System")]
        [InlineData("System")]
        [InlineData("csrss")]
        [InlineData("lsass")]
        [InlineData("Memory Compression.exe")]
        public void TokenTheft_OsProcessNames_AreAllowlisted(string name)
        {
            Assert.True(TokenTheftMonitor.IsLikelyProtectedOsProcess(name) ||
                        TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Theory]
        [InlineData("evil.exe")]
        [InlineData("GodPotato")]
        [InlineData("mimikatz")]
        [InlineData("TotallyNormal")]
        public void TokenTheft_UserMalwareNames_NotAllowlisted(string name)
        {
            Assert.False(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
            Assert.False(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Fact]
        public void TokenTheft_EmptyPath_IsNotSuspicious()
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(""));
            Assert.False(TokenTheftMonitor.IsSuspiciousPath("   "));
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(null!));
        }

        [Theory]
        [InlineData(@"C:\Users\bob\AppData\Local\Temp\potato.exe")]
        [InlineData(@"C:\Users\bob\Downloads\tool.exe")]
        [InlineData(@"C:\Users\Public\evil.exe")]
        public void TokenTheft_UserWritablePaths_AreSuspicious(string path)
        {
            Assert.True(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\svchost.exe")]
        [InlineData(@"C:\Program Files\App\app.exe")]
        public void TokenTheft_SystemPaths_NotSuspicious(string path)
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Fact]
        public void AutoIncident_ShouldNotPack_MemoryCompression_TokenTheft()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                ProcessName = "Memory Compression",
                ProcessId = 2520,
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = "Process 'Memory Compression' (PID 2520) at '' holds a NT AUTHORITY\\SYSTEM token"
            };

            Assert.True(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_ShouldNotPack_Registry_SeImpersonate()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessName = "Registry",
                ProcessId = 340,
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = "Process 'Registry' (PID 340) at '' has SeImpersonatePrivilege"
            };

            Assert.True(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_ShouldStillPack_RealPotatoPath()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessName = "GodPotato",
                ProcessId = 9999,
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = @"Process 'GodPotato' (PID 9999) at 'C:\Users\bob\AppData\Local\Temp\gp.exe' has SeImpersonatePrivilege"
            };

            Assert.False(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Fact]
        public void AutoIncident_NonTokenTheftRules_NotBlockedByOsFpGate()
        {
            var det = new DetectionEvent
            {
                RuleName = "Ransomware: Mass Encryption",
                ProcessName = "Memory Compression", // weird but shouldn't use token-theft FP gate
                ProcessId = 1,
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                SignalType = SignalType.Ransomware
            };

            Assert.False(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        // --- v1.8.3: UUP dump / aria2c must not be treated as potato token theft ---

        [Theory]
        [InlineData("aria2c")]
        [InlineData("aria2c.exe")]
        [InlineData("7z")]
        [InlineData("wimlib-imagex")]
        public void InstallerHeuristics_PortableDownloadTools_Recognized(string name)
        {
            Assert.True(InstallerHeuristics.IsPortableDownloadOrArchiveTool(name));
        }

        [Theory]
        [InlineData(@"C:\Users\Admin\Downloads\28000.2608_amd64_en-us_professional_81988c5b_convert\files\aria2c.exe")]
        [InlineData(@"D:\work\uupdump\files\aria2c.exe")]
        [InlineData(@"C:\ISO\UUPs\payload.esd")]
        public void InstallerHeuristics_OfflineImageWorkPaths_Recognized(string path)
        {
            Assert.True(InstallerHeuristics.IsOfflineImageWorkPath(path));
        }

        [Fact]
        public void InstallerHeuristics_BenignPortableWork_Aria2cFromUupConvert()
        {
            var path = @"C:\Users\Admin\Downloads\28000.2608_amd64_en-us_professional_81988c5b_convert\files\aria2c.exe";
            Assert.True(InstallerHeuristics.IsBenignPortableWorkContext("aria2c", path));
            Assert.True(InstallerHeuristics.IsBenignPortableWorkContext(null, path));
        }

        [Fact]
        public void InstallerHeuristics_RandomMalwareInUupsFolder_NotBenignWithoutKnownToolName()
        {
            // Path matches offline-image layout but binary is not a known tool - no free pass
            var path = @"C:\Users\Admin\Downloads\evil_convert\files\malware.exe";
            Assert.False(InstallerHeuristics.IsBenignPortableWorkContext("malware", path));
            Assert.False(InstallerHeuristics.IsPortableDownloadOrArchiveTool("malware", path));
        }

        [Fact]
        public void AutoIncident_ShouldNotPack_Aria2c_TokenTheft_UupPath()
        {
            var det = new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessName = "aria2c",
                ProcessId = 70968,
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.CredentialTheft,
                Evidence = @"Process 'aria2c' (PID 70968) at 'C:\Users\Admin\Downloads\28000.2608_amd64_en-us_professional_81988c5b_convert\files\aria2c.exe' has SeImpersonatePrivilege enabled."
            };

            Assert.True(AutoIncidentReporter.IsTokenTheftOsFalsePositive(det));
        }

        [Theory]
        [InlineData(23)]    // Telnet
        [InlineData(4444)]  // Meterpreter
        [InlineData(31337)] // BackOrifice
        public void Hardening_AttackOnlyPorts_AreBlockedByDefault(int port)
        {
            Assert.True(HardeningModule.IsAttackOnlyBlockedPort(port));
        }

        [Theory]
        [InlineData(22)]   // SSH
        [InlineData(3389)] // RDP
        [InlineData(445)]  // SMB
        [InlineData(3306)] // MySQL
        [InlineData(1080)] // SOCKS
        public void Hardening_UserServicePorts_NotInAttackOnlySet(int port)
        {
            Assert.False(HardeningModule.IsAttackOnlyBlockedPort(port));
        }

        [Theory]
        [InlineData("Reverse Shell: Suspicious Outbound Connection")]
        [InlineData("Token Theft: SeImpersonatePrivilege from Suspicious Path")]
        [InlineData("Data Exfiltration: Cloud Sync Tool Running")]
        [InlineData("Attack Tool: Connection from Suspicious Path")]
        public void Response_WeakUserActivityHeuristics_AreObserveOnly(string rule)
        {
            Assert.True(AdvancedResponseEngine.IsObserveOnlyUserActivityHeuristic(rule));
        }

        [Theory]
        [InlineData("Composite: Covert RAT: Unsigned + Hidden + Network")]
        [InlineData("Token Theft: Non-Service Process with SYSTEM Token")]
        [InlineData("Ransomware: Mass Encryption")]
        public void Response_ConfirmedAttackRules_NotObserveOnly(string rule)
        {
            Assert.False(AdvancedResponseEngine.IsObserveOnlyUserActivityHeuristic(rule));
        }
    }
}
