using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    /// <summary>
    /// Tests for TokenTheftMonitor - verifies path classification, legitimate system
    /// token holder detection, impersonator allowlisting, and OS process identification.
    /// </summary>
    public class TokenTheftMonitorTests
    {
        // 
        // IsSuspiciousPath - staging/drop locations
        // 

        [Theory]
        [InlineData(@"C:\Users\victim\AppData\Local\Temp\payload.exe")]
        [InlineData(@"C:\Windows\Temp\dropper.exe")]
        [InlineData(@"C:\Users\victim\Downloads\exploit.exe")]
        [InlineData(@"C:\Users\Public\malware.exe")]
        [InlineData(@"C:\ProgramData\Temp\stager.exe")]
        [InlineData(@"C:\Users\victim\Desktop\evil.exe")]
        public void IsSuspiciousPath_ReturnsTrue_ForDropLocations(string path)
        {
            Assert.True(TokenTheftMonitor.IsSuspiciousPath(path));
        }

        [Theory]
        [InlineData(@"C:\Program Files\App\legitimate.exe")]
        [InlineData(@"C:\Program Files (x86)\Tool\tool.exe")]
        [InlineData(@"C:\Windows\System32\svchost.exe")]
        [InlineData("")]
        [InlineData(null)]
        public void IsSuspiciousPath_ReturnsFalse_ForLegitPaths(string? path)
        {
            Assert.False(TokenTheftMonitor.IsSuspiciousPath(path!));
        }

        // 
        // IsLegitimateSystemTokenHolder - known SYSTEM services
        // 

        [Theory]
        [InlineData("svchost")]
        [InlineData("svchost.exe")]
        [InlineData("lsass")]
        [InlineData("services")]
        [InlineData("csrss")]
        [InlineData("wininit")]
        [InlineData("smss")]
        [InlineData("MsMpEng")]
        public void IsLegitimateSystemTokenHolder_ReturnsTrue_ForSystemServices(string name)
        {
            Assert.True(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name));
        }

        [Theory]
        [InlineData("malware.exe")]
        [InlineData("beacon.exe")]
        [InlineData("unknown")]
        [InlineData("")]
        [InlineData(null)]
        public void IsLegitimateSystemTokenHolder_ReturnsFalse_ForUnknown(string? name)
        {
            Assert.False(TokenTheftMonitor.IsLegitimateSystemTokenHolder(name!));
        }

        // 
        // IsLegitimateImpersonator - services that legitimately impersonate
        // 

        [Theory]
        [InlineData("sqlservr")]
        [InlineData("w3wp")]
        [InlineData("iisexpress")]
        public void IsLegitimateImpersonator_ReturnsTrue_ForKnownServices(string name)
        {
            Assert.True(TokenTheftMonitor.IsLegitimateImpersonator(name));
        }

        [Theory]
        [InlineData("evil.exe")]
        [InlineData("mimikatz")]
        [InlineData("")]
        public void IsLegitimateImpersonator_ReturnsFalse_ForUnknown(string name)
        {
            Assert.False(TokenTheftMonitor.IsLegitimateImpersonator(name));
        }

        // 
        // IsLikelyProtectedOsProcess
        // 

        [Theory]
        [InlineData("svchost")]
        [InlineData("Registry")]
        [InlineData("Memory Compression")]
        [InlineData("Secure System")]
        public void IsLikelyProtectedOsProcess_ReturnsTrue_ForOsProcesses(string name)
        {
            Assert.True(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("notepad")]
        [InlineData("malware.exe")]
        public void IsLikelyProtectedOsProcess_ReturnsFalse_ForUserProcesses(string name)
        {
            Assert.False(TokenTheftMonitor.IsLikelyProtectedOsProcess(name));
        }

        // 
        // Token theft signal model
        // 

        [Fact]
        public void TokenTheftSignal_SystemToken_Model()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 1234,
                ProcessName = "evil.exe",
                TokenUserName = "NT AUTHORITY\\SYSTEM",
                TheftType = TokenTheftType.SystemTokenFromUserProcess,
                ImagePath = @"C:\Temp\evil.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(TokenTheftType.SystemTokenFromUserProcess, signal.TheftType);
            Assert.True(signal.HasImpersonatePrivilege);
        }

        [Fact]
        public void TokenTheft_IsPresidentsLaw()
        {
            // Privilege escalation = President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("SeImpersonatePrivilege from Suspicious Path"));
        }
    }
}
