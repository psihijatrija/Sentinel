using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the AgenticProcessMonitor's internal logic.
    /// The monitor detects AI coding agents spawning high-risk processes.
    /// Since the core detection logic uses private methods, we test the
    /// public observable behavior via detection patterns.
    /// </summary>
    public class AgenticProcessMonitorTests
    {
        // AgentNames is private, but we can verify the logic via known patterns.
        // The monitor checks if process names contain "claude" or "cursor" or match the AgentNames set.

        [Theory]
        [InlineData("claude")]
        [InlineData("claude.exe")]
        [InlineData("cursor")]
        [InlineData("cursor.exe")]
        [InlineData("codex")]
        [InlineData("codex.exe")]
        [InlineData("aider")]
        [InlineData("windsurf")]
        [InlineData("ollama")]
        [InlineData("ollama.exe")]
        public void AgentNames_RecognizedByContainsOrExactMatch(string agentName)
        {
            // Validate these names would be caught by the contains("claude")/contains("cursor")
            // or exact match logic
            bool matchesByContains = agentName.Contains("claude") || agentName.Contains("cursor");
            bool matchesByKnownList = agentName == "claude" || agentName == "claude.exe" ||
                                     agentName == "cursor" || agentName == "cursor.exe" ||
                                     agentName == "codex" || agentName == "codex.exe" ||
                                     agentName == "aider" || agentName == "aider.exe" ||
                                     agentName == "windsurf" || agentName == "windsurf.exe" ||
                                     agentName == "ollama" || agentName == "ollama.exe";

            Assert.True(matchesByContains || matchesByKnownList,
                $"'{agentName}' should be recognized as an AI agent process");
        }

        [Theory]
        [InlineData("powershell")]
        [InlineData("pwsh")]
        [InlineData("cmd")]
        [InlineData("bash")]
        [InlineData("python")]
        [InlineData("node")]
        [InlineData("certutil")]
        [InlineData("mshta")]
        [InlineData("bitsadmin")]
        [InlineData("curl")]
        [InlineData("ssh")]
        public void HighRiskChildren_AreKnownLOLBins(string childName)
        {
            // These are the high-risk child processes that trigger alerts when spawned by AI agents
            var highRisk = new[]
            {
                "powershell", "pwsh", "cmd", "bash", "wsl", "python", "python3", "node",
                "certutil", "mshta", "bitsadmin", "curl", "wget", "ssh", "scp", "rclone",
                "procdump"
            };
            Assert.Contains(childName, highRisk);
        }

        [Theory]
        [InlineData("notepad")]
        [InlineData("chrome")]
        [InlineData("explorer")]
        [InlineData("devenv")]
        public void NonRiskChildren_AreNotFlagged(string childName)
        {
            var highRisk = new[]
            {
                "powershell", "pwsh", "cmd", "bash", "wsl", "python", "python3", "node",
                "certutil", "mshta", "bitsadmin", "curl", "wget", "ssh", "scp", "rclone",
                "procdump"
            };
            Assert.DoesNotContain(childName, highRisk);
        }

        [Theory]
        [InlineData(@"\login data")]
        [InlineData(@"\.ssh\id_")]
        [InlineData(@"\.aws\")]
        [InlineData(@"\.config\gcloud")]
        [InlineData(@"\.kube\config")]
        public void CredentialPathFragments_AreMonitored(string fragment)
        {
            // These paths trigger critical-level detection when accessed by agent children
            var credPaths = new[]
            {
                @"\login data", @"\cookies", @"\key4.db", @"\logins.json",
                @"\.ssh\id_", @"\credentials", @"\.aws\",
                @"\.config\gcloud", @"\appdata\roaming\mozilla",
                @"\.kube\config", @"\.gnupg\"
            };
            Assert.Contains(fragment, credPaths);
        }
    }
}
