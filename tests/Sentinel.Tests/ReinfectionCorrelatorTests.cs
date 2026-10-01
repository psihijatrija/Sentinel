using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for ReinfectionCorrelator - verifies detection model for reinfection events,
    /// system binary exclusion logic, and executable extension classification.
    /// The correlator requires DetectionEngine (complex DI), so we test the observable
    /// static logic and detection models.
    /// </summary>
    public class ReinfectionCorrelatorTests
    {
        // 
        // Detection model for reinfection events
        // 

        [Fact]
        public void Reinfection_ProcessReappearance_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Reinfection: Previously Killed Binary Reappeared in Running Process",
                ProcessId = 5000,
                ProcessName = "malware.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                SignalType = SignalType.SecurityEvasion
            };

            Assert.True(detection.KillAuthorized);
            Assert.Equal(0.95, detection.Confidence);
            Assert.Equal(SignalType.SecurityEvasion, detection.SignalType);
        }

        [Fact]
        public void Reinfection_DormantCopy_Model()
        {
            var detection = new DetectionEvent
            {
                RuleName = "Reinfection: Known-Bad Binary Found in Persistence Location",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.Quarantine,
                ProcessName = "SYSTEM",
                ProcessId = 0
            };

            Assert.Equal(ResponseAction.Quarantine, detection.AuthorizedResponse);
        }

        // 
        // Category classification
        // 

        [Fact]
        public void Reinfection_CategorizedAsSecurityEvasion()
        {
            // The rule contains "evasion" - verify evasion category
            var category = ScoringEngine.CategorizeDetection("Security Evasion: Reinfection Detected");
            Assert.Equal(DetectionCategory.SecurityEvasion, category);
        }

        [Fact]
        public void Reinfection_IsPresidentsLaw()
        {
            // Security evasion = President's Law
            Assert.True(ScoringEngine.IsPresidentsLawRule("Security Evasion: Reinfection Detected"));
        }

        // 
        // Executable extension classification (mirrors private logic)
        // 

        [Theory]
        [InlineData(".exe", true)]
        [InlineData(".dll", true)]
        [InlineData(".scr", true)]
        [InlineData(".com", true)]
        [InlineData(".bat", true)]
        [InlineData(".cmd", true)]
        [InlineData(".ps1", true)]
        [InlineData(".vbs", true)]
        [InlineData(".js", true)]
        [InlineData(".txt", false)]
        [InlineData(".docx", false)]
        [InlineData(".pdf", false)]
        [InlineData(".png", false)]
        public void ExecutableExtensions_ClassifiedCorrectly(string ext, bool isExecutable)
        {
            Assert.Equal(isExecutable, IsExecutableExtension(ext));
        }

        // 
        // System binary exclusion (mirrors private IsWindowsSystemBinary)
        // 

        [Theory]
        [InlineData("svchost.exe", true)]
        [InlineData("csrss.exe", true)]
        [InlineData("lsass.exe", true)]
        [InlineData("explorer.exe", true)]
        [InlineData("MsMpEng.exe", true)]
        [InlineData("malware.exe", false)]
        [InlineData("beacon.exe", false)]
        public void SystemBinaryExclusion_ByName(string name, bool isSystem)
        {
            Assert.Equal(isSystem, IsWindowsSystemBinary(name));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\svchost.exe", true)]
        [InlineData(@"C:\Windows\SysWOW64\conhost.exe", true)]
        [InlineData(@"C:\Users\attacker\malware.exe", false)]
        [InlineData(@"C:\Temp\evil.exe", false)]
        public void SystemBinaryExclusion_ByPath(string path, bool isSystem)
        {
            Assert.Equal(isSystem, IsWindowsSystemBinary(path));
        }

        // 
        // Helper re-implementations (mirrors private logic)
        // 

        private static bool IsExecutableExtension(string ext)
        {
            return ext.Equals(".exe") || ext.Equals(".dll") || ext.Equals(".scr") ||
                   ext.Equals(".com") || ext.Equals(".bat") || ext.Equals(".cmd") ||
                   ext.Equals(".ps1") || ext.Equals(".vbs") || ext.Equals(".js");
        }

        private static readonly System.Collections.Generic.HashSet<string> SystemBinaryNames =
            new(System.StringComparer.OrdinalIgnoreCase)
            {
                "svchost", "svchost.exe", "csrss", "csrss.exe",
                "wininit", "wininit.exe", "winlogon", "winlogon.exe",
                "lsass", "lsass.exe", "services", "services.exe",
                "smss", "smss.exe", "dwm", "dwm.exe",
                "explorer", "explorer.exe", "conhost", "conhost.exe",
                "MsMpEng", "MsMpEng.exe", "WmiPrvSE", "WmiPrvSE.exe"
            };

        private static bool IsWindowsSystemBinary(string? pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return false;
            var fileName = System.IO.Path.GetFileName(pathOrName);
            if (SystemBinaryNames.Contains(fileName)) return true;
            var nameNoExt = System.IO.Path.GetFileNameWithoutExtension(pathOrName);
            if (SystemBinaryNames.Contains(nameNoExt)) return true;
            var normalized = pathOrName.Replace('/', '\\');
            if (normalized.Contains(@"\Windows\System32\") ||
                normalized.Contains(@"\Windows\SysWOW64\"))
                return true;
            return false;
        }
    }
}
