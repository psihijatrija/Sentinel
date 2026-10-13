using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Pure-function tests for ComHijackEvaluator (T1546.015 COM-hijack classifier). No registry
    /// or network access - deterministic and CI-safe. Verifies the verdict paths that the new
    /// ComHijackMonitor relies on, and the ShouldQuarantinePayload gate used by DllUnloadEngine.
    /// </summary>
    public class ComHijackEvaluatorTests
    {
        private static ComHijackEvaluator.Registration Inproc(
            string clsid, string hive, string server,
            string? baseline = null, bool shadow = false, string? hklm = null) =>
            new ComHijackEvaluator.Registration(
                clsid, hive, ComHijackEvaluator.ServerKind.InprocServer32, server,
                baseline, shadow, hklm);

        [Fact]
        public void UserWritableDrop_IsHijack_AndQuarantines()
        {
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{11111111-1111-1111-1111-111111111111}", "HKCU",
                @"C:\Users\bob\AppData\Local\Temp\evil.dll"));

            Assert.True(v.IsHijack);
            Assert.True(v.ShouldQuarantinePayload);
            Assert.Equal(DetectionTier.Tier2Indicator, v.Tier);           // never solo-acts
            Assert.Equal(ResponseAction.LogOnly, v.AuthorizedResponse);   // observe until chain
        }

        [Fact]
        public void ServicingImpersonation_IsHijack_AndQuarantines()
        {
            // A CBS servicing DLL name outside WinSxS/servicing (the cbsapi.dll plant class).
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{22222222-2222-2222-2222-222222222222}", "HKLM",
                @"C:\Windows\System32\cbsapi.dll"));

            Assert.True(v.IsHijack);
            Assert.True(v.ShouldQuarantinePayload);
        }

        [Fact]
        public void ScriptHostServer_IsHijack_ButDoesNotQuarantineLolbin()
        {
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{33333333-3333-3333-3333-333333333333}", "HKCU",
                @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAA"));

            Assert.True(v.IsHijack);
            Assert.False(v.ShouldQuarantinePayload); // OS LOLBin - observe only, never quarantine
        }

        [Fact]
        public void HkcuShadowsHklm_WithDifferentPath_IsHijack()
        {
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{44444444-4444-4444-4444-444444444444}", "HKCU",
                @"C:\ProgramData\weird\shadow.dll",
                shadow: true,
                hklm: @"C:\Windows\System32\legit.dll"));

            Assert.True(v.IsHijack);
        }

        [Fact]
        public void TrustedSystem32Server_IsNotHijack()
        {
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{55555555-5555-5555-5555-555555555555}", "HKLM",
                @"C:\Windows\System32\shell32.dll"));

            Assert.False(v.IsHijack);
            Assert.False(v.ShouldQuarantinePayload);
        }

        [Fact]
        public void ProgramFilesServer_IsNotHijack()
        {
            var v = ComHijackEvaluator.Evaluate(Inproc(
                "{66666666-6666-6666-6666-666666666666}", "HKLM",
                "\"C:\\Program Files\\Vendor\\App\\server.dll\""));

            Assert.False(v.IsHijack);
        }

        [Fact]
        public void TreatAs_Hkcu_IsHijack_NoQuarantine()
        {
            var v = ComHijackEvaluator.Evaluate(new ComHijackEvaluator.Registration(
                "{77777777-7777-7777-7777-777777777777}", "HKCU",
                ComHijackEvaluator.ServerKind.TreatAs,
                "{88888888-8888-8888-8888-888888888888}"));

            Assert.True(v.IsHijack);
            Assert.False(v.ShouldQuarantinePayload); // key redirect - never delete/quarantine a class
        }

        [Theory]
        [InlineData(@"C:\Users\bob\AppData\Local\Temp\x.dll", true)]
        [InlineData(@"C:\Users\Public\x.dll", true)]
        [InlineData(@"C:\Windows\System32\cbsapi.dll", true)]      // servicing impersonation
        [InlineData(@"C:\Windows\System32\shell32.dll", false)]    // trusted OS
        [InlineData(@"C:\Program Files\App\x.dll", false)]         // trusted install
        [InlineData(@"C:\Windows\System32\rundll32.exe", false)]   // OS LOLBin - observe only
        public void ShouldQuarantinePayload_Matrix(string server, bool expected)
        {
            Assert.Equal(expected, ComHijackEvaluator.ShouldQuarantinePayload(server));
        }

        [Fact]
        public void ExtractServerPath_StripsQuotesAndArgs()
        {
            Assert.Equal(@"C:\a\b.dll",
                ComHijackEvaluator.ExtractServerPath("\"C:\\a\\b.dll\""));
            Assert.Equal(@"C:\a\b.exe",
                ComHijackEvaluator.ExtractServerPath(@"C:\a\b.exe --run foo"));
            Assert.Equal("", ComHijackEvaluator.ExtractServerPath(null));
            Assert.Equal("", ComHijackEvaluator.ExtractServerPath("   "));
        }
    }
}
