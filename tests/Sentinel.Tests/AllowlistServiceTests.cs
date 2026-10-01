using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class AllowlistServiceTests
    {
        private readonly SignerTrustService _signerTrust = new(NullLogger<SignerTrustService>.Instance);

        private AllowlistService CreateService()
        {
            // Unique temp dir per test to avoid cross-test data leakage
            var dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_test_" + System.Guid.NewGuid().ToString("N")[..8]);
            var cache = new SecureCacheStore(dir);
            return new AllowlistService(cache, NullLogger<AllowlistService>.Instance, _signerTrust);
        }

        //  ShouldSuppress 

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForPresidentsLawRule_Lsass()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("steam", null, "LSASS Memory Dump"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForPresidentsLawRule_Ransomware()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("steam", null, "Ransomware Shadow Copy Deletion"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForGamingProcess_WithoutAllowlist()
        {
            var svc = CreateService();
            // Gaming processes get NO special treatment - only user allowlist matters
            Assert.False(svc.ShouldSuppress("steam", @"C:\Windows\System32\cmd.exe", "UnsignedBinaryRule"));
            Assert.False(svc.ShouldSuppress("EasyAntiCheat", @"C:\Windows\System32\cmd.exe", "SomeRule"));
        }

        [Fact]
        public void ShouldSuppress_ReturnsFalse_ForUnknownProcess()
        {
            var svc = CreateService();
            Assert.False(svc.ShouldSuppress("unknown_malware.exe", null, "SomeRule"));
        }

        //  GetConfidenceReduction 

        [Fact]
        public void GetConfidenceReduction_ReturnsZero_ForPresidentsLawRule()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("devenv", null, "Microsoft Corporation", "LSASS Access");
            Assert.Equal(0.0, reduction);
        }

        [Fact]
        public void GetConfidenceReduction_OnlyReducesForUserAllowlisted()
        {
            var svc = CreateService();
            var path = @"C:\Windows\System32\cmd.exe";
            _signerTrust.AddTestOverride(path, true, "Microsoft Corporation");

            // Not allowlisted - no reduction
            double reduction = svc.GetConfidenceReduction("cmd.exe", path, "Microsoft Corporation", "UnsignedBinaryRule");
            Assert.Equal(0.0, reduction);

            // User-allowlisted - gets reduction
            svc.AddToUserAllowlist("cmd.exe", path, "Dev tool");
            reduction = svc.GetConfidenceReduction("cmd.exe", path, "Microsoft Corporation", "UnsignedBinaryRule");
            Assert.Equal(0.3, reduction);
        }

        [Fact]
        public void GetConfidenceReduction_ReturnsZero_ForUnknown()
        {
            var svc = CreateService();
            double reduction = svc.GetConfidenceReduction("malware.exe", @"C:\Windows\System32\cmd.exe", null, "SomeRule");
            Assert.Equal(0.0, reduction);
        }

        //  Helper methods 

        [Fact]
        public void IsDevelopmentProcess_Recognizes_DevTools()
        {
            var svc = CreateService();
            Assert.True(svc.IsDevelopmentProcess("code"));
            Assert.True(svc.IsDevelopmentProcess("dotnet"));
            Assert.True(svc.IsDevelopmentProcess("cargo"));
            Assert.False(svc.IsDevelopmentProcess("malware"));
        }

        //  User allowlist 

        [Fact]
        public void UserAllowlist_AddAndRemove()
        {
            var svc = CreateService();
            var path = @"C:\Windows\System32\cmd.exe";
            _signerTrust.AddTestOverride(path, true, "Microsoft Corporation");

            svc.AddToUserAllowlist("cmd.exe", path, "User trusted");
            Assert.True(svc.ShouldSuppress("cmd.exe", path, "UnsignedBinaryRule"));

            svc.RemoveFromUserAllowlist("cmd.exe");
            Assert.False(svc.ShouldSuppress("cmd.exe", path, "UnsignedBinaryRule"));
        }

        [Fact]
        public void UserAllowlist_NeverSuppressesPresidentsLaw()
        {
            var svc = CreateService();
            svc.AddToUserAllowlist("myapp.exe", null, "I trust it");
            Assert.False(svc.ShouldSuppress("myapp.exe", null, "LSASS Access"));
        }

        [Fact]
        public void UserAllowlist_GetReturnsEntries()
        {
            var svc = CreateService();
            svc.AddToUserAllowlist("app1.exe", null, "Test");
            svc.AddToUserAllowlist("app2.exe", null, "Test");
            var list = svc.GetUserAllowlist();
            Assert.Equal(2, list.Count);
        }

        [Fact]
        public void ShouldSuppress_BeaconingIsPresidentsLaw()
        {
            var svc = CreateService();
            var path = @"C:\Windows\System32\cmd.exe";
            _signerTrust.AddTestOverride(path, true, "Microsoft Corporation");

            // Without user allowlist - not suppressed
            Assert.False(svc.ShouldSuppress("cmd.exe", path, "C2 Beaconing Behavior (Statistical)"));
            // v1.5.9: With user allowlist - beaconing is now President's Law and CANNOT be suppressed.
            // This prevents an attacker from using an allowlisted process to maintain a C2 channel.
            svc.AddToUserAllowlist("cmd.exe", path, "Game launcher");
            Assert.False(svc.ShouldSuppress("cmd.exe", path, "C2 Beaconing Behavior (Statistical)"));
            // User allowlist CAN still suppress non-President's-Law rules
            Assert.True(svc.ShouldSuppress("cmd.exe", path, "UnsignedBinaryRule"));
        }
    }
}
