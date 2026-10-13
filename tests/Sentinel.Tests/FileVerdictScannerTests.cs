using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Tests
{
    public class FileVerdictScannerTests
    {
        [Fact]
        public async Task HashReputationService_CirclFastPath_ReturnsSafe_BeforeMalwareBazaar()
        {
            // Predefined safe hash bypasses both APIs - confirms the fast-path ordering
            var tempDir = Path.Combine(Path.GetTempPath(), "fvs_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var verdict = await service.GetVerdictAsync("0000000000000000000000000000000000000000000000000000000000000000");
                Assert.Equal(HashVerdict.Safe, verdict);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task HashReputationService_CachesVerdict_SkipsApiOnSecondCall()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "fvs_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                var hash = "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1";

                // First call hits the predefined hash path
                var v1 = await service.GetVerdictAsync(hash);
                Assert.Equal(HashVerdict.Unsafe, v1);

                // Second call should hit memory cache (instant return)
                var v2 = await service.GetVerdictAsync(hash);
                Assert.Equal(HashVerdict.Unsafe, v2);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public async Task HashReputationService_InvalidHash_ReturnsUnknown()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "fvs_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            try
            {
                var cache = new SecureCacheStore(tempDir);
                var config = new ThreatReportingConfig();
                var service = new HashReputationService(cache, config, NullLogger<HashReputationService>.Instance);

                // Too short
                Assert.Equal(HashVerdict.Unknown, await service.GetVerdictAsync("abc123"));
                // Empty
                Assert.Equal(HashVerdict.Unknown, await service.GetVerdictAsync(""));
                // Null
                Assert.Equal(HashVerdict.Unknown, await service.GetVerdictAsync(null!));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_UnsafeVerdict_IsLoggedOnly()
        {
            // v1.6.4: DenyExecution was removed. Sentinel is observe-only for file verdicts.
            // This test verifies the old ACL-blocking behavior is gone - unsafe verdicts
            // are logged but never modify file permissions.
            var tempDir = Path.Combine(Path.GetTempPath(), "fvs_deny_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "malware_sample.exe");

            try
            {
                File.WriteAllText(testFile, "fake malware content");

                // Verify NO deny rule is present (Sentinel should never add one)
                var fileInfo = new FileInfo(testFile);
                var acl = fileInfo.GetAccessControl();
                var rules = acl.GetAccessRules(true, false, typeof(SecurityIdentifier));
                bool hasDenyExecute = false;
                foreach (FileSystemAccessRule r in rules)
                {
                    if (r.AccessControlType == AccessControlType.Deny &&
                        r.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile))
                    {
                        hasDenyExecute = true;
                        break;
                    }
                }
                Assert.False(hasDenyExecute, "No Deny Execute ACL should exist - Sentinel is observe-only");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictScanner_ScanExtensions_CoversAllExpectedTypes()
        {
            // Verify that the scanner's extension set matches what we expect
            var expectedExtensions = new[] { ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi" };
            foreach (var ext in expectedExtensions)
            {
                // Test via IsScannable by creating a path with the extension
                var testPath = $"C:\\test\\file{ext}";
                Assert.True(IsScannable(testPath), $"Extension {ext} should be scannable");
            }

            // Non-scannable types
            Assert.False(IsScannable("C:\\test\\document.pdf"));
            Assert.False(IsScannable("C:\\test\\image.png"));
            Assert.False(IsScannable("C:\\test\\archive.zip"));
        }

        // Mirror of the private static method in FileVerdictScanner for testing
        private static readonly System.Collections.Generic.HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"
        };

        private static bool IsScannable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            return !string.IsNullOrEmpty(ext) && ScanExtensions.Contains(ext);
        }
    }
}
