using System;
using System.IO;
using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class FileVerdictAdsTests
    {
        [Fact]
        public void FileVerdictAds_CreatesSecureDirAndHmacKey()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                var ads = new FileVerdictAds(tempDir);
                var keyFilePath = Path.Combine(tempDir, "ads_hmac.key");

                Assert.True(Directory.Exists(tempDir));
                Assert.True(File.Exists(keyFilePath));
                
                // Verify directory has restricted ACLs
                var dirInfo = new DirectoryInfo(tempDir);
                var security = dirInfo.GetAccessControl();
                Assert.True(security.AreAccessRulesProtected);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_PersistsAndLoadsSameKey()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                // First initialization creates the key
                var ads1 = new FileVerdictAds(tempDir);
                var keyFilePath = Path.Combine(tempDir, "ads_hmac.key");
                Assert.True(File.Exists(keyFilePath));
                var keyBytes1 = File.ReadAllBytes(keyFilePath);

                // Second initialization should read and use the exact same key
                var ads2 = new FileVerdictAds(tempDir);
                var keyBytes2 = File.ReadAllBytes(keyFilePath);

                Assert.Equal(keyBytes1, keyBytes2);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_CanSetAndGetVerdict()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "test_target.exe");

            try
            {
                File.WriteAllText(testFile, "dummy executable content");
                var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // example sha256

                var ads = new FileVerdictAds(tempDir);
                
                // Verify initial verdict is Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, sha256));

                // Set verdict to Safe
                ads.SetVerdict(testFile, sha256, HashVerdict.Safe);
                Assert.Equal(HashVerdict.Safe, ads.GetVerdict(testFile, sha256));

                // Must not pollute adjacent path with legacy sidecars
                Assert.False(File.Exists(testFile + ".sentinel_verdict"),
                    "SetVerdict must not create *.sentinel_verdict sidecars next to user files");

                // Central content-addressed cache should exist
                var cacheDir = ads.VerdictCacheDirectory;
                Assert.True(Directory.Exists(cacheDir));
                Assert.NotEmpty(Directory.GetFiles(cacheDir, "*.verdict", SearchOption.AllDirectories));

                // Set verdict to Unsafe
                ads.SetVerdict(testFile, sha256, HashVerdict.Unsafe);
                Assert.Equal(HashVerdict.Unsafe, ads.GetVerdict(testFile, sha256));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_RejectsModifiedSignatureOrMismatchingHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "test_target2.exe");

            try
            {
                File.WriteAllText(testFile, "dummy content");
                var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                var ads = new FileVerdictAds(tempDir);
                ads.SetVerdict(testFile, sha256, HashVerdict.Unsafe);

                // Mismatching SHA256 should return Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, "different_sha256_hash_here_12345678"));

                // Corrupt signature in central cache (primary store)
                var hash = sha256.ToLowerInvariant();
                var cachePath = Path.Combine(ads.VerdictCacheDirectory, hash.Substring(0, 2), hash + ".verdict");
                Assert.True(File.Exists(cachePath), "Expected central VerdictCache entry after SetVerdict");
                var payload = File.ReadAllText(cachePath);

                var parts = payload.Split('|');
                parts[3] = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // fake hmac
                File.WriteAllText(cachePath, string.Join("|", parts));

                // Verdict should be rejected and return Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, sha256));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_MigratesAndRemovesLegacySidecar()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "legacy_target.exe");

            try
            {
                File.WriteAllText(testFile, "legacy content");
                var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                // First write produces valid HMAC payload in central store
                var ads = new FileVerdictAds(tempDir);
                ads.SetVerdict(testFile, sha256, HashVerdict.Safe);

                var hash = sha256.ToLowerInvariant();
                var cachePath = Path.Combine(ads.VerdictCacheDirectory, hash.Substring(0, 2), hash + ".verdict");
                var payload = File.ReadAllText(cachePath);

                // Simulate legacy pollution: copy payload to sidecar and wipe central cache
                var sidecar = testFile + ".sentinel_verdict";
                File.WriteAllText(sidecar, payload);
                Directory.Delete(ads.VerdictCacheDirectory, true);

                // Read should recover via sidecar, re-populate cache, and delete sidecar
                Assert.Equal(HashVerdict.Safe, ads.GetVerdict(testFile, sha256));
                Assert.True(File.Exists(cachePath), "Legacy sidecar should migrate into central cache");
                Assert.False(File.Exists(sidecar), "Legacy sidecar should be deleted after migration");
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_PurgeLegacySidecarFiles_DeletesOnlySidecars()
        {
            var root = Path.Combine(Path.GetTempPath(), "sentinel_purge_test_" + Guid.NewGuid().ToString("N")[..8]);
            var nested = Path.Combine(root, "a", "b");
            Directory.CreateDirectory(nested);

            var keep = Path.Combine(nested, "real.exe");
            var side1 = keep + ".sentinel_verdict";
            var side2 = Path.Combine(root, "orphan.sentinel_verdict");
            var other = Path.Combine(root, "notes.txt");

            try
            {
                File.WriteAllText(keep, "exe");
                File.WriteAllText(side1, "legacy");
                File.WriteAllText(side2, "legacy2");
                File.WriteAllText(other, "keep me");

                var deleted = FileVerdictAds.PurgeLegacySidecarFiles(new[] { root });
                Assert.Equal(2, deleted);
                Assert.False(File.Exists(side1));
                Assert.False(File.Exists(side2));
                Assert.True(File.Exists(keep));
                Assert.True(File.Exists(other));
            }
            finally
            {
                try { Directory.Delete(root, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_PurgeLegacySidecarsOnce_IsIdempotentViaMarker()
        {
            var secure = Path.Combine(Path.GetTempPath(), "sentinel_purge_once_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(secure);

            try
            {
                var ads = new FileVerdictAds(secure);
                // Pre-create marker as if a prior upgrade pass already completed
                File.WriteAllText(ads.LegacySidecarPurgeMarkerPath, "prior");

                var skipped = ads.PurgeLegacySidecarsOnce(force: false);
                Assert.Equal(0, skipped);
                Assert.True(File.Exists(ads.LegacySidecarPurgeMarkerPath));

                // force=true re-runs and rewrites marker (may delete 0 files if no sidecars on fixed drives)
                var forced = ads.PurgeLegacySidecarsOnce(force: true);
                Assert.True(forced >= 0);
                Assert.True(File.Exists(ads.LegacySidecarPurgeMarkerPath));
            }
            finally
            {
                try { Directory.Delete(secure, true); } catch { }
            }
        }
    }
}

