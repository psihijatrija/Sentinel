using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SecurityFileScopeTests
    {
        [Theory]
        [InlineData(@"C:\Users\Admin\Downloads\payload.exe", true)]
        [InlineData(@"C:\Windows\Temp\evil.dll", true)]
        [InlineData(@"C:\Windows\System32\drivers\bad.sys", true)]
        [InlineData(@"C:\Users\Admin\Desktop\run.ps1", true)]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\cache.tmp", false)]
        [InlineData(@"C:\Users\Admin\Pictures\photo.jpg", false)]
        [InlineData("payload.exe", false)]
        [InlineData(null, false)]
        public void IsEtwFileEventRelevant_FiltersFirehose(string? path, bool expected)
        {
            Assert.Equal(expected, SecurityFileScope.IsEtwFileEventRelevant(path));
        }

        [Theory]
        // High-risk staging / autostart locations: novel extension is still in scope.
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\payload.xyz", true)]
        [InlineData(@"C:\Windows\Temp\stage.dat", true)]
        [InlineData(@"C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.bin", true)]
        [InlineData(@"C:\Users\Public\drop.q", true)]
        [InlineData(@"C:\ProgramData\Vendor\loader.zzz", true)]
        // Firehose directories stay OUT of the high-risk set (no 1.6 GB regression).
        [InlineData(@"C:\Users\Admin\AppData\Local\Google\Chrome\User Data\Default\Cache\f_00001", false)]
        [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Scans\x.log", false)]
        [InlineData(@"C:\Users\Admin\Pictures\photo.jpg", false)]
        [InlineData(null, false)]
        public void IsHighRiskDropDirectory_CoversStagingNotFirehose(string? path, bool expected)
        {
            Assert.Equal(expected, SecurityFileScope.IsHighRiskDropDirectory(path));
        }

        [Fact]
        public void LooksExecutableByContent_DetectsRenamedPe()
        {
            // A PE renamed to a benign-looking extension must be detected by content.
            string tmp = Path.Combine(Path.GetTempPath(), $"sent_test_{Guid.NewGuid():N}.xyz");
            try
            {
                File.WriteAllBytes(tmp, new byte[] { (byte)'M', (byte)'Z', 0x90, 0x00 });
                Assert.True(SecurityFileScope.LooksExecutableByContent(tmp));
            }
            finally { try { File.Delete(tmp); } catch { } }
        }

        [Fact]
        public void LooksExecutableByContent_IgnoresRealImage()
        {
            // A genuine JPEG (FF D8 FF ...) is not executable content.
            string tmp = Path.Combine(Path.GetTempPath(), $"sent_test_{Guid.NewGuid():N}.jpg");
            try
            {
                File.WriteAllBytes(tmp, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 });
                Assert.False(SecurityFileScope.LooksExecutableByContent(tmp));
            }
            finally { try { File.Delete(tmp); } catch { } }
        }

        [Fact]
        public void IsRelevantOrHighRisk_ClosesUnmonitoredExtensionEvasion()
        {
            // PE dropped into Temp with a novel extension: allow-list misses it, but the
            // high-risk-directory + content check catches it.
            string dir = Path.Combine(Path.GetTempPath()); // GetTempPath() -> ...\AppData\Local\Temp\
            string tmp = Path.Combine(dir, $"sent_evil_{Guid.NewGuid():N}.totallybenign");
            try
            {
                File.WriteAllBytes(tmp, new byte[] { (byte)'M', (byte)'Z', 0x90, 0x00 });
                Assert.False(SecurityFileScope.IsEtwFileEventRelevant(tmp)); // extension not on list
                // Only assert the strengthened path when the temp dir is the expected user Temp.
                if (SecurityFileScope.IsHighRiskDropDirectory(tmp))
                    Assert.True(SecurityFileScope.IsRelevantOrHighRisk(tmp));
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
    }
}
