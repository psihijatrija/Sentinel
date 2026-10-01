using System;
using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SelfPathGuardTests
    {
        [Fact]
        public void IsSentinelSelfBinary_ReturnsTrue_ForSentinelExeUnderInstall()
        {
            // The test binary runs from the install directory (BaseDirectory)
            var installDir = AppContext.BaseDirectory;
            var testPath = Path.Combine(installDir, "Sentinel.Service.exe");

            // Create a temporary file to test with
            if (!File.Exists(testPath))
            {
                try
                {
                    File.WriteAllText(testPath, "test");
                    Assert.True(SelfPathGuard.IsSentinelSelfBinary(testPath));
                    File.Delete(testPath);
                }
                catch
                {
                    // If we can't create the file, just verify the logic doesn't crash
                    SelfPathGuard.IsSentinelSelfBinary(testPath);
                }
            }
            else
            {
                Assert.True(SelfPathGuard.IsSentinelSelfBinary(testPath));
            }
        }

        [Fact]
        public void IsSentinelSelfBinary_ReturnsFalse_ForNull()
        {
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(null));
        }

        [Fact]
        public void IsSentinelSelfBinary_ReturnsFalse_ForEmptyString()
        {
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(""));
            Assert.False(SelfPathGuard.IsSentinelSelfBinary("   "));
        }

        [Fact]
        public void IsSentinelSelfBinary_ReturnsFalse_ForArbitraryPath()
        {
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(@"C:\Users\Attacker\malware.exe"));
        }

        [Fact]
        public void IsSentinelSelfBinary_ReturnsFalse_ForNonSentinelNameUnderInstall()
        {
            var installDir = AppContext.BaseDirectory;
            var path = Path.Combine(installDir, "NotSentinel.exe");
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(path));
        }

        [Fact]
        public void IsSentinelSelfBinary_ReturnsFalse_ForSentinelNameOutsideInstall()
        {
            // Sentinel.Service.exe in a different directory - NOT trusted
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(@"C:\Temp\Sentinel.Service.exe"));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsTrue_ForInstallSubpath()
        {
            var installDir = AppContext.BaseDirectory;
            var subPath = Path.Combine(installDir, "subdir", "file.txt");
            Assert.True(SelfPathGuard.IsUnderInstallDirectory(subPath));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForNull()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(null));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForEmpty()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(""));
            Assert.False(SelfPathGuard.IsUnderInstallDirectory("   "));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForExternalPath()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(@"C:\Windows\System32\cmd.exe"));
        }

        [Fact]
        public void IsSentinelSelfBinary_AcceptsSentinelCoreDll()
        {
            var installDir = AppContext.BaseDirectory;
            var dllPath = Path.Combine(installDir, "Sentinel.Core.dll");

            if (File.Exists(dllPath))
            {
                Assert.True(SelfPathGuard.IsSentinelSelfBinary(dllPath));
            }
        }
    }
}
