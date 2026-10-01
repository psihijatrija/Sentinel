using System;
using System.IO;
using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class FileActivityMonitorTests : IDisposable
    {
        private readonly string _tempPath;

        public FileActivityMonitorTests()
        {
            _tempPath = Path.Combine(Path.GetTempPath(), "sentinel_fam_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempPath);
        }

        private FileActivityMonitor CreateMonitor(out SignerTrustService signerTrust)
        {
            var logger = NullLogger<FileActivityMonitor>.Instance;
            var trustLogger = NullLogger<SignerTrustService>.Instance;
            signerTrust = new SignerTrustService(trustLogger);
            
            var config = new SentinelConfig { WatchPath = _tempPath };

            return new FileActivityMonitor(null!, null!, config, logger, signerTrust);
        }

        [Fact]
        public void IsTrustedSystemWriter_TrustedProcessNames_ReturnsTrue()
        {
            using var monitor = CreateMonitor(out _);
            Assert.True(monitor.IsTrustedSystemWriter(1234, "trustedinstaller", "dummy.txt"));
            Assert.True(monitor.IsTrustedSystemWriter(1234, "svchost", "dummy.txt"));
            Assert.True(monitor.IsTrustedSystemWriter(1234, "windowssentinel.service", "dummy.txt"));
        }

        [Fact]
        public void IsTrustedSystemWriter_SystemPid_ReturnsTrue()
        {
            using var monitor = CreateMonitor(out _);
            Assert.True(monitor.IsTrustedSystemWriter(4, "any_process", "dummy.txt"));
        }

        [Fact]
        public void IsTrustedSystemWriter_UntrustedProcess_ReturnsFalse()
        {
            using var monitor = CreateMonitor(out _);
            // Use a PID that cannot exist and a name that does not substring-match
            // trusted writers (e.g. "services"/"msiexec"). PID 9999 can be a live
            // Microsoft-signed process on GitHub-hosted runners, which made this flaky.
            Assert.False(monitor.IsTrustedSystemWriter(
                int.MaxValue - 13,
                "totally-evil-dropper.exe",
                @"C:\Temp\sentinel_fp_untrusted_writer_test.dll"));
        }

        [Fact]
        public void IsTrustedSystemWriter_PidZeroNonExistentFile_ReturnsFalse()
        {
            using var monitor = CreateMonitor(out _);
            // Non-existent file should return false for PID 0
            Assert.False(monitor.IsTrustedSystemWriter(0, "unknown", "C:\\nonexistent_file_path_12345.dll"));
        }

        [Fact]
        public void IsTrustedSystemWriter_PidZeroMicrosoftSignedFile_ReturnsTrue()
        {
            using var monitor = CreateMonitor(out _);
            
            // 1. Verify embedded-signed Microsoft/Dotnet binary (should always succeed)
            var dotnetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "host", "fxr");
            if (Directory.Exists(dotnetDir))
            {
                var files = Directory.GetFiles(dotnetDir, "hostfxr.dll", SearchOption.AllDirectories);
                if (files.Length > 0)
                {
                    Assert.True(monitor.IsTrustedSystemWriter(0, "unknown", files[0]));
                }
            }

            // 2. Verify catalog-signed system file (if catalog checking works in this environment)
            var cmdPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            if (File.Exists(cmdPath) && SecurityValidation.VerifyAuthenticodeSignature(cmdPath))
            {
                Assert.True(monitor.IsTrustedSystemWriter(0, "unknown", cmdPath));
            }
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempPath))
                    Directory.Delete(_tempPath, true);
            }
            catch { }
        }
    }
}
