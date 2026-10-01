using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>v1.6.3: OS-critical quarantine gate, USB trust, AMSI demotion helpers.</summary>
    public class V163SecurityHardeningTests : IDisposable
    {
        private readonly string _tempDir;

        public V163SecurityHardeningTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_v163_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void IsOsCriticalPath_System32PowerShell_IsCritical()
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            Assert.True(SecurityValidation.IsOsCriticalPath(path));
        }

        [Fact]
        public void IsOsCriticalPath_UserTempDrop_IsNotCritical()
        {
            var path = Path.Combine(Path.GetTempPath(), "evil-powershell.exe");
            Assert.False(SecurityValidation.IsOsCriticalPath(path));
        }

        [Fact]
        public void IsSystemPowerShellPath_RecognizesStockHosts()
        {
            var ps = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            Assert.True(SecurityValidation.IsSystemPowerShellPath(ps));
            Assert.False(SecurityValidation.IsSystemPowerShellPath(
                Path.Combine(Path.GetTempPath(), "powershell.exe")));
        }

        [Fact]
        public async Task QuarantineManager_RefusesOsCriticalPath()
        {
            var qDir = Path.Combine(_tempDir, "q");
            Directory.CreateDirectory(qDir);
            var qm = new QuarantineManager(qDir);

            // Place a decoy under a fake Windows-like path is hard without elevation;
            // instead copy a temp file and verify IsOsCriticalPath is the gate for real System32.
            var systemPs = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

            if (!File.Exists(systemPs))
            {
                // Host may be broken (exactly the production bug) - still assert the gate
                Assert.True(SecurityValidation.IsOsCriticalPath(systemPs));
                return;
            }

            var result = await qm.QuarantineFileAtomicAsync(systemPs);
            Assert.Null(result);
            Assert.True(File.Exists(systemPs), "System powershell.exe must remain on disk");
        }

        [Fact]
        public async Task QuarantineManager_StillQuarantinesUnsignedUserDrop()
        {
            var qDir = Path.Combine(_tempDir, "q2");
            Directory.CreateDirectory(qDir);
            var qm = new QuarantineManager(qDir);

            var drop = Path.Combine(_tempDir, "unsigned-drop.exe");
            // Minimal MZ stub - unsigned
            File.WriteAllBytes(drop, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 });

            var result = await qm.QuarantineFileAtomicAsync(drop);
            Assert.NotNull(result);
            Assert.False(File.Exists(drop));
            Assert.True(File.Exists(result));
        }

        [Theory]
        [InlineData("0951:1666", "0951:1666")]
        [InlineData("VID_0951&PID_1666", "0951:1666")]
        [InlineData("0951-1666", "0951:1666")]
        [InlineData("bad", null)]
        [InlineData("", null)]
        public void NormalizeVidPid_ParsesCommonFormats(string input, string? expected)
        {
            Assert.Equal(expected, UsbDeviceFingerprinter.NormalizeVidPid(input));
        }

        [Fact]
        public void Config_Defaults_UsbHardening()
        {
            var cfg = new SentinelConfig();
            Assert.False(cfg.AutoDisableFailedUsbEnumeration); // v1.9.7 work-first default
            Assert.Empty(cfg.TrustedUsbDevices);
        }
    }
}
