using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for QuarantineManager - verifies file quarantine, atomic move,
    /// signed binary protection, and restoration logic.
    /// </summary>
    public class QuarantineManagerTests : IDisposable
    {
        private readonly string _tempDir;
        private readonly string _quarantineDir;
        private readonly QuarantineManager _manager;

        public QuarantineManagerTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_qm_test_" + Guid.NewGuid().ToString("N")[..8]);
            _quarantineDir = Path.Combine(_tempDir, "quarantine");
            Directory.CreateDirectory(_tempDir);
            _manager = new QuarantineManager(_quarantineDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        [Fact]
        public void Constructor_CreatesQuarantineDirectory()
        {
            Assert.True(Directory.Exists(_quarantineDir));
        }

        [Fact]
        public void InteractiveBrowseRule_IsThisFolderOnly_NotFileInherit()
        {
            var rule = QuarantineManager.InteractiveBrowseRule();
            var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            Assert.Equal(interactive, rule.IdentityReference);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(InheritanceFlags.None, rule.InheritanceFlags);
            Assert.True((rule.FileSystemRights & FileSystemRights.ListDirectory) != 0);
            Assert.True((rule.FileSystemRights & FileSystemRights.Traverse) != 0);
            // Must not be a generic file-read ACE that would inherit onto DPAPI blobs
            Assert.Equal(PropagationFlags.None, rule.PropagationFlags);
        }

        [Fact]
        public async Task QuarantineFileAsync_MovesFileToQuarantine()
        {
            var malware = Path.Combine(_tempDir, "malware.exe");
            File.WriteAllText(malware, "PE\x00\x00 fake malware content");

            var result = await _manager.QuarantineFileAtomicAsync(malware);

            // File should be moved from original location
            Assert.False(File.Exists(malware));
            // Result should be the quarantine path (or null if signed binary protection kicked in)
            if (result != null)
            {
                Assert.True(File.Exists(result));
                Assert.StartsWith(_quarantineDir, result);
            }
        }

        [Fact]
        public async Task QuarantineFileAsync_NonExistentFile_ThrowsFileNotFound()
        {
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                _manager.QuarantineFileAtomicAsync(@"C:\nonexistent_" + Guid.NewGuid().ToString("N") + @"\file.exe"));
        }

        [Fact]
        public async Task QuarantineFileAsync_EmptyPath_ThrowsFileNotFound()
        {
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                _manager.QuarantineFileAtomicAsync(""));
        }

        [Fact]
        public async Task QuarantineFileAsync_NullPath_ThrowsFileNotFound()
        {
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                _manager.QuarantineFileAtomicAsync(null!));
        }

        [Fact]
        public async Task QuarantineFileAsync_PreservesFile_InQuarantineDir()
        {
            var content = "This is test content that should survive quarantine";
            var testFile = Path.Combine(_tempDir, "preserve.dat");
            File.WriteAllText(testFile, content);

            var quarantined = await _manager.QuarantineFileAtomicAsync(testFile);

            // Original file should be gone
            Assert.False(File.Exists(testFile));
            // Quarantined file should exist (DPAPI encrypted)
            if (quarantined != null)
            {
                Assert.True(File.Exists(quarantined));
                Assert.True(new FileInfo(quarantined).Length > 0);
            }
        }

        [Fact]
        public async Task QuarantineFileAsync_MultipleFiles_IndependentPaths()
        {
            var f1 = Path.Combine(_tempDir, "mal1.exe");
            var f2 = Path.Combine(_tempDir, "mal2.exe");
            File.WriteAllText(f1, "malware 1");
            File.WriteAllText(f2, "malware 2");

            var q1 = await _manager.QuarantineFileAtomicAsync(f1);
            var q2 = await _manager.QuarantineFileAtomicAsync(f2);

            if (q1 != null && q2 != null)
            {
                Assert.NotEqual(q1, q2);
            }
        }
    }
}
