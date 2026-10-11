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

        // ------------------------------------------------------------------
        // Round-trip + encryption integrity (previously untested branches:
        // DPAPI protect/unprotect, SENQ vault wrap/unwrap, restore happy path).
        // ------------------------------------------------------------------

        [Fact]
        public async Task QuarantineThenRestore_RecoversExactOriginalBytes()
        {
            var original = Path.Combine(_tempDir, "payload.bin");
            var bytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF };
            File.WriteAllBytes(original, bytes);

            var quarantined = await _manager.QuarantineFileAtomicAsync(original);
            Assert.NotNull(quarantined);
            Assert.False(File.Exists(original));

            var dest = Path.Combine(_tempDir, "restored.bin");
            var restoredPath = await _manager.RestoreAsync(quarantined!, dest);

            Assert.Equal(Path.GetFullPath(dest), restoredPath);
            Assert.True(File.Exists(restoredPath));
            Assert.Equal(bytes, File.ReadAllBytes(restoredPath));
            // Restore consumes the vault blob and its sidecar.
            Assert.False(File.Exists(quarantined!));
            Assert.False(File.Exists(quarantined! + ".meta"));
        }

        [Fact]
        public async Task QuarantineBlob_IsEncrypted_WithSenqMagicHeader()
        {
            var original = Path.Combine(_tempDir, "secret.dat");
            var plaintext = "TOP-SECRET-MARKER-STRING-THAT-MUST-NOT-APPEAR-IN-VAULT";
            File.WriteAllText(original, plaintext);

            var quarantined = await _manager.QuarantineFileAtomicAsync(original);
            Assert.NotNull(quarantined);

            var vault = File.ReadAllBytes(quarantined!);
            // SENQ magic + version header.
            Assert.True(vault.Length > 8);
            Assert.Equal((byte)'S', vault[0]);
            Assert.Equal((byte)'E', vault[1]);
            Assert.Equal((byte)'N', vault[2]);
            Assert.Equal((byte)'Q', vault[3]);
            Assert.Equal(1, vault[4]);
            // Plaintext must not survive in the encrypted blob.
            var vaultText = System.Text.Encoding.ASCII.GetString(vault);
            Assert.DoesNotContain("TOP-SECRET-MARKER", vaultText);
        }

        [Fact]
        public async Task QuarantineFileAsync_OverSizeCap_RefusesAndLeavesFileOnDisk()
        {
            var big = Path.Combine(_tempDir, "huge.bin");
            // Create a sparse file just over the cap without allocating it all in RAM.
            using (var fs = new FileStream(big, FileMode.CreateNew, FileAccess.Write))
            {
                fs.SetLength(QuarantineManager.MaxQuarantineFileBytes + 1);
            }

            var result = await _manager.QuarantineFileAtomicAsync(big);

            Assert.Null(result);
            // Over-cap files are left in place rather than loaded into memory.
            Assert.True(File.Exists(big));
        }

        [Fact]
        public async Task QuarantineFileAsync_InstallerInTrustedDownloadsPath_IsSkipped()
        {
            // IsLikelyInstallerPath is PATH-based, not name-based: an installer name alone
            // in an arbitrary temp dir is deliberately NOT trusted (RT-LOW-2 anti-spoof).
            // The trusted branch requires a real download/install location (\Downloads\).
            var downloads = Path.Combine(_tempDir, "Downloads");
            Directory.CreateDirectory(downloads);
            var installer = Path.Combine(downloads, "ChromeSetup.exe");
            File.WriteAllText(installer, "fake installer");

            var result = await _manager.QuarantineFileAtomicAsync(installer);

            Assert.Null(result);
            // Installer heuristic refuses quarantine; the file stays untouched.
            Assert.True(File.Exists(installer));
        }

        [Fact]
        public async Task QuarantineFileAsync_InstallerNameInUntrustedTemp_IsNotSkipped()
        {
            // The anti-evasion counterpart: the same installer name in an arbitrary temp
            // location must NOT be spared by name alone - it is quarantined like any drop.
            var installer = Path.Combine(_tempDir, "ChromeSetup.exe");
            File.WriteAllText(installer, "fake installer");

            var result = await _manager.QuarantineFileAtomicAsync(installer);

            Assert.NotNull(result);
            Assert.False(File.Exists(installer));
        }

        [Fact]
        public async Task QuarantineFileAsync_CleanInPlaceDelete_NotDeferredToReboot()
        {
            var f = Path.Combine(_tempDir, "unlocked.bin");
            File.WriteAllText(f, "no process maps this file");

            var result = await _manager.QuarantineFileAtomicAsync(f);

            Assert.NotNull(result);
            Assert.False(File.Exists(f));
            // Nothing held the file, so the in-place delete succeeded immediately.
            Assert.False(_manager.WasLastQuarantineDeferred);
        }

        // ------------------------------------------------------------------
        // Restore safety guards (previously untested branches).
        // ------------------------------------------------------------------

        [Fact]
        public async Task RestoreAsync_BlobOutsideQuarantineDir_Throws()
        {
            var strayBlob = Path.Combine(_tempDir, "q_deadbeef_evil.exe.senq");
            File.WriteAllBytes(strayBlob, new byte[] { 1, 2, 3 });

            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _manager.RestoreAsync(strayBlob, Path.Combine(_tempDir, "out.exe")));
        }

        [Fact]
        public async Task RestoreAsync_NonExistentBlob_ThrowsFileNotFound()
        {
            var missing = Path.Combine(_quarantineDir, "q_dead_missing.exe.senq");
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                _manager.RestoreAsync(missing));
        }

        [Fact]
        public async Task RestoreAsync_TraversalDestination_Throws()
        {
            var original = Path.Combine(_tempDir, "trav.bin");
            File.WriteAllText(original, "data");
            var quarantined = await _manager.QuarantineFileAtomicAsync(original);
            Assert.NotNull(quarantined);

            var evilDest = Path.Combine(_tempDir, "..", "escape.bin");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _manager.RestoreAsync(quarantined!, evilDest));
        }

        [Fact]
        public async Task RestoreAsync_OsCriticalDestination_Throws()
        {
            var original = Path.Combine(_tempDir, "crit.bin");
            File.WriteAllText(original, "data");
            var quarantined = await _manager.QuarantineFileAtomicAsync(original);
            Assert.NotNull(quarantined);

            var systemDest = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "sentinel_evil.dll");
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _manager.RestoreAsync(quarantined!, systemDest));
        }

        // ------------------------------------------------------------------
        // Metadata parsing + listing (previously untested branches).
        // ------------------------------------------------------------------

        [Fact]
        public void ParseQuarantineMetadata_ValidSenqName_ExtractsIdAndName()
        {
            var ok = _manager.ParseQuarantineMetadata("q_abc123_malware.exe.senq",
                out var id, out var name);

            Assert.True(ok);
            Assert.Equal("abc123", id);
            Assert.Equal("malware.exe", name);
        }

        [Fact]
        public void ParseQuarantineMetadata_ValidWithoutSenqSuffix_Parses()
        {
            var ok = _manager.ParseQuarantineMetadata("q_deadbeef_sample.dll",
                out var id, out var name);

            Assert.True(ok);
            Assert.Equal("deadbeef", id);
            Assert.Equal("sample.dll", name);
        }

        [Fact]
        public void ParseQuarantineMetadata_NonMatchingName_ReturnsFalse()
        {
            var ok = _manager.ParseQuarantineMetadata("not_a_quarantine_file.txt",
                out var id, out var name);

            Assert.False(ok);
            Assert.Equal(string.Empty, id);
            Assert.Equal(string.Empty, name);
        }

        [Fact]
        public async Task ListQuarantined_ReturnsEntry_WithOriginalPathFromMeta()
        {
            var originalPath = Path.Combine(_tempDir, "listme.exe");
            File.WriteAllText(originalPath, "sample");
            var quarantined = await _manager.QuarantineFileAtomicAsync(originalPath);
            Assert.NotNull(quarantined);

            var listed = _manager.ListQuarantined();

            Assert.Single(listed);
            Assert.Equal(quarantined, listed[0].QuarantineFile);
            Assert.Equal(originalPath, listed[0].OriginalPath);
            // .tmp / .meta sidecars are never surfaced as entries.
            Assert.DoesNotContain(listed, e => e.QuarantineFile.EndsWith(".meta"));
        }

        [Fact]
        public void ListQuarantined_EmptyDirectory_ReturnsEmpty()
        {
            var listed = _manager.ListQuarantined();
            Assert.Empty(listed);
        }
    }
}
