using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class QuarantineManager
    {
        private readonly string _quarantineDir = null!;
        // Optional .senq suffix marks Sentinel quarantine vault blobs (not in-place ransomware).
        private static readonly Regex MetadataRegex = new(@"^q_([a-fA-F0-9]+)_([a-zA-Z0-9_\-\s\.]+?)(?:\.senq)?$", RegexOptions.Compiled);

        /// <summary>ASCII magic + version distinguishing EDR vault blobs from ransomware payloads.</summary>
        private static readonly byte[] VaultMagic = { (byte)'S', (byte)'E', (byte)'N', (byte)'Q', 1, 0, 0, 0 };

        /// <summary>v1.8.1 RT-NEW-5: refuse multi-GB in-memory quarantine (OOM / service death).</summary>
        public const long MaxQuarantineFileBytes = 128L * 1024 * 1024;

        /// <summary>
        /// Authenticode signer common-names (as returned by
        /// <see cref="SecurityValidation.TryGetAuthenticodePublisher"/>) that are never quarantined
        /// when the file carries a VALID signature. Signer identity is the non-attacker-controllable
        /// anchor required by constraints.md ("no attacker-controllable trust") - a filename or path
        /// must never self-authorize, but a forged publisher subject on a validly-signed binary is
        /// not achievable. Extend this set rather than reintroducing per-path allowlists.
        ///   - "Johannes Schindelin": the Git for Windows release signer.
        /// </summary>
        private static readonly HashSet<string> TrustedPublishers =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "Johannes Schindelin",
            };

        public string QuarantineDirectory => _quarantineDir;

        public QuarantineManager(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _quarantineDir = customPath!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _quarantineDir = Path.Combine(programData, "Sentinel", "Quarantine");
            }

            // Only create the directory if we have access (Service runs as SYSTEM, Agent as user).
            // The Agent doesn't write to quarantine - the Service handles all quarantine operations.
            try
            {
                if (!Directory.Exists(_quarantineDir))
                {
                    Directory.CreateDirectory(_quarantineDir);
                }
                // v1.8.1 RT-NEW-4: lock production quarantine only (not unit-test temp dirs -
                // SYSTEM+Admins-only ACLs break non-elevated Admin tests under UAC).
                if (IsProductionQuarantinePath(_quarantineDir!))
                    SecureQuarantineDirectory(_quarantineDir);
            }
            catch (UnauthorizedAccessException)
            {
                // Running as user-session Agent - quarantine dir is owned by SYSTEM.
                // This is expected; the Agent only reads quarantine metadata for display.
            }
            catch
            {
                // ACL lock may fail as non-elevated agent - ignore
            }
        }

        private static bool IsProductionQuarantinePath(string dirPath)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var expected = Path.GetFullPath(Path.Combine(programData, "Sentinel", "Quarantine"));
                var actual = Path.GetFullPath(dirPath).TrimEnd('\\');
                return actual.Equals(expected.TrimEnd('\\'))
                    || actual.StartsWith(expected.TrimEnd('\\') + "\\");
            }
            catch { return false; }
        }

        /// <summary>
        /// SYSTEM + Admins full control on the folder and blobs.
        /// Interactive users: this-folder-only List/Traverse so Explorer and the tray Agent
        /// can open the directory. No ObjectInherit - sample bytes stay unreadable (UAC-filtered
        /// Admin tokens are not BUILTIN\Administrators, which is why SYSTEM+Admins-only
        /// made Settings -> Open Folder say "insufficient permissions").
        /// Only applied to production %ProgramData%\Sentinel\Quarantine.
        /// </summary>
        public static void SecureQuarantineDirectory(string dirPath)
        {
            if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath))
                return;
            if (!IsProductionQuarantinePath(dirPath))
                return;
            try
            {
                var dirInfo = new DirectoryInfo(dirPath);
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));

                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    adminsSid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));

                security.AddAccessRule(InteractiveBrowseRule());

                dirInfo.SetAccessControl(security);
            }
            catch { }
        }

        /// <summary>
        /// Explorer / tray Agent browse: ListDirectory + Traverse on the folder object only.
        /// Files do not inherit this ACE (no sample theft; DPAPI blobs stay SYSTEM/Admin).
        /// </summary>
        public static FileSystemAccessRule InteractiveBrowseRule()
        {
            var interactiveSid = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            return new FileSystemAccessRule(
                interactiveSid,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.None,
                PropagationFlags.None,
                AccessControlType.Allow);
        }

        /// <summary>
        /// Quarantines a file (DPAPI-encrypt, move to quarantine, delete original).
        ///
        /// By default, <b>refuses Authenticode-signed binaries</b> - official installers
        /// (Git for Windows, ChromeSetup, VS Code, etc.) must not be destroyed on disk
        /// by chain-trace FPs. Kill-process is still allowed by callers; only quarantine
        /// is blocked. Pass <paramref name="forceQuarantineSigned"/> only for deliberate
        /// impostor/sideload remediation where the signed file is known-bad in context.
        ///
        /// Returns the quarantine path, or <c>null</c> if the file was refused (signed)
        /// or missing.
        ///
        /// <paramref name="hardenedRemoval"/> (opt-in, used only by the aggressive unsigned-module
        /// sweep): when the original cannot be deleted in place because it is mapped into a live
        /// process or its ACL denies delete, terminate the holder processes and seize ownership
        /// (takeown/icacls) so the file leaves disk immediately instead of waiting for reboot.
        /// Default callers (signed installers, normal detections) must NOT set this - they keep
        /// the conservative retry-then-delete-on-reboot behavior.
        /// </summary>
        public async Task<string?> QuarantineFileAtomicAsync(string filePath, bool forceQuarantineSigned = false, bool hardenedRemoval = false)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found for quarantine", filePath);
            }

            // Avoid quarantining known installer executables (e.g. ChromeSetup) which are legitimate.
            if (InstallerHeuristics.IsLikelyInstallerPath(filePath))
                return null; // skip quarantine for installer-like paths

            // Trusted-publisher allowlist (signer-based, path-independent).
            //
            // Replaces an older hardcoded list of absolute git.exe paths. Four literal paths
            // were fragile (broke for Git installed to D:\, Program Files (x86), %LOCALAPPDATA%
            // per-user, winget/scoop/choco, or the Git \bin\ dir the list didn't even cover) and,
            // worse, path-only trust is attacker-controllable: a planted git.exe at one of those
            // paths would self-authorize, violating "no attacker-controllable trust" (constraints.md).
            //
            // The non-attacker-controllable anchor is the Authenticode signer. We require a VALID
            // signature (so the subject can't be forged) AND a signer in the trusted set. This holds
            // at any install location and even on forceQuarantineSigned callers (impostor /
            // dashboard-remediate), where the generic signed-file refusal below is intentionally
            // bypassed but a genuine Git binary must still be spared.
            if (SecurityValidation.VerifyAuthenticodeSignature(filePath))
            {
                var publisher = SecurityValidation.TryGetAuthenticodePublisher(filePath);
                if (!string.IsNullOrWhiteSpace(publisher) &&
                    TrustedPublishers.Contains(publisher!))
                {
                    return null; // signed by a trusted publisher - never quarantine
                }
            }

            // removing the host binary and breaking PowerShell / shell integrations system-wide.
            // forceQuarantineSigned cannot override this gate.
            if (SecurityValidation.IsOsCriticalPath(filePath))
            {
                return null;
            }

            // Central gate: never wipe signed software unless explicitly forced.
            // Covers ChainTracer, IncidentResponse, QuarantineAndKill, and any future caller.
            if (!forceQuarantineSigned)
            {
                try
                {
                    if (SecurityValidation.VerifyAuthenticodeSignature(filePath))
                    {
                        return null; // preserved on disk
                    }
                }
                catch
                {
                    // v1.6.3: Fail CLOSED for Program Files / Windows-adjacent paths when
                    // signature verification throws - never treat "check failed" as unsigned.
                    var lower = filePath.ToLowerInvariant();
                    if (lower.Contains(@"\program files") || lower.Contains(@"\windows\"))
                        return null;
                    // Outside protected trees: proceed only for clearly user-writable drops.
                }
            }

            // Read with FileShare.Delete - never block user from deleting files
            byte[] fileBytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            {
                // v1.8.1 RT-NEW-5: hard cap to prevent SYSTEM OOM on huge decoy files
                if (fs.Length > MaxQuarantineFileBytes)
                    return null;

                fileBytes = new byte[fs.Length];
                await fs.ReadExactlyAsync(fileBytes);
            }

            if (IsProductionQuarantinePath(_quarantineDir))
            {
                try { SecureQuarantineDirectory(_quarantineDir); } catch { }
            }

            // Machine-scoped DPAPI vault blob with SENQ magic header (Alyac/MSIL.Ransom FP mitigation:
            // structured EDR vault under ProgramData, not in-place user-file encryption).
            var protectedBytes = ProtectedData.Protect(fileBytes, null, DataProtectionScope.LocalMachine);
            var vaultBytes = new byte[VaultMagic.Length + protectedBytes.Length];
            Buffer.BlockCopy(VaultMagic, 0, vaultBytes, 0, VaultMagic.Length);
            Buffer.BlockCopy(protectedBytes, 0, vaultBytes, VaultMagic.Length, protectedBytes.Length);

            var fileName = Path.GetFileName(filePath);
            var safeName = Regex.Replace(fileName, @"[^a-zA-Z0-9_\-\.]", "_");
            var uniqueId = Guid.NewGuid().ToString("N");

            // Format: q_<uniqueId>_<safeName>.senq (+ sibling .meta for restore path)
            var quarantineFileName = $"q_{uniqueId}_{safeName}.senq";
            var tempPath = Path.Combine(_quarantineDir, $"{quarantineFileName}.tmp");
            var finalPath = Path.Combine(_quarantineDir, quarantineFileName);
            var metaPath = Path.Combine(_quarantineDir, $"{quarantineFileName}.meta");

            // Write, move, and delete source atomically
            await System.IO.FileNet48.WriteAllBytesAsync(tempPath, vaultBytes);

            if (File.Exists(finalPath))
            {
                File.Delete(finalPath);
            }
            File.Move(tempPath, finalPath);

            try
            {
                // v2.0.4 MED-4: Encrypt .meta content (original path) with DPAPI to prevent
                // information leakage about detected file locations to attackers with Admin access.
                var metaBytes = System.Text.Encoding.UTF8.GetBytes(filePath);
                var encryptedMeta = ProtectedData.Protect(metaBytes, null, DataProtectionScope.LocalMachine);
                await System.IO.FileNet48.WriteAllBytesAsync(metaPath, encryptedMeta);
            }
            catch { /* restore still possible by filename guess */ }

            // Remove original attributes and delete. The vault copy is already written,
            // so from here the goal is to guarantee the ORIGINAL leaves disk - if it does
            // not, quarantine has not actually neutralized anything and the same file will
            // be re-detected on the next scan / next install (the "why did it quarantine
            // the same DLL again" bug). A DLL that was flagged because a live process mapped
            // it is HELD by the OS with a delete lock, so an in-place delete throws
            // UnauthorizedAccessException / IOException even after the host is killed (the
            // unmap is not instantaneous). We retry briefly, then fall back to a
            // delete-on-reboot so the file is guaranteed gone after the next boot rather
            // than silently surviving.
            bool removedNow = await TryDeleteWithRetriesAsync(filePath);
            if (!removedNow && hardenedRemoval)
            {
                // Opt-in aggressive removal (unsigned-module sweep): the file is still on disk
                // because it is mapped into a live process (delete lock) or its ACL denies
                // delete. Mirror the PS DLL remover - terminate the holder processes and seize
                // ownership (takeown/icacls), then retry the delete before deferring to reboot.
                removedNow = await TryHardenedDeleteAsync(filePath);
            }
            if (!removedNow)
            {
                bool scheduled = TryScheduleDeleteOnReboot(filePath);
                // finalPath is still returned: the encrypted vault copy exists and the file
                // is either gone or guaranteed to be deleted on reboot. Callers that need to
                // know it is still on disk until reboot can check WasLastQuarantineDeferred.
                _lastQuarantineDeferredToReboot = scheduled || File.Exists(filePath);
            }
            else
            {
                _lastQuarantineDeferredToReboot = false;
            }

            return finalPath;
        }

        /// <summary>
        /// True when the most recent successful <see cref="QuarantineFileAtomicAsync"/> could
        /// not delete the original in place (locked because a process still maps it) and had to
        /// schedule a delete-on-reboot. The vault copy exists either way; this tells the caller
        /// the source file is still on disk until the next boot, so it must not claim the file
        /// was removed. Best-effort/advisory - single-writer service, not thread-safe by design.
        /// </summary>
        public bool WasLastQuarantineDeferred => _lastQuarantineDeferredToReboot;
        private bool _lastQuarantineDeferredToReboot;

        private static async Task<bool> TryDeleteWithRetriesAsync(string filePath)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    if (!File.Exists(filePath)) return true;
                    File.SetAttributes(filePath, FileAttributes.Normal);
                    File.Delete(filePath);
                    return !File.Exists(filePath);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    // File is locked (mapped into a running process) - the host kill has not
                    // fully unmapped it yet. Brief backoff and retry.
                    await Task.Delay(120);
                }
                catch
                {
                    return false;
                }
            }
            return !File.Exists(filePath);
        }

        /// <summary>
        /// Aggressive opt-in removal used by the unsigned-module sweep (hardenedRemoval=true).
        /// Ports the PS DLL remover's locked-file path: kill every process that currently maps
        /// the file, seize ownership and reset the ACL via takeown/icacls, then retry the delete.
        /// Never used by the default callers - signed installers and normal detections keep the
        /// conservative retry-then-reboot behavior. Returns true only if the original is gone.
        /// </summary>
        private static async Task<bool> TryHardenedDeleteAsync(string filePath)
        {
            if (!File.Exists(filePath)) return true;

            // 1. Terminate processes that hold the file mapped (Stop-ProcessesUsingDLL parity).
            try { KillProcessesMappingFile(filePath); }
            catch { /* best effort - continue to ownership seize + delete */ }

            // Give the OS a moment to unmap after the holders die.
            if (await TryDeleteWithRetriesAsync(filePath)) return true;

            // 2. Seize ownership + reset ACL (Set-DLLFileOwnership parity), then retry.
            try { SeizeOwnership(filePath); }
            catch { /* best effort */ }

            return await TryDeleteWithRetriesAsync(filePath);
        }

        /// <summary>
        /// Kills every process whose loaded modules include <paramref name="filePath"/>.
        /// Mirrors the PS remover's Stop-ProcessesUsingDLL. Uses the hardened
        /// <see cref="HardeningModule.SafeKillProcessTree"/> so Sentinel's own binaries and
        /// BSOD-critical system processes are never terminated.
        /// </summary>
        private static void KillProcessesMappingFile(string filePath)
        {
            var full = Path.GetFullPath(filePath);
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4) continue;
                    bool maps = false;
                    foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
                    {
                        try
                        {
                            if (string.Equals(Path.GetFullPath(mod.FileName), full,
                                    StringComparison.OrdinalIgnoreCase))
                            {
                                maps = true;
                                break;
                            }
                        }
                        catch { /* module path unreadable - skip */ }
                    }
                    if (maps)
                        HardeningModule.SafeKillProcessTree(proc.Id);
                }
                catch { /* access denied / process exited - skip */ }
                finally { try { proc.Dispose(); } catch { } }
            }
        }

        /// <summary>
        /// Seizes ownership and resets the ACL on <paramref name="filePath"/> so a
        /// delete-denied file becomes deletable. Mirrors the PS remover's Set-DLLFileOwnership
        /// (takeown /F + icacls /reset + icacls /grant Administrators:F /inheritance:d). The
        /// native managed ACL path is attempted first; takeown/icacls is the fallback (the only
        /// place in QuarantineManager that shells out, and only on this opt-in aggressive path).
        /// </summary>
        private static void SeizeOwnership(string filePath)
        {
            try { File.SetAttributes(filePath, FileAttributes.Normal); } catch { }

            // Preferred: managed ACL - take ownership for Administrators and grant full control.
            try
            {
                var fi = new FileInfo(filePath);
                var sec = fi.GetAccessControl();
                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                sec.SetAccessRuleProtection(true, false);
                sec.AddAccessRule(new FileSystemAccessRule(
                    adminsSid, FileSystemRights.FullControl,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                fi.SetAccessControl(sec);
                return;
            }
            catch { /* fall through to takeown/icacls */ }

            // Fallback: shell out exactly like the PS script. Scoped to this aggressive path.
            RunSilent("takeown.exe", $"/F \"{filePath}\" /A");
            RunSilent("icacls.exe", $"\"{filePath}\" /reset");
            RunSilent("icacls.exe", $"\"{filePath}\" /grant Administrators:F /inheritance:d");
        }

        private static void RunSilent(string exe, string args)
        {
            try
            {
                using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                p?.WaitForExit(5000);
            }
            catch { /* best effort */ }
        }

        /// <summary>
        /// Schedules the OS to delete <paramref name="filePath"/> on the next reboot via
        /// MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT). Used when a quarantined file is locked and
        /// cannot be deleted in place, so a mapped hostile DLL is still guaranteed to be gone
        /// after reboot instead of surviving to be "re-quarantined" forever.
        /// </summary>
        private static bool TryScheduleDeleteOnReboot(string filePath)
        {
            try
            {
                // lpNewFileName = null with MOVEFILE_DELAY_UNTIL_REBOOT means "delete on reboot".
                return MoveFileEx(filePath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
            catch { return false; }
        }

        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);

        /// <summary>
        /// Lists quarantine entries (encrypted blob filename + optional original path from .meta).
        /// </summary>
        public IReadOnlyList<(string QuarantineFile, string? OriginalPath, string DisplayName)> ListQuarantined()
        {
            var results = new List<(string, string?, string)>();
            try
            {
                if (!Directory.Exists(_quarantineDir)) return results;
                foreach (var file in Directory.EnumerateFiles(_quarantineDir))
                {
                    var name = Path.GetFileName(file);
                    if (name.EndsWith(".tmp") ||
                        name.EndsWith(".meta"))
                        continue;
                    if (!name.StartsWith("q_"))
                        continue;

                    string? original = null;
                    var meta = file + ".meta";
                    if (File.Exists(meta))
                    {
                        try { original = TryReadMetaPath(meta); } catch { }
                    }

                    ParseQuarantineMetadata(name, out _, out var display);
                    if (string.IsNullOrEmpty(display)) display = name;
                    results.Add((file, original, display));
                }
            }
            catch { }
            return results;
        }

        /// <summary>
        /// Restores a quarantined file to <paramref name="destinationPath"/> (or the path
        /// recorded in the .meta sidecar). Decrypts DPAPI machine-scope blob.
        /// </summary>
        public async Task<string> RestoreAsync(string quarantineFilePath, string? destinationPath = null)
        {
            if (!File.Exists(quarantineFilePath))
                throw new FileNotFoundException("Quarantine file not found", quarantineFilePath);

            // v1.8.1: quarantine blob must live under the ACL-locked quarantine directory
            if (!SecurityValidation.IsPathWithinDirectory(quarantineFilePath, QuarantineDirectory))
                throw new InvalidOperationException("Restore denied: quarantine file is outside the quarantine directory.");

            if (string.IsNullOrEmpty(destinationPath))
            {
                var meta = quarantineFilePath + ".meta";
                if (File.Exists(meta) && SecurityValidation.IsPathWithinDirectory(meta, QuarantineDirectory))
                {
                    destinationPath = TryReadMetaPath(meta);
                }
                if (string.IsNullOrEmpty(destinationPath))
                {
                    ParseQuarantineMetadata(Path.GetFileName(quarantineFilePath), out _, out var originalName);
                    if (string.IsNullOrEmpty(originalName) || !SecurityValidation.IsSafeFilename(originalName))
                        throw new InvalidOperationException("No restore path recorded and could not parse a safe original name.");
                    destinationPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        "Downloads",
                        originalName);
                }
            }

            // Never restore into OS-critical paths (WRP / System32 / Windows)
            if (string.IsNullOrWhiteSpace(destinationPath) ||
                SecurityValidation.IsOsCriticalPath(destinationPath) ||
                destinationPath!.Contains(".."))
            {
                throw new InvalidOperationException("Restore denied: destination path is missing, traversal-like, or OS-critical.");
            }

            destinationPath = Path.GetFullPath(destinationPath);

            var vault = await FileNet48.ReadAllBytesAsync(quarantineFilePath);
            var plain = OpenVaultBlob(vault);

            var destDir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);

            await System.IO.FileNet48.WriteAllBytesAsync(destinationPath, plain);

            try
            {
                File.Delete(quarantineFilePath);
                var meta = quarantineFilePath + ".meta";
                if (File.Exists(meta)) File.Delete(meta);
            }
            catch { }

            return destinationPath;
        }

        public bool ParseQuarantineMetadata(string quarantineFileName, out string uniqueId, out string originalName)
        {
            uniqueId = string.Empty;
            originalName = string.Empty;

            var match = MetadataRegex.Match(quarantineFileName);
            if (match.Success && match.Groups.Count == 3)
            {
                uniqueId = match.Groups[1].Value;
                originalName = match.Groups[2].Value;
                return true;
            }
            return false;
        }

        /// <summary>Unwrap SENQ vault header (v2.3.8+) or legacy bare DPAPI blob.</summary>
        private static byte[] OpenVaultBlob(byte[] vault)
        {
            if (vault.Length > VaultMagic.Length && HasVaultMagic(vault))
            {
                var protectedBytes = new byte[vault.Length - VaultMagic.Length];
                Buffer.BlockCopy(vault, VaultMagic.Length, protectedBytes, 0, protectedBytes.Length);
                return ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
            }
            return ProtectedData.Unprotect(vault, null, DataProtectionScope.LocalMachine);
        }

        private static bool HasVaultMagic(byte[] vault)
        {
            for (int i = 0; i < VaultMagic.Length; i++)
            {
                if (vault[i] != VaultMagic[i]) return false;
            }
            return true;
        }

        /// <summary>Read .meta path: DPAPI-protected (current) or plain UTF-8 (legacy).</summary>
        private static string? TryReadMetaPath(string metaPath)
        {
            var raw = File.ReadAllBytes(metaPath);
            if (raw.Length == 0) return null;
            try
            {
                var plain = ProtectedData.Unprotect(raw, null, DataProtectionScope.LocalMachine);
                return System.Text.Encoding.UTF8.GetString(plain).Trim();
            }
            catch (CryptographicException)
            {
                return System.Text.Encoding.UTF8.GetString(raw).Trim();
            }
        }
    }
}
