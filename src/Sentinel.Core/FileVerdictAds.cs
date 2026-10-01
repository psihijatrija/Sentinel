using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Sentinel.Core
{
    public class FileVerdictAds
    {
        private readonly byte[] _hmacKey;
        private readonly string _secureDir = null!;
        private readonly bool _isCustomDir;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            IntPtr ppszDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        public FileVerdictAds(string? customSecureDir = null)
        {
            if (!string.IsNullOrWhiteSpace(customSecureDir))
            {
                _secureDir = customSecureDir!;
                _isCustomDir = true;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _secureDir = Path.Combine(programData, "Sentinel", "Secure");
                _isCustomDir = false;
            }

            _hmacKey = GetOrCreateHmacKey();
        }

        private byte[] GetOrCreateHmacKey()
        {
            var keyFilePath = Path.Combine(_secureDir, "ads_hmac.key");
            try
            {
                var dirInfo = new DirectoryInfo(_secureDir);
                if (!dirInfo.Exists)
                {
                    dirInfo.Create();
                }

                // Apply secure ACLs to restrict access to local SYSTEM and Administrators only
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var systemSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                // v2.2.0: Admins ReadAndExecute - do not reopen Secure for admin rewrite of HMAC keys.
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                if (_isCustomDir)
                {
                    var currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                    if (currentUserSid != null)
                    {
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            currentUserSid,
                            System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                            System.Security.AccessControl.PropagationFlags.None,
                            System.Security.AccessControl.AccessControlType.Allow));
                    }
                }

                dirInfo.SetAccessControl(security);
            }
            catch { }

            try
            {
                if (File.Exists(keyFilePath))
                {
                    var encryptedBytes = File.ReadAllBytes(keyFilePath);
                    var rawKey = Unprotect(encryptedBytes);
                    if (rawKey != null && rawKey.Length == 32)
                    {
                        return rawKey;
                    }
                }
            }
            catch { }

            // Create new key
            var newKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(newKey);
            }

            try
            {
                var encryptedBytes = Protect(newKey);
                File.WriteAllBytes(keyFilePath, encryptedBytes);
            }
            catch { }

            return newKey;
        }

        private static byte[] Protect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT();

            try
            {
                // Remove CRYPTPROTECT_LOCAL_MACHINE to restrict decryption to the current user (SYSTEM in service context)
                if (CryptProtectData(ref dataIn, "SentinelAdsKey", ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                throw new CryptographicException("DPAPI encryption failed");
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        private static byte[]? Unprotect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT();

            try
            {
                // Remove CRYPTPROTECT_LOCAL_MACHINE to restrict decryption to the current user (SYSTEM in service context)
                if (CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        public HashVerdict GetVerdict(string filePath, string expectedSha256)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(expectedSha256))
                    return HashVerdict.Unknown;

                // Target may be gone; still allow cache lookup by hash
                var text = TryReadVerdictPayload(filePath, expectedSha256);
                if (string.IsNullOrWhiteSpace(text)) return HashVerdict.Unknown;

                return ParseAndValidatePayload(text!, expectedSha256);
            }
            catch
            {
                // Degrade gracefully
            }
            return HashVerdict.Unknown;
        }

        public void SetVerdict(string filePath, string fileSha256, HashVerdict verdict)
        {
            try
            {
                if (string.IsNullOrEmpty(fileSha256))
                    return;

                // Prefer content-addressed store even if the file disappeared mid-scan
                var timestampTicks = DateTime.UtcNow.Ticks;
                var payloadStr = $"{verdict}|{timestampTicks}|{fileSha256.ToLowerInvariant()}";
                var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);

                byte[] signature;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    signature = hmac.ComputeHash(payloadBytes);
                }
                var signatureHex = ConvertHex.ToHexString(signature);

                var finalPayload = $"{payloadStr}|{signatureHex}";
                TryWriteVerdictPayload(filePath, fileSha256, finalPayload);
            }
            catch
            {
                // Degrade gracefully
            }
        }

        /// <summary>
        /// Legacy per-file pollution (must never be written again). Still read for migration.
        /// </summary>
        internal static string LegacySidecarPath(string filePath)
            => filePath + ".sentinel_verdict";

        private static string AdsPath(string filePath)
            => filePath + ":sentinel_verdict";

        /// <summary>
        /// Central content-addressed cache under ProgramData\Sentinel\Secure\VerdictCache.
        /// Avoids sprinkling *.sentinel_verdict next to every scanned PE on every drive.
        /// </summary>
        private string CentralCachePath(string fileSha256)
        {
            var hash = fileSha256.ToLowerInvariant();
            if (hash.Length < 2)
                hash = hash.PadRight(2, '0');
            return Path.Combine(_secureDir, "VerdictCache", hash.Substring(0, 2), hash + ".verdict");
        }

        /// <summary>Expose cache root for tests / cleanup tools.</summary>
        public string VerdictCacheDirectory => Path.Combine(_secureDir, "VerdictCache");

        /// <summary>
        /// Marker written after a successful one-shot legacy-sidecar purge (upgrade cleanup).
        /// </summary>
        public string LegacySidecarPurgeMarkerPath =>
            Path.Combine(_secureDir, "legacy_sidecar_purge_1_9_2.done");

        /// <summary>
        /// One-shot (per machine): walk fixed local drives and delete every visible
        /// <c>*.sentinel_verdict</c> sidecar left by pre-1.8.8 builds. Central
        /// <see cref="VerdictCacheDirectory"/> entries are left intact.
        /// Safe to call repeatedly; subsequent calls no-op when the marker exists
        /// unless <paramref name="force"/> is true.
        /// </summary>
        /// <returns>Number of sidecar files deleted (0 if skipped via marker).</returns>
        public int PurgeLegacySidecarsOnce(
            bool force = false,
            Action<string>? log = null,
            CancellationToken cancellationToken = default)
        {
            var marker = LegacySidecarPurgeMarkerPath;
            if (!force && File.Exists(marker))
            {
                log?.Invoke("Legacy *.sentinel_verdict purge already completed (marker present).");
                return 0;
            }

            var deleted = PurgeLegacySidecarFiles(roots: null, log, cancellationToken);

            try
            {
                var dir = Path.GetDirectoryName(marker);
                if (dir != null && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllText(marker,
                    $"utc={DateTime.UtcNow:O}{Environment.NewLine}deleted={deleted}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                log?.Invoke("Could not write purge marker: " + ex.Message);
            }

            return deleted;
        }

        /// <summary>
        /// Force-delete all <c>*.sentinel_verdict</c> files under <paramref name="roots"/>
        /// (or all ready fixed drives when roots is null). Does not touch central VerdictCache.
        /// </summary>
        public static int PurgeLegacySidecarFiles(
            IEnumerable<string>? roots = null,
            Action<string>? log = null,
            CancellationToken cancellationToken = default)
        {
            var deleted = 0;
            IEnumerable<string> scanRoots;
            if (roots != null)
            {
                scanRoots = roots;
            }
            else
            {
                var drives = new List<string>();
                try
                {
                    foreach (var d in DriveInfo.GetDrives())
                    {
                        try
                        {
                            if (d.DriveType != DriveType.Fixed || !d.IsReady)
                                continue;
                            drives.Add(d.RootDirectory.FullName);
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    log?.Invoke("Drive enumeration failed: " + ex.Message);
                }
                scanRoots = drives;
            }

            foreach (var root in scanRoots)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;
                if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                    continue;

                log?.Invoke("Purging legacy *.sentinel_verdict under " + root);
                try
                {
                    WalkAndDeleteLegacySidecars(root, ref deleted, log, cancellationToken);
                }
                catch (Exception ex)
                {
                    log?.Invoke("Purge walk failed for " + root + ": " + ex.Message);
                }
            }

            log?.Invoke($"Legacy *.sentinel_verdict purge finished: deleted={deleted}");
            return deleted;
        }

        private static readonly string[] SkipDirNameExact =
        {
            "System Volume Information",
            "$Recycle.Bin",
            "Recovery",
            "Config.Msi",
            "WindowsApps",
        };

        private static readonly string[] SkipDirNameContains =
        {
            // Avoid multi-hour / high-IO walks that do not host user pollution
            "\\Windows\\WinSxS",
            "\\Windows\\Installer",
            "\\Windows\\SoftwareDistribution",
            "\\Windows\\servicing",
            "\\Windows\\CSC",
            "\\$Windows.~BT",
            "\\$Windows.~WS",
        };

        private static bool ShouldSkipDirectory(string path)
        {
            try
            {
                var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                foreach (var skip in SkipDirNameExact)
                {
                    if (string.Equals(name, skip, StringComparison.OrdinalIgnoreCase))
                        return true;
                }

                // Normalize for contains checks
                var full = path.Replace('/', '\\');
                foreach (var skip in SkipDirNameContains)
                {
                    if (full.IndexOf(skip, StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }

                var di = new DirectoryInfo(path);
                if ((di.Attributes & FileAttributes.ReparsePoint) != 0)
                    return true;
            }
            catch
            {
                return true;
            }
            return false;
        }

        private static void WalkAndDeleteLegacySidecars(
            string directory,
            ref int deleted,
            Action<string>? log,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;
            if (ShouldSkipDirectory(directory))
                return;

            try
            {
                foreach (var file in Directory.EnumerateFiles(directory, "*.sentinel_verdict"))
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;
                    try
                    {
                        // Extra guard: only delete the exact legacy suffix pollution
                        if (!file.EndsWith(".sentinel_verdict", StringComparison.OrdinalIgnoreCase))
                            continue;
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                        deleted++;
                        if (deleted <= 20 || deleted % 100 == 0)
                            log?.Invoke($"Deleted legacy verdict sidecar ({deleted}): {file}");
                    }
                    catch
                    {
                        // locked / ACL - best effort
                    }
                }
            }
            catch
            {
                // no list permission
            }

            string[]? children = null;
            try
            {
                children = Directory.GetDirectories(directory);
            }
            catch
            {
                return;
            }

            foreach (var child in children)
            {
                if (cancellationToken.IsCancellationRequested)
                    return;
                WalkAndDeleteLegacySidecars(child, ref deleted, log, cancellationToken);
            }
        }

        private void TryWriteVerdictPayload(string filePath, string fileSha256, string payload)
        {
            // 1) Always write central cache (no user-directory pollution)
            try
            {
                var cachePath = CentralCachePath(fileSha256);
                var dir = Path.GetDirectoryName(cachePath);
                if (dir != null && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllText(cachePath, payload, Encoding.UTF8);
            }
            catch
            {
                // continue - try ADS if path available
            }

            // 2) Optional NTFS ADS on the target (invisible; not a separate visible file)
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return;

            try
            {
                var ads = AdsPath(filePath);
                using (var fs = new FileStream(ads, FileMode.Create, FileAccess.Write,
                    FileShare.ReadWrite | FileShare.Delete))
                using (var sw = new StreamWriter(fs, Encoding.UTF8))
                {
                    sw.Write(payload);
                }
            }
            catch
            {
                // ADS unavailable (FAT, some network shares, path validation) - central cache is enough
            }

            // 3) NEVER write adjacent .sentinel_verdict sidecars (legacy pollution)
            // If a legacy sidecar exists, remove it after successful central write.
            try
            {
                var side = LegacySidecarPath(filePath);
                if (File.Exists(side))
                    File.Delete(side);
            }
            catch
            {
                // best-effort cleanup
            }
        }

        private string? TryReadVerdictPayload(string filePath, string expectedSha256)
        {
            // 1) Central cache (primary)
            try
            {
                var cachePath = CentralCachePath(expectedSha256);
                if (File.Exists(cachePath))
                    return File.ReadAllText(cachePath, Encoding.UTF8);
            }
            catch
            {
                // fall through
            }

            // 2) NTFS ADS on the target
            if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
            {
                try
                {
                    var ads = AdsPath(filePath);
                    using (var fs = new FileStream(ads, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete))
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        return sr.ReadToEnd();
                    }
                }
                catch
                {
                    // fall through
                }

                // 3) Legacy sidecar - migrate into central cache, then delete
                try
                {
                    var side = LegacySidecarPath(filePath);
                    if (File.Exists(side))
                    {
                        var text = File.ReadAllText(side, Encoding.UTF8);
                        // Only migrate if payload validates for this hash
                        if (ParseAndValidatePayload(text, expectedSha256) != HashVerdict.Unknown)
                        {
                            try
                            {
                                var cachePath = CentralCachePath(expectedSha256);
                                var dir = Path.GetDirectoryName(cachePath);
                                if (dir != null && !Directory.Exists(dir))
                                    Directory.CreateDirectory(dir);
                                File.WriteAllText(cachePath, text, Encoding.UTF8);
                            }
                            catch { }

                            try { File.Delete(side); } catch { }
                        }
                        return text;
                    }
                }
                catch
                {
                    // fall through
                }
            }

            return null;
        }

        private HashVerdict ParseAndValidatePayload(string text, string expectedSha256)
        {
            var parts = text.Split('|');
            if (parts.Length != 4) return HashVerdict.Unknown;

            var verdictStr = parts[0];
            var timestampStr = parts[1];
            var sha256 = parts[2];
            var signatureHex = parts[3];

            if (!string.Equals(expectedSha256, sha256, StringComparison.OrdinalIgnoreCase))
                return HashVerdict.Unknown;

            var payloadStr = $"{verdictStr}|{timestampStr}|{sha256.ToLowerInvariant()}";
            var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);

            byte[] computedSignature;
            using (var hmac = new HMACSHA256(_hmacKey))
            {
                computedSignature = hmac.ComputeHash(payloadBytes);
            }
            var signatureBytes = ConvertHex.FromHexString(signatureHex);

            if (!SecurityValidation.SecureCompare(computedSignature, signatureBytes))
                return HashVerdict.Unknown;

            if (long.TryParse(timestampStr, out var ticks))
            {
                var signedAt = new DateTime(ticks, DateTimeKind.Utc);
                if (DateTime.UtcNow - signedAt > TimeSpan.FromDays(365) || signedAt > DateTime.UtcNow.AddHours(1))
                    return HashVerdict.Unknown;
            }
            else
            {
                return HashVerdict.Unknown;
            }

            if (Enum.TryParse<HashVerdict>(verdictStr, out var verdict))
                return verdict;

            return HashVerdict.Unknown;
        }
    }
}
