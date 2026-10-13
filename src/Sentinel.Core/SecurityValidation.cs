using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public static class SecurityValidation
    {
        private static readonly Regex SafePathRegex = new(@"^[a-zA-Z]:\\[a-zA-Z0-9_\-\s\\\.%()\[\]]*$", RegexOptions.Compiled);
        private static readonly Regex SafeFileNameRegex = new(@"^[a-zA-Z0-9_\-\s\.]+\.[a-zA-Z0-9]+$", RegexOptions.Compiled);

        /// <summary>
        /// v2.2.0: Interactive user profile roots (LocalAppData, Roaming, Temp, Downloads, Desktop).
        /// SYSTEM services must not scan Environment.SpecialFolder.LocalApplicationData - that is
        /// the SYSTEM profile, not the logged-on user.
        /// </summary>
        public static List<string> EnumerateInteractiveUserWritableRoots()
        {
            var roots = new List<string>();
            try
            {
                var systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
                var usersDir = Path.Combine(systemRoot, "Users");
                if (!Directory.Exists(usersDir))
                    return roots;

                foreach (var userDir in Directory.GetDirectories(usersDir))
                {
                    var name = Path.GetFileName(userDir);
                    if (string.Equals(name, "Public", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "Default User", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "All Users", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith(".", StringComparison.Ordinal))
                        continue;

                    roots.Add(Path.Combine(userDir, "AppData", "Local"));
                    roots.Add(Path.Combine(userDir, "AppData", "Roaming"));
                    roots.Add(Path.Combine(userDir, "AppData", "Local", "Temp"));
                    roots.Add(Path.Combine(userDir, "Downloads"));
                    roots.Add(Path.Combine(userDir, "Desktop"));
                }

                var winTemp = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
                if (!string.IsNullOrEmpty(winTemp))
                    roots.Add(winTemp);
            }
            catch
            {
                // Best-effort
            }
            return roots;
        }

        public static bool ValidatePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                // Prevent path traversal
                if (path!.Contains("..")) return false;
                
                // Absolute path check
                if (!Path.IsPathRooted(path)) return false;
                
                // Format check
                return SafePathRegex.IsMatch(path);
            }
            catch
            {
                return false;
            }
        }

        public static bool ValidateFileName(string? fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return false;
            return SafeFileNameRegex.IsMatch(fileName!) && !fileName!.Contains("..");
        }

        public static bool ValidateIpAddress(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return IPAddress.TryParse(ip, out _);
        }



        private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
            "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
        };

        /// <summary>
        /// Validates a filename is safe: no path separators, no traversal, no reserved names,
        /// no null bytes, no dangerous characters.
        /// </summary>
        public static bool IsSafeFilename(string? filename)
        {
            if (string.IsNullOrWhiteSpace(filename)) return false;
            if (filename.Contains('\0')) return false;
            if (filename!.IndexOf('/') >= 0 || filename.Contains('\\')) return false;
            if (filename.Contains("..")) return false;

            // Dangerous characters
            foreach (var c in new[] { '<', '>', '|', '*', '?', '"', ':' })
                if (filename.Contains(c)) return false;

            // Windows reserved names
            var nameOnly = Path.GetFileNameWithoutExtension(filename);
            if (WindowsReservedNames.Contains(nameOnly)) return false;

            return true;
        }

        /// <summary>
        /// Checks if a full path is within the expected directory (prevents path traversal).
        /// </summary>
        public static bool IsPathWithinDirectory(string? fullPath, string? expectedDir)
        {
            if (string.IsNullOrWhiteSpace(fullPath) || string.IsNullOrWhiteSpace(expectedDir))
                return false;
            try
            {
                var normalizedPath = Path.GetFullPath(fullPath);
                var normalizedDir = Path.GetFullPath(expectedDir);
                if (!normalizedDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
                    normalizedDir += Path.DirectorySeparatorChar;
                return normalizedPath.StartsWith(normalizedDir);
            }
            catch { return false; }
        }

        /// <summary>
        /// Returns true if the IP is a private/reserved address (loopback, RFC1918, link-local).
        /// Treats null/empty as private (safe default).
        /// </summary>
        public static bool IsPrivateIpAddress(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return true;
            if (ip == "localhost" || ip == "::1") return true;
            if (!IPAddress.TryParse(ip, out var addr)) return true; // Unparseable = treat as private
            var bytes = addr.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 127) return true;                                          // 127.x.x.x
                if (bytes[0] == 10) return true;                                            // 10.x.x.x
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;       // 172.16-31.x.x
                if (bytes[0] == 192 && bytes[1] == 168) return true;                        // 192.168.x.x
                if (bytes[0] == 169 && bytes[1] == 254) return true;                        // 169.254.x.x
            }
            return false;
        }

        /// <summary>
        /// v1.6.3: Paths that must never be deleted or quarantined (WRP / OS integrity).
        /// Quarantining these (e.g. powershell.exe under System32) bricks the host.
        /// </summary>
        public static bool IsOsCriticalPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                var full = Path.GetFullPath(path);
                var resolved = SelfPathGuard.TryGetFinalPath(full);
                if (resolved != null)
                    full = resolved;
                var lower = full.ToLowerInvariant();

                // Entire Windows tree except Windows\Temp (user/installer scratch)
                var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(windows))
                {
                    var winRoot = Path.GetFullPath(windows).TrimEnd('\\') + "\\";
                    var winTemp = Path.Combine(windows, "Temp").ToLowerInvariant() + "\\";
                    if (lower.StartsWith(winRoot.ToLowerInvariant()) &&
                        !lower.StartsWith(winTemp))
                        return true;
                }

                // Defender / Windows Apps under Program Files
                if (lower.Contains(@"\program files\windows defender") ||
                    lower.Contains(@"\program files (x86)\windows defender") ||
                    lower.Contains(@"\program files\windowsapps\") ||
                    lower.Contains(@"\program files\windows security\") ||
                    lower.Contains(@"\program files\powershell\") || // store/pwsh install
                    lower.Contains(@"\program files (x86)\powershell\"))
                    return true;

                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// True when path is a stock Windows PowerShell / pwsh host binary.
        /// Used to demote AMSI false positives without ignoring impostor powershell.exe drops.
        /// </summary>
        public static bool IsSystemPowerShellPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                var lower = Path.GetFullPath(path).ToLowerInvariant();
                if (lower.Contains(@"\windows\system32\windowspowershell\") ||
                    lower.Contains(@"\windows\syswow64\windowspowershell\") ||
                    lower.Contains(@"\program files\powershell\") ||
                    lower.Contains(@"\program files (x86)\powershell\"))
                {
                    var name = Path.GetFileName(lower);
                    return name is "powershell.exe" or "powershell_ise.exe" or "pwsh.exe";
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>Validates a process ID is within a reasonable range.</summary>
        public static bool IsValidProcessId(int pid) => pid >= 1 && pid <= 999999;

        /// <summary>Validates a port number (1-65535).</summary>
        public static bool IsValidPort(int port) => port >= 1 && port <= 65535;

        /// <summary>Validates a timestamp is within a reasonable range (not far past or future).</summary>
        public static bool IsValidTimestamp(DateTime timestamp)
        {
            var utc = timestamp.ToUniversalTime();
            var now = DateTime.UtcNow;
            // Reject timestamps more than 365 days in the past
            if ((now - utc).TotalDays > 365) return false;
            // Reject timestamps more than 1 day in the future (clock skew tolerance)
            if ((utc - now).TotalDays > 1) return false;
            return true;
        }

        /// <summary>Checks if a string is safe (no injection characters).</summary>
        public static bool IsSafeString(string? input)
        {
            if (input == null) return false;
            if (string.IsNullOrEmpty(input)) return true;
            // v2.0.4 MED-2: Added &, ;, |, {, }, (, ) to prevent shell metacharacter injection
            foreach (var c in new[] { '<', '>', '\'', '`', '$', '&', ';', '|', '{', '}', '(', ')' })
                if (input.Contains(c)) return false;
            return true;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        public static bool SecureCompare(byte[]? a, byte[]? b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pFile;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        //  CryptCATAdmin P/Invoke for catalog signature verification 
        // Used as fallback when WinVerifyTrust fails for catalog-signed system files
        // (explorer.exe, powershell.exe, cmd.exe, etc.). These binaries don't have
        // embedded Authenticode signatures - they're signed via the Windows catalog
        // store and require explicit catalog lookup.

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminAcquireContext2(
            out IntPtr phCatAdmin,
            IntPtr pgSubsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm,
            IntPtr pStrongHashPolicy,
            int dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(
            IntPtr hCatAdmin,
            IntPtr hFile,
            ref int pcbHash,
            IntPtr pbHash,
            int dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin,
            IntPtr pbHash,
            int cbHash,
            int dwFlags,
            ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseCatalogContext(
            IntPtr hCatAdmin,
            IntPtr hCatInfo,
            int dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATAdminReleaseContext(
            IntPtr hCatAdmin,
            int dwFlags);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo,
            ref CATALOG_INFO psCatInfo,
            int dwFlags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_CATALOG_INFO
        {
            public int cbStruct;
            public int dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public int cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_CHOICE_CATALOG = 2;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const int WTD_LIFETIME_SIGNING_FLAG = 0x00000800;

        /// <summary>
        /// Verifies the Authenticode signature of a PE file using WinVerifyTrust.
        /// Falls back to Windows Catalog Store verification for catalog-signed system
        /// binaries (explorer.exe, powershell.exe, cmd.exe, etc.) using native
        /// CryptCATAdmin APIs - no PowerShell dependency, no PATH poisoning risk.
        ///
        /// Returns the Authenticode simple name (CN) or null if unsigned / unreadable.
        /// </summary>
        public static string? TryGetAuthenticodePublisher(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return null;
            try
            {
#pragma warning disable SYSLIB0057
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                var simple = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (!string.IsNullOrWhiteSpace(simple))
                    return simple;
                return string.IsNullOrWhiteSpace(cert.Subject) ? null : cert.Subject;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// True when both files are Authenticode-signed by the same publisher.
        /// Used to pin Sentinel.Agent to the same signer as Sentinel.Service.
        /// </summary>
        public static bool VerifySameAuthenticodePublisher(string fileA, string fileB)
        {
            var a = TryGetAuthenticodePublisher(fileA);
            var b = TryGetAuthenticodePublisher(fileB);
            return !string.IsNullOrEmpty(a) && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        // WinVerifyTrust / catalog hash maps the PE. Uncached calls on the 5s
        // file-watcher and module scan were the remaining hard pagefaults after WS pin.
        //
        // Tuple field meanings:
        //   Write    - file LastWriteTimeUtc (cache invalidation key)
        //   Length   - file Length           (cache invalidation key)
        //   Signed   - WinVerifyTrust result
        //   Cached   - wall-clock time this entry was inserted (for LRU trim)
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime Write, long Length, bool Signed, DateTime Cached)> AuthenticodeCache =
            new(StringComparer.OrdinalIgnoreCase);

        private const int AuthenticodeCacheMax = 20_000;
        private const int AuthenticodeCacheTrim = 2_000; // evict oldest 10 % when cap is hit

        private static void CacheAuthenticode(string path, DateTime writeUtc, long length, bool signed)
        {
            if (string.IsNullOrEmpty(path) || length < 0) return;
            AuthenticodeCache[path] = (writeUtc, length, signed, DateTime.UtcNow);
            if (AuthenticodeCache.Count > AuthenticodeCacheMax)
                TrimAuthenticodeCache();
        }

        private static readonly object _authenticodeTrimLock = new();

        private static void TrimAuthenticodeCache()
        {
            // Only one thread does the trim; others skip and let the next write retry.
            if (!System.Threading.Monitor.TryEnter(_authenticodeTrimLock))
                return;
            try
            {
                // Re-check inside the lock - another thread may have already trimmed.
                if (AuthenticodeCache.Count <= AuthenticodeCacheMax)
                    return;

                // Collect (path, insertedAt) pairs, sort oldest-first, remove the bottom 10 %.
                var snapshot = new List<(string Path, DateTime Cached)>(AuthenticodeCache.Count);
                foreach (var kv in AuthenticodeCache)
                    snapshot.Add((kv.Key, kv.Value.Cached));

                snapshot.Sort((a, b) => a.Cached.CompareTo(b.Cached));

                int toRemove = Math.Max(AuthenticodeCacheTrim, snapshot.Count - AuthenticodeCacheMax);
                for (int i = 0; i < toRemove && i < snapshot.Count; i++)
                    AuthenticodeCache.TryRemove(snapshot[i].Path, out _);
            }
            finally
            {
                System.Threading.Monitor.Exit(_authenticodeTrimLock);
            }
        }

        /// <summary>
        /// Returns true only if the signature is valid AND chains to a trusted root.
        /// </summary>
        public static bool VerifyAuthenticodeSignature(string filePath, Microsoft.Extensions.Logging.ILogger? logger = null)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            DateTime writeUtc = DateTime.MinValue;
            long length = -1;
            try
            {
                var info = new FileInfo(filePath);
                writeUtc = info.LastWriteTimeUtc;
                length = info.Length;
                if (AuthenticodeCache.TryGetValue(filePath, out var cached) &&
                    cached.Write == writeUtc && cached.Length == length)
                    return cached.Signed;
            }
            catch
            {
                /* fall through to verify */
            }

            IntPtr fileInfoPtr = IntPtr.Zero;
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_LIFETIME_SIGNING_FLAG
                };

                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                if (result == 0)
                {
                    CacheAuthenticode(filePath, writeUtc, length, true);
                    return true;
                }

                // FIX v1.5.6: Embedded Authenticode check failed - try catalog signature verification.
                // Many Windows system binaries (explorer.exe, powershell.exe, cmd.exe, conhost.exe,
                // svchost.exe, etc.) use catalog signatures rather than embedded Authenticode.
                // WinVerifyTrust with WTD_CHOICE_FILE only checks embedded signatures.
                // We now use the native CryptCATAdmin APIs to look up the file's hash in the
                // Windows catalog store and verify via WinVerifyTrust with WTD_CHOICE_CATALOG.
                //
                // SECURITY: This is a pure native P/Invoke path - no shell commands, no PATH
                // dependency, no risk of poisoning. The catalog store is protected by Windows
                // and only writable by TrustedInstaller.
                bool catalog = VerifyCatalogSignature(filePath, logger);
                CacheAuthenticode(filePath, writeUtc, length, catalog);
                return catalog;
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[SecurityValidation] Authenticode verification failed for '{Path}'", filePath);
                CacheAuthenticode(filePath, writeUtc, length, false);
                return false;
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPtr);
            }
        }

        /// <summary>
        /// Verifies a file's signature via the Windows Catalog Store using native CryptCATAdmin APIs.
        /// This handles system binaries that are catalog-signed rather than having embedded
        /// Authenticode signatures (explorer.exe, powershell.exe, cmd.exe, svchost.exe, etc.).
        ///
        /// Flow:
        ///   1. Acquire a catalog admin context (SHA-256)
        ///   2. Calculate the file's hash
        ///   3. Look up the hash in the system catalog store
        ///   4. If found, verify the catalog file itself via WinVerifyTrust (WTD_CHOICE_CATALOG)
        ///
        /// SECURITY: Pure native API path. The catalog store (%SystemRoot%\System32\catroot2)
        /// is ACL-protected and only writable by TrustedInstaller. An attacker cannot inject
        /// a fake catalog without kernel-level access or TrustedInstaller token - at which
        /// point they have full control anyway.
        /// </summary>
        private static bool VerifyCatalogSignature(string filePath, Microsoft.Extensions.Logging.ILogger? logger)
        {
            IntPtr hCatAdmin = IntPtr.Zero;
            IntPtr hFile = IntPtr.Zero;
            IntPtr hashPtr = IntPtr.Zero;

            try
            {
                // Step 1: Acquire catalog admin context with SHA-256
                if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                {
                    logger?.LogDebug("[SecurityValidation] CryptCATAdminAcquireContext2 failed for catalog verification");
                    return false;
                }

                // Step 2: Open the file and calculate its catalog hash
                hFile = CreateFileW(
                    filePath,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hFile == INVALID_HANDLE_VALUE)
                {
                    logger?.LogDebug("[SecurityValidation] Cannot open file for catalog hash: '{Path}'", filePath);
                    return false;
                }

                // First call: get required hash size
                int hashSize = 0;
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, IntPtr.Zero, 0);
                if (hashSize <= 0)
                {
                    logger?.LogDebug("[SecurityValidation] CryptCATAdminCalcHashFromFileHandle2 returned zero hash size");
                    return false;
                }

                // Second call: calculate the actual hash
                hashPtr = Marshal.AllocHGlobal(hashSize);
                if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, hashPtr, 0))
                {
                    logger?.LogDebug("[SecurityValidation] CryptCATAdminCalcHashFromFileHandle2 failed");
                    return false;
                }

                // Step 3: Look up the hash in the catalog store
                IntPtr hPrevCatInfo = IntPtr.Zero;
                IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashPtr, hashSize, 0, ref hPrevCatInfo);

                if (hCatInfo == IntPtr.Zero)
                {
                    // File hash not found in any catalog - genuinely unsigned
                    return false;
                }

                // Step 4: Get catalog file path and verify it with WinVerifyTrust
                try
                {
                    var catInfo = new CATALOG_INFO { cbStruct = Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                    {
                        return false;
                    }

                    // Build the member tag (hex-encoded hash) for the WINTRUST_CATALOG_INFO
                    var hashBytes = new byte[hashSize];
                    Marshal.Copy(hashPtr, hashBytes, 0, hashSize);
                    var memberTag = BitConverter.ToString(hashBytes).Replace("-", "");

                    // Verify the catalog signature via WinVerifyTrust with WTD_CHOICE_CATALOG
                    return VerifyCatalogWithWinVerifyTrust(catInfo.wszCatalogFile, memberTag, filePath, hFile, hashPtr, hashSize, hCatAdmin, logger);
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
            catch (Exception ex)
            {
                logger?.LogDebug(ex, "[SecurityValidation] Catalog signature verification failed for '{Path}'", filePath);
                return false;
            }
            finally
            {
                if (hashPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(hashPtr);
                if (hFile != IntPtr.Zero && hFile != INVALID_HANDLE_VALUE)
                    NativeProcessMemory.CloseHandle(hFile);
                if (hCatAdmin != IntPtr.Zero)
                    CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }

        /// <summary>
        /// Performs WinVerifyTrust verification using WTD_CHOICE_CATALOG to validate
        /// that the catalog file containing this binary's hash is itself properly signed
        /// and chains to a trusted root.
        /// </summary>
        private static bool VerifyCatalogWithWinVerifyTrust(
            string catalogFilePath, string memberTag, string filePath,
            IntPtr hFile, IntPtr hashPtr, int hashSize,
            IntPtr hCatAdmin, Microsoft.Extensions.Logging.ILogger? logger)
        {
            IntPtr catInfoPtr = IntPtr.Zero;
            try
            {
                var catWintrustInfo = new WINTRUST_CATALOG_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catalogFilePath,
                    pcwszMemberTag = memberTag,
                    pcwszMemberFilePath = filePath,
                    hMemberFile = hFile,
                    pbCalculatedFileHash = hashPtr,
                    cbCalculatedFileHash = hashSize,
                    pcCatalogContext = IntPtr.Zero,
                    hCatAdmin = hCatAdmin
                };

                catInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                Marshal.StructureToPtr(catWintrustInfo, catInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_CATALOG,
                    pFile = catInfoPtr, // pCatalog shares the union offset with pFile
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_LIFETIME_SIGNING_FLAG
                };

                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                // AUDIT v1.5.6 (BT-MEDIUM-1): Close the trust provider state to prevent
                // internal wintrust.dll memory leaks. Required per Windows SDK documentation
                // after any WTD_STATEACTION_VERIFY call.
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                if (result == 0)
                {
                    logger?.LogDebug("[SecurityValidation] Catalog-signed verification succeeded for '{Path}' via catalog '{Catalog}'",
                        filePath, catalogFilePath);
                    return true;
                }

                logger?.LogDebug("[SecurityValidation] Catalog WinVerifyTrust returned 0x{Result:X8} for '{Path}'",
                    result, filePath);
                return false;
            }
            finally
            {
                if (catInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(catInfoPtr);
            }
        }

        //  File access P/Invoke for catalog hash calculation 

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, System.Text.StringBuilder lpExeName, ref int lpdwSize);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        /// <summary>
        /// Full image path via QUERY_LIMITED only (no VM_READ). Open uses runtime-resolved API.
        /// Prefer this over Process.MainModule / Process.Modules.
        /// </summary>
        public static string? GetProcessImagePath(int pid)
        {
            IntPtr hProcess = NativeProcessMemory.OpenRemoteHandle(PROCESS_QUERY_LIMITED_INFORMATION, pid);
            if (hProcess == IntPtr.Zero) return null;
            try
            {
                var builder = new System.Text.StringBuilder(1024);
                int size = builder.Capacity;
                if (QueryFullProcessImageName(hProcess, 0, builder, ref size))
                    return builder.ToString();
            }
            catch { }
            finally
            {
                NativeProcessMemory.CloseHandle(hProcess);
            }
            return null;
        }

        /// <summary>
        /// Whether remote process-memory inspection is allowed for this PID.
        ///
        /// Workaround (not a disable): Denuvo/anti-cheat games self-terminate on
        /// PROCESS_VM_READ - skip those paths only. All other processes remain fully scannable.
        /// Prefer <see cref="NativeProcessMemory"/> for VM_READ so APIs are not PE imports.
        /// </summary>
        public static bool MayInspectProcessMemory(int pid, string? imagePath = null)
            => NativeProcessMemory.CanInspect(pid, imagePath);

        /// <summary>
        /// Legacy overload: evidence flag always allows non-game PIDs (defenses stay armed).
        /// </summary>
        public static bool MayInspectProcessMemory(bool hasIndependentMaliciousEvidence)
            => true; // defenses stay on; game skip is path-based via CanInspect/IsGameOrAntiCheatPath

        /// <summary>
        /// True when <paramref name="path"/> lives under a user profile, Temp, Downloads,
        /// Desktop, Documents, or Public. Used to refuse reputation-skip / trust grants
        /// for substring "game" matches (v2.2.0: `%AppData%\steamapps\common\` is not Steam).
        /// </summary>
        public static bool IsUserProfileOrStagingPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path!.ToLowerInvariant().Replace('/', '\\');

            // Windows Store / Xbox packages are under Program Files\WindowsApps - not a user profile.
            if (lower.Contains(@"\windowsapps\"))
                return false;

            if (lower.Contains(@"\temp\") ||
                lower.Contains(@"\downloads\") ||
                lower.Contains(@"\desktop\") ||
                lower.Contains(@"\documents\") ||
                lower.Contains(@"\appdata\"))
                return true;

            // C:\Users\<name>\... except the Public/Default folders we already caught via desktop/documents
            var usersNeedle = @"\users\";
            var idx = lower.IndexOf(usersNeedle, StringComparison.Ordinal);
            if (idx >= 0)
            {
                var after = lower.Substring(idx + usersNeedle.Length);
                // \Users\Public\... still staging; \Users\Default\ too.
                return true;
            }

            return false;
        }

        /// <summary>
        /// v2.2.0: Reputation / hash-skip for entertainment binaries. Requires a game-tree
        /// fragment AND must not be under a user-writable staging path. Memory-inspection
        /// skip may still use <see cref="IsGameOrAntiCheatPath"/> (Denuvo on D:\ is fine;
        /// reputation skip is the trust grant).
        /// </summary>
        public static bool ShouldSkipReputationForGamePath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (IsUserProfileOrStagingPath(path)) return false;
            return IsGameOrAntiCheatPath(path);
        }

        /// <summary>
        /// Identifies game / launcher / anti-cheat install trees so scanners can skip
        /// even QUERY-level work when unnecessary, and so response code can avoid
        /// collateral on interactive entertainment workloads.
        /// Path-substring only - never a sole basis for trust of unknown binaries.
        /// v2.2.0: still rejects Temp/Downloads; reputation skip uses
        /// <see cref="ShouldSkipReputationForGamePath"/> which also rejects user profiles.
        /// </summary>
        public static bool IsGameOrAntiCheatPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path!.ToLowerInvariant();

            // Never treat staging dirs as "game" even if renamed steam/epic folders.
            // Use the authoritative user-writable-drop set (ModuleIdentity.IsUserWritableDrop)
            // so this rejects every known drop - Temp/Downloads/Desktop/Users\Public,
            // AppData overlays, AND the writable subdirs under the Windows tree - not just the
            // three checked inline before. A game-folder substring inside a writable drop
            // (e.g. C:\Users\Public\steamapps\common\evil.exe) must NOT read as a game.
            // \appdata\local\programs\ hosts legitimately-installed per-user apps (some Xbox /
            // Epic / launcher installs land here) and is the one AppData location this check has
            // always allowed; keep that carve-out. Every OTHER writable drop is rejected.
            bool perUserProgramsInstall = lower.Contains(@"\appdata\local\programs\");
            if (!perUserProgramsInstall &&
                (ModuleIdentity.IsUserWritableDrop(path) ||
                 lower.Contains(@"\temp\") ||
                 lower.Contains(@"\downloads\") ||
                 lower.Contains(@"\appdata\local\temp\")))
                return false;

            bool fragment =
                   lower.Contains(@"\steamapps\common\") ||
                   lower.Contains(@"\steamapps\workshop\") ||
                   lower.Contains(@"\steam\steamapps\") ||
                   lower.Contains(@"\program files (x86)\steam\") ||
                   lower.Contains(@"\program files\steam\") ||
                   lower.Contains(@"\gog games\") ||
                   lower.Contains(@"\gog galaxy\") ||
                   lower.Contains(@"\epic games\") ||
                   lower.Contains(@"\ea games\") ||
                   lower.Contains(@"\origin games\") ||
                   lower.Contains(@"\ubisoft\") ||
                   lower.Contains(@"\ubisoft game launcher\") ||
                   lower.Contains(@"\riot games\") ||
                   lower.Contains(@"\battle.net\") ||
                   lower.Contains(@"\blizzard\") ||
                   lower.Contains(@"\xboxgames\") ||
                   lower.Contains(@"\xbox games\") ||
                   lower.Contains(@"\windowsapps\") ||
                   lower.Contains(@"\gamingservices\") ||
                   lower.Contains(@"\xboxapp\") ||
                   lower.Contains(@"\gamebar\") ||
                   lower.Contains(@"\microsoft.xbox") ||
                   lower.Contains(@"\microsoft.gamingapp") ||
                   lower.Contains(@"\obs-studio\") ||
                   lower.Contains(@"\obs studio\") ||
                   lower.Contains(@"\streamlabs\") ||
                   lower.Contains(@"\nvidia corporation\") ||
                   lower.Contains(@"\sports interactive\") ||
                   lower.Contains(@"\football manager\") ||
                   lower.Contains(@"\sega\") ||
                   lower.Contains(@"\rockstar games\") ||
                   lower.Contains(@"\bethesda\") ||
                   lower.Contains(@"\paradox interactive\") ||
                   lower.Contains(@"\easyanticheat\") ||
                   lower.Contains(@"\battleye\") ||
                   lower.Contains(@"\vanguard\") ||
                   lower.Contains(@"\denuvo\") ||
                   lower.Contains(@"\common redist\") ||
                   lower.Contains(@"\steamworks shared\") ||
                   lower.Contains(@"\world of warcraft\") ||
                   lower.Contains(@"\blizzard entertainment\");
            if (!fragment)
                return false;

            // v2.5.3: C:\Users\attacker\epic games\malware.exe is not Epic.
            // Steam libraries under the user profile still have \steamapps\common\.
            // AppData\Roaming\steamapps is an impostor (reputation tests).
            if (lower.Contains(@"\appdata\") &&
                !lower.Contains(@"\appdata\local\programs\"))
                return false;
            if (lower.Contains(@"\users\") &&
                !lower.Contains(@"\steamapps\common\") &&
                !lower.Contains(@"\xboxgames\") &&
                !lower.Contains(@"\windowsapps\") &&
                !lower.Contains(@"\appdata\local\programs\"))
                return false;

            return true;
        }

        /// <summary>
        /// True when the image is the real System32/SysWOW64 copy - not svchost.exe in Temp.
        /// </summary>
        public static bool IsWindowsSystemImage(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path!.ToLowerInvariant();
            if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\"))
                return false;
            return lower.Contains(@"\windows\system32\") ||
                   lower.Contains(@"\windows\syswow64\");
        }

        /// <summary>
        /// Process basenames that commonly host Denuvo / anti-cheat and self-terminate
        /// on PROCESS_VM_READ. Used when image path is not yet resolvable (startup race).
        /// Name-only - not trust; only skips memory inspection, never authorizes allow.
        /// </summary>
        private static readonly HashSet<string> GameOrAntiCheatProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // Football Manager family
            "fm", "fm2015", "fm2016", "fm2017", "fm2018", "fm2019", "fm2020",
            "fm2021", "fm2022", "fm2023", "fm2024", "fm2025", "fm2026",
            "football manager",
            // Common launchers / overlays / anti-cheat agents
            "steam", "steamwebhelper", "gameoverlayui", "steamerrorreporter",
            "steamservice", "steamsetup",
            "easyanticheat", "easyanticheat_eos", "beclient", "beclient_x64",
            "beservice", "vgc", "vgtray", "riotclientservices",
            "epicgameslauncher", "eadesktop", "ubisoftconnect",
            "galaxyclient",
            "obs64", "obs32", "obs", "obs-browser-page", "obs-ffmpeg-mux",
            "streamlabs obs", "streamlabs",
            "gamebar", "gamebarftw", "xboxapp", "xboxpcappft", "gamingservices",
            "gamingoverlay", "xboxgamebar"
        };

        /// <summary>
        /// True if path and/or live process name indicate a game / anti-cheat workload
        /// that must not receive PROCESS_VM_READ (Denuvo self-exit).
        /// </summary>
        public static bool IsGameOrAntiCheatProcess(int pid, string? imagePath = null)
        {
            if (IsGameOrAntiCheatPath(imagePath))
                return true;

            // Resolve the image path once so the name-set skip can be anchored.
            imagePath ??= GetProcessImagePath(pid);

            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                var name = proc.ProcessName;
                if (!string.IsNullOrEmpty(name) && GameOrAntiCheatProcessNames.Contains(name))
                {
                    // The name set exists for the startup race where the image path has not yet
                    // resolved (Denuvo titles self-exit on VM_READ). A game NAME is attacker-
                    // controllable, so if the path IS resolvable it must not be a user-writable
                    // drop - "vgc.exe" or "steam.exe" sitting in Temp/Downloads/AppData is a
                    // disguised implant, and skipping its memory inspection would only help the
                    // attacker. Honor the name skip only when the path is genuinely unresolved.
                    if (string.IsNullOrEmpty(imagePath) || !ModuleIdentity.IsUserWritableDrop(imagePath))
                        return true;
                }
            }
            catch { }

            return IsGameOrAntiCheatPath(imagePath);
        }

        /// <summary>
        /// Name-only check against the known game/anti-cheat process name set.
        /// Used by EphemeralProcessMonitor to suppress Prefetch false positives
        /// on games that exit quickly (Denuvo crash, anti-cheat self-exit).
        /// NOT a trust grant - only suppresses "ephemeral process" alerts.
        /// </summary>
        public static bool IsKnownGameProcessName(string? processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            return GameOrAntiCheatProcessNames.Contains(processName!);
        }
    }
}
