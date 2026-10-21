using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 RT-HIGH-2 - Hardlink-aware self-path exclusion.
    /// Path.GetFullPath alone does not resolve hardlinks; an attacker could hardlink
    /// malware to a path under the install directory string-prefix and skip reputation.
    /// We compare final NT path when available, plus require our known binary names.
    /// </summary>
    public static class SelfPathGuard
    {
        private static readonly string[] KnownSelfNames =
        {
            "Sentinel.Service.exe",
            "Sentinel.Agent.exe",
            "NanoAV.exe",
            "NanoAV.dll",
            "Sentinel.Core.dll",
            "Sentinel.Service.dll",
            "Sentinel.Agent.dll",
        };

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandleW(
            IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint FILE_READ_ATTRIBUTES = 0x80;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint FILE_SHARE_WRITE = 0x2;
        private const uint FILE_SHARE_DELETE = 0x4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        /// <summary>
        /// True when path is a known Sentinel binary under the install directory
        /// (final path when resolvable). Hardlink outside install with our name is NOT trusted.
        /// </summary>
        public static bool IsSentinelSelfBinary(string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath))
                return false;

            string normalized;
            try
            {
                normalized = Path.GetFullPath(imagePath);
            }
            catch
            {
                return false;
            }

            string installDir;
            try
            {
                installDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
            }
            catch
            {
                return false;
            }

            string finalInstall = TryGetFinalPath(installDir.TrimEnd('\\')) ?? installDir.TrimEnd('\\');
            if (!finalInstall.EndsWith("\\", StringComparison.Ordinal))
                finalInstall += "\\";

            // v2.0.8: When final NT path resolves, require it under install (hardlink-safe).
            // Only fall back to Path.GetFullPath when final path is unavailable.
            string? resolvedPath = TryGetFinalPath(normalized);
            bool underInstall;
            if (resolvedPath != null)
            {
                underInstall = resolvedPath.StartsWith(finalInstall, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                underInstall = normalized.StartsWith(installDir, StringComparison.OrdinalIgnoreCase);
            }
            if (!underInstall)
                return false;

            var fileName = Path.GetFileName(normalized);
            foreach (var name in KnownSelfNames)
            {
                if (fileName.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>The original NanoAV bootstrap copies its EXE to this DLL path.
        /// Trust only an identical copy of the co-installed payload, never the filename alone.</summary>
        public static bool IsNanoAvRuntimeCopy(string? path)
            => MatchesNanoAvRuntimeCopy(path, Path.Combine(AppContext.BaseDirectory, "NanoAV.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NanoAV", "NanoAV.dll"));

        internal static bool MatchesNanoAvRuntimeCopy(string? path, string source, string expected)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                if (!Path.GetFullPath(path).Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase)) return false;
                if (!File.Exists(source) || !File.Exists(path)) return false;
                using var first = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var second = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (first.Length != second.Length || first.Length > 16 * 1024 * 1024) return false;
                using var sha = System.Security.Cryptography.SHA256.Create();
                return System.Linq.Enumerable.SequenceEqual(sha.ComputeHash(first), sha.ComputeHash(second));
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            { return false; }
        }

        public static bool IsInstalledNanoAvBinary(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            string name = Path.GetFileName(path);
            return (name.Equals("NanoAV.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("NanoAV.dll", StringComparison.OrdinalIgnoreCase)) && IsSentinelSelfBinary(path);
        }

        /// <summary>
        /// True when target path is under Sentinel install (directory-level exclusion).
        /// Uses final path when available; still requires the path to resolve under install.
        /// </summary>
        public static bool IsUnderInstallDirectory(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            try
            {
                var normalized = Path.GetFullPath(path);
                var installDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
                var finalInstall = TryGetFinalPath(installDir.TrimEnd('\\')) ?? installDir.TrimEnd('\\');
                if (!finalInstall.EndsWith("\\", StringComparison.Ordinal))
                    finalInstall += "\\";

                // v2.0.8: prefer final path; no OR-fallback that ignores resolution
                var resolved = TryGetFinalPath(normalized);
                if (resolved != null)
                    return resolved.StartsWith(finalInstall, StringComparison.OrdinalIgnoreCase);
                return normalized.StartsWith(installDir, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        internal static string? TryGetFinalPath(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path) && !Directory.Exists(path))
                return null;

            IntPtr handle = INVALID_HANDLE_VALUE;
            try
            {
                handle = CreateFileW(
                    path,
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (handle == INVALID_HANDLE_VALUE || handle == IntPtr.Zero)
                    return null;

                var sb = new StringBuilder(1024);
                uint len = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
                if (len == 0 || len >= sb.Capacity)
                    return null;

                var result = sb.ToString();
                // Strip \\?\ or \??\ prefix
                if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    result = @"\\" + result.Substring(8);
                else if (result.StartsWith(@"\\?\", StringComparison.Ordinal))
                    result = result.Substring(4);

                return result;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (handle != INVALID_HANDLE_VALUE && handle != IntPtr.Zero)
                    CloseHandle(handle);
            }
        }
    }
}
