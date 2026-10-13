using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// Shared installer / packager heuristics used by PPID spoof, ransomware IO,
    /// ephemeral process, and token monitors to avoid treating official installs as malware.
    /// Name patterns alone are never sufficient for kill decisions - callers must also
    /// require Authenticode or path context where trust is granted.
    /// </summary>
    public static class InstallerHeuristics
    {
        /// <summary>
        /// Git-2.47.0-64-bit, ChromeSetup, VSCodeUserSetup, python-3.12.0-amd64, etc.
        /// </summary>
        public static bool LooksLikeInstallerName(string? processName, string? imagePath = null)
        {
            // Normalize to lowercase so name matching is case-insensitive on net48
            // (string.IndexOf/StartsWith without StringComparison are ordinal case-sensitive).
            var n = StringNet48.ReplaceIgnoreCase(processName ?? "", ".exe", "").ToLowerInvariant();
            if (string.IsNullOrEmpty(n) && !string.IsNullOrEmpty(imagePath))
                n = (Path.GetFileNameWithoutExtension(imagePath) ?? "").ToLowerInvariant();

            if (string.IsNullOrEmpty(n)) return false;

            if (IsDirectXOrRuntimeRedist(n, imagePath))
                return true;

            if (n.IndexOf("setup", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("install", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("update", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("unins", StringComparison.Ordinal) >= 0 ||
                n.StartsWith("git-", StringComparison.Ordinal) ||
                n.StartsWith("git_", StringComparison.Ordinal) ||
                n.Equals("git", StringComparison.Ordinal) ||
                n.StartsWith("node-v", StringComparison.Ordinal) ||
                n.StartsWith("python-", StringComparison.Ordinal) ||
                (n.StartsWith("go", StringComparison.Ordinal) && n.IndexOf("windows", StringComparison.Ordinal) >= 0) ||
                n.IndexOf("vscode", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("docker", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("chrome", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("firefox", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("edge", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("brave", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("dotnet", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("jdk", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("jre", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("msiexec", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("windowsdesktop-runtime", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("vcredist", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("sentinelsetup", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("finalizer", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("steamsetup", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("steamservice", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("xbox", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("gamingservices", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("windowsgaming", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("obs-studio", StringComparison.Ordinal) >= 0 ||
                n.IndexOf("obs studio", StringComparison.Ordinal) >= 0)
                return true;

            // Product-1.2.3-64-bit / Product-x64 / Product-amd64
            if (Regex.IsMatch(n, @"-\d+(\.\d+)+", RegexOptions.CultureInvariant) &&
                (n.Contains("64") ||
                 n.Contains("86") ||
                 n.Contains("arm") ||
                 n.Contains("bit") ||
                 n.Contains("amd64") ||
                 n.Contains("x64")))
                return true;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var file = (Path.GetFileNameWithoutExtension(imagePath) ?? "").ToLowerInvariant();
                if (!string.IsNullOrEmpty(file) &&
                    !file.Equals(n, StringComparison.Ordinal) &&
                    LooksLikeInstallerName(file, null))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Inno Setup extracts innosetup-*.tmp / is-XXXXX stubs; NSIS uses nst/nsm/nsu temp dirs.
        /// These cause PPID ancestry races and ephemeral "self-delete" false positives.
        /// </summary>
        public static bool IsInstallerExtractor(string? processName, string? imagePath = null)
        {
            var n = (processName ?? "").ToLowerInvariant().Replace(".exe", "");
            if (n.StartsWith("innosetup") || n.Contains("innosetup")) return true;
            if (n.StartsWith("is-") && n.Length <= 16) return true;
            if (n.Contains("nsis") || n.Contains("_setup.tmp")) return true;
            if (n.EndsWith(".tmp") && n.Contains("setup")) return true;
            if (n is "iside" or "issetup" or "setup.tmp") return true;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var file = Path.GetFileName(imagePath).ToLowerInvariant();
                if (file.StartsWith("innosetup") || file.StartsWith("is-")) return true;
                if (file.Contains("innosetup") && file.EndsWith(".tmp")) return true;

                var lower = imagePath!.ToLowerInvariant();
                if (lower.Contains(@"\temp\is-") || lower.Contains(@"\temp\nst") ||
                    lower.Contains(@"\temp\nsm") || lower.Contains(@"\temp\nsu") ||
                    lower.Contains(@"\temp\7zs") || lower.Contains(@"\.be\")) // WiX burn extract
                    return true;
            }

            return false;
        }

        /// <summary>
        /// v1.8.1 RT-LOW-2: Path must look like a real install/download location before
        /// HighRisk->Tier2 demotion applies. Blocks evasion via ChromeSetup.exe in
        /// AppData\Roaming or arbitrary Temp without installer-extractor context.
        /// </summary>
        public static bool IsLikelyInstallerPath(string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath))
                return false;

            string full;
            try { full = Path.GetFullPath(imagePath); }
            catch { return false; }

            var lower = full.ToLowerInvariant();

            // Explicit deny: classic malware staging locations (name-only installer spoof)
            if (lower.Contains(@"\appdata\roaming\") ||
                lower.Contains(@"\appdata\local\programs\") ||
                lower.Contains(@"\appdata\local\microsoft\windows\inetcache\") ||
                lower.Contains(@"\appdata\local\microsoft\windows\inetcookies\"))
                return false;

            // Trusted install roots
            if (lower.Contains(@"\program files\") ||
                lower.Contains(@"\program files (x86)\") ||
                lower.Contains(@"\windows\installer\") ||
                lower.Contains(@"\package cache\") ||
                lower.Contains(@"\programdata\package cache\"))
                return true;

            // User download / desktop drop of official installers
            if (lower.Contains(@"\downloads\") ||
                lower.Contains(@"\desktop\"))
                return true;

            // Temp only when path matches known extractor layout (Inno/NSIS/7z/WiX)
            if (IsInstallerExtractor(null, full))
                return true;

            return false;
        }

        /// <summary>
        /// Prefetch basenames that are normal short-lived install activity, not droppers.
        /// </summary>
        public static bool IsBenignEphemeralPrefetchName(string? exeOrPrefetchStem)
        {
            if (string.IsNullOrEmpty(exeOrPrefetchStem)) return false;
            var n = StringNet48.ReplaceIgnoreCase(
                Path.GetFileNameWithoutExtension(exeOrPrefetchStem) ?? "", ".tmp", "");

            if (IsInstallerExtractor(n, null) || LooksLikeInstallerName(n, null) ||
                IsDirectXOrRuntimeRedist(n, null))
                return true;

            // Prefetch often uppercases and truncates
            var u = n.ToUpperInvariant();
            if (u.StartsWith("GIT-") || u.StartsWith("INNOSETUP") || u.StartsWith("DOTNET") ||
                u.StartsWith("PYTHON-") || u.StartsWith("NODE-V") || u.Contains("SETUP") ||
                u.Contains("INSTALL") || u.StartsWith("ISIDE") || u.StartsWith("FINALIZER") ||
                u.Contains("CHROME") || u.Contains("VSCODE") || u.Contains("VCREDIST") ||
                u.Contains("DXSETUP") || u.Contains("DIRECTX") || u.Contains("XNAFX") ||
                u.Contains("SENTINELSETUP") || u.Contains("GOOGLEUPDATE"))
                return true;

            return false;
        }

        /// <summary>
        /// Steam / game DirectX, VC++/XNA redistributables, GPU runtime drops.
        /// These write System32 DLLs and look "suspicious" but must never be kill-grade
        /// or composite legs - at most Tier2 observe noise.
        /// </summary>
        public static bool IsDirectXOrRuntimeRedist(string? processName, string? imagePath = null)
        {
            var n = StringNet48.ReplaceIgnoreCase(processName ?? "", ".exe", "").ToLowerInvariant();
            var path = (imagePath ?? "").ToLowerInvariant();
            var file = string.IsNullOrEmpty(imagePath)
                ? ""
                : StringNet48.ReplaceIgnoreCase(Path.GetFileNameWithoutExtension(imagePath) ?? "", ".exe", "")
                    .ToLowerInvariant();

            string[] names =
            {
                "dxsetup", "dsetup", "dsetup32", "dxdllreg", "directx",
                "vcredist", "vc_redist", "vcredist_x86", "vcredist_x64",
                "xnafx40", "xnafx", "dotnetfx", "ndp48", "ndp48-x86",
                "oalinst", "openal", "physx", "nvdx", "nvinst",
            };
            foreach (var s in names)
            {
                if (n == s || n.Contains(s) || file == s || file.Contains(s))
                    return true;
            }

            // Steam/game redistributable layouts
            if (path.Contains(@"\steamapps\common\") &&
                (path.Contains(@"\directx") || path.Contains(@"\_commonredist") ||
                 path.Contains(@"\redist") || path.Contains(@"\vcredist") ||
                 path.Contains(@"\dxsetup")))
                return true;

            if (path.Contains(@"\directx\") || path.Contains(@"\microsoft directx"))
                return true;

            // File drops that are pure redist DLLs into System32 (attribution may be PID 0 / dxsetup)
            string[] redistDllHints =
            {
                "d3dx", "d3dcompiler", "xinput", "xaudio", "xacteng", "xapofx",
                "x3daudio", "d2d1", "dxgi", "vulkan-1", "nvcuda", "nvapi",
                "nvencode", "openal32", "physx",
            };
            var leaf = Path.GetFileName(path);
            if (!string.IsNullOrEmpty(leaf))
            {
                foreach (var h in redistDllHints)
                {
                    if (leaf.IndexOf(h) >= 0)
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Portable download / archive / offline-image tools used by UUP dump converters,
        /// Chocolatey, winget scripts, MSMG Toolkit, NTLite, etc.
        /// These commonly run from Downloads/Temp and may inherit SeImpersonatePrivilege from
        /// an elevated parent shell - that is NOT potato-class token theft.
        /// Name alone is weak trust: pair with path checks when granting broad exemptions.
        /// </summary>
        private static readonly HashSet<string> PortableDownloadArchiveTools = new(StringComparer.OrdinalIgnoreCase)
        {
            // Downloaders
            "aria2c", "aria2", "curl", "wget",
            // Archives
            "7z", "7za", "7zr", "cabextract",
            // WIM / ISO / offline Windows image tooling (UUP dump convert scripts)
            "wimlib-imagex", "imagex", "oscdimg", "cdimage", "bfi",
            "psfextractor", "sxsexpand", "offlinereg", "dism", "dismhost"
        };

        public static bool IsPortableDownloadOrArchiveTool(string? processName, string? imagePath = null)
        {
            var n = NormalizeProcessStem(processName);
            if (!string.IsNullOrEmpty(n) && PortableDownloadArchiveTools.Contains(n))
                return true;

            if (!string.IsNullOrEmpty(imagePath))
            {
                var file = NormalizeProcessStem(Path.GetFileNameWithoutExtension(imagePath));
                if (!string.IsNullOrEmpty(file) && PortableDownloadArchiveTools.Contains(file))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// UUP dump / offline ISO converter worktrees: multi-GB Microsoft CDN pulls via aria2,
        /// WIM extraction, etc. Matches both official "uupdump" layouts and generated
        /// "*_convert\files\aria2c.exe" folders under Downloads.
        /// </summary>
        public static bool IsOfflineImageWorkPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var lower = path!.ToLowerInvariant();

            if (lower.Contains(@"\uupdump\") ||
                lower.Contains(@"\uups\") ||
                lower.Contains(@"\uup\") ||
                lower.Contains(@"\ntlite\") ||
                lower.Contains(@"\msmg toolkit\") ||
                lower.Contains(@"\msmgtoolkit\"))
                return true;

            // uup.dump generated package: ...\28000...._convert\files\aria2c.exe
            if (lower.Contains(@"_convert\") &&
                (lower.Contains(@"\files\") || lower.Contains(@"\uups\") || lower.Contains(@"\bin\")))
                return true;

            return false;
        }

        /// <summary>
        /// True when this process should not be kill-scored solely for network-from-Downloads
        /// or SeImpersonate-from-Downloads heuristics (UUP / portable tooling).
        /// </summary>
        public static bool IsBenignPortableWorkContext(string? processName, string? imagePath)
        {
            if (IsPortableDownloadOrArchiveTool(processName, imagePath))
                return true;

            // Only trust offline-image path exemption when the binary itself is a known tool
            // (prevents malware.exe under a folder named "uups" from full bypass).
            if (IsOfflineImageWorkPath(imagePath) &&
                IsPortableDownloadOrArchiveTool(null, imagePath))
                return true;

            return false;
        }

        private static string NormalizeProcessStem(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            var n = name!.Trim();
            if (n.EndsWith(".exe"))
                n = n[..^4];
            return n;
        }
    }
}
