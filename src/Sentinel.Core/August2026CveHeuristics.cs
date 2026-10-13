using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure helpers for August 2026 Patch Tuesday userland coverage.
    /// Does not patch kernel races (CVE-2026-68820 / afd.sys). Used by campaign,
    /// KEV posture, LegacyHive, and Cloud Files / ShieldBreak sensors.
    /// </summary>
    public static class August2026CveHeuristics
    {
        public const string CveAfdSys = "CVE-2026-68820";
        public const string CveLegacyHive = "CVE-2026-62832";
        public const string CveCloudFiles = "CVE-2026-62713";
        // Common Log File System (clfs.sys) LPE class - a recurring, actively-exploited
        // kernel primitive. CVE-2025-29824 was an in-the-wild 0-day used to deploy ransomware;
        // the class also covers CVE-2025-32706/-60709/-62470 and CVE-2026-40407. We reference
        // the exploited 0-day as the representative id for the .blf-manipulation footprint.
        public const string CveClfs = "CVE-2025-29824";
        public const string August2026KbWin11 = "KB5121003";
        public const int MinUbrWin11_24H2_25H2 = 9168;

        // FILE_ATTRIBUTE_* not on net48 FileAttributes enum
        public const int FileAttributeRecallOnDataAccess = 0x00400000;
        public const int FileAttributeRecallOnOpen = 0x00040000;
        public const int FileAttributeUnpinned = 0x00100000;
        public const int FileAttributePinned = 0x00080000;

        public static readonly HashSet<string> DreamJobFileNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "SecurityPDF.exe", "SecurityPDF",
            "Afd4Eop12_x64.dll", "Afd4Eop12_x64",
            "OneScreenCapture64.dll", "OneScreenCapture64",
            "Release_GetInfoPlugin_x64.dll", "GetInfoPlugin",
            "Release_PvPlugin_x64.dll", "PvPlugin",
        };

        public static readonly HashSet<string> DreamJobSideloadDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            "libmupdf.dll",
        };

        public static readonly HashSet<string> PdfViewerProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "SecurityPDF", "SumatraPDF", "mupdf", "MuPDF", "pdfviewer", "PDFXCview",
            "Acrobat", "AcroRd32", "FoxitReader", "FoxitPDFReader",
        };

        public static readonly HashSet<string> DreamJobDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "envell.xyz", "enveil.online", "uxtramine.org",
        };

        public static readonly HashSet<string> DreamJobIps = new(StringComparer.OrdinalIgnoreCase)
        {
            "135.181.67.203", "135.181.185.158",
        };

        /// <summary>Public Check Point Research SHA-256 IOCs for Operation Dream Job (Aug 2026).</summary>
        public static readonly HashSet<string> DreamJobSha256 = new(StringComparer.OrdinalIgnoreCase)
        {
            // SecurityPDF.exe
            "743172aab606974b054a64561534ae66baa3a840657f79d7c6fa18350e8d45d1",
            "db3d69b7eeda2e35e23006bf4b7e206281fce809584207214fc213f9bc30376d",
            // FudModule
            "3b6378df8442e63a6ed7317075913e4720847a510d95022d4a8347b2637c245d",
            // Troy
            "590fb6ae19480d694e08ee85859cad8066f2f87e7e5abba2960c6d115e1615d6",
            "68d4fba7b1300a59cd6212c08910a260cd71b40cd9f51cac933030a68faac0bb",
            "a738059ce07c951c31ab2da3d93d8f69bff32f9b7d933dbf5943441b9cc99075",
            // ForestTiger
            "72dccae85e062f541fecad9ec7a18a3123e7ae5ac5d53c91709b53a46dbbd289",
            "231b1ef8b95bf77887d5377e2a60f649035e78f543af1b82877db36a5759d858",
            "6da9b1e6f3315ceb77dd14a937a26cc3602bf6a7e2c2ecafb3c65ce5319837be",
            "a0578a2b7821d7e2c573530648f26d7a0d98b373ab24fb7f0c792736761e542d",
            "82268052f94df6f4870d02e57b18d4c54136cc7a8c8d80ad162631f99462c943",
            // MISTPEN
            "2db25ac41a66aa523c79e23e00443573530dd7bd82b8371bcc87bd7232e141eb",
            "5278ee922838352f1480a73e971161017d643a80b7ec22bf725897dfd088696d",
            "b4082d21070d9ddf53fde4ea22524d09e41ec9826ce63cef3c6235e458d21afb",
            "fb3fc5626f68677fb1269a2fefbe70e719211b4065e836ab92e06a8210139a2d",
            "ea7056f2bf36c66a61ff787ff5be975a85f534c3c5ca178791dac2504db2c619",
            "13d10bc99f7f7abe7ee0902be87920b73b2ea41bd9683dbfcad340dacbcdef79",
            "4fd32432341dfcf54d0517a6bbc38e5d265be70933493e4183c2a340cdde9a2d",
            "4dd792c9f672bbdcc8d363d745994efe90f4ffc5fdc2c059c8e379a48ad6a68a",
            "ba96c603e44046de703c67b2c3b7e4ca974afef7b437a0244418bc4edc781bb7",
        };

        public static readonly string[] FudModuleStrings =
        {
            "enable_god_mode passed",
            "GetGodMode failed",
            "Afd4Eop12",
            "ClearVaccine",
            "This document is encrypted with sumatrapdf reader",
        };

        public static readonly string[] StagingPathMarkers =
        {
            @"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Public\",
            @"\Users\Public\", @"\Desktop\",
        };

        public static readonly string[] KnownSyncRootFragments =
        {
            "OneDrive", "SkyDrive", "GoogleDrive", "Google Drive", "Dropbox",
            "iCloud", "WorkFolders", "SharePoint", "SkyDriveSync",
            "Adobe.CCFiles", "CreativeCloud", "BoxSync", "Nextcloud",
        };

        public static readonly string[] KnownSyncFolderFragments =
        {
            @"\onedrive", @"\google drive", @"\google drive fs", @"\dropbox",
            @"\icloud drive", @"\creative cloud files", @"\sharepoint",
        };

        public static readonly string[] KnownCloudSyncClients =
        {
            "onedrive", "onedrive.setup", "filecoauth", "googledrivefs",
            "dropbox", "icloudservices", "applemobiledeviceservice",
            "workfolders", "groove", "box", "nextcloud",
        };

        public static bool MatchesDreamJobFileName(string? nameOrPath)
        {
            if (string.IsNullOrWhiteSpace(nameOrPath)) return false;
            var file = Path.GetFileName(nameOrPath!.TrimEnd('.', ' ', '\0'));
            if (string.IsNullOrEmpty(file)) return false;
            if (DreamJobFileNames.Contains(file)) return true;
            var noExt = Path.GetFileNameWithoutExtension(file);
            return !string.IsNullOrEmpty(noExt) && DreamJobFileNames.Contains(noExt!);
        }

        public static bool IsFudModuleName(string? nameOrPath)
        {
            if (string.IsNullOrWhiteSpace(nameOrPath)) return false;
            var file = Path.GetFileName(nameOrPath);
            return file.IndexOf("Afd4Eop", StringComparison.OrdinalIgnoreCase) >= 0
                || file.IndexOf("FudModule", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsPdfViewerProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = Path.GetFileNameWithoutExtension(processName) ?? processName;
            return PdfViewerProcessNames.Contains(n!) || PdfViewerProcessNames.Contains(processName!);
        }

        public static bool IsStagingPath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            foreach (var m in StagingPathMarkers)
            {
                if (path!.IndexOf(m, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsLibmupdfSideload(string? dllPath, string? hostExePath)
        {
            if (string.IsNullOrWhiteSpace(dllPath)) return false;
            var dllName = Path.GetFileName(dllPath);
            if (!DreamJobSideloadDlls.Contains(dllName)) return false;
            var dir = Path.GetDirectoryName(dllPath) ?? hostExePath;
            return IsStagingPath(dllPath) || IsStagingPath(dir) || IsStagingPath(hostExePath);
        }

        public static bool ContainsDreamJobDomain(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            foreach (var d in DreamJobDomains)
            {
                if (text!.IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            foreach (var ip in DreamJobIps)
            {
                if (text!.IndexOf(ip, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool ContainsFudModuleString(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            foreach (var s in FudModuleStrings)
            {
                if (text!.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsDreamJobHash(string? sha256) =>
            !string.IsNullOrWhiteSpace(sha256) && DreamJobSha256.Contains(sha256!.Trim());

        public static bool IsTempNewExe(string? path, string? processName)
        {
            if (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(processName))
                return false;
            var name = Path.GetFileName(path ?? processName ?? "");
            if (!name.Equals("new.exe", StringComparison.OrdinalIgnoreCase)
                && !name.Equals("new", StringComparison.OrdinalIgnoreCase))
                return false;
            return IsStagingPath(path);
        }

        public static bool IsKnownCloudSyncClient(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = Path.GetFileNameWithoutExtension(processName)?.ToLowerInvariant() ?? "";
            foreach (var c in KnownCloudSyncClients)
            {
                if (n.IndexOf(c, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsKnownCloudSyncFolder(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var p = path!.ToLowerInvariant();
            foreach (var f in KnownSyncFolderFragments)
            {
                if (p.Contains(f)) return true;
            }
            return false;
        }

        public static bool IsKnownSyncRootId(string? syncRootId)
        {
            if (string.IsNullOrWhiteSpace(syncRootId)) return false;
            foreach (var f in KnownSyncRootFragments)
            {
                if (syncRootId!.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsCloudPlaceholderAttributes(int attributes)
        {
            return (attributes & FileAttributeRecallOnDataAccess) != 0
                || (attributes & FileAttributeRecallOnOpen) != 0
                || ((attributes & 0x400) != 0 && (attributes & FileAttributeUnpinned) != 0);
        }

        public static bool IsHiveFilePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var p = path!.ToLowerInvariant();
            return p.EndsWith("\\ntuser.dat")
                || p.Contains("\\ntuser.dat.")
                || p.EndsWith("\\usrclass.dat")
                || p.Contains("\\usrclass.dat.");
        }

        public static bool IsWellKnownOrServiceSid(string? sid)
        {
            if (string.IsNullOrWhiteSpace(sid)) return true;
            if (sid!.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase)) return true;
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) return true;
            // SYSTEM / Local Service / Network Service / well-known
            if (sid.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase)
                || sid.Equals("S-1-5-19", StringComparison.OrdinalIgnoreCase)
                || sid.Equals("S-1-5-20", StringComparison.OrdinalIgnoreCase)
                || sid.Equals("S-1-5-17", StringComparison.OrdinalIgnoreCase))
                return true;
            if (sid.StartsWith("S-1-5-80-", StringComparison.OrdinalIgnoreCase)) return true; // services
            if (sid.StartsWith("S-1-5-82-", StringComparison.OrdinalIgnoreCase)) return true; // IIS
            if (sid.StartsWith("S-1-5-90-", StringComparison.OrdinalIgnoreCase)) return true;
            if (sid.StartsWith("S-1-5-96-", StringComparison.OrdinalIgnoreCase)) return true;
            if (sid.StartsWith("S-1-5-88-", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public static bool IsCustomNamedHive(string? keyName)
        {
            if (string.IsNullOrWhiteSpace(keyName)) return false;
            if (IsWellKnownOrServiceSid(keyName)) return false;
            if (keyName!.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }

        public static bool IsServiceProfilePath(string? profileImagePath)
        {
            if (string.IsNullOrWhiteSpace(profileImagePath)) return true;
            var p = profileImagePath!.ToLowerInvariant();
            return p.Contains(@"\windows\serviceprofiles\")
                || p.Contains(@"\windows\system32\config\systemprofile")
                || p.Contains(@"\windows\system32\config\")
                || p.Contains(@"\windows\syswow64\config\");
        }

        /// <summary>
        /// A loaded HKU SID is unexpected when it is a real user profile hive
        /// and that SID is not in the currently logged-on (incl. disconnected) set.
        /// </summary>
        public static bool IsUnexpectedUserHive(
            string loadedKey,
            ISet<string> loggedOnSids,
            string? profileImagePath)
        {
            if (IsCustomNamedHive(loadedKey)) return true;
            if (IsWellKnownOrServiceSid(loadedKey)) return false;
            if (IsServiceProfilePath(profileImagePath)) return false;
            if (loggedOnSids == null || loggedOnSids.Count == 0)
                return false; // fail closed: no session data -> do not alert
            return !loggedOnSids.Contains(loadedKey);
        }

        public static KevPatchEvaluation EvaluateKevAfdPatch(int currentBuild, int ubr, DateTime? lastInstallLocal)
        {
            // Win11 24H2 (26100) / 25H2 (26200): August 2026 CU is UBR 9168 (KB5121003)
            if (currentBuild == 26100 || currentBuild == 26200)
            {
                if (ubr < MinUbrWin11_24H2_25H2)
                {
                    return new KevPatchEvaluation
                    {
                        Unpatched = true,
                        HighConfidence = true,
                        CveId = CveAfdSys,
                        Detail = $"Windows 11 build {currentBuild}.{ubr} is below {currentBuild}.{MinUbrWin11_24H2_25H2} ({August2026KbWin11}). {CveAfdSys} (afd.sys, Lazarus, CISA KEV) is unpatched.",
                    };
                }

                return new KevPatchEvaluation { Unpatched = false, HighConfidence = true, CveId = CveAfdSys, Detail = $"Build {currentBuild}.{ubr} meets {August2026KbWin11}." };
            }

            var patchDay = new DateTime(2026, 8, 11);
            if (lastInstallLocal.HasValue && lastInstallLocal.Value.Date < patchDay)
            {
                return new KevPatchEvaluation
                {
                    Unpatched = true,
                    HighConfidence = false,
                    CveId = CveAfdSys,
                    Detail = $"Last Windows Update install {lastInstallLocal.Value:yyyy-MM-dd} is before 2026-08-11 ({August2026KbWin11}). Host may still be exposed to {CveAfdSys}.",
                };
            }

            return new KevPatchEvaluation { Unpatched = false, HighConfidence = false, CveId = CveAfdSys, Detail = "No Win11 24H2/25H2 UBR signal; last install not before Patch Tuesday." };
        }
    }

    public sealed class KevPatchEvaluation
    {
        public bool Unpatched { get; set; }
        public bool HighConfidence { get; set; }
        public string CveId { get; set; } = "";
        public string Detail { get; set; } = "";
    }
}
