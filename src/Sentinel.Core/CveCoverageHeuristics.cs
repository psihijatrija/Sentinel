using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure helpers for generic CVE-class coverage that does not depend on a named campaign.
    /// Catches the userland *shape* of new kernel EoP / installer EoP / MOTW / package-manager
    /// bugs as they ship. Does not patch kernel races. Filename matches are observe fuel only.
    /// </summary>
    public static class CveCoverageHeuristics
    {
        // August 2026 workstation CVEs beyond Dream Job / LegacyHive / Cloud Files
        public const string CveAfdAlt1 = "CVE-2026-61348";
        public const string CveAfdAlt2 = "CVE-2026-70307";
        public const string CveInstallerEop = "CVE-2026-61925";
        public const string CveWingetEop = "CVE-2026-68821";
        public const string CveUnionFs = "CVE-2026-72971";
        public const string CveMidi = "CVE-2026-62688";
        public const string CveVsCodeSfb = "CVE-2026-58650";
        public const string CveCopilotVscode = "CVE-2026-70335";
        public const string CvePowerShellRce = "CVE-2026-70337";
        public const string CveCrossDevice = "CVE-2026-66804";
        public const string CveDigestAuth = "CVE-2026-62698";
        public const string CveAtBroker = "CVE-2026-61358";
        public const string CveDhcpClient = "CVE-2026-62755";
        public const string CveRdpClient = "CVE-2026-62824";
        public const string CveVhdMiniport = "CVE-2026-59125";
        public const string CveHttpSys = "CVE-2026-62735";
        public const string CveCloudFilesAlt = "CVE-2026-62771";

        public static readonly string[] KernelExploitNameFragments =
        {
            "AfdEo", "Afd4Eo", "AfdLpe", "WinSockEo", "KernelEo", "KernelLpe",
            "CVE-202", "CVE-201", "EoPPOC", "EopPoc", "LpePoc", "exploit",
            "FudModule", "GodMode", "ClearVaccine", "unionfs", "wcifs",
        };

        public static readonly string[] DeviceIoctlFragments =
        {
            @"\Device\Afd", @"\Device\AfdEndpoint", @"\\.\Afd",
            @"\Device\Nsi", @"\Device\Tcp", @"\Device\Udp",
            @"\Device\KsecDD", @"\Device\CNG", @"\Device\FltMgr",
            @"\Device\WinSock2", "DeviceIoControl",
        };

        public static readonly string[] StagingPathMarkers =
        {
            @"\Temp\", @"\AppData\Local\Temp\", @"\Downloads\", @"\Public\",
            @"\Users\Public\", @"\Desktop\", @"\PerfLogs\",
        };

        public static readonly string[] IsolationDriverNames =
        {
            "unionfs.sys", "unionfs", "wcifs.sys", "wcifs",
            "bindflt.sys", "bindflt", "cimfs.sys",
        };

        public static readonly string[] VsCodeHostNames =
        {
            "code", "code - insiders", "code - oss", "cursor", "cursor-tunnel",
            "windsurf", "antigravity", "trae", "comate", "qoder",
        };

        public static readonly string[] LolBins =
        {
            "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "cmstp", "certutil", "bitsadmin", "curl", "wget",
            "msbuild", "installutil", "regasm", "regsvcs", "odbcconf",
            "forfiles", "hh", "pcalua", "wmic", "wt", "conhost",
        };

        public static readonly string[] DiskImageExtensions =
        {
            ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".wim",
        };

        // Script-class droppers that execute via WSH / mshta / batch. These don't need
        // to be PE to detonate a drive-by / XSS-forced-download, and a browser download
        // normally still stamps them with a Zone.Identifier. Missing MOTW on one of these
        // in a delivery folder is the classic MOTW-strip / archive-smuggle shape.
        public static readonly string[] ScriptDropperExtensions =
        {
            ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
            ".ps1", ".bat", ".cmd", ".lnk", ".chm", ".scf", ".url",
        };

        public static readonly string[] AppInstallerPackageExtensions =
        {
            ".appinstaller", ".msix", ".msixbundle", ".appx", ".appxbundle",
        };

        public static readonly string[] ServerOnlyProducts =
        {
            "sharepoint", "exchange server", "sql server", "windows server",
            "deployment services", "dhcp server", "dns server", "iis",
            "hyper-v", "active directory", "ad cs", "hpc pack",
            "system center", "azure stack", "windows admin center",
        };

        private static readonly Regex CveIdRegex = new Regex(
            @"CVE-\d{4}-\d{4,}",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex EncodedPsRegex = new Regex(
            @"(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}|FromBase64String|IEX\s*\(|Invoke-Expression)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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

        public static bool LooksLikeCveId(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            return CveIdRegex.IsMatch(text!);
        }

        public static bool IsKernelExploitLoaderName(string? nameOrPath)
        {
            if (string.IsNullOrWhiteSpace(nameOrPath)) return false;
            var file = Path.GetFileName(nameOrPath) ?? nameOrPath!;
            foreach (var frag in KernelExploitNameFragments)
            {
                if (frag.Length < 4) continue;
                if (file.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return LooksLikeCveId(file);
        }

        public static bool ContainsDeviceIoctlPrimitive(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            foreach (var frag in DeviceIoctlFragments)
            {
                if (commandLine!.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsLolBinName(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = Path.GetFileNameWithoutExtension(processName) ?? processName!;
            foreach (var b in LolBins)
            {
                if (n.Equals(b, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsVsCodeHost(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = (Path.GetFileNameWithoutExtension(processName) ?? processName!).Trim();
            foreach (var h in VsCodeHostNames)
            {
                if (n.Equals(h, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return n.StartsWith("Code -", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsClickFixEncodedCommand(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            return EncodedPsRegex.IsMatch(commandLine!);
        }

        public static bool IsAppInstallerProtocol(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            return commandLine!.IndexOf("ms-appinstaller:", StringComparison.OrdinalIgnoreCase) >= 0
                || commandLine.IndexOf("ms-appx:", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsUntrustedWingetSource(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            var c = commandLine!;
            bool sourceAdd = c.IndexOf("source add", StringComparison.OrdinalIgnoreCase) >= 0
                             || c.IndexOf("sourceadd", StringComparison.OrdinalIgnoreCase) >= 0;
            bool http = c.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0
                        || c.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0;
            return sourceAdd && http;
        }

        public static bool IsMsiFromStaging(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            var c = commandLine!;
            bool msi = c.IndexOf(".msi", StringComparison.OrdinalIgnoreCase) >= 0
                       || c.IndexOf("/i ", StringComparison.OrdinalIgnoreCase) >= 0
                       || c.IndexOf("/fa", StringComparison.OrdinalIgnoreCase) >= 0
                       || c.IndexOf("/fpcms", StringComparison.OrdinalIgnoreCase) >= 0
                       || c.IndexOf("REINSTALL=", StringComparison.OrdinalIgnoreCase) >= 0;
            return msi && IsStagingPath(c);
        }

        public static bool IsDiskImagePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var ext = Path.GetExtension(path);
            if (string.IsNullOrEmpty(ext)) return false;
            foreach (var e in DiskImageExtensions)
            {
                if (ext.Equals(e, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsAppInstallerPackagePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var ext = Path.GetExtension(path);
            if (string.IsNullOrEmpty(ext)) return false;
            foreach (var e in AppInstallerPackageExtensions)
            {
                if (ext.Equals(e, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsIsolationDriverName(string? nameOrPath)
        {
            if (string.IsNullOrWhiteSpace(nameOrPath)) return false;
            var file = Path.GetFileName(nameOrPath) ?? nameOrPath!;
            foreach (var d in IsolationDriverNames)
            {
                if (file.Equals(d, StringComparison.OrdinalIgnoreCase)
                    || file.StartsWith(d, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public static bool IsMidiServiceProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = Path.GetFileNameWithoutExtension(processName) ?? processName!;
            return n.Equals("midisrv", StringComparison.OrdinalIgnoreCase)
                   || n.Equals("MIDISrv", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsPeExtension(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var ext = Path.GetExtension(path);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".scr", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".cpl", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".com", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// True for script-class droppers (.hta/.js/.vbs/.wsf/.ps1/.lnk/etc.) that
        /// detonate via WSH/mshta/batch without needing to be a PE. A browser download
        /// normally stamps these with a Zone.Identifier, so a missing MOTW in a delivery
        /// folder is a drive-by / archive-smuggle / MOTW-strip indicator.
        /// </summary>
        public static bool IsScriptDropperExtension(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            var ext = Path.GetExtension(path);
            if (string.IsNullOrEmpty(ext)) return false;
            foreach (var e in ScriptDropperExtensions)
            {
                if (ext.Equals(e, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Second Tuesday of the calendar month containing <paramref name="asOf"/>,
        /// or the previous month's second Tuesday if <paramref name="asOf"/> is before
        /// this month's Patch Tuesday.
        /// </summary>
        public static DateTime MostRecentPatchTuesday(DateTime asOf)
        {
            var candidate = SecondTuesdayOfMonth(asOf.Year, asOf.Month);
            if (asOf.Date < candidate.Date)
            {
                var prev = new DateTime(asOf.Year, asOf.Month, 1).AddMonths(-1);
                candidate = SecondTuesdayOfMonth(prev.Year, prev.Month);
            }
            return candidate.Date;
        }

        public static DateTime SecondTuesdayOfMonth(int year, int month)
        {
            var first = new DateTime(year, month, 1);
            int offset = ((int)DayOfWeek.Tuesday - (int)first.DayOfWeek + 7) % 7;
            return first.AddDays(offset + 7);
        }

        /// <summary>
        /// True when the host has not installed a cumulative update since the last
        /// Patch Tuesday, after a grace window (default 7 days) so CU rollout is not
        /// treated as an incident on Wednesday morning.
        /// </summary>
        public static bool MissedLatestPatchTuesday(DateTime? lastInstallLocal, DateTime asOf, int graceDays = 7)
        {
            var pt = MostRecentPatchTuesday(asOf);
            if (asOf.Date < pt.AddDays(Math.Max(0, graceDays)))
                return false;
            if (!lastInstallLocal.HasValue)
                return false; // fail closed: missing WU telemetry is not an incident
            return lastInstallLocal.Value.Date < pt;
        }

        public static bool IsWindowsOsProduct(string? product, string? vendor)
        {
            var p = product ?? "";
            var v = vendor ?? "";
            bool ms = v.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0
                      || string.IsNullOrWhiteSpace(v);
            if (!ms && p.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) < 0)
                return false;

            if (p.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            if (p.IndexOf("Win32", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            if (p.Equals("WinSock", StringComparison.OrdinalIgnoreCase)
                || p.IndexOf("Ancillary Function Driver", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("HTTP.sys", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("WinSock", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("NTFS", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("Kernel", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            return false;
        }

        public static bool IsServerRoleProduct(string? product)
        {
            if (string.IsNullOrWhiteSpace(product)) return false;
            var p = product!;
            foreach (var s in ServerOnlyProducts)
            {
                if (p.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static KevHostMatch ClassifyKevForWorkstation(
            string? cveId,
            string? vendor,
            string? product,
            IReadOnlyList<string> installedApps,
            IReadOnlyList<string> runningProcesses)
        {
            var result = new KevHostMatch();
            var prod = product ?? "";
            var vend = vendor ?? "";

            if (IsServerRoleProduct(prod))
            {
                string? app = null;
                string? proc = null;
                if (TryContains(installedApps, prod, out app)
                    || TryContains(runningProcesses, prod, out proc))
                {
                    result.Matched = true;
                    result.MatchType = app != null ? "InstalledSoftware" : "RunningProcess";
                    result.MatchedAsset = app ?? proc ?? prod;
                    result.DeployProcessRules = true;
                    return result;
                }

                result.Matched = false;
                result.MatchType = "ServerRoleAbsent";
                return result;
            }

            if (IsWindowsOsProduct(prod, vend))
            {
                result.Matched = true;
                result.MatchType = "WorkstationOs";
                result.MatchedAsset = "Windows";
                result.DeployProcessRules = false;
                return result;
            }

            if (!string.IsNullOrWhiteSpace(prod))
            {
                if (TryProcessAliasMatch(prod, runningProcesses, out var aliasProc))
                {
                    result.Matched = true;
                    result.MatchType = "RunningProcess";
                    result.MatchedAsset = aliasProc!;
                    result.DeployProcessRules = true;
                    return result;
                }

                if (TryContains(runningProcesses, prod, out var rp))
                {
                    result.Matched = true;
                    result.MatchType = "RunningProcess";
                    result.MatchedAsset = rp!;
                    result.DeployProcessRules = true;
                    return result;
                }

                if (TryContains(installedApps, prod, out var ia)
                    || (!string.IsNullOrWhiteSpace(vend)
                        && vend.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0
                        && TryContains(installedApps, vend, out ia)))
                {
                    result.Matched = true;
                    result.MatchType = "InstalledSoftware";
                    result.MatchedAsset = ia!;
                    result.DeployProcessRules = true;
                    return result;
                }
            }

            return result;
        }

        public static IReadOnlyList<string> ProcessRuleParentsForProduct(string? product, string? matchedAsset)
        {
            var list = new List<string>();
            void Add(string? s)
            {
                if (string.IsNullOrWhiteSpace(s)) return;
                var n = s!.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? Path.GetFileNameWithoutExtension(s)!
                    : s!;
                if (!list.Contains(n))
                    list.Add(n);
            }

            Add(matchedAsset);
            var p = product ?? "";
            if (p.IndexOf("Visual Studio Code", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("VS Code", StringComparison.OrdinalIgnoreCase) >= 0
                || p.IndexOf("Copilot", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("Code");
                Add("Cursor");
                Add("windsurf");
            }
            else if (p.IndexOf("Word", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("Office", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("Excel", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("Outlook", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("PowerPoint", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("WINWORD");
                Add("EXCEL");
                Add("POWERPNT");
                Add("OUTLOOK");
            }
            else if (p.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("powershell");
                Add("pwsh");
            }
            else if (p.IndexOf("Edge", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("Chrome", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("Chromium", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("msedge");
                Add("chrome");
                Add("msedgewebview2");
            }
            else if (p.IndexOf("Installer", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("msiexec");
            }
            else if (p.IndexOf("Package Manager", StringComparison.OrdinalIgnoreCase) >= 0
                     || p.IndexOf("App Installer", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add("winget");
                Add("AppInstaller");
                Add("WindowsPackageManagerServer");
            }

            return list;
        }

        public static string? VulnerabilityClass(string? vulnerabilityName, string? shortDescription)
        {
            var t = (vulnerabilityName ?? "") + " " + (shortDescription ?? "");
            if (t.IndexOf("Remote Code Execution", StringComparison.OrdinalIgnoreCase) >= 0
                || t.IndexOf(" RCE", StringComparison.OrdinalIgnoreCase) >= 0)
                return "RCE";
            if (t.IndexOf("Elevation of Privilege", StringComparison.OrdinalIgnoreCase) >= 0
                || t.IndexOf("Privilege Escalation", StringComparison.OrdinalIgnoreCase) >= 0)
                return "EoP";
            if (t.IndexOf("Security Feature Bypass", StringComparison.OrdinalIgnoreCase) >= 0)
                return "SFB";
            if (t.IndexOf("Spoof", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Spoofing";
            if (t.IndexOf("Tamper", StringComparison.OrdinalIgnoreCase) >= 0)
                return "Tampering";
            if (t.IndexOf("Information Disclosure", StringComparison.OrdinalIgnoreCase) >= 0)
                return "InfoDisc";
            if (t.IndexOf("Denial of Service", StringComparison.OrdinalIgnoreCase) >= 0)
                return "DoS";
            return "Other";
        }

        private static bool TryContains(IReadOnlyList<string> haystack, string needle, out string? hit)
        {
            hit = null;
            if (string.IsNullOrWhiteSpace(needle) || haystack == null) return false;
            foreach (var item in haystack)
            {
                if (string.IsNullOrEmpty(item)) continue;
                if (item.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    hit = item;
                    return true;
                }
                // Reverse match only for distinctive tokens (avoid "Microsoft" / "Server" / "e")
                if (item.Length >= 6 && needle.IndexOf(item, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    hit = item;
                    return true;
                }
            }
            return false;
        }

        private static bool TryProcessAliasMatch(string product, IReadOnlyList<string> running, out string? hit)
        {
            hit = null;
            var aliases = ProcessRuleParentsForProduct(product, null);
            foreach (var a in aliases)
            {
                if (TryContains(running, a, out hit))
                    return true;
            }
            return false;
        }
    }

    public sealed class KevHostMatch
    {
        public bool Matched { get; set; }
        public string MatchType { get; set; } = "";
        public string MatchedAsset { get; set; } = "";
        public bool DeployProcessRules { get; set; }
    }
}
