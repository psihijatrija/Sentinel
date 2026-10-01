using System;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure COM-hijack classifier (T1546.015).
    ///
    /// Sentinel previously only flagged *new* HKCR InprocServer32 keys and then baselined
    /// them forever, so hijacking an existing CLSID (the real attack) was invisible. It
    /// also scored anything under C:\Windows\ as fine, so a Component Based Servicing
    /// impersonation (cbsapi.dll outside WinSxS) was allowed.
    ///
    /// Registry keys are never deleted here. A hijacked well-known CLSID still belongs
    /// to the shell; deleting the class bricks explorer/logon. The payload DLL is what
    /// gets quarantined, via <see cref="ShouldQuarantinePayload"/>.
    /// </summary>
    public static class ComHijackEvaluator
    {
        public enum ServerKind
        {
            InprocServer32,
            InprocHandler32,
            LocalServer32,
            TreatAs
        }

        public readonly struct Registration
        {
            public Registration(
                string clsid,
                string hive,
                ServerKind kind,
                string serverValue,
                string? baselineValue = null,
                bool hkcuShadowsHklm = false,
                string? hklmValue = null)
            {
                Clsid = clsid ?? "";
                Hive = hive ?? "";
                Kind = kind;
                ServerValue = serverValue ?? "";
                BaselineValue = baselineValue;
                HkcuShadowsHklm = hkcuShadowsHklm;
                HklmValue = hklmValue;
            }

            public string Clsid { get; }
            public string Hive { get; }
            public ServerKind Kind { get; }
            public string ServerValue { get; }
            public string? BaselineValue { get; }
            public bool HkcuShadowsHklm { get; }
            public string? HklmValue { get; }
        }

        public readonly struct Verdict
        {
            public bool IsHijack { get; init; }
            public bool ShouldQuarantinePayload { get; init; }
            public double Confidence { get; init; }
            public string RuleName { get; init; }
            public string Reasoning { get; init; }
            public DetectionTier Tier { get; init; }
            public ResponseAction AuthorizedResponse { get; init; }
        }

        /// <summary>
        /// Expand REG_EXPAND_SZ and strip LocalServer32 arguments. TreatAs values are
        /// CLSIDs, not paths - callers should not run this on TreatAs.
        /// </summary>
        public static string ExtractServerPath(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            // raw is non-null here (guarded above). net48 reference assemblies lack the
            // [NotNullWhen(false)] annotation on IsNullOrWhiteSpace, so the flow analysis still
            // sees string? - the null-forgiving operator reflects the guarantee (CS8602).
            var s = raw!.Trim();
            try { s = Environment.ExpandEnvironmentVariables(s); }
            catch { /* keep raw */ }
            s = s.Trim().Trim('"');
            if (s.Length == 0) return "";

            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int end = s.IndexOf('"', 1);
                if (end > 1) s = s.Substring(1, end - 1);
            }
            else
            {
                int dotExe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                int dotDll = s.IndexOf(".dll", StringComparison.OrdinalIgnoreCase);
                int ext = dotExe >= 0 ? dotExe + 4 : (dotDll >= 0 ? dotDll + 4 : -1);
                if (ext > 0 && ext < s.Length && s[ext] == ' ')
                    s = s.Substring(0, ext).Trim('"');
            }

            return s.Trim().Trim('"');
        }

        public static bool IsPublicDrop(string? path)
        {
            var p = ModuleIdentity.Normalize(path);
            if (p.Length == 0) return false;
            return p.IndexOf(@"\users\public\", StringComparison.Ordinal) >= 0
                || p.StartsWith(@"c:\public\", StringComparison.Ordinal)
                || p.Equals(@"c:\public", StringComparison.Ordinal);
        }

        public static bool IsScriptHostServer(string? path)
        {
            string file;
            try { file = Path.GetFileName(ExtractServerPath(path)) ?? ""; }
            catch { return false; }
            if (file.Length == 0) return false;
            return file.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("cscript.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase)
                || file.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The DLL/EXE the COM class points at is the payload. Never the CLSID key.
        /// Never an OS LOLBin (powershell/rundll32) - those stay observe-only.
        /// </summary>
        public static bool ShouldQuarantinePayload(string? rawServer)
        {
            var path = ExtractServerPath(rawServer);
            if (path.Length == 0) return false;
            if (ModuleIdentity.IsOsServicingPath(path)) return false;
            if (IsScriptHostServer(path)) return false;
            if (ModuleIdentity.IsServicingNameOutsideStore(path)) return true;
            if (ModuleIdentity.IsUserWritableDrop(path)) return true;
            if (IsPublicDrop(path)) return true;
            return false;
        }

        public static bool IsTrustedComServerPath(string? rawServer)
        {
            var path = ExtractServerPath(rawServer);
            if (path.Length == 0) return false;
            if (ModuleIdentity.IsServicingNameOutsideStore(path)) return false;
            if (ModuleIdentity.IsOsServicingPath(path)) return true;
            if (ModuleIdentity.IsKeepTree(path) && !ModuleIdentity.IsUserWritableDrop(path)) return true;
            if (ModuleIdentity.IsProgramFilesTree(path) && !ModuleIdentity.IsUserWritableDrop(path)) return true;
            return false;
        }

        private static readonly HashSet<string> KnownWindowsComDllNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "combase.dll",
            "ole32.dll",
            "oleaut32.dll",
            "actxprxy.dll",
            "propsys.dll",
            "appxdeploymentclient.dll"
        };

        public static bool IsKnownWindowsSystemComDll(in Registration r)
        {
            // 1. MUST be machine-wide (HKLM), never user-writable HKCU
            if (r.Hive.IndexOf("HKCU", StringComparison.OrdinalIgnoreCase) >= 0) return false;

            var raw = (r.ServerValue ?? "").Trim().Trim('"');
            if (raw.Length == 0) return false;

            // Only bare filenames without directory separators (must not be relative traversal)
            if (raw.IndexOfAny(new[] { '\\', '/', ':', '%', '$' }) >= 0) return false;

            // 2. Closed, immutable set of core Windows COM subsystem DLLs
            if (!KnownWindowsComDllNames.Contains(raw)) return false;

            // 3. Must physically exist in System32
            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sys32File = Path.Combine(windir, "System32", raw);
            return File.Exists(sys32File);
        }

        private static bool IsLegitimateWindowsScriptHostRegistration(in Registration r)
        {
            // 1. MUST be machine-wide (HKLM), never user-writable HKCU
            if (r.Hive.IndexOf("HKCU", StringComparison.OrdinalIgnoreCase) >= 0) return false;

            var raw = (r.ServerValue ?? "").Trim();
            var exePath = ExtractServerPath(raw);
            if (exePath.Length == 0) return false;

            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sys32 = Path.Combine(windir, "System32");
            var syswow64 = Path.Combine(windir, "SysWOW64");

            // No command chaining or shell redirection characters
            if (raw.IndexOfAny(new[] { '&', '|', ';', '`', '$', '\n', '\r', '<', '>' }) >= 0)
                return false;

            // Case A: Windows Shell rundll32 surrogate
            // Standard pattern: "C:\WINDOWS\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {CLSID}"
            // or "C:\WINDOWS\system32\rundll32.exe /sta {CLSID}"
            if (exePath.Equals(Path.Combine(sys32, "rundll32.exe"), StringComparison.OrdinalIgnoreCase) ||
                exePath.Equals(Path.Combine(syswow64, "rundll32.exe"), StringComparison.OrdinalIgnoreCase))
            {
                bool isShCreate = raw.IndexOf("shell32.dll,SHCreateLocalServerRunDll", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isSta = raw.IndexOf("/sta ", StringComparison.OrdinalIgnoreCase) >= 0;

                if (!isShCreate && !isSta) return false;

                if (isShCreate)
                {
                    // Verify shell32 is either bare "shell32.dll" or fully-qualified inside System32/SysWOW64
                    int idx = raw.IndexOf("shell32.dll", StringComparison.OrdinalIgnoreCase);
                    if (idx > 0)
                    {
                        int spaceBefore = raw.LastIndexOf(' ', idx);
                        if (spaceBefore >= 0 && spaceBefore < idx)
                        {
                            string prefix = raw.Substring(spaceBefore + 1, idx - spaceBefore - 1).Trim();
                            if (prefix.Length > 0 &&
                                !prefix.Equals(sys32 + @"\", StringComparison.OrdinalIgnoreCase) &&
                                !prefix.Equals(syswow64 + @"\", StringComparison.OrdinalIgnoreCase))
                            {
                                return false; // Non-system path to shell32.dll!
                            }
                        }
                    }
                }

                return true;
            }

            // Case B: Windows built-in HTML Document COM server (MSHTA)
            // Strictly for CLSID {3050f4d8-98B5-11CF-BB82-00AA00BDCE0B} without external script or URL arguments
            if (exePath.Equals(Path.Combine(sys32, "mshta.exe"), StringComparison.OrdinalIgnoreCase) ||
                exePath.Equals(Path.Combine(syswow64, "mshta.exe"), StringComparison.OrdinalIgnoreCase))
            {
                if (!r.Clsid.Equals("{3050f4d8-98B5-11CF-BB82-00AA00BDCE0B}", StringComparison.OrdinalIgnoreCase) &&
                    !r.Clsid.Equals("3050f4d8-98B5-11CF-BB82-00AA00BDCE0B", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Must NOT contain scripts, URLs, protocols, or file paths
                if (raw.IndexOf("http:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf("https:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf("javascript:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf("vbscript:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    raw.IndexOf(".hta", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }

                return true;
            }

            return false;
        }

        public static Verdict Evaluate(in Registration r)
        {
            if (r.Kind == ServerKind.TreatAs)
                return EvaluateTreatAs(in r);

            var path = ExtractServerPath(r.ServerValue);
            if (path.Length == 0)
                return None();

            var baselinePath = string.IsNullOrEmpty(r.BaselineValue)
                ? ""
                : ExtractServerPath(r.BaselineValue);
            bool isNew = baselinePath.Length == 0;
            bool changed = !isNew && !string.Equals(baselinePath, path, StringComparison.OrdinalIgnoreCase);

            if (ModuleIdentity.IsOsServicingPath(path))
                return None();

            if (ModuleIdentity.IsServicingNameOutsideStore(path))
            {
                return Hijack(
                    0.92,
                    "Registry: COM Servicing-DLL Impersonation",
                    "COM InprocServer32/Handler points at a Component Based Servicing DLL name " +
                    "(cbsapi/cbscore/cbsmsg) that is not under WinSxS or Windows\\servicing. " +
                    "On current Windows the real CBS stack lives in the component store; a copy " +
                    "anywhere else - including System32 - is a plant. Quarantine the file, never the CLSID.");
            }

            if (ModuleIdentity.IsUserWritableDrop(path) || IsPublicDrop(path))
            {
                return Hijack(
                    0.88,
                    "Registry: COM Server in User-Writable Path",
                    "COM InprocServer32/LocalServer32 points at Temp/AppData/Downloads/Desktop/Public. " +
                    "Classic COM hijack persistence (T1546.015). Quarantine the payload DLL; do not delete the class.");
            }

            if (IsScriptHostServer(path))
            {
                if (IsLegitimateWindowsScriptHostRegistration(in r))
                    return None();

                return Hijack(
                    0.90,
                    "Registry: COM Server is Script Host",
                    "COM LocalServer32/InprocServer32 launches powershell/cmd/wscript/mshta/rundll32. " +
                    "Observe-only for the LOLBin itself; the CLSID key is not deleted.",
                    quarantine: false);
            }

            if (r.HkcuShadowsHklm
                && !string.IsNullOrEmpty(r.HklmValue)
                && !string.Equals(path, ExtractServerPath(r.HklmValue), StringComparison.OrdinalIgnoreCase)
                && !IsTrustedComServerPath(path)
                && !IsKnownWindowsSystemComDll(in r))
            {
                return Hijack(
                    0.84,
                    "Registry: HKCU COM CLSID Shadow",
                    "HKCU\\Software\\Classes\\CLSID overrides an HKLM class with a different server path. " +
                    "HKCU wins at activation with no admin required.");
            }

            if (changed && !IsTrustedComServerPath(path) && !IsKnownWindowsSystemComDll(in r))
            {
                return Hijack(
                    0.80,
                    "Registry: COM Server Path Changed",
                    "An existing CLSID server path changed to a location outside the OS / Program Files trees. " +
                    "This is the hijack Sentinel used to miss by only watching for *new* CLSIDs.");
            }

            if (isNew && !IsTrustedComServerPath(path) && !IsKnownWindowsSystemComDll(in r))
            {
                return Hijack(
                    0.70,
                    "Registry: Suspicious COM CLSID Registration",
                    "New COM server registered outside System32/WinSxS/Program Files.");
            }

            return None();
        }

        private static Verdict EvaluateTreatAs(in Registration r)
        {
            var value = (r.ServerValue ?? "").Trim();
            if (value.Length == 0)
                return None();

            bool hkcu = r.Hive.IndexOf("HKCU", StringComparison.OrdinalIgnoreCase) >= 0;
            var baseline = (r.BaselineValue ?? "").Trim();
            bool isNew = baseline.Length == 0;
            bool changed = !isNew && !string.Equals(baseline, value, StringComparison.OrdinalIgnoreCase);

            if (!hkcu && !changed)
                return None();

            if (hkcu || changed)
            {
                return Hijack(
                    0.78,
                    "Registry: COM TreatAs Redirect",
                    "TreatAs redirects a CLSID to another class. HKCU TreatAs leaves the original " +
                    "InprocServer32 untouched and is a documented COM hijack. LogOnly - do not delete the class.",
                    quarantine: false);
            }

            return None();
        }

        private static Verdict None() => new()
        {
            IsHijack = false,
            ShouldQuarantinePayload = false,
            Confidence = 0,
            RuleName = "",
            Reasoning = "",
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly
        };

        private static Verdict Hijack(double confidence, string rule, string reasoning, bool quarantine = true) => new()
        {
            IsHijack = true,
            ShouldQuarantinePayload = quarantine,
            Confidence = confidence,
            RuleName = rule,
            Reasoning = reasoning,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly
        };
    }
}
