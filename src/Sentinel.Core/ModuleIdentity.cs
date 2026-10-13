using System;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Identity of a mapped PE: path tree + Microsoft signature.
    /// Count is not identity (Chromium loading Edge DLLs is not injection).
    /// Hijack names (dbghelp, version, winmm, ...) next to the exe are plants even
    /// when Microsoft-signed - DLL search order loads the local copy first.
    /// </summary>
    public static class ModuleIdentity
    {
        /// <summary>
        /// Loadable-module file extensions. The unloader enumerates every mapped PE via
        /// EnumProcessModules regardless of extension, so identity applies to all of them.
        /// This set is used by the filename-keyed helpers (bundled / sideload plant) so a
        /// non-.dll module (WinRT .winmd with MSIL, .ocx, .cpl, .node, .ax, .drv, ...) is not
        /// silently treated as "not a module". A system-provided .winmd is pure metadata and
        /// stays keep-tree; a third-party managed .winmd can carry code, so it is in scope.
        /// </summary>
        public static readonly System.Collections.Generic.HashSet<string> ModuleExtensions =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ".dll",   // classic PE library
                ".winmd", // WinRT metadata (managed ones carry MSIL)
                ".ocx",   // ActiveX / OLE control
                ".cpl",   // Control Panel applet (PE)
                ".ax",    // DirectShow filter (PE)
                ".node",  // Node.js native addon (PE)
                ".drv",   // legacy driver-model user DLL
                ".acm",   // audio compression manager (PE)
                ".tsp",   // TAPI service provider (PE)
                ".mui",   // resource-only module
                ".efi",   // EFI application/driver (PE)
            };

        /// <summary>
        /// True when the file name (or path) ends with a known loadable-module extension.
        /// Executables (.exe) are their own process image and are handled separately.
        /// </summary>
        public static bool IsModuleFileName(string? pathOrName)
        {
            if (string.IsNullOrWhiteSpace(pathOrName)) return false;
            string ext;
            try { ext = Path.GetExtension(pathOrName) ?? ""; }
            catch { return false; }
            return ext.Length > 0 && ModuleExtensions.Contains(ext);
        }

        public readonly struct Verdict
        {
            public Verdict(bool allowed, string reason)
            {
                Allowed = allowed;
                Reason = reason;
            }

            public bool Allowed { get; }
            public string Reason { get; }
        }

        /// <summary>
        /// <paramref name="isMicrosoftSigned"/> is only consulted when path trees are not enough.
        /// Pass null to treat unknown signatures as unsigned (fail closed).
        /// </summary>
        public static Verdict Evaluate(
            string? processImagePath,
            string? modulePath,
            Func<string, bool>? isMicrosoftSigned = null)
        {
            if (string.IsNullOrWhiteSpace(modulePath))
                return Deny("empty-path");

            var mod = Normalize(modulePath);
            if (mod.Length == 0)
                return Deny("empty-path");

            if (IsOsServicingPath(mod))
                return Allow("os-servicing");

            // CBS/servicing-stack DLL names are only legitimate in the component store.
            // keep-tree would otherwise allow C:\Windows\System32\cbsapi.dll, which is
            // how a COM-hijack plant wearing a servicing name slipped identity.
            if (IsServicingNameOutsideStore(mod))
                return Deny("servicing-name-outside-store");

            var image = Normalize(processImagePath);
            if (image.Length > 0 && PathsEqual(mod, image))
                return Allow("process-image");

            // Roslyn build-server analyzer shadow-copy. VBCSCompiler / dotnet / MSBuild
            // shadow-copy NuGet-cached analyzers and source generators into
            // %TEMP%\VBCSCompiler\AnalyzerAssemblyLoader\<guid>\N\ and load them from there,
            // so the .nuget\packages keep-tree never matches the loaded copy and every .NET
            // build/test tripped "user-writable-drop" (Microsoft.Extensions.*.SourceGeneration,
            // System.Text.Json.SourceGeneration, xunit.analyzers, ...). This is a documented SDK
            // mechanism, not a sideload plant. Gated on the LOADING PROCESS being a Microsoft
            // Roslyn/SDK host so a hostile process cannot self-authorize by merely naming its
            // drop folder "VBCSCompiler\AnalyzerAssemblyLoader" - behavioral, not path-only.
            if (IsRoslynAnalyzerShadowCopy(mod) && IsRoslynBuildHost(image))
                return Allow("roslyn-analyzer-shadowcopy");

            // NuGet package cache. This lives under the user profile (%USERPROFILE%\.nuget\
            // packages) - anyone who can write the user profile can plant a DLL here, so it is
            // NOT a blanket keep-tree. It is only legitimate as a load source for a Microsoft
            // Roslyn / .NET SDK build host (VBCSCompiler/dotnet/msbuild loading NuGet-cached
            // source generators and analyzers). Gate on the loading host, same as the analyzer
            // shadow-copy allowance, so an arbitrary process cannot self-authorize from it.
            if (IsNuGetPackageCache(mod) && IsRoslynBuildHost(image))
                return Allow("nuget-cache-buildhost");

            // GPU ICD names (nvapi*, amdocl*, igc64*, ...) are only trusted when they load
            // from a plausible driver location AND are not in a user-writable drop. The ICD
            // name alone is attacker-controllable (rename payload to nvapi64.dll), so a bare
            // filename match anywhere - including %TEMP% - previously self-authorized. Real
            // ICDs live in the OS tree (System32 / DriverStore) or a vendor Program Files
            // install; both are covered by keep-tree / Program Files below, so gate on that.
            if (IsGpuIcdName(mod) &&
                !IsUserWritableDrop(mod) &&
                (IsKeepTree(mod) || IsProgramFilesTree(mod)))
                return Allow("gpu-icd");

            if (IsKeepTree(mod))
            {
                // A module that lands in a user-writable drop that happens to sit inside the
                // keep-tree (Windows\Tasks, Windows\tracing, the spool color dir, ...) is NOT
                // trusted just for being under the Windows root - those ACL holes are exactly
                // where a low-priv attacker plants. Sideload-name plants are always denied.
                // Any other module in such a drop is only spared if it is Microsoft-signed
                // (real OS servicing writes signed files there); everything else falls through
                // to the standard user-writable-drop deny below.
                if (IsUserWritableDrop(mod))
                {
                    if (DllUnloadEngine.IsSideloadTargetFileName(mod))
                        return Deny("sideload-name-in-writable");
                    if (!MicrosoftSigned(mod, isMicrosoftSigned) && !IsAuthenticodeTrusted(mod))
                        return Deny("keep-tree-writable-drop");
                    return Allow("keep-tree-signed-in-writable");
                }
                return Allow("keep-tree");
            }

            var procDir = image.Length > 0 ? DirOf(image) : "";
            var modDir = DirOf(mod);
            bool underApp = procDir.Length > 0 && IsUnderDirectory(modDir, procDir);

            if (underApp)
            {
                // Known hijack names must come from the OS keep-tree (already
                // allowed above). A real Microsoft dbghelp.dll copied next to
                // the exe is still a search-order hijack. Do not use module
                // count; do not unload every unsigned app DLL (games, plugins).
                if (DllUnloadEngine.IsSideloadTargetFileName(mod))
                    return Deny("sideload-plant-in-appdir");
                return Allow("app-directory");
            }

            if (MicrosoftSigned(mod, isMicrosoftSigned) &&
                IsProgramFilesTree(mod) &&
                !IsUserWritableDrop(mod))
                return Allow("microsoft-signed-programfiles");

            // Any Authenticode-trusted third-party DLL installed under Program Files is a
            // legitimately-installed component (7-Zip, Notepad++, GPU/vendor tools, shell
            // extensions), NOT a foreign-path injection - even when its host process lives
            // elsewhere (e.g. a shell extension loaded into explorer.exe). Quarantining these
            // on signer!=Microsoft alone is identity-based response, which the constraints
            // forbid: we must act on what a module DOES, not who signed it.
            //
            // The search-order-hijack defense is preserved: known hijack-target names
            // (dbghelp/version/winmm/...) are still denied above when planted in the app dir,
            // and any DLL in a user-writable drop (Temp/Downloads/AppData) is denied below.
            // So a signed DLL in Program Files that is not a hijack name is allowed.
            if (IsProgramFilesTree(mod) &&
                !IsUserWritableDrop(mod) &&
                !DllUnloadEngine.IsSideloadTargetFileName(mod) &&
                IsAuthenticodeTrusted(mod))
                return Allow("signed-programfiles");

            if (IsUserWritableDrop(mod))
                return Deny("user-writable-drop");

            return Deny("foreign-path");
        }

        public static bool IsAllowed(
            string? processImagePath,
            string? modulePath,
            Func<string, bool>? isMicrosoftSigned = null) =>
            Evaluate(processImagePath, modulePath, isMicrosoftSigned).Allowed;

        public static bool IsKeepTree(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;

            // Whole OS tree except Windows\Temp (that is still a drop folder).
            // NativeImages, Microsoft.NET, SystemApps, UUS were missed by the
            // system32-only check and got FreeLibrary'd - CLR 80131506 / StartMenu loop.
            var win = WindowsRoot();
            if (p.Equals(win, StringComparison.Ordinal) ||
                p.StartsWith(win + @"\", StringComparison.Ordinal))
            {
                if (ContainsDir(p, @"\windows\temp\") || ContainsDir(p, @"\windows\tmp\"))
                    return false;
                return true;
            }

            if (ContainsDir(p, @"\microsoft\edgewebview\")) return true;
            if (ContainsDir(p, @"\microsoft\edge\")) return true;
            if (ContainsDir(p, @"\microsoft\edgecore\")) return true;
            if (ContainsDir(p, @"\microsoft\edgeupdate\")) return true;
            if (ContainsDir(p, @"\microsoft shared\")) return true;
            if (ContainsDir(p, @"\windowsapps\")) return true;
            if (ContainsDir(p, @"\webview2userdata\")) return true;
            if (ContainsDir(p, @"\ebwebview\")) return true;
            if (ContainsDir(p, @"\dotnet\")) return true;
            if (ContainsDir(p, @"\microsoft.net\")) return true;
            // Vendor GPU/driver install trees. These folder names (\amd\, \intel\,
            // \nvidia corporation\, \ati technologies\) are short and attacker-controllable:
            // a substring match anywhere previously trusted C:\ProgramData\amd\evil.dll or
            // D:\games\amd\evil.dll. Real vendor components install under Program Files (their
            // Windows-tree copies are already covered by the WindowsRoot() branch above), so
            // only trust the vendor folder name when it also sits under Program Files.
            if (IsProgramFilesTree(p) && IsVendorTree(p)) return true;

            return false;
        }

        /// <summary>
        /// True when the path contains a known GPU/driver vendor folder name. Callers must
        /// also confirm a trusted root location (Program Files / OS tree) before trusting -
        /// the folder name alone is attacker-controllable.
        /// </summary>
        private static bool IsVendorTree(string normalizedPath)
        {
            if (ContainsDir(normalizedPath, @"\nvidia corporation\")) return true;
            if (ContainsDir(normalizedPath, @"\amd\")) return true;
            if (ContainsDir(normalizedPath, @"\ati technologies\")) return true;
            if (ContainsDir(normalizedPath, @"\intel\")) return true;
            return false;
        }

        public static bool IsUserWritableDrop(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\temp\")) return true;
            if (p.EndsWith(@"\temp", StringComparison.Ordinal)) return true;
            if (ContainsDir(p, @"\downloads\")) return true;
            if (ContainsDir(p, @"\desktop\")) return true;
            if (ContainsDir(p, @"\users\public\")) return true;
            if (ContainsDir(p, @"\appdata\local\temp\")) return true;

            // Directories UNDER the Windows tree that a standard (non-admin) user can write to
            // by default. IsKeepTree trusts the whole Windows root except \Temp; these are the
            // other classic default-writable ACL holes a low-priv attacker can plant into, so
            // treat them as drops and let the keep-tree branch reject a plant that lands here.
            if (ContainsDir(p, @"\windows\tasks\")) return true;
            if (ContainsDir(p, @"\windows\tracing\")) return true;
            if (ContainsDir(p, @"\windows\registration\crmlog\")) return true;
            if (ContainsDir(p, @"\windows\system32\spool\drivers\color\")) return true;
            if (ContainsDir(p, @"\windows\system32\tasks\")) return true;
            if (ContainsDir(p, @"\windows\syswow64\tasks\")) return true;
            if (ContainsDir(p, @"\windows\system32\com\dmp\")) return true;
            if (ContainsDir(p, @"\windows\system32\fxstmp\")) return true;
            if (ContainsDir(p, @"\windows\syswow64\com\dmp\")) return true;
            if (ContainsDir(p, @"\windows\syswow64\fxstmp\")) return true;
            if (ContainsDir(p, @"\windows\pla\reports\")) return true;
            if (ContainsDir(p, @"\windows\pla\rules\")) return true;
            if (ContainsDir(p, @"\windows\pla\templates\")) return true;
            if (ContainsDir(p, @"\windows\pla\traces\")) return true;
            if (ContainsDir(p, @"\windows\debug\wia\")) return true;
            // AppData overlays except Edge/WebView user-data (keep-tree already matched those).
            if (ContainsDir(p, @"\appdata\local\") || ContainsDir(p, @"\appdata\roaming\"))
            {
                if (ContainsDir(p, @"\microsoft\edge")) return false;
                if (ContainsDir(p, @"\webview2userdata\")) return false;
                if (ContainsDir(p, @"\ebwebview\")) return false;
                return true;
            }
            return false;
        }

        /// <summary>
        /// True when the module lives in the Roslyn build server's analyzer shadow-copy tree
        /// (<c>...\VBCSCompiler\AnalyzerAssemblyLoader\...</c>). The compiler server copies
        /// analyzers/source-generators out of the NuGet cache into a per-build temp folder and
        /// loads them from there; that copy is not covered by the <c>.nuget\packages</c> keep-tree.
        /// Structural match only - callers must ALSO confirm the loading host is a Roslyn/SDK
        /// binary via <see cref="IsRoslynBuildHost"/> before allowing.
        /// </summary>
        public static bool IsRoslynAnalyzerShadowCopy(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            return ContainsDir(p, @"\vbcscompiler\analyzerassemblyloader\");
        }

        /// <summary>
        /// True when the module lives in the NuGet package cache (<c>...\.nuget\packages\...</c>).
        /// This cache sits under the user profile and is user-writable, so a match here must be
        /// combined with a Roslyn/SDK build-host check (<see cref="IsRoslynBuildHost"/>) before
        /// trusting - an arbitrary process loading from the cache is not automatically legitimate.
        /// </summary>
        public static bool IsNuGetPackageCache(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            return ContainsDir(p, @"\.nuget\packages\");
        }

        /// <summary>
        /// True when the process image is a Microsoft Roslyn / .NET SDK build host that
        /// legitimately shadow-copies and loads analyzers (VBCSCompiler, csc, vbc, dotnet,
        /// MSBuild). Path-shaped identity of the HOST, used only to gate the analyzer
        /// shadow-copy allowance so an arbitrary process cannot abuse the folder name.
        /// </summary>
        public static bool IsRoslynBuildHost(string? processImagePath)
        {
            var p = Normalize(processImagePath);
            if (p.Length == 0) return false;
            // Must sit in a Microsoft SDK/Roslyn tree AND be a known build-host image.
            bool sdkTree = ContainsDir(p, @"\dotnet\") ||
                           ContainsDir(p, @"\roslyn\") ||
                           ContainsDir(p, @"\msbuild\") ||
                           ContainsDir(p, @"\microsoft visual studio\") ||
                           ContainsDir(p, @"\microsoft.net\");
            if (!sdkTree) return false;
            string file;
            try { file = Path.GetFileName(p) ?? ""; }
            catch { return false; }
            return file is "vbcscompiler.exe" or "csc.exe" or "vbc.exe"
                        or "dotnet.exe" or "msbuild.exe";
        }

        /// <summary>
        /// Component Based Servicing stack DLL names. The real copies live under
        /// WinSxS / Windows\servicing (CbsCore, CbsMsg; CbsApi on older servicing
        /// stacks). A file with one of these names anywhere else - including
        /// System32 - is impersonation, not the OS component.
        /// </summary>
        public static readonly System.Collections.Generic.HashSet<string> ServicingStackDllNames =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "cbsapi.dll",
                "cbscore.dll",
                "cbsmsg.dll",
            };

        public static bool IsServicingImpersonationName(string? pathOrName)
        {
            if (string.IsNullOrWhiteSpace(pathOrName)) return false;
            string file;
            try { file = Path.GetFileName(pathOrName) ?? ""; }
            catch { return false; }
            return file.Length > 0 && ServicingStackDllNames.Contains(file);
        }

        /// <summary>
        /// True when the path is a servicing-stack DLL name and is NOT under WinSxS /
        /// Windows\servicing / CBS scratch. System32\cbsapi.dll is true.
        /// </summary>
        public static bool IsServicingNameOutsideStore(string? path) =>
            IsServicingImpersonationName(path) && !IsOsServicingPath(path);

        public static bool IsOsServicingPath(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\nltmpscratch\")) return true;
            if (ContainsDir(p, @"\nltmps\")) return true;
            if (ContainsDir(p, @"\winsxs\")) return true;
            if (ContainsDir(p, @"\servicing\")) return true;
            if (ContainsDir(p, @"\cbstemp\")) return true;
            if (ContainsDir(p, @"\windows\system32\dism\")) return true;
            if (ContainsDir(p, @"\windows\syswow64\dism\")) return true;
            if (ContainsDir(p, @"\microsoft\windows\servicing\")) return true;
            return false;
        }

        public static bool IsGpuIcdName(string? path)
        {
            string file;
            try { file = Path.GetFileNameWithoutExtension(path) ?? ""; }
            catch { return false; }
            if (file.Length == 0) return false;
            file = file.ToLowerInvariant();
            foreach (var prefix in GpuIcdPrefixes)
            {
                if (file.StartsWith(prefix, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        public static bool IsProgramFilesTree(string? path)
        {
            var p = Normalize(path);
            if (p.Length == 0) return false;
            if (ContainsDir(p, @"\program files\")) return true;
            if (ContainsDir(p, @"\program files (x86)\")) return true;
            return false;
        }

        private static readonly string[] GpuIcdPrefixes =
        {
            "nvldumd", "nvwgf2um", "nvd3dum", "nvoglv", "nvapi", "nvopencl", "nvcuda",
            "atidxx", "atio6axx", "amdxc", "amdvlk", "atiadlxx", "atioglxx", "amdocl",
            "igc64", "igc32", "igd10", "igd12", "igdail", "igd9s", "ig4icd", "ig9icd",
            "ig11icd", "ig12icd", "igvk", "intelocl", "igdrcl",
        };

        private static bool MicrosoftSigned(string path, Func<string, bool>? isMicrosoftSigned)
        {
            if (isMicrosoftSigned == null) return false;
            try { return isMicrosoftSigned(path); }
            catch { return false; }
        }

        /// <summary>
        /// True when the module carries a valid Authenticode signature that chains to a
        /// trusted root - regardless of publisher. Used only to spare legitimately-installed
        /// third-party DLLs under Program Files from foreign-path quarantine. Fails closed:
        /// any verification error is treated as untrusted.
        /// </summary>
        private static bool IsAuthenticodeTrusted(string path)
        {
            try { return SecurityValidation.VerifyAuthenticodeSignature(path); }
            catch { return false; }
        }

        private static Verdict Allow(string reason) => new(true, reason);
        private static Verdict Deny(string reason) => new(false, reason);

        internal static string Normalize(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return "";
            try
            {
                var p = path!.Trim().Replace('/', '\\');
                if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p.Substring(4);
                if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
                return p.TrimEnd('\\').ToLowerInvariant();
            }
            catch { return ""; }
        }

        private static string DirOf(string normalizedPath)
        {
            try
            {
                var d = Path.GetDirectoryName(normalizedPath);
                return string.IsNullOrEmpty(d) ? "" : d.TrimEnd('\\');
            }
            catch { return ""; }
        }

        private static bool PathsEqual(string a, string b) =>
            string.Equals(a, b, StringComparison.Ordinal);

        internal static bool IsUnderDirectory(string childDir, string parentDir)
        {
            if (childDir.Length == 0 || parentDir.Length == 0) return false;
            if (childDir.Equals(parentDir, StringComparison.Ordinal)) return true;
            return childDir.StartsWith(parentDir + @"\", StringComparison.Ordinal);
        }

        private static bool ContainsDir(string normalizedPath, string needle) =>
            normalizedPath.IndexOf(needle, StringComparison.Ordinal) >= 0;

        private static string WindowsRoot()
        {
            try
            {
                var w = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return string.IsNullOrEmpty(w) ? @"c:\windows" : w.TrimEnd('\\').ToLowerInvariant();
            }
            catch { return @"c:\windows"; }
        }
    }
}
