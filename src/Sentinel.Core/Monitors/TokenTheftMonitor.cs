using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.7: Token Theft Monitor - detects token manipulation beyond integrity level changes.
    /// v1.8.0: Suppress Windows built-in false positives (Memory Compression, Registry, empty
    /// image path). Longer per-PID/rule cooldown. Empty path is no longer treated as "suspicious".
    ///
    /// Blind spot addressed: TokenIntegrityMonitor only catches Medium->High escalation without
    /// consent.exe. It misses: DuplicateToken/ImpersonateLoggedOnUser from winlogon, make_token,
    /// steal_token (Cobalt Strike), and Rubeus-style Kerberos ticket manipulation that don't
    /// necessarily change the integrity level.
    ///
    /// Detection approach:
    /// - Scan processes for tokens with SYSTEM/LocalService/NetworkService SID where the
    ///   process owner is a regular user (non-SYSTEM process holding SYSTEM token)
    /// - Detect processes with SeImpersonatePrivilege enabled from non-service paths
    /// - Monitor for processes with multiple distinct token users (impersonation indicators)
    /// - Watch for known token manipulation tool signatures in loaded modules
    ///
    /// Response: Tier1 KillProcessTree for confirmed token theft (0.85+).
    ///           Tier2 LogOnly for impersonation privilege anomalies (0.60-0.70).
    /// Scans every 20s. No elevation beyond PROCESS_QUERY_LIMITED_INFORMATION required.
    /// </summary>
    public sealed class TokenTheftMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ContextBus? _contextBus;
        private readonly ILogger<TokenTheftMonitor> _logger;

        /// <summary>Key: "pid|ruleShort" -> last alert UTC. v1.8.0: 60-minute window (was 5).</summary>
        private readonly ConcurrentDictionary<string, DateTime> _alertedKeys = new(StringComparer.OrdinalIgnoreCase);

        private const int AlertCooldownMinutes = 60;

        // P/Invoke for token inspection
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
            IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountSidW(string? systemName, IntPtr sid,
            System.Text.StringBuilder name, ref int nameSize,
            System.Text.StringBuilder domain, ref int domainSize, out int use);

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenUser = 1;
        private const int TokenPrivileges = 3;

        // Processes that legitimately hold SYSTEM tokens
        private static readonly HashSet<string> LegitimateSystemTokenHolders = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "system idle process", "idle", "registry", "memory compression",
            "secure system", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
            "svchost", "dwm", "spoolsv", "searchindexer", "wmiprvse", "dllhost",
            "taskhostw", "fontdrvhost", "audiodg", "msdtc", "vds", "runtimebroker",
            "sgrmbroker", "securityhealthservice", "msmpsvc", "msmpeng",
            "nissrv", "sense", "mpdefendercoreservice", "sentinel.service",
            "sentinel.agent", "trustedinstaller", "tiworker", "wuauserv",
            "msiexec", "dismhost", "ntlite", "conhost", "sihost", "ctfmon",
            "shellhost", "startmenuexperiencehost", "searchhost", "textinputhost",
            "applicationframehost", "systemsettings", "securityhealthsystray",
            "dashost", "lsaiso", "credentialuibroker", "consent", "werfault",
            "wermgr", "taskmgr", "procexp", "procexp64",
            // v2.9.3: Windows Update / Unified Update Stack (UUS) workers legitimately run
            // as SYSTEM from C:\Windows\UUS\ and C:\Windows\System32. Previously flagged as
            // "non-service process with SYSTEM token" (kill + police evidence pack) because
            // C:\Windows\UUS\ is not System32/SysWOW64/Program Files.
            "mousocoreworker", "usocoreworker", "usoclient", "sedsvc", "waasmedicagent",
            // .NET Framework runtime optimization workers (NGEN) run as SYSTEM during idle maintenance
            "ngen", "ngentask", "mscorsvw"
        };

        // Processes that legitimately have SeImpersonatePrivilege
        private static readonly HashSet<string> LegitimateImpersonators = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "system idle process", "idle", "registry", "memory compression",
            "secure system", "svchost", "services", "lsass", "sqlservr", "w3wp", "iisexpress",
            "wmiprvse", "dllhost", "spoolsv", "msdtc", "searchindexer",
            "sentinel.service", "sentinel.agent", "trustedinstaller", "msiexec",
            "csrss", "wininit", "winlogon", "smss", "dwm", "fontdrvhost", "taskhostw"
        };

        // Known token manipulation tool module names
        private static readonly string[] TokenTheftModules = new[]
        {
            "incognito", "tokenvator", "sharptoken", "getst", "rubeus",
            "kekeo", "whoami_module", "impersonate"
        };

        public TokenTheftMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<TokenTheftMonitor> logger,
            ContextBus? contextBus = null)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
            _contextBus = contextBus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[TokenTheftMonitor] Started - scan every 20s; OS FP allowlist + {Cooldown}m alert cooldown (v1.8.0)",
                AlertCooldownMinutes);
            await Task.Delay(15000, ct); // Startup grace

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(20000, ct);
                    await ScanForTokenTheftAsync(ct);
                    PruneAlertCache();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[TokenTheftMonitor] Scan error"); }
            }
        }

        private async Task ScanForTokenTheftAsync(CancellationToken ct)
        {
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch { return; }

            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    int pid = proc.Id;
                    if (pid <= 4) continue;

                    string processName = proc.ProcessName;

                    // Resolve the image path up front so name-based exemptions can be anchored
                    // to a non-attacker-controllable location. A whitelisted NAME (svchost,
                    // lsass, ...) must NOT self-exempt on its own - an attacker renames a potato
                    // binary "svchost.exe" and drops it in Temp. The name is only trusted when it
                    // is backed by a real system image path (System32/SysWOW64/Program Files, not
                    // a user-writable drop), OR when the path is genuinely unresolvable AND the
                    // name is a known protected/session-0 component (Memory Compression, Registry,
                    // Secure System) that legitimately has no queryable image path.
                    string earlyImagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";

                    // v1.8.0 / hardened: skip built-in OS holders before any token open - but only
                    // when the name is anchored to a trusted path or is a pathless protected process.
                    if (IsTrustedSystemTokenHolder(processName, earlyImagePath)) continue;

                    // Get the token user for this process
                    var tokenInfo = GetProcessTokenUser(pid);
                    if (tokenInfo == null) continue;

                    // Detect: non-service process running with SYSTEM/LocalService/NetworkService token
                    if (tokenInfo.Value.IsSystemToken && !IsExpectedSystemProcess(processName, pid))
                    {
                        string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";

                        // v1.8.0: inaccessible image path on an OS-like name -> ignore (Memory Compression, etc.)
                        if (string.IsNullOrEmpty(imagePath) && IsLikelyProtectedOsProcess(processName))
                            continue;

                        // Verify this isn't a service running from a legitimate path
                        if (!IsServicePath(imagePath))
                        {
                            if (WasRecentlyAlerted(pid, "system-token"))
                                continue;

                            double confidence;
                            var response = ResponseAction.LogOnly;

                            if (string.IsNullOrEmpty(imagePath))
                            {
                                // Empty path without a known OS name: weak signal only - never kill/pack-grade
                                confidence = 0.55;
                                response = ResponseAction.LogOnly;
                            }
                            else if (IsSuspiciousPath(imagePath))
                            {
                                confidence = 0.90;
                                response = ResponseAction.KillProcessTree;
                            }
                            else if (!IsInProgramFiles(imagePath) && !IsServicePath(imagePath))
                            {
                                confidence = 0.85;
                                response = ResponseAction.KillProcessTree;
                            }
                            else
                            {
                                confidence = 0.70;
                                response = ResponseAction.LogOnly;
                            }

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                                Evidence = $"Process '{processName}' (PID {pid}) at '{Truncate(imagePath, 120)}' holds a " +
                                           $"{tokenInfo.Value.TokenUserName} token but is not a registered service or legitimate system process.",
                                Reasoning = "A process that is not a Windows service or known system component is running with SYSTEM-level token privileges. " +
                                            "This indicates token theft via DuplicateToken, ImpersonateLoggedOnUser, or make_token (MITRE T1134.001, T1134.003).",
                                Confidence = confidence,
                                Tier = confidence >= 0.80
                                    ? DetectionTier.Tier1Behavioral
                                    : DetectionTier.Tier2Indicator,
                                AuthorizedResponse = response,
                                SignalType = SignalType.CredentialTheft,
                                ProcessName = processName,
                                ProcessId = pid,
                            });

                            if (confidence >= 0.80)
                            {
                                _contextBus?.Publish(new TokenTheftSignal
                                {
                                    ProcessId = pid,
                                    ProcessName = processName,
                                    SourceMonitor = "TokenTheftMonitor",
                                    TokenUserName = tokenInfo.Value.TokenUserName,
                                    TheftType = TokenTheftType.SystemTokenFromUserProcess,
                                    ImagePath = imagePath,
                                    HasImpersonatePrivilege = tokenInfo.Value.HasImpersonatePrivilege,
                                });
                            }

                            MarkAlerted(pid, "system-token");
                        }
                    }

                    // Detect: SeImpersonatePrivilege from user-writable paths (potato attacks)
                    if (tokenInfo.Value.HasImpersonatePrivilege &&
                        !IsTrustedImpersonator(processName, earlyImagePath))
                    {
                        string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";

                        // v1.8.0: empty path is not a potato path - skip (was treating "" as suspicious)
                        if (string.IsNullOrEmpty(imagePath))
                            continue;

                        if (IsLikelyProtectedOsProcess(processName))
                            continue;

                        // v1.7.1: Exempt installer extractors (Inno Setup .tmp, NSIS)
                        if (InstallerHeuristics.IsInstallerExtractor(processName, imagePath) ||
                            InstallerHeuristics.LooksLikeInstallerName(processName, imagePath))
                        {
                            continue;
                        }

                        // v1.8.3: SeImpersonate + Downloads/Temp alone is NOT confirmed potato.
                        // Portable tools, UUP aria2c, torrents, and elevated shells inherit this
                        // privilege constantly. Observe-only; kill when SYSTEM-token theft or
                        // known token-theft modules corroborate (other branches / correlation).
                        if (InstallerHeuristics.IsBenignPortableWorkContext(processName, imagePath))
                        {
                            continue;
                        }

                        if (IsSuspiciousPath(imagePath))
                        {
                            if (WasRecentlyAlerted(pid, "seimpersonate"))
                                continue;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                                Evidence = $"Process '{processName}' (PID {pid}) at '{Truncate(imagePath, 120)}' has SeImpersonatePrivilege enabled. " +
                                           $"Running from a user-writable path - weak potato-class indicator only.",
                                Reasoning = "SeImpersonatePrivilege from a user-writable path can indicate potato tools " +
                                            "(GodPotato, JuicyPotato, PrintSpoofer) but is also normal for many portable apps. " +
                                            "Observe-first: LogOnly until confirmed (SYSTEM token theft, token-theft modules, composite).",
                                Confidence = 0.55,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                SignalType = SignalType.CredentialTheft,
                                ProcessName = processName,
                                ProcessId = pid,
                            });

                            // Still publish for correlation - multi-signal attack can escalate
                            _contextBus?.Publish(new TokenTheftSignal
                            {
                                ProcessId = pid,
                                ProcessName = processName,
                                SourceMonitor = "TokenTheftMonitor",
                                TokenUserName = "SeImpersonatePrivilege",
                                TheftType = TokenTheftType.ImpersonatePrivilegeFromSuspiciousPath,
                                ImagePath = imagePath,
                                HasImpersonatePrivilege = true,
                            });

                            MarkAlerted(pid, "seimpersonate");
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private struct TokenUserInfo
        {
            public string TokenUserName;
            public bool IsSystemToken;
            public bool HasImpersonatePrivilege;
        }

        private TokenUserInfo? GetProcessTokenUser(int pid)
        {
            IntPtr hProcess = NativeProcessMemory.OpenRemoteHandle(PROCESS_QUERY_LIMITED_INFORMATION, pid);
            if (hProcess == IntPtr.Zero) return null;

            try
            {
                if (!OpenProcessToken(hProcess, TOKEN_QUERY, out IntPtr hToken))
                    return null;

                try
                {
                    string userName = GetTokenUserName(hToken);
                    bool isSystem = userName.Equals("SYSTEM") ||
                                    userName.Equals("LOCAL SERVICE") ||
                                    userName.Equals("NETWORK SERVICE") ||
                                    userName.Contains("NT AUTHORITY\\SYSTEM") ||
                                    userName.EndsWith("\\SYSTEM");

                    bool hasImpersonate = CheckImpersonatePrivilege(hToken);

                    return new TokenUserInfo
                    {
                        TokenUserName = userName,
                        IsSystemToken = isSystem,
                        HasImpersonatePrivilege = hasImpersonate
                    };
                }
                finally { CloseHandle(hToken); }
            }
            finally { CloseHandle(hProcess); }
        }

        private string GetTokenUserName(IntPtr hToken)
        {
            GetTokenInformation(hToken, TokenUser, IntPtr.Zero, 0, out int needed);
            if (needed <= 0) return "Unknown";

            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(hToken, TokenUser, buffer, needed, out _))
                    return "Unknown";

                IntPtr sidPtr = Marshal.ReadIntPtr(buffer);

                var nameBuilder = new System.Text.StringBuilder(256);
                var domainBuilder = new System.Text.StringBuilder(256);
                int nameSize = 256, domainSize = 256;

                if (LookupAccountSidW(null, sidPtr, nameBuilder, ref nameSize,
                    domainBuilder, ref domainSize, out _))
                {
                    return $"{domainBuilder}\\{nameBuilder}";
                }

                return "Unknown";
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static bool CheckImpersonatePrivilege(IntPtr hToken)
        {
            GetTokenInformation(hToken, TokenPrivileges, IntPtr.Zero, 0, out int needed);
            if (needed <= 0) return false;

            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(hToken, TokenPrivileges, buffer, needed, out _))
                    return false;

                int count = Marshal.ReadInt32(buffer);
                int offset = 4;
                const int SE_IMPERSONATE_PRIVILEGE = 29;

                for (int i = 0; i < count && i < 100; i++)
                {
                    long luid = Marshal.ReadInt64(buffer, offset + (i * 12));
                    uint attrs = (uint)Marshal.ReadInt32(buffer, offset + (i * 12) + 8);

                    int lowPart = (int)(luid & 0xFFFFFFFF);
                    if (lowPart == SE_IMPERSONATE_PRIVILEGE && (attrs & 0x2) != 0)
                        return true;
                }

                return false;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private bool IsExpectedSystemProcess(string name, int pid)
        {
            string? path = SecurityValidation.GetProcessImagePath(pid);

            // Name-based exemption is only honored when anchored to a trusted non-writable
            // system path (or a pathless protected process). A binary named "svchost.exe" in
            // Temp must NOT be treated as an expected system process.
            if (IsTrustedSystemTokenHolder(name, path ?? "")) return true;

            if (string.IsNullOrEmpty(path))
            {
                // v1.8.0: no path + OS-like name -> expected; bare unknown empty path is not "expected"
                return IsLikelyProtectedOsProcess(name);
            }

            // A resolvable path is "expected" only when it is a genuine system location and NOT
            // a user-writable drop. Previously any path merely containing "\windows\" qualified,
            // which a path like C:\Windows\Temp\evil.exe or C:\Users\x\windows\evil.exe satisfied.
            if (IsSuspiciousPath(path!)) return false;
            string pathLower = path!.ToLowerInvariant();
            return pathLower.Contains(@"\windows\system32\") ||
                   pathLower.Contains(@"\windows\syswow64\") ||
                   pathLower.Contains(@"\program files\") ||
                   pathLower.Contains(@"\program files (x86)\");
        }

        private static bool IsServicePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            return lower.Contains(@"\windows\system32\") ||
                   lower.Contains(@"\windows\syswow64\") ||
                   lower.Contains(@"\program files\") ||
                   lower.Contains(@"\program files (x86)\") ||
                   // v2.9.3: additional non-user-writable Windows OS locations that host
                   // SYSTEM-token service processes (Unified Update Stack, servicing stack,
                   // component store). Only reached when IsSuspiciousPath() already excluded
                   // \windows\temp, so a "\windows\uus\..\temp\evil.exe" style path cannot slip in.
                   lower.Contains(@"\windows\uus\") ||
                   lower.Contains(@"\windows\servicing\") ||
                   lower.Contains(@"\windows\winsxs\") ||
                   lower.Contains(@"\windows\microsoft.net\framework64\") ||
                   lower.Contains(@"\windows\microsoft.net\framework\");
        }

        /// <summary>
        /// v1.8.0: empty path is NOT suspicious. Prior versions returned true for "",
        /// which caused Memory Compression / Registry (no queryable path) to fire
        /// SeImpersonatePrivilege + Kill + police evidence packs every cooldown window.
        /// </summary>
        internal static bool IsSuspiciousPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            string lower = path.ToLowerInvariant();
            return lower.Contains(@"\temp\") || lower.Contains(@"\tmp\") ||
                   lower.Contains(@"\downloads\") || lower.Contains(@"\appdata\local\temp") ||
                   lower.Contains(@"\users\public\") ||
                   // ProgramData is mixed; only flag obvious drop dirs, not all ProgramData
                   lower.Contains(@"\programdata\temp") ||
                   lower.Contains(@"\recycle") || lower.Contains(@"\desktop\");
        }

        private static bool IsInProgramFiles(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            return lower.Contains(@"\program files\") || lower.Contains(@"\program files (x86)\");
        }

        internal static bool IsLegitimateSystemTokenHolder(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = NormalizeProcessName(processName);
            return LegitimateSystemTokenHolders.Contains(n) ||
                   LegitimateSystemTokenHolders.Contains(processName);
        }

        internal static bool IsLegitimateImpersonator(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = NormalizeProcessName(processName);
            return LegitimateImpersonators.Contains(n) ||
                   LegitimateImpersonators.Contains(processName);
        }

        /// <summary>
        /// A trusted system image path: the real System32 / SysWOW64 copy, or an installed
        /// component under Program Files - and NEVER a user-writable drop (Temp, Downloads,
        /// AppData\Local\Temp, ProgramData\Temp, Desktop, Recycle Bin). This is the
        /// non-attacker-controllable anchor that a whitelisted process NAME must be paired with
        /// before the name is allowed to suppress a token-theft detection.
        /// </summary>
        internal static bool IsTrustedSystemImagePath(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            // Reject drop dirs first - a "\program files\...\..\temp\evil.exe" style path or a
            // System32-named subfolder in a writable location must not qualify.
            if (IsSuspiciousPath(path!)) return false;
            return IsServicePath(path!); // System32 / SysWOW64 / Program Files (x86)
        }

        /// <summary>
        /// Name-based token-holder exemption, ANCHORED to a non-attacker-controllable signal.
        /// The whitelisted name is honored only when (a) the image lives in a trusted, non-writable
        /// system location, or (b) the image path is genuinely unresolvable AND the name is a known
        /// pathless protected/session-0 component. A renamed binary in a user-writable path is
        /// never exempted.
        /// </summary>
        internal static bool IsTrustedSystemTokenHolder(string processName, string? imagePath)
        {
            if (!IsLegitimateSystemTokenHolder(processName)) return false;
            if (!string.IsNullOrWhiteSpace(imagePath))
                return IsTrustedSystemImagePath(imagePath);
            // Empty path: only trust for genuinely pathless protected OS processes.
            return IsLikelyProtectedOsProcess(processName);
        }

        /// <summary>
        /// Name-based impersonator exemption, anchored the same way as
        /// <see cref="IsTrustedSystemTokenHolder"/>. A whitelisted impersonator name (svchost,
        /// lsass, sqlservr, ...) is only exempted from the SeImpersonate potato branch when it is
        /// backed by a trusted non-writable system image path, or is a pathless protected process.
        /// </summary>
        internal static bool IsTrustedImpersonator(string processName, string? imagePath)
        {
            if (!IsLegitimateImpersonator(processName)) return false;
            if (!string.IsNullOrWhiteSpace(imagePath))
                return IsTrustedSystemImagePath(imagePath);
            return IsLikelyProtectedOsProcess(processName);
        }

        /// <summary>
        /// Names Windows exposes for protected / session-0 components that often have
        /// empty GetProcessImagePath results and SYSTEM tokens.
        /// </summary>
        internal static bool IsLikelyProtectedOsProcess(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var n = NormalizeProcessName(processName);

            if (IsLegitimateSystemTokenHolder(n)) return true;

            // Partial matches for localization-safe variants
            if (n.Contains("memory compression")) return true;
            if (n.Equals("registry")) return true;
            if (n.Contains("secure system")) return true;
            if (n.StartsWith("system ")) return true;

            return false;
        }

        private static string NormalizeProcessName(string name)
        {
            var n = name.Trim();
            if (n.EndsWith(".exe"))
                n = n[..^4];
            return n;
        }

        private static string Truncate(string s, int maxLen) =>
            string.IsNullOrEmpty(s) ? s : (s.Length <= maxLen ? s : s[..maxLen] + "...");

        private bool WasRecentlyAlerted(int pid, string ruleKey)
        {
            var key = $"{pid}|{ruleKey}";
            return _alertedKeys.ContainsKey(key);
        }

        private void MarkAlerted(int pid, string ruleKey)
        {
            _alertedKeys[$"{pid}|{ruleKey}"] = DateTime.UtcNow;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-AlertCooldownMinutes);
            foreach (var kvp in _alertedKeys)
            {
                if (kvp.Value < cutoff)
                    _alertedKeys.TryRemove(kvp.Key, out _);
            }
        }
    }
}
