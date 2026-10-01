using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// DLL identity defense - remediation on map, not on count.
    ///
    /// Every mapped module is run through <see cref="ModuleIdentity"/>. Foreign
    /// path / user-writable drop / unsigned sideload plant -> immediate containment
    /// and disk quarantine (constraint: DLL remediation may act without a chain).
    /// Hijack-name plants on disk (dbghelp/version/winmm/...) are quarantined so
    /// the loader cannot bind them. Never kill a process from a disk plant alone (0.5.3).
    /// Games skipped for handle safety only. Never terminate lsass/csrss/DISM/NTLite.
    ///
    /// ARCHITECTURE NOTE (v2.3.7): Remote foreign module response uses standard EDR
    /// Process Containment (KillProcessTree) and atomic disk quarantine.
    /// </summary>
    public sealed class DllUnloadEngine : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantineManager;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<DllUnloadEngine> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertHistory = new();
        private readonly ConcurrentDictionary<string, DateTimeOffset> _remediationHistory = new();
        // MBA runs every 5s. Re-Authenticode of the same mapped PE was the LatencyMon
        // hard-fault source (mba-hf.log: 30-107 faults/cycle). Evaluate+WinVerifyTrust
        // only on first sight of a path in that PID. New mapped modules still run identity.
        private readonly ConcurrentDictionary<int, PidModuleCache> _pidModules = new();
        private int _remediationsThisMinute;
        private DateTimeOffset _minuteStart = DateTimeOffset.UtcNow;
        private readonly object _rateLock = new();

        private const int MaxRemediationsPerMinute = 20;

        /// <summary>
        /// Hosts where termination is a boot-loop or self-kill. Identity still
        /// applies to explorer/svchost - those are inject targets.
        /// </summary>
        private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass",
            "dwm", "winlogon", "MsMpEng", "NisSrv",
            "Sentinel.Service", "Sentinel.Agent",
            // OS servicing / imaging - NEVER terminate/quarantine (NTLite, DISM, Setup)
            "DismHost", "Dism", "TrustedInstaller", "TiWorker", "NTLite",
            "SetupHost", "WUSA", "msiexec", "Setup", "WindowsPackageManagerServer",
            "MoUsoCoreWorker", "UsoClient", "wuauclt", "MusNotification",
        };

        /// <summary>
        /// Paths used by legitimate offline/online servicing (NTLite scratch, CBS, WinSxS, DISM).
        /// Modules here are not "Temp sideload plants".
        /// </summary>
        private static bool IsOsServicingPath(string? path) => ModuleIdentity.IsOsServicingPath(path);

        private static bool IsOsServicingProcess(string processName, string? imagePath)
        {
            if (!string.IsNullOrEmpty(processName) && ProtectedProcessNames.Contains(processName))
            {
                // Only treat the servicing names as protected when path matches OR name is exclusive
                var n = processName;
                if (n.Equals("DismHost", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("Dism", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("TrustedInstaller", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("TiWorker", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("NTLite", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("SetupHost", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("WUSA", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return IsOsServicingPath(imagePath);
        }

        public static readonly HashSet<string> SideloadTargets = new(StringComparer.OrdinalIgnoreCase)
        {
            "dbghelp.dll", "version.dll", "winmm.dll", "dwrite.dll",
            "cryptsp.dll", "userenv.dll", "profapi.dll", "wtsapi32.dll",
            "dhcpcsvc.dll", "iphlpapi.dll", "msasn1.dll", "netapi32.dll",
            "samcli.dll", "sspicli.dll", "crypt32.dll", "textshaping.dll",
            "winhttp.dll", "urlmon.dll", "propsys.dll", "dwmapi.dll",
        };

        public DllUnloadEngine(
            DetectionEngine de,
            QuarantineManager qm,
            ILogger<DllUnloadEngine> l,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = de;
            _quarantineManager = qm;
            _logger = l;
            _signerTrust = signerTrust ?? new SignerTrustService(
                new Microsoft.Extensions.Logging.Abstractions.NullLogger<SignerTrustService>());
        }

        /// <summary>
        /// Per-process scan used by timers. Observe-first:
        /// - Hijack-name disk plant -> quarantine the file (no process kill).
        /// - Process has loaded a hostile module -> proven load -> Contain & Quarantine.
        /// </summary>
        public Task<DllUnloadResult> CheckAndUnloadAsync(int processId, string processName)
            => ScanProcessAsync(processId, processName, allowRemediateOnProvenLoad: true);

        /// <summary>
        /// ETW ImageLoad path: identity-check one mapped PE without EnumModules of the whole process.
        /// </summary>
        public Task NotifyMappedModuleAsync(int processId, string? processName, string? modulePath)
        {
            if (processId <= 4 || string.IsNullOrEmpty(modulePath))
                return Task.CompletedTask;

            try
            {
                var imagePath = SecurityValidation.GetProcessImagePath(processId);
                if (!NativeProcessMemory.CanInspect(processId, imagePath))
                    return Task.CompletedTask;
                if (string.Equals(modulePath, imagePath, StringComparison.OrdinalIgnoreCase))
                    return Task.CompletedTask;

                var cache = _pidModules.GetOrAdd(processId, _ => new PidModuleCache());
                cache.LastSeenUtc = DateTime.UtcNow;

                bool inStartup = cache.InStartupWindow;
                bool firstSight;
                lock (cache.Paths)
                {
                    firstSight = cache.Paths.Add(modulePath!);
                    // During the startup window, record the module as part of the process's
                    // expected/normal set. These are never treated as late-load anomalies.
                    if (inStartup)
                        cache.StartupModules.Add(modulePath!);
                }
                if (!firstSight)
                    return Task.CompletedTask;

                var verdict = ModuleIdentity.Evaluate(imagePath, modulePath, IsMicrosoftFamilySigned);
                if (verdict.Allowed)
                {
                    // The module FILE itself is legitimate (signed / trusted tree). But if it
                    // appeared AFTER the process's startup window and was not part of the
                    // baseline module set, its PROVENANCE-IN-THIS-HOST is anomalous: a signed,
                    // otherwise-trusted DLL materializing late in a process that never loaded it
                    // at launch is the classic shape of COM-hijack / AppInit / late side-load
                    // into a signed host. This is "what happened" (an unexpected late load), not
                    // "what it is", so it is a weak Tier2 observe-fuel contributor - never a solo
                    // action. It only escalates via a composite when it chains with a local-harm
                    // behavioral act (see BehavioralCorrelationEngine local composites).
                    return MaybeEmitUnexpectedLateLoadAsync(processId, processName, imagePath, modulePath!, cache, inStartup);
                }

                return ScanProcessAsync(processId, processName ?? "", allowRemediateOnProvenLoad: true, forceRemediate: true);
            }
            catch
            {
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// v2.7.3: Emits a weak Tier2 "Unexpected Late Module Load" observe-fuel signal when a
        /// module that PASSED <see cref="ModuleIdentity"/> (the file is signed/trusted) loads
        /// AFTER the process startup window and was not part of the process's baseline module
        /// set. Intentionally conservative to avoid flagging normal deferred/lazy loading:
        ///   - Never fires during the startup window.
        ///   - Never fires for a module in the process's own application directory (plugins,
        ///     codecs, and app-bundled DLLs load late legitimately).
        ///   - Fires at most once per process (LateLoadFlagged latch) so it cannot spam.
        /// This is LogOnly / Tier2 and NEVER acts on its own; escalation happens only via a
        /// composite when it chains with a local-harm behavioral act. Honors the constraint
        /// "Tier2 can never trigger a response" and "behavioral signals only for kill authority".
        /// </summary>
        private Task MaybeEmitUnexpectedLateLoadAsync(
            int processId, string? processName, string? imagePath, string modulePath,
            PidModuleCache cache, bool inStartup)
        {
            try
            {
                // Only late loads (past the startup window) are anomalous.
                if (inStartup) return Task.CompletedTask;

                // One weak signal per process - do not flood the correlation buffer.
                if (cache.LateLoadFlagged) return Task.CompletedTask;

                // A module already recorded in the baseline set is a normal re-load, not new.
                lock (cache.Paths)
                {
                    if (cache.StartupModules.Contains(modulePath))
                        return Task.CompletedTask;
                }

                // App-directory modules (the host's own bundled DLLs / plugins) load late as a
                // matter of course. Path is not attacker-controllable here because it must sit
                // under the already-trusted host image directory; skip to avoid false positives.
                var procDir = string.IsNullOrEmpty(imagePath) ? "" : (Path.GetDirectoryName(imagePath) ?? "");
                if (procDir.Length > 0)
                {
                    var modDir = Path.GetDirectoryName(modulePath) ?? "";
                    if (!string.IsNullOrEmpty(modDir) &&
                        modDir.StartsWith(procDir, StringComparison.OrdinalIgnoreCase))
                        return Task.CompletedTask;
                }

                cache.LateLoadFlagged = true;

                var name = string.IsNullOrEmpty(processName)
                    ? (Path.GetFileNameWithoutExtension(imagePath) ?? "")
                    : processName!;

                return _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Module Provenance: Unexpected Late Module Load",
                    Evidence = $"Process '{name}' (PID {processId}) loaded module '{modulePath}' after its startup " +
                               $"window and outside its baseline module set. The module file is individually trusted, " +
                               $"but its appearance in this host is unexpected (possible COM-hijack / AppInit / late side-load).",
                    Reasoning = "A signed/trusted DLL materialized late in a process that did not load it at launch. " +
                                "On its own this is only weak observe-fuel (legitimate lazy-loading also looks like this), " +
                                "so it never acts alone. It contributes weight to the behavioral chain and escalates only " +
                                "when correlated with a local-harm act (mass encryption, credential/LSASS access, security " +
                                "tampering) or an injection signal on the same process.",
                    Confidence = 0.40,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = name,
                    ProcessId = processId,
                    SignalType = SignalType.ProcessInjection,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ImagePath"] = imagePath ?? "",
                        ["ModulePath"] = modulePath,
                        // Provenance tag is how the correlation engine's local composites find
                        // this signal. Deliberately NOT tagged WeakObserveSeed=true: that flag
                        // routes through IsPureUxObserveNoise -> IsNonCorrelatingObserveNoise,
                        // which RegisterSignalAsync uses to DROP a signal before buffering - it
                        // would prevent this signal from ever correlating. It doesn't need that
                        // flag for solo-safety anyway: it is Tier2 + LogOnly and its rule name is
                        // in no IsAttackClassTerminal list, so it can never authorize a response
                        // alone; it only ever contributes to a composite.
                        ["Provenance"] = "unexpected-late-load"
                    }
                });
            }
            catch
            {
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Response path after AdvancedResponseEngine Tier1 (already proven malicious chain).
        /// Always remediates hostile modules/plants for that PID.
        /// </summary>
        public async Task<DllUnloadResult> UnloadInjectedDllAsync(int targetPid)
        {
            string name = "";
            try
            {
                using var proc = Process.GetProcessById(targetPid);
                name = proc.ProcessName;
            }
            catch { /* dead */ }

            return await ScanProcessAsync(targetPid, name, allowRemediateOnProvenLoad: true, forceRemediate: true);
        }

        /// <summary>
        /// Hijack-name plant on disk (dbghelp/version/winmm/... outside the OS tree).
        /// Quarantine the file so the loader cannot bind it on next start. Never
        /// kill a process from this path alone (0.5.3 cascade). If a host already mapped
        /// it, ScanProcessAsync terminates and cleans up.
        /// </summary>
        public async Task<DllUnloadResult> OnSideloadDllDroppedAsync(string dllPath, int writerPid = 0, string? writerName = null)
        {
            var result = new DllUnloadResult { ProcessId = writerPid, ProcessName = writerName ?? "" };
            if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath)) return result;
            if (!IsHijackPlantPath(dllPath) && !ComHijackEvaluator.ShouldQuarantinePayload(dllPath))
                return result;

            try
            {
                var fileName = Path.GetFileName(dllPath);
                var dir = Path.GetDirectoryName(dllPath) ?? "";

                var hosts = FindProcessIdsFromDirectory(dir);
                foreach (var pid in hosts)
                {
                    var r = await ScanProcessAsync(pid, "", allowRemediateOnProvenLoad: true);
                    if (r.Success)
                    {
                        result.Success = true;
                        result.UnloadedDlls.AddRange(r.UnloadedDlls);
                        result.ProcessId = pid;
                    }
                }

                var alertKey = $"plant:{dllPath.ToLowerInvariant()}";
                if (_alertHistory.ContainsKey(alertKey) && result.Success)
                    return result;
                _alertHistory[alertKey] = DateTimeOffset.UtcNow;

                if (!TryConsumeRateLimit())
                    return result;

                // Only mark success and emit the "quarantined" event if remediation actually
                // removed (or scheduled removal of) the file. A refused/failed quarantine must
                // not report success - otherwise the file survives while we claim we handled it.
                if (await RemediateDroppedDll(dllPath, writerName ?? "", writerPid))
                {
                    result.UnloadedDlls.Add(dllPath);
                    result.Success = true;
                    await EmitHijackPlantQuarantinedAsync(dllPath, fileName, dir, writerPid, writerName);
                }
                else
                {
                    // Let a later scan retry: do not leave this path marked as handled.
                    _alertHistory.TryRemove(alertKey, out _);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] OnSideloadDllDropped failed for {Path}", dllPath);
            }

            return result;
        }

        /// <summary>
        /// COM InprocServer32/Handler payload that failed <see cref="ComHijackEvaluator"/>.
        /// Quarantines the file (including a user-writable non-sideload DLL). Never
        /// deletes the CLSID key.
        /// </summary>
        public Task<DllUnloadResult> OnComServerPlantAsync(string dllPath, int writerPid = 0, string? writerName = null)
            => OnSideloadDllDroppedAsync(dllPath, writerPid, writerName);

        public static bool IsSideloadTargetFileName(string? pathOrName)
        {
            if (string.IsNullOrEmpty(pathOrName)) return false;
            return SideloadTargets.Contains(Path.GetFileName(pathOrName));
        }

        /// <summary>
        /// True when <paramref name="pathOrName"/> is a loadable module by extension
        /// (.dll, .winmd, .ocx, .cpl, .ax, .node, .drv, ...). The engine enumerates and
        /// evaluates every mapped PE regardless of extension; this helper exists so
        /// filename-keyed logic and disk scans are not silently .dll-only.
        /// </summary>
        public static bool IsLoadableModuleFileName(string? pathOrName)
            => ModuleIdentity.IsModuleFileName(pathOrName);

        /// <summary>
        /// True when <paramref name="dllPath"/> is a disk plant that should be
        /// quarantined on sight: a search-order hijack name outside the OS tree,
        /// or a CBS/servicing-stack DLL name outside WinSxS/Windows\servicing
        /// (including a fake cbsapi.dll in System32).
        /// </summary>
        public static bool IsHijackPlantPath(string? dllPath)
        {
            if (string.IsNullOrEmpty(dllPath))
                return false;
            try
            {
                if (IsSentinelHoneypotPath(dllPath!))
                    return false;

                // Servicing-name plants are hostile even in System32. The real CBS
                // stack is the component store; keep-tree must not spare a fake
                // cbsapi.dll sitting next to kernel32.
                if (ModuleIdentity.IsServicingNameOutsideStore(dllPath))
                    return true;

                if (!IsSideloadTargetFileName(dllPath))
                    return false;

                var dir = Path.GetDirectoryName(dllPath);
                if (string.IsNullOrEmpty(dir) || IsWindowsSystemDirectory(dir))
                    return false;
                if (ModuleIdentity.IsOsServicingPath(dllPath))
                    return false;
                if (ModuleIdentity.IsKeepTree(dllPath) && !ModuleIdentity.IsUserWritableDrop(dllPath))
                    return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Filename that FileActivityMonitor must not skip: classic sideload
        /// targets plus CBS/servicing impersonation names.
        /// </summary>
        public static bool IsImmediatePlantFileName(string? pathOrName) =>
            IsSideloadTargetFileName(pathOrName) || ModuleIdentity.IsServicingImpersonationName(pathOrName);

        private static bool IsSentinelHoneypotPath(string path)
        {
            var n = ModuleIdentity.Normalize(path);
            return n.IndexOf(@"\" + HoneypotDllMonitor.HoneypotSubdir + @"\", StringComparison.Ordinal) >= 0;
        }

        /// <param name="allowRemediateOnProvenLoad">
        /// When true, remediates if process has loaded hostile modules (behavior).
        /// </param>
        /// <param name="forceRemediate">
        /// When true (Tier1 response path), remediate disk plants for this PID even if not yet enumerated as loaded.
        /// </param>
        private async Task<DllUnloadResult> ScanProcessAsync(
            int processId,
            string processName,
            bool allowRemediateOnProvenLoad,
            bool forceRemediate = false)
        {
            var result = new DllUnloadResult { ProcessId = processId, ProcessName = processName ?? "" };
            if (processId <= 4) return result;

            try
            {
                var imagePath = SecurityValidation.GetProcessImagePath(processId);
                if (string.IsNullOrEmpty(imagePath)) return result;

                if (!AlwaysOnPolicies.MayUnloadDllsFrom(processId, imagePath))
                    return result;

                var name = string.IsNullOrEmpty(processName)
                    ? (Path.GetFileNameWithoutExtension(imagePath) ?? "")
                    : processName;
                result.ProcessName = name!;

                // Never touch NTLite / DISM / TrustedInstaller / offline servicing hosts.
                if (IsOsServicingProcess(name!, imagePath))
                    return result;

                if (ProtectedProcessNames.Contains(name!) && IsProtectedPath(imagePath))
                    return result;

                var procDir = Path.GetDirectoryName(imagePath);
                if (ModuleIdentity.IsOsServicingPath(procDir) || ModuleIdentity.IsOsServicingPath(imagePath))
                    return result;

                var cache = _pidModules.GetOrAdd(processId, _ => new PidModuleCache());
                cache.LastSeenUtc = DateTime.UtcNow;

                var hostileDisk = new List<string>();
                if (forceRemediate || !cache.DiskPlantsChecked)
                {
                    hostileDisk = string.IsNullOrEmpty(procDir)
                        ? new List<string>()
                        : FindHostileSideloadDlls(procDir!);
                    cache.DiskPlantsChecked = true;
                }
                var hostileLoaded = new List<(string Path, IntPtr Base, int Size)>();

                if (NativeProcessMemory.CanInspect(processId, imagePath))
                {
                    foreach (var mod in NativeProcessMemory.EnumModules(processId))
                    {
                        if (string.IsNullOrEmpty(mod.Path)) continue;
                        if (string.Equals(mod.Path, imagePath, StringComparison.OrdinalIgnoreCase))
                            continue;

                        bool firstSight;
                        lock (cache.Paths)
                            firstSight = cache.Paths.Add(mod.Path);
                        if (!firstSight && !forceRemediate)
                            continue;

                        var verdict = ModuleIdentity.Evaluate(
                            imagePath, mod.Path, IsMicrosoftFamilySigned);
                        if (verdict.Allowed) continue;

                        hostileLoaded.Add((mod.Path, mod.Base, mod.Size));
                    }
                }

                // Proven malicious behavior: process loaded hostile DLL(s)
                bool provenLoad = hostileLoaded.Count > 0;

                // Disk plant not yet mapped: quarantine the file so the loader cannot
                // bind it. Do not kill the host (0.5.3).
                if (!provenLoad && hostileDisk.Count > 0 && !forceRemediate)
                {
                    foreach (var plant in hostileDisk)
                    {
                        if (!IsHijackPlantPath(plant)) continue;
                        var rkey = $"diskq:{plant.ToLowerInvariant()}";
                        if (_remediationHistory.ContainsKey(rkey)) continue;
                        if (!TryConsumeRateLimit()) break;
                        // Record history only on actual success, so a failed/refused quarantine
                        // is retried on the next scan instead of being marked permanently handled.
                        if (await RemediateDroppedDll(plant, name!, processId))
                        {
                            _remediationHistory[rkey] = DateTimeOffset.UtcNow;
                            result.UnloadedDlls.Add(plant);
                            result.Success = true;
                        }
                    }

                    if (result.Success)
                    {
                        await EmitHijackPlantQuarantinedAsync(
                            result.UnloadedDlls[0],
                            Path.GetFileName(result.UnloadedDlls[0]),
                            procDir ?? "",
                            processId,
                            name);
                    }

                    return result;
                }

                if (!provenLoad && !forceRemediate)
                    return result;

                // Proven: remediate (contain process tree -> quarantine hostile DLL on disk)
                if (!allowRemediateOnProvenLoad && !forceRemediate)
                    return result;

                var pathsToQuarantine = hostileLoaded.Select(h => h.Path)
                    .Concat(forceRemediate ? hostileDisk : Array.Empty<string>())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (pathsToQuarantine.Count == 0 && provenLoad)
                    pathsToQuarantine = hostileLoaded.Select(h => h.Path).ToList();

                if (pathsToQuarantine.Count == 0) return result;

                // Process Containment: Safely terminate the compromised process tree
                bool hostTerminated = false;
                try
                {
                    HardeningModule.SafeKillProcessTree(processId);
                    hostTerminated = true;
                }
                catch
                {
                    try
                    {
                        using var p = Process.GetProcessById(processId);
                        p.KillTree();
                        hostTerminated = true;
                    }
                    catch { }
                }

                foreach (var dllPath in pathsToQuarantine)
                {
                    var rkey = $"{processId}:{dllPath.ToLowerInvariant()}";
                    if (_remediationHistory.ContainsKey(rkey)) continue;
                    if (!TryConsumeRateLimit()) break;
                    // Record history only on actual success, so a failed/refused quarantine is
                    // retried on the next scan rather than being marked permanently handled.
                    if (await RemediateDroppedDll(dllPath, name!, processId))
                    {
                        _remediationHistory[rkey] = DateTimeOffset.UtcNow;
                        result.UnloadedDlls.Add(dllPath);
                    }
                }

                foreach (var (path, _, _) in hostileLoaded)
                {
                    if (!result.UnloadedDlls.Contains(path, StringComparer.OrdinalIgnoreCase))
                        result.UnloadedDlls.Add(path);
                }

                result.Success = result.UnloadedDlls.Count > 0;
                if (result.Success)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "DLL Injection: Foreign Module Remediated",
                        Evidence = $"Process '{name}' (PID {processId}) loaded hostile DLL(s): " +
                                   string.Join(", ", result.UnloadedDlls) +
                                   $". HostContained={hostTerminated}; quarantined={result.UnloadedDlls.Count}.",
                        Reasoning = "Proven behavior: a mapped module failed path+signer identity " +
                                    "(foreign folder, user-writable drop, or sideload plant). Process contained and hostile DLL quarantined immediately (T1055 / T1574.001).",
                        Confidence = 0.95,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly, // already acted
                        ProcessName = name!,
                        ProcessId = processId,
                        SignalType = SignalType.ProcessInjection,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ImagePath"] = imagePath!,
                            ["SideloadedDlls"] = string.Join(";", result.UnloadedDlls),
                            ["Phase"] = "Remediate",
                            ["DllUnloadExempt"] = "true",
                            ["PermanentRule"] = "ModuleIdentityUnload",
                            ["AlwaysOnPolicy"] = "DllUnload"
                        }
                    });
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DllUnloadEngine] ScanProcess failed for PID {Pid}", processId);
                return result;
            }
        }

        private async Task EmitHijackPlantQuarantinedAsync(
            string dllPath, string? fileName, string dir, int writerPid, string? writerName)
        {
            bool servicingPlant = ModuleIdentity.IsServicingNameOutsideStore(dllPath);
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = servicingPlant
                    ? "Servicing Impersonation: CBS DLL Plant Quarantined"
                    : "DLL Sideloading: Hijack-Name Plant Quarantined",
                Evidence = servicingPlant
                    ? $"Servicing-stack DLL name '{fileName}' at '{dllPath}' is not under WinSxS/Windows\\servicing " +
                      $"(writer='{writerName}' PID {writerPid}). File quarantined; CLSID keys left intact."
                    : $"Hostile sideload-target '{fileName}' written to '{dllPath}' " +
                      $"(writer='{writerName}' PID {writerPid}). File quarantined; no process killed.",
                Reasoning = servicingPlant
                    ? "Component Based Servicing DLLs (cbsapi/cbscore/cbsmsg) live in the component store. " +
                      "A copy in System32, Temp, AppData, or anywhere else is a plant used for COM hijack / " +
                      "servicing impersonation. Quarantine the file; never delete the COM class."
                    : "Search-order hijack: a local dbghelp/version/winmm copy is loaded " +
                      "before System32, including a real Microsoft-signed copy. Quarantining " +
                      "the file (not the host) is the prevention; FreeLibrary is cleanup if already mapped.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = writerName ?? "unknown",
                ProcessId = writerPid,
                SignalType = SignalType.ProcessInjection,
                Metadata = new Dictionary<string, string>
                {
                    ["DllPath"] = dllPath,
                    ["Directory"] = dir,
                    ["Phase"] = "Remediate",
                    ["DllUnloadExempt"] = "true",
                    ["PermanentRule"] = "ModuleIdentityUnload",
                    ["AlwaysOnPolicy"] = "DllUnload"
                }
            });
        }

        private List<string> FindHostileSideloadDlls(string directory)
        {
            var found = new List<string>();
            try
            {
                foreach (var target in SideloadTargets)
                {
                    var path = Path.Combine(directory, target);
                    if (File.Exists(path) && IsHostileSideloadDll(path))
                        found.Add(path);
                }
                foreach (var target in ModuleIdentity.ServicingStackDllNames)
                {
                    var path = Path.Combine(directory, target);
                    if (File.Exists(path) && IsHijackPlantPath(path) && !found.Contains(path))
                        found.Add(path);
                }
            }
            catch { }
            return found;
        }

        private bool IsHostileSideloadDll(string dllPath) => IsHijackPlantPath(dllPath);

        private bool IsMicrosoftFamilySigned(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (!_signerTrust.IsSignedFile(path)) return false;
            var signer = _signerTrust.GetSignerName(path) ?? "";
            return signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0
                   || signer.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private List<int> FindProcessIdsFromDirectory(string directory)
        {
            var list = new List<int>();
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        var path = SecurityValidation.GetProcessImagePath(proc.Id);
                        if (string.IsNullOrEmpty(path)) continue;
                        if (SecurityValidation.IsGameOrAntiCheatPath(path)) continue;
                        var pDir = Path.GetDirectoryName(path);
                        if (string.IsNullOrEmpty(pDir)) continue;
                        if (!pDir.TrimEnd('\\').Equals(directory.TrimEnd('\\')))
                            continue;
                        list.Add(proc.Id);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
            return list;
        }

        /// <summary>
        /// Quarantines a hostile DLL and reports whether the ORIGINAL was actually removed.
        /// Returns true only when quarantine succeeded (vault written AND the source file is
        /// gone now or guaranteed to be deleted on reboot). Returns false when quarantine was
        /// refused or failed - the caller must NOT then claim the file was neutralized.
        ///
        /// This closes the "quarantined the same DLL again" bug: the previous code logged
        /// "Quarantined" unconditionally and ignored the return value, so a locked/mapped DLL
        /// (which cannot be deleted in place) survived on disk while Sentinel reported success -
        /// and was re-detected on the next scan / install as if nothing had happened.
        /// </summary>
        private async Task<bool> RemediateDroppedDll(string dllPath, string processName, int processId)
        {
            try
            {
                await Task.Delay(150);
                if (!File.Exists(dllPath))
                {
                    // Already gone (e.g. removed by a prior remediation) - nothing to do.
                    return true;
                }

                var vaultPath = await _quarantineManager.QuarantineFileAtomicAsync(
                    dllPath, forceQuarantineSigned: true);

                if (vaultPath == null)
                {
                    // QuarantineManager refused (OS-critical path, size cap, or verification
                    // error). The file is UNTOUCHED - do not pretend it was quarantined.
                    _logger.LogWarning(
                        "[DllUnloadEngine] Quarantine REFUSED for '{Dll}' (host {Name} PID {Pid}) - file left on disk",
                        dllPath, processName, processId);
                    return false;
                }

                // No zero-byte Hidden|System stub after quarantine - that pattern scores as
                // wiper/ransom agent behavior (Alyac MSIL.Ransom.Agent). Re-drops are caught
                // by FileActivityMonitor; sideload names must not be re-planted either
                // (search order would bind the stub instead of System32).

                if (_quarantineManager.WasLastQuarantineDeferred)
                {
                    // Vault copy exists and a delete-on-reboot is scheduled, but the original
                    // is still on disk until the next boot because a process still maps it.
                    // Report this honestly instead of claiming it is already gone.
                    _logger.LogWarning(
                        "[DllUnloadEngine] Quarantined '{Dll}' (host {Name} PID {Pid}) - LOCKED, deletion scheduled for next reboot",
                        dllPath, processName, processId);
                }
                else
                {
                    _logger.LogInformation(
                        "[DllUnloadEngine] Quarantined '{Dll}' (host {Name} PID {Pid}) - original removed",
                        dllPath, processName, processId);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DllUnloadEngine] Failed to quarantine '{Dll}'", dllPath);
                return false;
            }
        }

        private bool TryConsumeRateLimit()
        {
            lock (_rateLock)
            {
                var now = DateTimeOffset.UtcNow;
                if ((now - _minuteStart).TotalMinutes >= 1)
                {
                    _minuteStart = now;
                    _remediationsThisMinute = 0;
                }
                if (_remediationsThisMinute >= MaxRemediationsPerMinute) return false;
                _remediationsThisMinute++;
                return true;
            }
        }

        internal void PruneStalePidCaches()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-3);
            foreach (var kv in _pidModules)
            {
                if (kv.Value.LastSeenUtc < cutoff)
                    _pidModules.TryRemove(kv.Key, out _);
            }
        }

        public void Dispose()
        {
            var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
            foreach (var kv in _alertHistory)
                if (kv.Value < cutoff) _alertHistory.TryRemove(kv.Key, out _);
            foreach (var kv in _remediationHistory)
                if (kv.Value < cutoff) _remediationHistory.TryRemove(kv.Key, out _);
            _pidModules.Clear();
        }

        private sealed class PidModuleCache
        {
            public readonly HashSet<string> Paths = new(StringComparer.OrdinalIgnoreCase);
            public DateTime LastSeenUtc;
            public bool DiskPlantsChecked;

            // v2.7.3: Per-process module-provenance baseline for the "unexpected late load"
            // detector. A process establishes its normal module set during a short startup
            // window; a module that appears AFTER that window and is not part of the expected
            // set is treated as a late load. This closes the "malicious DLL that harms locally
            // without ever phoning home" gap: a late, anomalous load becomes a Tier2 weighted
            // contributor that only escalates when it chains with a local-harm behavioral act.
            //
            // FirstSeenUtc is when this PID was first observed loading a module (proxy for
            // process start on the ETW path). The startup window is FirstSeenUtc + StartupWindow.
            public DateTime FirstSeenUtc = DateTime.UtcNow;

            // Modules observed during the startup window - the "expected" set for this process.
            // A late load whose path is in this set is a normal re-load, not an anomaly.
            public readonly HashSet<string> StartupModules = new(StringComparer.OrdinalIgnoreCase);

            // Dedup: PIDs already flagged for a late-load anomaly, so a single process cannot
            // spam the correlation buffer with the same weak signal.
            public bool LateLoadFlagged;

            // The startup window after which a first-sight module counts as a "late" load.
            // Kept short but generous enough to cover normal lazy/deferred loading at launch.
            public static readonly TimeSpan StartupWindow = TimeSpan.FromSeconds(20);

            public bool InStartupWindow => (DateTime.UtcNow - FirstSeenUtc) < StartupWindow;
        }

        private static bool IsWindowsSystemDirectory(string directory)
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var lower = directory.ToLowerInvariant();
            return lower.StartsWith((win + @"\system32").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\syswow64").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\winsxs").ToLowerInvariant()) ||
                   lower.StartsWith((win + @"\servicing").ToLowerInvariant());
        }

        private static bool IsProtectedPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            return path!.StartsWith(@"C:\Windows\") ||
                   path.StartsWith(@"C:\Program Files") ||
                   path.Contains(@"\AppData\Local\Google\") ||
                   path.Contains(@"\AppData\Local\Microsoft\") ||
                   path.Contains(@"\AppData\Local\Programs\") ||
                   path.Contains(@"\Sentinel");
        }
    }

    public sealed class DllUnloadResult
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public bool Success { get; set; }
        public List<string> UnloadedDlls { get; set; } = new();
    }
}
