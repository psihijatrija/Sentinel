using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// v-next: Trusted-host module integrity monitor (ATT&amp;CK T1547 Boot/Logon Autostart +
    /// T1574 Hijack Execution Flow).
    ///
    /// Several trusted Windows host processes load DLLs that are chosen by a <b>registry value</b>,
    /// not by a filesystem drop. An attacker who can write those values points a trusted SYSTEM
    /// host at a malicious / hijacked DLL and gets code execution inside it - no kernel driver, no
    /// new service. This monitor baselines the registry-driven DLL-load points below and flags any
    /// DLL that is newly added after baseline AND is unsigned, lives in a user-writable path, or
    /// cannot be resolved on disk (fail-closed). Trust is by valid Authenticode signature OR an
    /// OS-trusted non-user-writable location ONLY - never by file name or registry key name.
    ///
    /// COVERS:
    ///   (1) Audio APOs (Audio Processing Objects) under
    ///       HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\{Render|Capture}\{endpoint}\FxProperties
    ///       (these keys are ACL-protected; reads are best-effort and log + continue on access-denied).
    ///   (2) Print monitors: HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\{name}\Driver.
    ///   (3) Print processors: HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\{env}\Print Processors\{name}\Driver.
    ///
    /// EXCLUDES (owned by other monitors, deliberately not duplicated):
    ///   - Winsock LSP catalog -> <see cref="WinsockLspIntegrityMonitor"/> owns the Winsock2 catalog entirely.
    ///   - Print filesystem driver store (...\System32\spool\drivers\...) and the spoolsv child-process /
    ///     PrintNightmare surface -> <see cref="PrintSpoolerMonitor"/> owns those. That monitor watches the
    ///     filesystem driver store for planted DLLs; it does NOT read the Print Monitors / Print Processors
    ///     registry Driver values, which point a loaded DLL by registry value and can target any path. Those
    ///     registry registration points are therefore in scope here and are not a duplicate.
    ///
    /// RESPONSE: Tier2Indicator + LogOnly, unconditionally. Registry-driven DLL registration has no
    /// userland-attributable owning PID, so there is nothing to kill; the signal is observe fuel that
    /// the correlation engine chains. This monitor never kills a process nor edits/deletes a registry key.
    /// </summary>
    public sealed class TrustedHostModuleIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<TrustedHostModuleIntegrityMonitor> _logger;
        private readonly IRegisteredModuleSource _moduleSource;

        private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(20);
        // Within the 30-60s window required by the task.
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(45);

        // Baseline of DLLs seen at startup + Trusted DLLs seen later (keyed RegistrationPoint|ResolvedPath).
        // No static mutable state - instance ConcurrentDictionary.
        private readonly ConcurrentDictionary<string, byte> _baseline = new(StringComparer.OrdinalIgnoreCase);
        // Flagged modules already emitted (dedup) so a persistent plant is reported once.
        private readonly ConcurrentDictionary<string, byte> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineComplete;

        public TrustedHostModuleIntegrityMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ILogger<TrustedHostModuleIntegrityMonitor> logger,
            IRegisteredModuleSource moduleSource)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _logger = logger;
            _moduleSource = moduleSource;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TrustedHostModuleIntegrityMonitor] Started");

            try { await Task.Delay(StartupDelay, ct); }
            catch (OperationCanceledException) { return; }

            // Baseline: everything registered right now is treated as the trusted starting state.
            // We only alert on DLLs that appear AFTER baseline (newly-added), per the task.
            try
            {
                foreach (var m in _moduleSource.GetRegisteredModules(_logger, ct))
                {
                    _baseline[BaselineKey(m)] = 0;
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Baseline read error");
            }
            _baselineComplete = true;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    // Graceful degradation: a scan failure must never crash the host.
                    _logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Scan error");
                }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        /// <summary>
        /// One scan pass. Internal so a test can drive a single deterministic pass without the
        /// 20s startup delay or the poll loop. Reads the current registered-module set, and for
        /// each module not in the baseline evaluates its trust and emits an observe-only event
        /// when the verdict is not <see cref="ModuleVerdict.Trusted"/>.
        /// </summary>
        internal async Task ScanAsync(CancellationToken ct)
        {
            foreach (var m in _moduleSource.GetRegisteredModules(_logger, ct))
            {
                if (ct.IsCancellationRequested) return;

                string key = BaselineKey(m);
                if (_baseline.ContainsKey(key)) continue;   // present since startup -> not newly added
                if (_alerted.ContainsKey(key)) continue;    // already reported this plant

                bool signed = !string.IsNullOrEmpty(m.ResolvedPath) && _signerTrust.IsSignedFile(m.ResolvedPath!);
                string? signer = signed ? _signerTrust.GetSignerName(m.ResolvedPath!) : null;

                var verdict = ClassifyModule(m.ResolvedPath, signed);
                if (verdict == ModuleVerdict.Trusted)
                {
                    // Newly-seen but trusted -> fold into baseline so it is not re-evaluated.
                    _baseline[key] = 0;
                    continue;
                }

                _alerted[key] = 0;
                await _detectionEngine.EmitAsync(BuildModuleEvent(m, verdict, signed, signer));
            }
        }

        private static string BaselineKey(RegisteredModule m) =>
            $"{m.RegistrationPoint}|{m.ResolvedPath ?? m.RawDllValue}";

        // ---- Pure trust classifier (signature / location ONLY, never name) ----

        /// <summary>
        /// Classifies a registered DLL by signature + location only. Fail-closed: an unresolved
        /// path is treated as untrusted. A valid Authenticode signature OR an OS-trusted,
        /// non-user-writable location exonerates; nothing else does. No file name or key name is
        /// ever a trust input, so classification works against a renamed binary.
        /// </summary>
        internal static ModuleVerdict ClassifyModule(string? resolvedPath, bool isSigned)
        {
            // Fail-closed: a value that never resolved to a path is untrusted. The module source
            // only populates ResolvedPath when the file exists on disk, so by the time a path
            // reaches here it is a real file; classification is then path + signature only (never
            // name), so it works against a renamed binary.
            if (string.IsNullOrWhiteSpace(resolvedPath))
                return ModuleVerdict.Unresolved;

            // ProgramData is user-writable per the task; ModuleIdentity does not list it, so add it here.
            bool userWritable =
                ModuleIdentity.IsUserWritableDrop(resolvedPath) ||
                resolvedPath!.Replace('/', '\\').ToLowerInvariant().Contains(@"\programdata\");

            if (userWritable)
                return ModuleVerdict.UserWritablePath;

            bool osTrusted =
                ModuleIdentity.IsOsServicingPath(resolvedPath) ||
                ModuleIdentity.IsKeepTree(resolvedPath) ||
                ModuleIdentity.IsProgramFilesTree(resolvedPath);

            if (isSigned || osTrusted)
                return ModuleVerdict.Trusted;

            return ModuleVerdict.Unsigned;
        }

        // ---- Detection-event factory (pure; unit-tested directly) ----

        /// <summary>
        /// Builds the observe-only detection for a flagged registered module. Tier2Indicator +
        /// LogOnly unconditionally; ProcessName="SYSTEM"/ProcessId=0 because registry-driven DLL
        /// registration has no userland-attributable owning process. Confidence is tuning only -
        /// the Tier/response contract is the invariant.
        /// </summary>
        internal static DetectionEvent BuildModuleEvent(
            RegisteredModule m, ModuleVerdict verdict, bool signed, string? signer)
        {
            string pathForEvidence = m.ResolvedPath ?? m.RawDllValue;

            string condition;
            double confidence;
            switch (verdict)
            {
                case ModuleVerdict.UserWritablePath:
                    condition = signed ? "User-writable path (signed)" : "User-writable path (unsigned)";
                    confidence = signed ? 0.40 : 0.55;
                    break;
                case ModuleVerdict.Unsigned:
                    condition = "Unsigned, non-OS-trusted location";
                    confidence = 0.45;
                    break;
                case ModuleVerdict.Unresolved:
                    condition = "Unresolved / missing DLL path";
                    confidence = 0.45;
                    break;
                default:
                    condition = verdict.ToString();
                    confidence = 0.40;
                    break;
            }

            var metadata = new Dictionary<string, string>
            {
                ["RegistrationPoint"] = m.RegistrationPoint,
                ["KeyPath"] = m.KeyPath,
                ["RawDllValue"] = m.RawDllValue,
                ["DllPath"] = pathForEvidence,
                ["Verdict"] = verdict.ToString(),
                ["Signed"] = signed.ToString()
            };
            if (!string.IsNullOrEmpty(signer)) metadata["Signer"] = signer!;

            return new DetectionEvent
            {
                RuleName = "Trusted Host Module: Suspicious Registered DLL",
                Evidence = $"A {RegistrationPointLabel(m.RegistrationPoint)} registration point newly points at a " +
                           $"DLL that is {condition.ToLowerInvariant()}: '{pathForEvidence}' " +
                           $"(registry: {m.KeyPath}){(signed && !string.IsNullOrEmpty(signer) ? $", signer: {signer}" : "")}.",
                Reasoning = "A trusted Windows host (audio engine / print spooler) loads DLLs chosen by a registry " +
                            "value. A DLL registered at one of these points that is unsigned, lives in a user-writable " +
                            "location, or cannot be resolved on disk is a classic registry-driven DLL hijack / autostart " +
                            "surface (T1547 / T1574): the host loads it with the host's privileges and no new process is " +
                            "created. Trust here is signature + location only, so renaming the binary does not evade it. " +
                            "This is observe-only chain fuel; Sentinel does not edit the registry or kill the host.",
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.Generic,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                Metadata = metadata
            };
        }

        private static string RegistrationPointLabel(string registrationPoint) => registrationPoint switch
        {
            "AudioAPO" => "audio APO (FxProperties)",
            "PrintMonitor" => "print monitor",
            "PrintProcessor" => "print processor",
            _ => registrationPoint
        };
    }

    /// <summary>
    /// Trust verdict for a single registered DLL. Only <see cref="Trusted"/> suppresses an alert.
    /// </summary>
    public enum ModuleVerdict
    {
        /// <summary>Valid signature or OS-trusted non-user-writable location - no alert.</summary>
        Trusted,
        /// <summary>Unsigned and not in an OS-trusted location - flagged.</summary>
        Unsigned,
        /// <summary>Resolves into a user-writable path (Users/AppData/Temp/Downloads/ProgramData) - flagged.</summary>
        UserWritablePath,
        /// <summary>Registry value could not be resolved to an existing file - flagged (fail-closed).</summary>
        Unresolved
    }

    /// <summary>
    /// A DLL registered at one of the monitored registry-driven DLL-load points.
    /// </summary>
    public sealed class RegisteredModule
    {
        public RegisteredModule(string registrationPoint, string keyPath, string rawDllValue, string? resolvedPath)
        {
            RegistrationPoint = registrationPoint;
            KeyPath = keyPath;
            RawDllValue = rawDllValue;
            ResolvedPath = resolvedPath;
        }

        /// <summary>"AudioAPO" | "PrintMonitor" | "PrintProcessor".</summary>
        public string RegistrationPoint { get; }

        /// <summary>Full registry key path the value was read from (evidence only).</summary>
        public string KeyPath { get; }

        /// <summary>The raw registry value (env-vars unexpanded) - evidence only, never a trust input.</summary>
        public string RawDllValue { get; }

        /// <summary>Full path resolved to an existing file, or null if it could not be resolved (fail-closed).</summary>
        public string? ResolvedPath { get; }
    }

    /// <summary>
    /// Seam for enumerating registry-driven DLL registration points. The default implementation
    /// reads HKLM; tests inject an in-memory fake so classification is deterministic with no
    /// elevation / network / machine-registry dependence.
    /// </summary>
    public interface IRegisteredModuleSource
    {
        IReadOnlyList<RegisteredModule> GetRegisteredModules(ILogger logger, CancellationToken ct);
    }

    /// <summary>
    /// Default <see cref="IRegisteredModuleSource"/> that reads the three registration points from
    /// HKLM read-only, best-effort. ACL-protected audio endpoints log at Debug and are skipped;
    /// a read failure anywhere logs and continues (never throws out of a single endpoint/key).
    /// </summary>
    public sealed class HklmRegisteredModuleSource : IRegisteredModuleSource
    {
        private const string AudioRenderKey =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render";
        private const string AudioCaptureKey =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture";
        private const string PrintMonitorsKey =
            @"SYSTEM\CurrentControlSet\Control\Print\Monitors";
        private const string PrintEnvironmentsKey =
            @"SYSTEM\CurrentControlSet\Control\Print\Environments";

        public IReadOnlyList<RegisteredModule> GetRegisteredModules(ILogger logger, CancellationToken ct)
        {
            var results = new List<RegisteredModule>();
            CollectAudioApos(AudioRenderKey, results, logger, ct);
            CollectAudioApos(AudioCaptureKey, results, logger, ct);
            CollectPrintMonitors(results, logger, ct);
            CollectPrintProcessors(results, logger, ct);
            return results;
        }

        private static void CollectAudioApos(
            string flowKeyPath, List<RegisteredModule> results, ILogger logger, CancellationToken ct)
        {
            RegistryKey? flowKey = null;
            try { flowKey = Registry.LocalMachine.OpenSubKey(flowKeyPath, writable: false); }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Audio key open failed: {Key}", flowKeyPath);
                return;
            }
            if (flowKey == null) return;

            using (flowKey)
            {
                string[] endpoints;
                try { endpoints = flowKey.GetSubKeyNames(); }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Audio endpoint enum failed: {Key}", flowKeyPath);
                    return;
                }

                foreach (var endpoint in endpoints)
                {
                    if (ct.IsCancellationRequested) return;

                    string fxPath = $@"{flowKeyPath}\{endpoint}\FxProperties";
                    try
                    {
                        using var fxKey = Registry.LocalMachine.OpenSubKey(fxPath, writable: false);
                        if (fxKey == null) continue;

                        foreach (var valueName in fxKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            string? raw = fxKey.GetValue(valueName) as string;
                            if (string.IsNullOrWhiteSpace(raw)) continue;

                            // FxProperties values can be APO CLSIDs or DLL path strings. We only
                            // care about values that resolve to a DLL on disk; CLSIDs resolve to
                            // null (fail-closed, skipped as unresolved only when they look like a path).
                            string? resolved = ResolveDllPath(raw!, printSpoolRelative: false);
                            if (resolved == null && !LooksLikeDllPath(raw!)) continue;

                            results.Add(new RegisteredModule("AudioAPO", $"{fxPath}\\{valueName}", raw!, resolved));
                        }
                    }
                    catch (System.Security.SecurityException ex)
                    {
                        // ACL-protected endpoint - log and continue, never crash.
                        logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Access denied reading audio FxProperties: {Key}", fxPath);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Access denied reading audio FxProperties: {Key}", fxPath);
                    }
                    catch (Exception ex)
                    {
                        logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Audio FxProperties read error: {Key}", fxPath);
                    }
                }
            }
        }

        private static void CollectPrintMonitors(
            List<RegisteredModule> results, ILogger logger, CancellationToken ct)
        {
            try
            {
                using var monitorsKey = Registry.LocalMachine.OpenSubKey(PrintMonitorsKey, writable: false);
                if (monitorsKey == null) return;

                foreach (var name in monitorsKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var mon = monitorsKey.OpenSubKey(name, writable: false);
                        string? raw = mon?.GetValue("Driver") as string;
                        if (string.IsNullOrWhiteSpace(raw)) continue;

                        string? resolved = ResolveDllPath(raw!, printSpoolRelative: true);
                        results.Add(new RegisteredModule(
                            "PrintMonitor", $"{PrintMonitorsKey}\\{name}\\Driver", raw!, resolved));
                    }
                    catch (Exception ex)
                    {
                        logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Print monitor read error: {Name}", name);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Print monitors enum error");
            }
        }

        private static void CollectPrintProcessors(
            List<RegisteredModule> results, ILogger logger, CancellationToken ct)
        {
            try
            {
                using var envsKey = Registry.LocalMachine.OpenSubKey(PrintEnvironmentsKey, writable: false);
                if (envsKey == null) return;

                foreach (var env in envsKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    string procsPath = $@"{PrintEnvironmentsKey}\{env}\Print Processors";
                    try
                    {
                        using var procsKey = Registry.LocalMachine.OpenSubKey(procsPath, writable: false);
                        if (procsKey == null) continue;

                        foreach (var name in procsKey.GetSubKeyNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            try
                            {
                                using var proc = procsKey.OpenSubKey(name, writable: false);
                                string? raw = proc?.GetValue("Driver") as string;
                                if (string.IsNullOrWhiteSpace(raw)) continue;

                                string? resolved = ResolveDllPath(raw!, printSpoolRelative: true);
                                results.Add(new RegisteredModule(
                                    "PrintProcessor", $"{procsPath}\\{name}\\Driver", raw!, resolved));
                            }
                            catch (Exception ex)
                            {
                                logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Print processor read error: {Name}", name);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Print processors enum error: {Env}", env);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "[TrustedHostModuleIntegrityMonitor] Print environments enum error");
            }
        }

        private static bool LooksLikeDllPath(string raw)
        {
            string s = raw.Trim();
            return s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                   s.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Resolves a raw registry DLL value to a full path to an existing file, or null (fail-closed).
        /// Expands environment variables; a bare filename for a print monitor/processor is resolved
        /// against the print driver store best-effort.
        /// </summary>
        private static string? ResolveDllPath(string raw, bool printSpoolRelative)
        {
            try
            {
                string expanded = Environment.ExpandEnvironmentVariables(raw.Trim());
                if (expanded.Length == 0) return null;

                if (Path.IsPathRooted(expanded))
                    return File.Exists(expanded) ? expanded : null;

                if (printSpoolRelative)
                {
                    // Print monitor/processor Driver values are typically a bare DLL name loaded
                    // from the spooler driver directories. Probe the common ones, best-effort.
                    string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    foreach (var sub in new[]
                    {
                        @"spool\drivers\x64\3",
                        @"spool\drivers\x64\4",
                        @"spool\drivers\W32X86\3",
                        "",
                    })
                    {
                        string candidate = sub.Length == 0
                            ? Path.Combine(system, expanded)
                            : Path.Combine(system, sub, expanded);
                        if (File.Exists(candidate)) return candidate;
                    }
                    return null;
                }

                // Non-rooted, non-print value: probe System32 best-effort.
                string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string sysCandidate = Path.Combine(sys, expanded);
                return File.Exists(sysCandidate) ? sysCandidate : null;
            }
            catch
            {
                return null;
            }
        }
    }
}
