using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public sealed class StateReconciliationMonitor : BackgroundService, ISensorProgressSource
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ModuleBaselineStore _store;
        private readonly ILogger<StateReconciliationMonitor> _logger;
        private readonly VisibilityGapTracker? _gaps;
        private long _reconciledGeneration;

        public SensorProgress Progress { get; } = new(TimeSpan.FromMinutes(11));

        private ModuleBaselineSnapshot _baseline = new();
        private readonly Dictionary<string, DateTime> _lastEmit =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan SettleDelay = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan Cadence = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan ReEmitCadence = TimeSpan.FromMinutes(30);

        /// <summary>
        /// Fixed set of long-lived / low-churn processes we baseline. Keyed by process name (no
        /// extension), because PIDs change across reboots. Deliberately conservative: these are
        /// processes whose module set is stable, so an unexplained new module is meaningful.
        /// High-churn hosts (browsers, games, Electron) are excluded - their legitimate plugin
        /// churn would drown the signal (documented blind spot in THREAT_MODEL).
        /// </summary>
        internal static readonly HashSet<string> LongLivedProcessNames =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "explorer", "winlogon", "services", "lsass", "csrss",
                "dwm", "sihost", "taskhostw", "runtimebroker",
            };

        public StateReconciliationMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ModuleBaselineStore store,
            ILogger<StateReconciliationMonitor> logger, VisibilityGapTracker? gaps = null)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _store = store;
            _logger = logger;
            _gaps = gaps;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[StateReconciliation] Started (module-inventory drift, observe-only)");
            _baseline = _store.Load();

            // Boot-settle: let the module sets of long-lived processes stabilize before first pass.
            try { await Task.Delay(SettleDelay, ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var visibilityGap = _gaps?.Snapshot();
                    await ReconcileOnceAsync(ct);
                    if (!_store.TrySave(_baseline)) throw new System.IO.IOException("Module baseline could not be persisted.");
                    Progress.Succeeded();
                    if (visibilityGap != null && visibilityGap.Generation != _reconciledGeneration)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "State Reconciliation: Snapshot After Visibility Gap",
                            Evidence = $"Current module state re-sampled after {visibilityGap.Source} reported a gap at {visibilityGap.ObservedUtc:O}.",
                            Reasoning = "A current snapshot cannot reconstruct missing events or establish attribution during the gap.",
                            Confidence = 0.5, Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            Metadata = new Dictionary<string, string>
                            { ["GapSource"] = visibilityGap.Source, ["GapReason"] = visibilityGap.Reason }
                        });
                        _reconciledGeneration = visibilityGap.Generation;
                    }
                    var gap = Progress.AcknowledgeRecovery();
                    if (gap.HasValue)
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "State Reconciliation: Coverage Restored",
                            Evidence = $"Collection resumed after a gap beginning {gap.Value:O}. Current module state was reconciled; activity during the gap is unknown.",
                            Reasoning = "Recovered visibility cannot retrospectively prove event coverage.",
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            Confidence = 0.5
                        });
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Progress.Failed(ex.Message);
                    _logger.LogDebug(ex, "[StateReconciliation] pass error");
                }
                try { await Task.Delay(Cadence, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        /// <summary>
        /// One reconciliation pass: snapshot the long-lived process set, diff against the baseline,
        /// attribute deltas, and emit observe-only signals for the unattributable ones. Re-emits
        /// durable "unexplained since X" observations on the re-emit cadence so they can participate
        /// in the (short) correlation window if a correlating leg appears.
        /// </summary>
        private async Task ReconcileOnceAsync(CancellationToken ct)
        {
            bool learnMode = _baseline.ModulesByProcess.Count == 0;
            var now = DateTime.UtcNow;

            foreach (var (pid, procName, imagePath, modules) in SnapshotLongLivedProcesses(ct))
            {
                if (ct.IsCancellationRequested) break;

                var known = _baseline.ModulesFor(procName);

                foreach (var mod in modules)
                {
                    if (string.IsNullOrEmpty(mod.Path)) continue;
                    var identity = ModuleIdentity.Normalize(mod.Path);
                    if (identity.Length == 0) continue;
                    if (!_baseline.NeedsAttribution(procName, identity)) continue;

                    var (attributed, reason, signer) = TryAttribute(imagePath, mod.Path);

                    if (attributed)
                    {
                        // Fold into baseline silently; grow the per-machine known-publisher ledger
                        // ONLY from accepted (trusted) modules - a surviving-unexplained module's
                        // signer is NOT trusted just because it was seen.
                        known.Add(identity);
                        _baseline.UnexplainedSince.Remove(identity);
                        if (!string.IsNullOrEmpty(signer))
                        {
                            var key = signer!.ToLowerInvariant();
                            if (!_baseline.KnownPublishers.ContainsKey(key))
                                _baseline.KnownPublishers[key] = now;
                        }
                        continue;
                    }

                    // Unattributable. In learn mode we adopt the initial state without alerting
                    // (R2: first snapshot becomes the baseline, emit nothing).
                    if (learnMode) { known.Add(identity); continue; }
                    // An unexplained observation is not an accepted baseline. Keep it
                    // eligible for review/re-emission on later cycles and after restart.

                    bool firstSight = !_baseline.UnexplainedSince.ContainsKey(identity);
                    if (firstSight)
                        _baseline.UnexplainedSince[identity] = now;

                    if (ShouldEmit(identity, now))
                    {
                        await EmitDriftAsync(procName, pid, imagePath, mod.Path, signer,
                            _baseline.UnexplainedSince[identity]);
                        _lastEmit[identity] = now;
                    }
                }
            }
        }

        /// <summary>
        /// Attribution: is this delta explainable by a trusted cause? Cheapest checks first.
        /// Returns (attributed, reason, signerCn). Reused by tests via <see cref="TryAttribute"/>.
        /// </summary>
        internal (bool Attributed, string Reason, string? Signer) TryAttribute(
            string? processImagePath, string modulePath)
        {
            // 1. Trusted load position - the existing ModuleIdentity trust ladder (os-servicing,
            //    keep-tree, signed Program Files, Roslyn shadow-copy, GPU ICD, app-directory).
            var verdict = ModuleIdentity.Evaluate(processImagePath, modulePath, IsMicrosoftFamilySigned);
            if (verdict.Allowed)
                return (true, "identity:" + verdict.Reason, SafeSigner(modulePath));

            // 2. Active (or recently active) OS servicing window - updates legitimately stage and
            //    load modules from otherwise-suspicious paths.
            if (ServicingWindow.IsActiveOrRecent())
                return (true, "servicing-window", SafeSigner(modulePath));

            // 3. Publisher already accepted on THIS machine. A signer new to this host is NOT
            //    attributed here (that is what makes first-seen meaningful vs. a stolen cert).
            var signer = SafeSigner(modulePath);
            if (!string.IsNullOrEmpty(signer) &&
                _baseline.KnownPublishers.ContainsKey(signer!.ToLowerInvariant()))
                return (true, "known-publisher", signer);

            return (false, "unattributable", signer);
        }

        private bool ShouldEmit(string identity, DateTime now)
        {
            if (!_lastEmit.TryGetValue(identity, out var last)) return true;
            return now - last >= ReEmitCadence;
        }

        private string? SafeSigner(string path)
        {
            try { return _signerTrust.GetSignerName(path); }
            catch { return null; }
        }

        /// <summary>
        /// Microsoft-family-signed delegate for <see cref="ModuleIdentity.Evaluate"/>: valid
        /// Authenticode signature whose signer CN reads as Microsoft. Composed from the cached
        /// signer service + the shared signer classifier.
        /// </summary>
        private bool IsMicrosoftFamilySigned(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) return false;
                if (!_signerTrust.IsSignedFile(path)) return false;
                return WinsockLspIntegrityMonitor.IsMicrosoftSigner(_signerTrust.GetSignerName(path));
            }
            catch { return false; }
        }

        /// <summary>
        /// Enumerates loaded modules for each live long-lived process. Skips processes that are not
        /// inspectable (PPL/anti-cheat/unresolved path) WITHOUT clobbering their MappedModuleCache
        /// (we simply do not call EnumModules for them).
        /// </summary>
        private IEnumerable<(int Pid, string ProcName, string? ImagePath,
            List<(string Name, string Path, IntPtr Base, int Size)> Modules)>
            SnapshotLongLivedProcesses(CancellationToken ct)
        {
            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { yield break; }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) yield break;

                string name;
                int pid;
                try { name = p.ProcessName; pid = p.Id; }
                catch { try { p.Dispose(); } catch { } continue; }

                if (!LongLivedProcessNames.Contains(name))
                {
                    try { p.Dispose(); } catch { }
                    continue;
                }

                var imagePath = SecurityValidation.GetProcessImagePath(pid);
                if (!NativeProcessMemory.CanInspect(pid, imagePath))
                {
                    // Not inspectable: skip. Do NOT enumerate (avoids clobbering MappedModuleCache).
                    try { p.Dispose(); } catch { }
                    continue;
                }

                List<(string, string, IntPtr, int)> modules;
                try { modules = NativeProcessMemory.EnumModules(pid); }
                catch { modules = new List<(string, string, IntPtr, int)>(); }
                finally { try { p.Dispose(); } catch { } }

                yield return (pid, name, imagePath, modules);
            }
        }

        private async Task EmitDriftAsync(
            string procName, int pid, string? hostImagePath,
            string modulePath, string? signer, DateTime sinceUtc)
        {
            var signerText = string.IsNullOrEmpty(signer) ? "unsigned/untrusted" : signer!;
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "State Drift: Unexplained Module in Long-Lived Process",
                Evidence = $"Process '{procName}' (PID {pid}) has module '{modulePath}' not present " +
                           $"at baseline; signer={signerText}; unexplained since {sinceUtc:O}.",
                Reasoning =
                    "State-baseline reconciliation: a module appeared in a normally low-churn " +
                    "system/shell process and could not be attributed to OS servicing, a trusted " +
                    "load position, or a publisher already accepted on this host. Surfaced for " +
                    "REVIEW and as weak correlation fuel - observe-only, never auto-killed. This " +
                    "does not identify who placed the module or assert that anyone is targeting " +
                    "the user. A validly-signed module (including one signed with a stolen " +
                    "certificate) that never behaves terminally cannot be deterministically " +
                    "stopped here - see THREAT_MODEL.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Family = null,
                ProcessName = procName,
                ProcessId = pid,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                    ["StateDrift"] = "true",
                    ["ModulePath"] = modulePath,
                    ["Signer"] = signer ?? "",
                    ["UnexplainedSinceUtc"] = sinceUtc.ToString("O"),
                    ["HostImagePath"] = hostImagePath ?? "",
                }
            });
        }

        // ---- Test seam ----------------------------------------------------------------
        // Lets unit tests drive attribution + diff without live process enumeration.

        /// <summary>Test hook: seed the in-memory baseline.</summary>
        internal void SetBaselineForTests(ModuleBaselineSnapshot snapshot) => _baseline = snapshot ?? new();

        /// <summary>Test hook: read the current in-memory baseline.</summary>
        internal ModuleBaselineSnapshot GetBaselineForTests() => _baseline;
    }
}
