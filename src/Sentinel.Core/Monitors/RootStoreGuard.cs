using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core.Monitors
{
    /// <summary>
    /// Autonomous root-store guard (SYSTEM session, SystemIntegrity group).
    ///
    /// Continuously (startup + poll) finds root certificates that the OS trusted-root program
    /// does NOT vouch for - carrying neither the AuthRoot-CTL stamp nor the Microsoft
    /// root-program marker (see <see cref="CertSuspicionAnalyzer"/>) - plus any thumbprint on
    /// the explicit <see cref="CertDistrustList"/>. For each such cert it:
    ///
    ///   1. Removes it from every trusted store and pins it to Disallowed (via
    ///      <see cref="CertRemediator"/>), and
    ///   2. Quarantines files that were Authenticode-signed by a chain rooting to the removed
    ///      cert - the things the planted root was used to vouch for.
    ///
    /// This is autonomous host mutation. It is gated on <c>ActiveResponse</c> and recorded as a
    /// Tier1 response (Tier2 can never act). The suspicion verdict is a non-attacker-controllable
    /// OS-CTL signal, re-checked inside <see cref="CertRemediator.DistrustSuspiciousRoot"/> as a
    /// hard safety floor so OS/public trust anchors are never touched. A failing cycle logs and
    /// continues (graceful degradation) - it must never crash the monitor group.
    /// </summary>
    public sealed class RootStoreGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly CertRemediator _remediator;
        private readonly QuarantineManager _quarantine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<RootStoreGuard> _logger;

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(90);

        // Blast-radius cap: never quarantine more than this many files per removed root in one
        // pass (mirrors ScanAndQuarantineSignedDriversAsync's maxDriversPerCert discipline).
        private const int MaxQuarantinePerCert = 25;

        private static readonly (StoreName Name, StoreLocation Location, string Label)[] TrustStores =
        {
            (StoreName.Root, StoreLocation.LocalMachine, "LocalMachine\\Root"),
            (StoreName.Root, StoreLocation.CurrentUser, "CurrentUser\\Root"),
            (StoreName.CertificateAuthority, StoreLocation.LocalMachine, "LocalMachine\\CA"),
            (StoreName.CertificateAuthority, StoreLocation.CurrentUser, "CurrentUser\\CA"),
        };

        // Roots already acted on this process lifetime (avoid re-logging every poll).
        private readonly HashSet<string> _handled = new(StringComparer.OrdinalIgnoreCase);

        public RootStoreGuard(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            CertRemediator remediator,
            QuarantineManager quarantine,
            JsonlEventLogger eventLogger,
            ILogger<RootStoreGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _remediator = remediator;
            _quarantine = quarantine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RootStoreGuard] Started - autonomous suspicious-root detection + removal");

            // Startup sweep immediately, then poll.
            try { await SweepAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { _logger.LogError(ex, "[RootStoreGuard] Startup sweep failed"); }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, ct).ConfigureAwait(false);
                    await SweepAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RootStoreGuard] Sweep error"); }
            }
        }

        private async Task SweepAsync(CancellationToken ct)
        {
            // Collect suspicious roots across the trusted stores (dedup by thumbprint).
            var suspicious = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            foreach (var (name, location, label) in TrustStores)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadOnly);
                    foreach (var cert in store.Certificates)
                    {
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            var norm = CertDistrustList.Normalize(cert.Thumbprint);
                            if (norm.Length == 0) continue;

                            // Flag if explicitly distrust-listed OR the analyzer verdict is suspicious.
                            bool listed = CertDistrustList.IsDistrusted(norm);
                            bool heuristic = CertSuspicionAnalyzer.IsSuspicious(cert);
                            if (!listed && !heuristic) continue;

                            if (!suspicious.ContainsKey(norm))
                                suspicious[norm] = new X509Certificate2(cert.RawData);
                        }
                        catch { /* per-cert best effort */ }
                        finally { cert.Dispose(); }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[RootStoreGuard] Store read failed for {Label}", label);
                }
            }

            if (suspicious.Count == 0) return;

            // Autonomous removal is a host mutation - gate on ActiveResponse. If disabled, we
            // still surface the detection (Tier1 LogOnly) so the operator sees it.
            bool mayAct = ResponsePolicy.MayPerformInlineHostMutation(_config);

            foreach (var kvp in suspicious)
            {
                if (ct.IsCancellationRequested) return;
                var norm = kvp.Key;
                using var cert = kvp.Value;

                bool firstSeen = _handled.Add(norm);
                if (!firstSeen && !mayAct) continue; // already logged; nothing to do without action

                if (!mayAct)
                {
                    await EmitAsync(cert, norm, removed: false, quarantined: 0,
                        note: "ActiveResponse disabled - detection only, no removal").ConfigureAwait(false);
                    continue;
                }

                // 1. Remove + block the root.
                CertRemediator.RemediationResult rr;
                if (CertDistrustList.IsDistrusted(norm))
                    rr = _remediator.Distrust(norm);               // explicit list (fail-closed)
                else
                    rr = _remediator.DistrustSuspiciousRoot(cert);  // analyzer-authorized

                // 2. Quarantine files signed by a chain rooting to this now-removed cert.
                int quarantined = 0;
                if (rr.Success)
                {
                    try { quarantined = await QuarantineFilesSignedByRootAsync(norm, ct).ConfigureAwait(false); }
                    catch (Exception ex) { _logger.LogDebug(ex, "[RootStoreGuard] Quarantine sweep error for {Thumb}", norm); }
                }

                await EmitAsync(cert, norm, removed: rr.Success, quarantined: quarantined,
                    note: rr.Message).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Walks candidate signed-file locations, builds each file's Authenticode chain, and
        /// quarantines files whose chain roots at the removed thumbprint. Exact root-thumbprint
        /// match only; WRP-safe (never deletes under System32); capped per cert.
        /// </summary>
        private async Task<int> QuarantineFilesSignedByRootAsync(string removedRootThumb, CancellationToken ct)
        {
            if (removedRootThumb.Length < 16) return 0;

            int acted = 0;
            foreach (var dir in CandidateSignedFileDirs())
            {
                if (acted >= MaxQuarantinePerCert || ct.IsCancellationRequested) break;
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;

                IEnumerable<string> files;
                try { files = EnumerateCandidateFiles(dir); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (acted >= MaxQuarantinePerCert || ct.IsCancellationRequested) break;

                    // WRP safety: never touch binaries under System32 - stopping/neutralizing
                    // OS files risks bricking. We only quarantine from user-writable / app dirs.
                    if (IsProtectedOsPath(file)) continue;

                    string? fileRoot;
                    try { fileRoot = GetSigningRootThumbprint(file); }
                    catch { continue; }
                    if (fileRoot == null) continue;

                    if (!string.Equals(fileRoot, removedRootThumb, StringComparison.OrdinalIgnoreCase))
                        continue;

                    try
                    {
                        // forceQuarantineSigned: the file IS signed (by the removed root) - that
                        // is exactly why we are removing it; the default signed-file skip must
                        // not spare it. hardenedRemoval for files that may be mapped/loaded.
                        var vault = await _quarantine.QuarantineFileAtomicAsync(
                            file, forceQuarantineSigned: true, hardenedRemoval: true).ConfigureAwait(false);
                        if (!string.IsNullOrEmpty(vault))
                        {
                            acted++;
                            await _eventLogger.LogEventAsync("response", new ResponseEvent
                            {
                                ProcessId = 0,
                                ProcessName = "RootStoreGuard",
                                ActionTaken = "QUARANTINE_SIGNED_BY_REMOVED_ROOT",
                                Reason = $"File '{file}' chains to removed suspicious root {removedRootThumb}. Quarantined."
                            }).ConfigureAwait(false);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[RootStoreGuard] Quarantine failed for {File}", file);
                    }
                }
            }
            return acted;
        }

        /// <summary>
        /// Builds the Authenticode signing chain for a file and returns the ROOT cert thumbprint
        /// (top of the chain), or null if unsigned / unresolvable. This is the file -> root map
        /// the project lacked; it lets us match a file against a removed root rather than only
        /// the leaf signer.
        /// </summary>
        private static string? GetSigningRootThumbprint(string filePath)
        {
            X509Certificate2? leaf = null;
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is obsolete but has no Authenticode replacement
                leaf = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            }
            catch
            {
                return null; // unsigned or unreadable
            }

            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags; // we only want the shape, not validity
                chain.Build(leaf);
                if (chain.ChainElements.Count == 0) return null;
                var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                return CertDistrustList.Normalize(root.Thumbprint);
            }
            catch
            {
                return null;
            }
            finally
            {
                leaf.Dispose();
            }
        }

        private static IEnumerable<string> CandidateSignedFileDirs()
        {
            // User-writable / app install locations where a planted-root-signed binary would
            // live. Deliberately excludes System32 (WRP-protected OS tree).
            var dirs = new List<string>();
            void Add(string? d) { if (!string.IsNullOrEmpty(d)) dirs.Add(d!); }

            Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string up ? Path.Combine(up, "Downloads") : null);
            Add(Path.GetTempPath());
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            return dirs.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> EnumerateCandidateFiles(string dir)
        {
            var exts = new[] { ".exe", ".dll", ".sys", ".ocx", ".cpl", ".msi" };
            // Shallow-ish: AllDirectories but let per-file failures be swallowed by the caller.
            return Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                .Where(f => exts.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase));
        }

        private static bool IsProtectedOsPath(string path)
        {
            try
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);        // System32
                var sysx = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);     // SysWOW64
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                var full = Path.GetFullPath(path);
                bool under(string root) => !string.IsNullOrEmpty(root) &&
                    full.StartsWith(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase);
                // Protect the core OS binary trees; allow the rest of %WINDIR% only if not System32/WOW64.
                if (under(sys) || under(sysx)) return true;
                // winsxs and the servicing stack live under Windows and are WRP-protected too.
                if (!string.IsNullOrEmpty(win))
                {
                    if (under(Path.Combine(win, "WinSxS"))) return true;
                    if (under(Path.Combine(win, "servicing"))) return true;
                }
                return false;
            }
            catch { return true; } // fail safe: if unsure, treat as protected
        }

        private async Task EmitAsync(X509Certificate2 cert, string thumb, bool removed, int quarantined, string note)
        {
            bool listed = CertDistrustList.IsDistrusted(thumb);
            var reasons = listed
                ? "On the explicit distrust list"
                : CertSuspicionAnalyzer.DescribeVerdict(cert);

            var evidence = $"Suspicious root in trusted store: Subject='{cert.Subject}', Thumbprint={thumb}, " +
                           $"Validity={cert.NotBefore:yyyy-MM-dd}->{cert.NotAfter:yyyy-MM-dd}. {reasons}. " +
                           $"Removed={removed}, FilesQuarantined={quarantined}. {note}";

            var reasoning = "A root certificate that the OS trusted-root program does not vouch for " +
                            "(no AuthRoot-CTL membership and no Microsoft root-program marker) was present " +
                            "in a trusted store. Such a root can anchor TLS interception (MITM) and vouch " +
                            "for malicious signed code. Sentinel removed it, pinned it to Disallowed, and " +
                            "quarantined files signed by a chain rooting to it.";

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = removed
                    ? "TLS: Suspicious Root Certificate Removed"
                    : "TLS: Suspicious Root Certificate Detected",
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = removed ? 0.95 : 0.80,
                // Removal/quarantine is an authorized host mutation -> Tier1. Detection-only is
                // still surfaced; keep it Tier1 LogOnly (never Tier2 for a cert-trust event we acted on).
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = removed ? ResponseAction.RemoveCert : ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.SecurityEvasion,
                Metadata = new Dictionary<string, string>
                {
                    { "CertThumbprint", thumb },
                    { "CertSubject", cert.Subject },
                    { "CertIssuer", cert.Issuer },
                    { "Removed", removed.ToString() },
                    { "FilesQuarantined", quarantined.ToString() },
                    { "MitmDefense", "true" },
                    { "DistrustListed", listed.ToString() }
                }
            }).ConfigureAwait(false);
        }
    }
}
