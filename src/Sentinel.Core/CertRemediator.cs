using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// SYSTEM-side certificate remediation primitive. Goal-oriented: make the target cert
    /// (identified by thumbprint) <b>untrusted and blocked</b>, by whatever means are most
    /// reliable - a superset of what Registry\Certificates.reg does:
    ///
    ///   1. Remove the certificate from every trust-granting store it may hide in - Root, CA
    ///      (intermediate), and TrustedPublisher - in both LocalMachine and CurrentUser.
    ///   2. Pin it into the Disallowed (Untrusted) store in both locations so Windows refuses
    ///      to trust it going forward. If we captured the cert bytes we add the real cert via
    ///      <see cref="X509Store"/>; if the cert was already gone from every trusted store we
    ///      still write a thumbprint-keyed Disallowed registry entry as a belt-and-braces block.
    ///
    /// This is a host mutation. It runs only when explicitly invoked from the dashboard
    /// remediation action (user-triggered), never autonomously, and only for thumbprints on
    /// <see cref="CertDistrustList"/> (fail-closed - an attacker-chosen thumbprint cannot drive
    /// arbitrary cert removal through this path).
    /// </summary>
    public sealed class CertRemediator
    {
        private readonly ILogger<CertRemediator> _logger;

        public CertRemediator(ILogger<CertRemediator> logger)
        {
            _logger = logger;
        }

        /// <summary>Trust-granting stores to purge the cert from (machine + user).</summary>
        private static readonly (StoreName Name, StoreLocation Location)[] TrustStores =
        {
            (StoreName.Root, StoreLocation.LocalMachine),
            (StoreName.Root, StoreLocation.CurrentUser),
            (StoreName.CertificateAuthority, StoreLocation.LocalMachine),
            (StoreName.CertificateAuthority, StoreLocation.CurrentUser),
            (StoreName.TrustedPublisher, StoreLocation.LocalMachine),
            (StoreName.TrustedPublisher, StoreLocation.CurrentUser),
        };

        /// <summary>Disallowed (Untrusted) stores to pin the cert into (machine + user).</summary>
        private static readonly (StoreName Name, StoreLocation Location)[] DisallowedStores =
        {
            (StoreName.Disallowed, StoreLocation.LocalMachine),
            (StoreName.Disallowed, StoreLocation.CurrentUser),
        };

        public sealed class RemediationResult
        {
            public bool Success { get; set; }
            public string Thumbprint { get; set; } = string.Empty;
            public int RemovedFromTrust { get; set; }
            public int AddedToDisallowed { get; set; }
            public string Message { get; set; } = string.Empty;
        }

        /// <summary>
        /// Distrusts a certificate identified by thumbprint: remove from all trusted stores,
        /// then block via the Disallowed store. Fail-closed: refuses any thumbprint not present
        /// on <see cref="CertDistrustList"/>.
        /// </summary>
        public RemediationResult Distrust(string? thumbprint)
        {
            var norm = CertDistrustList.Normalize(thumbprint);
            var result = new RemediationResult { Thumbprint = norm };

            if (norm.Length == 0)
            {
                result.Message = "Empty thumbprint";
                return result;
            }

            // Fail-closed: this primitive only ever acts on known-distrusted thumbprints.
            if (!CertDistrustList.IsDistrusted(norm))
            {
                result.Message = "Thumbprint is not on the distrust list; remediation refused";
                _logger.LogWarning("[CertRemediator] Refused remediation for non-distrusted thumbprint {Thumb}", norm);
                return result;
            }

            if (!IsSuspiciousInStore(norm))
            {
                result.Message = "Trust-stamp evidence is protected, unavailable, or absent; distrust refused";
                return result;
            }

            // Capture the cert bytes before removing, so we can pin the exact cert to Disallowed.
            var captured = CaptureCertificates(norm);

            result.RemovedFromTrust = RemoveFromStores(norm, TrustStores);
            result.AddedToDisallowed = AddToDisallowed(norm, captured);

            // Success means the cert is now blocked: either we pinned it to Disallowed, or we
            // removed it from trust and (if bytes were unavailable) wrote the registry block.
            result.Success = result.AddedToDisallowed > 0 || result.RemovedFromTrust > 0;
            result.Message = result.Success
                ? $"Removed from {result.RemovedFromTrust} trusted store(s); blocked in {result.AddedToDisallowed} Disallowed store(s)."
                : "Certificate not found in any trusted store and could not be pinned (nothing to do).";

            _logger.LogInformation(
                "[CertRemediator] Distrust {Thumb}: removedFromTrust={Removed}, addedToDisallowed={Added}, success={Success}",
                norm, result.RemovedFromTrust, result.AddedToDisallowed, result.Success);

            return result;
        }

        /// <summary>
        /// Distrusts a suspicious root the <see cref="CertSuspicionAnalyzer"/> has authorized.
        /// Unlike <see cref="Distrust(string)"/> (fail-closed to the hardcoded blocklist), this
        /// path handles arbitrary / previously-unseen roots - but it re-verifies the analyzer
        /// verdict here as a hard safety floor, so a trusted anchor (any root carrying the
        /// AuthRoot-CTL or Microsoft-program stamp) can NEVER be removed through this path even
        /// if a caller passes it in. The authorization anchor is the non-attacker-controllable
        /// OS CTL stamp, not the certificate's name.
        /// </summary>
        public RemediationResult DistrustSuspiciousRoot(X509Certificate2 cert)
        {
            var result = new RemediationResult
            {
                Thumbprint = CertDistrustList.Normalize(cert?.Thumbprint)
            };

            if (cert == null || result.Thumbprint.Length == 0)
            {
                result.Message = "Null/empty certificate";
                return result;
            }

            // HARD SAFETY FLOOR: re-check the verdict. Only act on a root that carries NEITHER
            // authoritative stamp. The OS CTL stamps (props 98/105) only exist on a cert context
            // that is CONNECTED TO THE STORE - a detached copy (e.g. built from RawData) loses
            // them, which would make even a genuine anchor look "suspicious". So we re-open the
            // cert FROM the store and evaluate the live context, never the passed-in copy. If the
            // live context says vouched-for, refuse. If the cert is no longer in any trusted store
            // we have nothing to remove and treat that as refuse-safe.
            if (!IsSuspiciousInStore(result.Thumbprint))
            {
                result.Message = "Certificate is a vouched-for trust anchor (or absent); removal refused (safety floor)";
                _logger.LogWarning(
                    "[CertRemediator] Refused removal of vouched-for/absent root {Thumb}",
                    result.Thumbprint);
                return result;
            }

            var captured = new List<X509Certificate2> { new X509Certificate2(cert.RawData) };

            result.RemovedFromTrust = RemoveFromStores(result.Thumbprint, TrustStores);
            result.AddedToDisallowed = AddToDisallowed(result.Thumbprint, captured);

            result.Success = result.AddedToDisallowed > 0 || result.RemovedFromTrust > 0;
            result.Message = result.Success
                ? $"Removed suspicious root from {result.RemovedFromTrust} trusted store(s); blocked in {result.AddedToDisallowed} Disallowed store(s)."
                : "Suspicious root not found in any trusted store (nothing to do).";

            _logger.LogWarning(
                "[CertRemediator] Distrusted SUSPICIOUS root {Thumb} ({Subject}): removed={Removed}, blocked={Added}",
                result.Thumbprint, cert.Subject, result.RemovedFromTrust, result.AddedToDisallowed);

            return result;
        }

        /// <summary>
        /// Re-opens the cert by thumbprint from each trusted store and evaluates the LIVE,
        /// store-connected context with <see cref="CertSuspicionAnalyzer"/>. The OS CTL stamps
        /// (props 98/105) only exist on a store-connected context, so this is the only correct
        /// place to make the safety-floor decision. Returns true only if the cert is actually
        /// present in a trusted store AND that live context is suspicious (no authoritative stamp).
        /// </summary>
        private bool IsSuspiciousInStore(string thumbprint)
        {
            bool present = false;
            foreach (var (name, location) in TrustStores)
            {
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    try
                    {
                        foreach (var cert in matches)
                        {
                            present = true;
                            if (!CertSuspicionAnalyzer.IsSuspicious(cert)) return false;
                        }
                    }
                    finally { foreach (var cert in matches) cert.Dispose(); }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[CertRemediator] Incomplete safety-floor evidence for {Store}/{Loc}; refusing", name, location);
                    return false;
                }
            }
            return present;
        }

        /// <summary>
        /// Reads matching certs out of the trusted stores (ReadOnly) so their exact bytes can be
        /// re-added to Disallowed. Returns distinct certs keyed by thumbprint.
        /// </summary>
        private List<X509Certificate2> CaptureCertificates(string thumbprint)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var captured = new List<X509Certificate2>();

            foreach (var (name, location) in TrustStores)
            {
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadOnly);
                    var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    foreach (var cert in matches)
                    {
                        if (seen.Add(cert.Thumbprint ?? string.Empty))
                        {
                            // Clone via raw-data copy so the handle survives store disposal.
                            captured.Add(new X509Certificate2(cert.RawData));
                        }
                        cert.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CertRemediator] Capture failed for {Store}/{Loc}", name, location);
                }
            }

            return captured;
        }

        private int RemoveFromStores(string thumbprint, (StoreName Name, StoreLocation Location)[] stores)
        {
            int removed = 0;
            foreach (var (name, location) in stores)
            {
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadWrite);
                    var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    foreach (var cert in matches)
                    {
                        try
                        {
                            // Recheck the live context immediately before mutation; the
                            // earlier scan is not authority for a subsequently opened store.
                            if (!CertSuspicionAnalyzer.IsSuspicious(cert))
                                throw new InvalidOperationException("Trust-stamp evidence forbids certificate removal");
                            store.Remove(cert);
                            removed++;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug(ex, "[CertRemediator] Remove failed for {Thumb} in {Store}/{Loc}", thumbprint, name, location);
                        }
                        finally
                        {
                            cert.Dispose();
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CertRemediator] Open RW failed for {Store}/{Loc}", name, location);
                }
            }
            return removed;
        }

        /// <summary>
        /// Pins the cert into the Disallowed store (machine + user). Preferred path adds the
        /// captured cert object. If no bytes were captured (already purged from trust), falls
        /// back to writing a thumbprint-keyed Disallowed registry entry so the block still sticks.
        /// </summary>
        private int AddToDisallowed(string thumbprint, List<X509Certificate2> certs)
        {
            int added = 0;

            foreach (var (name, location) in DisallowedStores)
            {
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadWrite);
                    if (certs.Count > 0)
                    {
                        foreach (var cert in certs)
                        {
                            try
                            {
                                var already = store.Certificates.Find(
                                    X509FindType.FindByThumbprint, cert.Thumbprint, validOnly: false);
                                if (already.Count == 0)
                                {
                                    store.Add(cert);
                                    added++;
                                }
                                foreach (var a in already) a.Dispose();
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, "[CertRemediator] Add to Disallowed failed in {Store}/{Loc}", name, location);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CertRemediator] Open Disallowed RW failed for {Store}/{Loc}", name, location);
                }
            }

            // Belt-and-braces: if we had no cert bytes to add via the store API, write a
            // thumbprint-keyed Disallowed registry entry directly so Windows still blocks it.
            if (certs.Count == 0)
            {
                added += WriteDisallowedRegistryBlock(thumbprint);
            }

            foreach (var cert in certs) cert.Dispose();
            return added;
        }

        /// <summary>
        /// Fallback block: creates the empty Disallowed registry key for the thumbprint under
        /// both the machine and user SystemCertificates hives. Windows treats presence in the
        /// Disallowed\Certificates subtree as an explicit distrust even without a Blob value.
        /// </summary>
        private int WriteDisallowedRegistryBlock(string thumbprint)
        {
            int written = 0;
            var hives = new (RegistryKey Root, string Path)[]
            {
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates"),
            };

            foreach (var (root, path) in hives)
            {
                try
                {
                    using var parent = root.OpenSubKey(path, writable: true)
                                       ?? root.CreateSubKey(path, writable: true);
                    if (parent == null) continue;
                    using var key = parent.OpenSubKey(thumbprint, writable: true)
                                    ?? parent.CreateSubKey(thumbprint, writable: true);
                    if (key != null) written++;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CertRemediator] Registry Disallowed block failed under {Hive}", root.Name);
                }
            }

            return written;
        }
    }
}
