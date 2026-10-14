using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Sentinel.Core
{
    /// <summary>
    /// Authoritative, thumbprint-keyed distrust list for certificates that must never be
    /// trusted even if they sit in a trusted store (Root / TrustedPublisher).
    ///
    /// Rationale (adversarial mindset): a certificate's Subject / Issuer strings are fully
    /// attacker-controlled, so name-based allow/deny heuristics are unsafe. The SHA-1
    /// thumbprint is a non-attacker-controllable identity anchor - it is derived from the
    /// DER-encoded certificate itself. This list keys exclusively on thumbprint.
    ///
    /// Seed contents:
    ///   - StartCom Certification Authority root (distrusted by Microsoft/Mozilla/Google/Apple
    ///     since the 2016-2017 WoSign ownership scandal; must not appear in a trusted store).
    ///
    /// Removed in v3.1.3 (previously added in v3.0.4, sourced from Registry\Certificates.reg /
    /// a local Zemana scan result):
    ///   - Microsoft Time Stamp Root Certificate Authority 2014 (0119E81...)
    ///   - Microsoft ECC TS Root Certificate Authority 2018 (31F9FC8...)
    ///   - Microsoft ECC Product Root Certificate Authority 2018 (06F1AA3...)
    ///
    /// These three are active, CTL-vouched Microsoft roots used by Windows Update, the
    /// Microsoft Store CDN, Authenticode time-stamping, and Windows component signing.
    /// CertSuspicionAnalyzer.IsSuspicious() correctly returns false for them (they carry
    /// prop 98/105), so RootStoreGuard's heuristic path would never remove them — but the
    /// explicit distrust-list path bypasses the heuristic safety floor and does act on them,
    /// causing RootStoreGuard to move them to Disallowed and break Store TLS on startup sweep.
    /// They must not be on this list. The fix-up repair script is installer/repair-certs.ps1.
    ///
    /// Thumbprints are stored uppercase, hex, no separators (the format
    /// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.Thumbprint"/>
    /// returns). Lookups are case-insensitive and tolerant of spaces.
    /// </summary>
    public static class CertDistrustList
    {
        /// <summary>
        /// Thumbprint -> human-readable label (what the cert is / why it is distrusted).
        /// Keep labels short; they surface in scan findings.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, string> _entries =
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // StartCom Certification Authority - globally distrusted CA (WoSign scandal).
                // Distrusted by Microsoft, Mozilla, Google, and Apple since the 2016-2017 WoSign
                // ownership and misissuance scandal. Should never appear in a trusted store.
                ["3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F"] = "StartCom Certification Authority (globally distrusted CA)",
            });

        /// <summary>All distrusted thumbprints (uppercase, no separators).</summary>
        public static IEnumerable<string> Thumbprints => _entries.Keys;

        /// <summary>Number of entries in the distrust list.</summary>
        public static int Count => _entries.Count;

        /// <summary>
        /// Normalizes a thumbprint for comparison: strips whitespace / common separators
        /// and uppercases. Returns empty string for null/blank input.
        /// </summary>
        public static string Normalize(string? thumbprint)
        {
            if (string.IsNullOrWhiteSpace(thumbprint)) return string.Empty;
            var span = thumbprint!.AsSpan();
            var buf = new char[span.Length];
            int n = 0;
            foreach (var c in span)
            {
                if (c == ' ' || c == ':' || c == '-' || c == '\t' || c == '\r' || c == '\n') continue;
                buf[n++] = char.ToUpperInvariant(c);
            }
            return new string(buf, 0, n);
        }

        /// <summary>True if the given thumbprint is on the distrust list.</summary>
        public static bool IsDistrusted(string? thumbprint)
        {
            var norm = Normalize(thumbprint);
            return norm.Length > 0 && _entries.ContainsKey(norm);
        }

        /// <summary>
        /// Returns the distrust label for a thumbprint, or null if it is not distrusted.
        /// </summary>
        public static string? GetLabel(string? thumbprint)
        {
            var norm = Normalize(thumbprint);
            return norm.Length > 0 && _entries.TryGetValue(norm, out var label) ? label : null;
        }
    }
}
