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
    ///   - The three roots enumerated in Registry\Certificates.reg, which that file removes
    ///     from the Root store and pins into the Disallowed (Untrusted) store. Sentinel
    ///     mirrors that policy: detect-on-presence, remediate-to-Disallowed.
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
                ["3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F"] = "StartCom Certification Authority (globally distrusted CA)",

                // Roots enumerated in Registry\Certificates.reg (removed from Root, pinned to Disallowed).
                ["0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8"] = "Microsoft Time Stamp Root Certificate Authority 2014 (Certificates.reg distrust)",
                ["31F9FC8BA3805986B721EA7295C65B3A44534274"] = "Microsoft ECC TS Root Certificate Authority 2018 (Certificates.reg distrust)",
                ["06F1AA330B927B753A40E68CDF22E34BCBEF3352"] = "Microsoft ECC Product Root Certificate Authority 2018 (Certificates.reg distrust)",
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
