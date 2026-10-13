using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Typed terminal-outcome families - the single source of truth for the attack
    /// outcome taxonomy used by <see cref="ResponsePolicy"/>. Historically these were
    /// bare string literals ("CredentialDump", "C2Beacon", ...) scattered across the kill
    /// classifier, the kill-grade set, and consumer metadata. A typo in any one of those
    /// literals could silently drop a family out of kill-grade authority - the highest
    /// consequence bug class on a SYSTEM-level responder.
    ///
    /// This enum + the <see cref="TerminalFamilies"/> helpers make the taxonomy and the
    /// kill-grade membership authoritative and typo-proof. The canonical string names are
    /// preserved exactly so every existing string contract (metadata keys, evidence text,
    /// tests) continues to hold byte-for-byte.
    /// </summary>
    public enum TerminalFamily
    {
        /// <summary>Bring-your-own-vulnerable-driver. Terminal but NOT solo kill-grade.</summary>
        Byovd,

        /// <summary>Credential dumping (LSASS, SAM/SECURITY hive, DCSync, ...). Kill-grade.</summary>
        CredentialDump,

        /// <summary>Token theft / impersonation / potato-family EoP. Kill-grade.</summary>
        TokenTheft,

        /// <summary>Reverse / bind / interactive shell. Kill-grade.</summary>
        ReverseShell,

        /// <summary>Data exfiltration / staging / DNS tunnel. Terminal but NOT solo kill-grade.</summary>
        Exfil,

        /// <summary>Command-and-control beaconing / covert channel. Kill-grade.</summary>
        C2Beacon,

        /// <summary>Defense evasion (AMSI/ETW patch, Hell's Gate, unmapped thread). Kill-grade.</summary>
        Evasion,

        /// <summary>Remote memory injection. Kill-grade.</summary>
        Injection,

        /// <summary>Executable WMI persistence / policy rewrite. Kill-grade.</summary>
        WmiPersistence,
    }

    /// <summary>
    /// Canonical string names and kill-grade membership for <see cref="TerminalFamily"/>.
    /// <see cref="ResponsePolicy"/> derives its string collections from here so there is
    /// exactly one place that defines the taxonomy.
    /// </summary>
    public static class TerminalFamilies
    {
        // Canonical string form of each family. These MUST match the historical literals
        // used in metadata (TerminalOutcome), evidence text, and the existing test suite.
        private static readonly IReadOnlyDictionary<TerminalFamily, string> Names =
            new Dictionary<TerminalFamily, string>
            {
                [TerminalFamily.Byovd] = "BYOVD",
                [TerminalFamily.CredentialDump] = "CredentialDump",
                [TerminalFamily.TokenTheft] = "TokenTheft",
                [TerminalFamily.ReverseShell] = "ReverseShell",
                [TerminalFamily.Exfil] = "Exfil",
                [TerminalFamily.C2Beacon] = "C2Beacon",
                [TerminalFamily.Evasion] = "Evasion",
                [TerminalFamily.Injection] = "Injection",
                [TerminalFamily.WmiPersistence] = "WmiPersistence",
            };

        // Families that, at sufficient confidence + chain confirmation, may authorize a kill.
        // BYOVD and Exfil are terminal (they seed chains) but never SOLO kill-grade.
        private static readonly HashSet<TerminalFamily> KillGrade = new()
        {
            TerminalFamily.CredentialDump,
            TerminalFamily.TokenTheft,
            TerminalFamily.ReverseShell,
            TerminalFamily.C2Beacon,
            TerminalFamily.WmiPersistence,
            TerminalFamily.Evasion,
            TerminalFamily.Injection,
        };

        /// <summary>Canonical string name for a family (e.g. "C2Beacon").</summary>
        public static string ToCanonicalString(this TerminalFamily family) => Names[family];

        /// <summary>True if the family may authorize a kill (given confidence + chain confirm).</summary>
        public static bool IsKillGrade(TerminalFamily family) => KillGrade.Contains(family);

        /// <summary>
        /// Parse a canonical family string back to the typed enum, or null if unrecognized.
        /// Case-insensitive to match the OrdinalIgnoreCase comparisons elsewhere.
        /// </summary>
        public static TerminalFamily? FromCanonicalString(string? name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            foreach (var kvp in Names)
            {
                if (string.Equals(kvp.Value, name, StringComparison.OrdinalIgnoreCase))
                    return kvp.Key;
            }
            return null;
        }

        /// <summary>All canonical kill-grade family strings (for building legacy string sets).</summary>
        public static IEnumerable<string> KillGradeCanonicalStrings()
            => KillGrade.Select(f => Names[f]);

        /// <summary>All canonical family strings.</summary>
        public static IEnumerable<string> AllCanonicalStrings() => Names.Values;
    }
}
