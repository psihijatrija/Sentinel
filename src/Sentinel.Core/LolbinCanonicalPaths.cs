using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// v-next: Canonical-path anchoring for high-abuse system LOLBins.
    ///
    /// Sentinel already detects LOLBin abuse behaviorally by command-line (Rules.cs,
    /// ScriptExecutionMonitor). This helper adds an orthogonal, cheap signal: a system binary
    /// like rundll32.exe / powershell.exe / regsvr32.exe has exactly one or two legitimate
    /// on-disk locations (System32 / SysWOW64 / the WindowsPowerShell path). A process with that
    /// FILENAME running from ANYWHERE ELSE (Temp, AppData, Downloads, a random folder) is a
    /// masquerade - malware renaming its payload to a trusted binary name to blend in, or a
    /// planted copy used to dodge path-based allowlists.
    ///
    /// This is a location-anomaly SIGNAL (chain fuel), not a kill: the name+path mismatch does
    /// not by itself prove intent. Behavioral confirmation (suspicious args, network, ancestry)
    /// is what promotes it. The technique is inspired by HijackThis' path-anchored LOLBin list;
    /// the mapping here is original and intentionally minimal (the binaries most abused as
    /// masquerade targets).
    /// </summary>
    public static class LolbinCanonicalPaths
    {
        // FileName (lower) -> allowed directory suffixes (matched case-insensitively as a
        // trailing path fragment under %SystemRoot%). Keeping this as suffixes avoids hard-coding
        // a drive letter and tolerates non-C: Windows installs.
        private static readonly Dictionary<string, string[]> CanonicalDirs =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["rundll32.exe"]   = new[] { @"\system32", @"\syswow64" },
                ["regsvr32.exe"]   = new[] { @"\system32", @"\syswow64" },
                ["mshta.exe"]      = new[] { @"\system32", @"\syswow64" },
                ["cmd.exe"]        = new[] { @"\system32", @"\syswow64" },
                ["wscript.exe"]    = new[] { @"\system32", @"\syswow64" },
                ["cscript.exe"]    = new[] { @"\system32", @"\syswow64" },
                ["certutil.exe"]   = new[] { @"\system32", @"\syswow64" },
                ["bitsadmin.exe"]  = new[] { @"\system32", @"\syswow64" },
                ["wmic.exe"]       = new[] { @"\system32\wbem", @"\syswow64\wbem" },
                ["schtasks.exe"]   = new[] { @"\system32", @"\syswow64" },
                ["sc.exe"]         = new[] { @"\system32", @"\syswow64" },
                ["msiexec.exe"]    = new[] { @"\system32", @"\syswow64" },
                ["powershell.exe"] = new[] { @"\system32\windowspowershell\v1.0", @"\syswow64\windowspowershell\v1.0" },
            };

        /// <summary>
        /// True when <paramref name="processName"/> (with or without .exe) is a system LOLBin
        /// whose location we anchor. Use this to gate the more expensive path evaluation.
        /// </summary>
        public static bool IsAnchoredLolbin(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            return CanonicalDirs.ContainsKey(NormalizeName(processName!));
        }

        /// <summary>
        /// Returns true when a known system LOLBin is running from a location OUTSIDE its
        /// canonical System32/SysWOW64 directory - a filename-masquerade / planted-copy signal.
        ///
        /// Returns false when the binary is unknown to us, when the path is empty (can't judge),
        /// or when the path is a legitimate canonical location. Fail-open: an empty/unparseable
        /// path is NOT flagged (we never fabricate a signal from missing data).
        /// </summary>
        public static bool IsLolbinFromNonCanonicalPath(string? processName, string? imagePath)
        {
            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(imagePath))
                return false;

            string name = NormalizeName(processName!);
            if (!CanonicalDirs.TryGetValue(name, out var allowedSuffixes))
                return false; // not an anchored LOLBin

            string dir;
            try
            {
                dir = (Path.GetDirectoryName(imagePath!.Trim()) ?? string.Empty)
                    .TrimEnd('\\')
                    .ToLowerInvariant();
            }
            catch
            {
                return false; // unparseable path - do not fabricate a signal
            }

            if (dir.Length == 0) return false;

            foreach (var suffix in allowedSuffixes)
            {
                if (dir.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return false; // in a canonical location
            }

            return true; // known LOLBin, but not in any canonical directory
        }

        private static string NormalizeName(string processName)
        {
            string n = processName.Trim().ToLowerInvariant();
            if (!n.EndsWith(".exe", StringComparison.Ordinal)) n += ".exe";
            return n;
        }
    }
}
