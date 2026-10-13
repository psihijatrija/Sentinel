using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Kernel-File ETW NameCreate of browser cache / .tmp filled 500-event fusion
    /// chains and grew the service to ~1.6 GB private - Windows then trimmed it
    /// (LatencyMon hard pagefaults). Fusion scoring only looks at 60s of module /
    /// script / installer drops.
    /// </summary>
    internal static class SecurityFileScope
    {
        private static readonly HashSet<string> RelevantExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi",
            ".com", ".pif", ".msc",
            ".ps1", ".psm1", ".psd1", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
            ".hta", ".bat", ".cmd", ".lnk", ".url",
            ".msi", ".msp", ".msix", ".appx", ".cab",
            ".iso", ".img", ".vhd", ".vhdx", ".wim",
            ".chm", ".reg", ".inf", ".job",
            ".winmd", ".node", ".ax", ".acm",
        };

        public const int MaxEtwPathChars = 520;

        public static bool IsEtwFileEventRelevant(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            if (path!.Length < 4 || path.Length > MaxEtwPathChars) return false;
            if (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0) return false;

            string ext;
            try { ext = Path.GetExtension(path); }
            catch { return false; }
            return ext.Length > 0 && RelevantExtensions.Contains(ext);
        }

        /// <summary>
        /// High-risk staging directories where a file with an UNKNOWN/novel extension is still
        /// suspicious. This is the "fail-open for sensitive locations" set: an attacker cannot
        /// evade the extension allow-list by dropping `payload.xyz` into Startup or Temp.
        ///
        /// Deliberately narrow. It does NOT include browser caches, GPUCache, app-state, or the
        /// broad user profile - those are the documented event firehose that ballooned the
        /// service to ~1.6 GB. Only autostart persistence points and known payload-staging
        /// areas are covered, so enabling content triage here cannot reintroduce that flood.
        /// </summary>
        public static bool IsHighRiskDropDirectory(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            string p = path!.ToLowerInvariant();

            // Autostart persistence points (any extension dropped here is worth a look).
            if (p.Contains(@"\start menu\programs\startup\")) return true;
            if (p.Contains(@"\appdata\roaming\microsoft\windows\start menu\")) return true;

            // Payload staging areas. Temp/Roaming/ProgramData are where fileless loaders and
            // droppers stage second-stage content before execution.
            if (p.Contains(@"\appdata\local\temp\")) return true;
            if (p.Contains(@"\windows\temp\")) return true;
            if (p.Contains(@"\programdata\") &&
                !p.Contains(@"\programdata\microsoft\")) return true;

            // Public share - a classic drop/lateral-staging location.
            if (p.Contains(@"\users\public\")) return true;

            return false;
        }

        // Max bytes to sniff. A PE/script signature is in the first few bytes; keep this tiny
        // so the read is a single page and cannot become an I/O firehose.
        private const int SniffBytes = 4;

        /// <summary>
        /// Content-based (magic-byte) triage: returns true when the file's leading bytes look
        /// like an executable or script REGARDLESS of extension. This catches a renamed dropper
        /// (`evil.xyz` whose bytes are a PE, or a `#!`/`&lt;?`/`&lt;script` text loader).
        ///
        /// Callers MUST only invoke this in an already-narrowed context (e.g. after
        /// <see cref="IsHighRiskDropDirectory"/>), never on the raw event firehose - it opens
        /// the file. Fully defensive: any failure returns false (fail-closed to "not executable"
        /// so we never block on an unreadable/locked file, and never throw on the event thread).
        /// </summary>
        public static bool LooksExecutableByContent(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                if (!File.Exists(path)) return false;
                var fi = new FileInfo(path!);
                if (fi.Length < 2) return false;

                var head = new byte[SniffBytes];
                int read;
                using (var fs = new FileStream(path!, FileMode.Open, FileAccess.Read,
                           FileShare.ReadWrite | FileShare.Delete, SniffBytes, FileOptions.SequentialScan))
                {
                    read = fs.Read(head, 0, SniffBytes);
                }
                if (read < 2) return false;

                // PE / DOS executable: "MZ"
                if (head[0] == (byte)'M' && head[1] == (byte)'Z') return true;
                // ELF (WSL / cross-platform payload): 0x7F 'E' 'L' 'F'
                if (read >= 4 && head[0] == 0x7F && head[1] == (byte)'E' &&
                    head[2] == (byte)'L' && head[3] == (byte)'F') return true;
                // Shell/script shebang: "#!"
                if (head[0] == (byte)'#' && head[1] == (byte)'!') return true;
                // HTML/XML-hosted script (HTA, .wsf, scriptlet): '<'
                if (head[0] == (byte)'<') return true;
                // MSI / OLE compound (D0 CF 11 E0): first two bytes are enough to flag.
                if (head[0] == 0xD0 && head[1] == 0xCF) return true;

                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// Stronger relevance check for callers that already know the directory context.
        /// Relevant if: the extension is on the allow-list (fast path, unchanged), OR the file
        /// sits in a high-risk drop directory AND its content looks executable/script. This
        /// closes the "unmonitored extension" evasion without touching the hot-path firehose
        /// filter used on the raw ETW stream.
        /// </summary>
        public static bool IsRelevantOrHighRisk(string? path)
        {
            if (IsEtwFileEventRelevant(path)) return true;
            if (!IsHighRiskDropDirectory(path)) return false;
            return LooksExecutableByContent(path);
        }
    }
}
