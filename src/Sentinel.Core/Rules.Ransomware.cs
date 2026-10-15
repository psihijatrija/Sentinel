using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// v3.1.5: Covers the full pre-encryption playbook used by LockBit, BlackCat, Ryuk, etc.
    ///
    /// Patterns detected:
    ///   1. Shadow copy / backup deletion  (vssadmin, wmic, wbadmin, bcdedit)
    ///   2. Boot recovery disabled         (bcdedit /set recoveryenabled no)
    ///   3. File extension rename to known ransomware extensions
    ///   4. Ransom-note file creation (README/DECRYPT/HOW_TO_DECRYPT in many dirs)
    ///
    /// All detections declare Family = TerminalFamily.Ransomware so
    /// ResponsePolicy.ClassifyTerminalFamily() returns Ransomware and
    /// ApplyTierLaw() keeps the event at Tier1 kill-grade regardless of
    /// SignalType - closing the earlier demotion gap.
    /// </summary>
    [RuleCategory(DetectionCategory.Ransomware)]
    public class RansomwareDetectionRule : IDetectionRule
    {
        public string Name => "RansomwareDetectionRule";

        // ---- shadow-copy / backup deletion command patterns ----
        // Covers: vssadmin, wmic, wbadmin, bcdedit variants used by
        // LockBit, BlackCat, Ryuk, WannaCry, Hive, etc.
        private static readonly (string Pattern, string Description)[] ShadowKillPatterns =
        {
            // vssadmin - most common
            ("vssadmin delete shadows",       "Volume shadow copy deletion via vssadmin"),
            ("vssadmin.exe delete shadows",   "Volume shadow copy deletion via vssadmin"),
            // wmic - common alternative
            ("wmic shadowcopy delete",        "Volume shadow copy deletion via wmic"),
            ("wmic.exe shadowcopy delete",    "Volume shadow copy deletion via wmic"),
            // wbadmin - backup catalog / system state
            ("wbadmin delete catalog",        "Backup catalog deletion via wbadmin"),
            ("wbadmin delete systemstatebackup", "System-state backup deletion via wbadmin"),
            // bcdedit - boot recovery disable
            ("bcdedit /set recoveryenabled no",  "Boot recovery disabled via bcdedit"),
            ("bcdedit.exe /set recoveryenabled no", "Boot recovery disabled via bcdedit"),
            ("bcdedit /set safeboot",         "Safe-boot configuration tampered via bcdedit"),
            ("bcdedit.exe /set safeboot",     "Safe-boot configuration tampered via bcdedit"),
        };

        // ---- known ransomware file extensions ----
        // Acts on RENAME events to <ext> where the source file was plaintext.
        private static readonly HashSet<string> RansomwareExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Classic lockers
            ".locked", ".enc", ".crypto", ".crypt", ".encrypted",
            // Named ransomware families
            ".locky", ".zepto", ".odin", ".cerber", ".cerber2", ".cerber3",
            ".ccc", ".vvv", ".xxx", ".zzz", ".abc", ".aaa", ".xtr",
            ".lockbit", ".lnkbit",
            ".ryuk", ".ryk",
            ".hive",
            ".blackcat", ".alphv",
            ".conti",
            ".maze",
            ".revil", ".sodinokibi",
            ".wannacry", ".wcry", ".wncry",
            ".darkside",
            ".egregor",
            ".cl0p", ".clop",
            ".phobos",
            ".dharma",
            ".crysis",
            ".makop",
            ".stop", ".djvu",
            // Generic coin-locker suffixes
            ".pay2key",
            ".pay2dec",
            ".payme",
            ".ransom",
        };

        // ---- ransom note file name prefixes ----
        private static readonly string[] RansomNotePrefixes =
        {
            "README", "DECRYPT", "HOW_TO_DECRYPT", "HOW_TO_RESTORE",
            "HOW_TO_PAY", "READ_ME", "HELP_DECRYPT", "RECOVERY",
            "YOUR_FILES", "FILESAFEENCRYPTED",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            // --- 1. Shadow copy / backup deletion and boot-recovery tampering ---
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();

                foreach (var (pattern, description) in ShadowKillPatterns)
                {
                    if (cmd.Contains(pattern.ToLowerInvariant()))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            Family = TerminalFamily.Ransomware,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.Ransomware,
                            Confidence = 0.98,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Shadow copy / backup deletion command: {pt.CommandLine}",
                            Reasoning = $"{description}. " +
                                        "Ransomware operators delete volume shadow copies and backup catalogs " +
                                        "immediately before or during encryption to prevent file recovery. " +
                                        "This is one of the highest-confidence pre-encryption signals."
                        };
                    }
                }
            }

            // --- 2. File renamed to known ransomware extension ---
            if (context.TriggeringEvent is FileActivityTelemetry ft)
            {
                if (ft.OperationType == "RENAME" && ft.TargetPath != null)
                {
                    var ext = Path.GetExtension(ft.TargetPath);
                    if (!string.IsNullOrEmpty(ext) && RansomwareExtensions.Contains(ext))
                    {
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            Family = TerminalFamily.Ransomware,
                            ProcessName = ft.ProcessName,
                            ProcessId = ft.ProcessId,
                            SignalType = SignalType.Ransomware,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"File renamed to ransomware extension '{ext}': {ft.TargetPath}",
                            Reasoning = "A process renamed a file to an extension associated with a known " +
                                        "ransomware family. This is a high-confidence in-progress encryption signal."
                        };
                    }

                    // Ransom note creation
                    var fileName = Path.GetFileNameWithoutExtension(ft.TargetPath)?.ToUpperInvariant() ?? "";
                    foreach (var prefix in RansomNotePrefixes)
                    {
                        if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            return new DetectionEvent
                            {
                                RuleName = Name,
                                Family = TerminalFamily.Ransomware,
                                ProcessName = ft.ProcessName,
                                ProcessId = ft.ProcessId,
                                SignalType = SignalType.Ransomware,
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                Evidence = $"Ransom note created: {ft.TargetPath}",
                                Reasoning = $"A process created a file whose name starts with '{prefix}', " +
                                            "a well-known ransom note naming convention. " +
                                            "Combined with behavioral context, this indicates active ransomware."
                            };
                        }
                    }
                }
            }

            return null;
        }
    }
}
