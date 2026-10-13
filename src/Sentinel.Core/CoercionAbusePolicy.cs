using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>
    /// Platform-agnostic classification of endpoint toolkits used for digital sexual
    /// coercion, stalking, account takeover, and remote-control abuse.
    ///
    /// Sentinel does NOT identify "rapists" or moderate chat. It classifies
    /// <em>machine behaviour</em> (remote control, covert surveillance, session theft,
    /// extortion malware) so response and evidence packs can use clear victim-facing
    /// language. Applies to Discord, email, social, browsers, messaging apps, games -
    /// any channel that leaves traces on Windows.
    /// </summary>
    public static class CoercionAbusePolicy
    {
        public const string AbuseCategoryKey = "AbuseCategory";
        public const string AbuseCategoryValue = "DigitalCoercionToolkit";

        /// <summary>Human-readable category for packs / UI (never a legal conclusion).</summary>
        public const string AbuseCategoryLabel =
            "Digital coercion / surveillance toolkit (endpoint technical indicators)";

        /// <summary>
        /// Commercial / open remote-control tools frequently abused for coercive
        /// control of a victim PC (also used legitimately - never kill on name alone).
        /// </summary>
        public static readonly HashSet<string> RemoteAccessToolNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "anydesk", "teamviewer", "teamviewer_service", "tv_w32", "tv_x64",
            "rustdesk", "rustdesk_service", "supremo", "supremohelper",
            "splashtop", "strwinclt", "vncserver", "vncviewer", "winvnc", "tightvnc",
            "ultravnc", "realvnc", "tvnserver", "dwagent", "dwagsvc",
            "ammyy", "aa_v3", "getscreen", "chrome_remote_desktop_host",
            "remotedesktop", "msrdc", "mstsc", "rdpclip", "logmein", "lmi_rescue",
            "bomgar", "beyondtrust", "connectwisecontrol", "screenconnect",
            "parsec", "toodesk", "sunloginclient", "oraybox",
            "quasar", "asyncrat", "njrat", "darkcomet", "nanocore", "remcos",
            "warzone", "netwire", "orcus", "luminositylink",
            "tailcat", "wireproxy", "sliver", "chisel", "ngrok",
        };

        private static readonly string[] SurveillanceRuleFragments =
        {
            "Screen Capture",
            "Desktop Duplication",
            "DXGI Desktop",
            "Webcam",
            "Camera",
            "Microphone",
            "Phantom Keystroke",
            "Keylog",
            "Clipboard",
            "ClipBanker",
        };

        private static readonly string[] RemoteControlRuleFragments =
        {
            "Remote Session",
            "Remote Access",
            "RDP",
            "Reverse Shell",
            "Bind Shell",
            "Interactive Shell",
            "Shadow Session",
            "WTS",
            "Terminal Services",
            "Unauthorized Cast",
        };

        private static readonly string[] SessionTheftRuleFragments =
        {
            "Credential Dump",
            "Credential Theft",
            "LSASS",
            "Browser Credential",
            "Cookie",
            "Token Theft",
            "SYSTEM Token",
            "Browser Extension",
            "CDP",
            "DevTools",
            "NativeMessaging",
            "Session Hijack",
            "Password Store",
            "DPAPI",
            "Login Data",
            "Web Data",
            "Local Storage",
            "LevelDB",
        };

        private static readonly string[] CoercionCompositeNames =
        {
            "Covert Surveillance + Remote Channel",
            "Remote Control Abuse Toolkit",
            "Session Theft + Abuse Channel",
            "Stalkerware Persistence Chain",
        };

        public static bool IsRemoteAccessToolProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var stem = processName!.Trim();
            if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                stem = stem.Substring(0, stem.Length - 4);
            if (RemoteAccessToolNames.Contains(stem))
                return true;
            // Substring for service variants (TeamViewer_Service -> teamviewer)
            foreach (var tool in RemoteAccessToolNames)
            {
                if (tool.Length < 4) continue;
                if (stem.IndexOf(tool, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        public static bool IsSurveillanceRule(DetectionEvent? d)
        {
            if (d == null) return false;
            return RuleContainsAny(d.RuleName, SurveillanceRuleFragments) ||
                   RuleContainsAny(d.Evidence, SurveillanceRuleFragments);
        }

        public static bool IsRemoteControlRule(DetectionEvent? d)
        {
            if (d == null) return false;
            if (IsRemoteAccessToolProcess(d.ProcessName))
                return true;
            if (d.SignalType == SignalType.ReverseShell)
                return true;
            return RuleContainsAny(d.RuleName, RemoteControlRuleFragments) ||
                   RuleContainsAny(d.Evidence, RemoteControlRuleFragments);
        }

        public static bool IsSessionTheftRule(DetectionEvent? d)
        {
            if (d == null) return false;
            if (d.SignalType is SignalType.CredentialTheft or SignalType.LsassAccess)
                return true;
            return RuleContainsAny(d.RuleName, SessionTheftRuleFragments) ||
                   RuleContainsAny(d.Evidence, SessionTheftRuleFragments);
        }

        public static bool IsCoercionCompositeRule(string? ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            foreach (var n in CoercionCompositeNames)
            {
                if (ruleName!.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// True when this detection should be presented as digital-coercion toolkit activity
        /// in evidence packs (composite or multi-leg surveillance/remote/session chain).
        /// </summary>
        public static bool IsDigitalCoercionToolkit(DetectionEvent? detection)
        {
            if (detection == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue(AbuseCategoryKey, out var cat) &&
                string.Equals(cat, AbuseCategoryValue, StringComparison.OrdinalIgnoreCase))
                return true;

            if (IsCoercionCompositeRule(detection.RuleName))
                return true;

            // Single high-confidence reverse shell / remote session still relevant for packs
            // when chain-confirmed (caller already gates packs).
            if (detection.SignalType == SignalType.ReverseShell)
                return true;

            return false;
        }

        public static void TagAsCoercionToolkit(DetectionEvent detection)
        {
            if (detection == null) return;
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata[AbuseCategoryKey] = AbuseCategoryValue;
            detection.Metadata["AbuseCategoryLabel"] = AbuseCategoryLabel;
        }

        public static string BuildPackSection(DetectionEvent detection)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("");
            sb.AppendLine("DIGITAL COERCION / SURVEILLANCE TOOLKIT (TECHNICAL SCOPE)");
            sb.AppendLine("");
            sb.AppendLine();
            sb.AppendLine("  This pack matches endpoint patterns often used to control, watch, or");
            sb.AppendLine("  take over a victim computer - including cases of online harassment,");
            sb.AppendLine("  sexual coercion, stalkerware, account takeover, and remote blackmail.");
            sb.AppendLine();
            sb.AppendLine("  WHAT SENTINEL ASSERTS (technical only):");
            sb.AppendLine("  - Machine behaviour on THIS Windows host matched a multi-signal attack");
            sb.AppendLine("    pattern (remote control, covert surveillance, session theft, and/or");
            sb.AppendLine("    related malware tooling).");
            sb.AppendLine();
            sb.AppendLine("  WHAT SENTINEL DOES NOT ASSERT:");
            sb.AppendLine("  - Identity or guilt of any person as a sexual offender");
            sb.AppendLine("  - Content of chat messages on Discord, email, social media, etc.");
            sb.AppendLine("  - That a sexual assault occurred offline");
            sb.AppendLine();
            sb.AppendLine("  Platforms in scope (examples - not an exclusive list):");
            sb.AppendLine("  messaging apps, social networks, email, browsers, games, voice/video,");
            sb.AppendLine("  remote-support tools, cloud sync - any channel that leaves host traces.");
            sb.AppendLine();
            sb.AppendLine($"  Matched rule: {detection.RuleName}");
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue(ResponsePolicy.TerminalOutcomeKey, out var outcome))
                sb.AppendLine($"  Terminal outcome family: {outcome}");
            sb.AppendLine();
            return sb.ToString();
        }

        public static string BuildAffidavitHarmHints()
        {
            return
                "   Optional harm categories (check any that apply - you complete this, not Sentinel):\n" +
                "   [ ] Unauthorized remote control of my computer\n" +
                "   [ ] Unauthorized screen / camera / microphone capture\n" +
                "   [ ] Theft of account sessions (email, messaging, social, games, banking)\n" +
                "   [ ] Threats, blackmail, or coercion after device or account compromise\n" +
                "   [ ] Stalking / ongoing surveillance via software on this PC\n" +
                "   [ ] Other: _______________________________________________________________\n";
        }

        private static bool RuleContainsAny(string? haystack, string[] fragments)
        {
            if (string.IsNullOrEmpty(haystack)) return false;
            foreach (var f in fragments)
            {
                if (haystack!.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }
    }
}
