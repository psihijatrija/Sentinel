using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Sentinel.Core
{
    /// <summary>
    /// Ports the PS script's Invoke-IdsDetection ($Script:IdsPatterns) as a Sentinel rule.
    /// Inspects ProcessTelemetry.CommandLine for LOLBin / evasion command-line patterns via
    /// case-insensitive compiled regexes and, on the first match, emits a Tier2 / LogOnly
    /// indicator that feeds the correlation engine. Per docs/constraints.md a command-line
    /// pattern alone never self-authorizes a response, so this is unconditionally LogOnly.
    /// </summary>
    [RuleCategory(DetectionCategory.SecurityEvasion)]
    public class IdsCommandLineRule : IDetectionRule
    {
        public string Name => "IdsCommandLineRule";

        // Compiled once (static readonly) for perf; IgnoreCase for command-line case variance.
        private static readonly (string Name, Regex Rx)[] Patterns = new[]
        {
            ("certutil-urlcache",      new Regex(@"certutil(\.exe)?\b.*-urlcache", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("bitsadmin-transfer",     new Regex(@"bitsadmin(\.exe)?\b.*/transfer", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("powershell-encoded",     new Regex(@"powershell(\.exe)?\b.*\s-(enc|encodedcommand)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("powershell-hidden",      new Regex(@"powershell(\.exe)?\b.*\s-w(indowstyle)?\s+hidden", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("invoke-expression",      new Regex(@"invoke-expression|\biex\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("net-downloadstring",     new Regex(@"downloadstring", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("net-downloadfile",       new Regex(@"downloadfile", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("net-webclient",          new Regex(@"net\.webclient", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("executionpolicy-bypass", new Regex(@"-executionpolicy\s+bypass", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("wmic-process-create",    new Regex(@"wmic\b.*process\s+call\s+create", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("reg-add-run",            new Regex(@"reg(\.exe)?\s+add\b.*hklm.*\\run", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("schtasks-create",        new Regex(@"schtasks(\.exe)?\b.*/create", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("netsh-firewall",         new Regex(@"netsh\b.*firewall", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("sc-create",              new Regex(@"\bsc(\.exe)?\s+create\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("rundll32-dll",           new Regex(@"rundll32(\.exe)?\b.*\.dll", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("regsvr32-silent",        new Regex(@"regsvr32(\.exe)?\b.*/s", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("mshta-http",             new Regex(@"mshta(\.exe)?\b.*http", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt) return null;
            if (string.IsNullOrEmpty(pt.CommandLine)) return null;

            foreach (var (patternName, rx) in Patterns)
            {
                if (!rx.IsMatch(pt.CommandLine)) continue;

                // Truncate the command line in the evidence to keep logs bounded.
                var cmd = pt.CommandLine!;
                var truncated = cmd.Length > 200 ? cmd.Substring(0, 200) + "..." : cmd;

                return new DetectionEvent
                {
                    RuleName           = Name,
                    ProcessName        = pt.ProcessName,
                    ProcessId          = pt.ProcessId,
                    SignalType         = SignalType.SuspiciousProcess,
                    Confidence         = 0.60,
                    Tier               = DetectionTier.Tier2Indicator, // Tier 2 - LogOnly, feeds correlation
                    AuthorizedResponse = ResponseAction.LogOnly,
                    Evidence           = $"IDS command-line pattern '{patternName}' matched: {truncated}",
                    Reasoning          = "Command line matches a known LOLBin / evasion pattern. This is a " +
                                         "Tier2 indicator only (LogOnly) - a command-line pattern alone never " +
                                         "authorizes a response; it feeds the correlation engine."
                };
            }

            return null;
        }
    }

    [RuleCategory(DetectionCategory.UnsignedBinary)]
    public class UnsignedBinaryRule : IDetectionRule
    {
        public string Name => "UnsignedBinaryRule";

        // Standard user-mode install paths that are NOT suspicious
        private static readonly string[] TrustedAppDataPaths = new[]
        {
            "\\appdata\\local\\programs\\",
            "\\appdata\\local\\microsoft\\",
            "\\appdata\\local\\google\\",
            "\\appdata\\local\\mozilla\\",
            "\\appdata\\local\\slack\\",
            "\\appdata\\local\\discord\\",
            "\\appdata\\local\\spotify\\",
            "\\appdata\\local\\steam\\",
            "\\appdata\\local\\brave software\\",
            "\\appdata\\local\\1password\\",
            "\\appdata\\local\\gitkraken\\",
            "\\appdata\\local\\postman\\",
        };

        private static readonly string[] TrustedTempInstallerPatterns = new[]
        {
            "devinusersetup-",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                // Skip checking if it lacks path separator (as per v4.1.0 fix)
                if (!pt.ImagePath.Contains('\\')) return null;

                var path = pt.ImagePath.ToLowerInvariant();

                // A trusted path fragment (installer prefix / known-app AppData dir) must NEVER
                // self-authorize on its own - an attacker can drop an unsigned payload into any
                // path that contains one of these substrings (e.g. a folder literally named
                // "...\appdata\local\discord\"). Per docs/constraints.md, a name/path allow must
                // combine with a NON-attacker-controllable anchor. Here that anchor is a valid
                // Authenticode signature: the trusted-path allowances only clear suspicion for a
                // SIGNED binary. Legitimate apps that stage in Temp/AppData (Discord, Slack,
                // Spotify, the Devin installer, etc.) are all code-signed, so this preserves their
                // FP protection while an unsigned impostor in the same path stays observe-fuel.
                bool signed = SecurityValidation.VerifyAuthenticodeSignature(pt.ImagePath);

                // Only flag truly suspicious locations (Temp, Downloads, raw AppData outside program installs)
                bool isSuspicious = path.Contains("\\temp\\") || path.Contains("\\downloads\\");
                if (isSuspicious && signed &&
                    TrustedTempInstallerPatterns.Any(pattern => path.Contains(pattern)))
                    isSuspicious = false;

                if (!isSuspicious && path.Contains("\\appdata\\"))
                {
                    // AppData is suspicious UNLESS it's a known app install path AND signed.
                    isSuspicious = true;
                    if (signed)
                    {
                        foreach (var trusted in TrustedAppDataPaths)
                        {
                            if (path.Contains(trusted))
                            {
                                isSuspicious = false;
                                break;
                            }
                        }
                    }
                }

                if (isSuspicious)
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.SuspiciousProcess,
                        Confidence = 0.60,
                        Tier = DetectionTier.Tier2Indicator, // Tier 2 - Log only
                        Evidence = $"Binary executed from user-writeable path: {pt.ImagePath}",
                        Reasoning = "Execution of a binary from temporary or user-profile directory. Feeds the correlation engine."
                    };
                }
            }
            return null;
        }
    }


    [RuleCategory(DetectionCategory.AttackOnUser)]
    public class FullPathParentChildRule : IDetectionRule
    {
        public string Name => "FullPathParentChildRule";

        // Map: parent exe name (lowercase) -> known legitimate install path fragments (lowercase)
        // If the parent's ImagePath contains NONE of these, the binary is not a genuine install.
        private static readonly Dictionary<string, string[]> ParentExpectedPaths =
            new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword.exe"]  = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["excel.exe"]    = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["powerpnt.exe"] = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["outlook.exe"]  = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["onenote.exe"]  = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["msaccess.exe"] = new[] { "\\microsoft office\\", "\\office\\", "\\microsoft 365\\" },
            ["soffice.exe"]  = new[] { "\\libreoffice\\", "\\openoffice\\" },
            ["chrome.exe"]   = new[] { "\\google\\chrome\\", "\\chromium\\" },
            ["msedge.exe"]   = new[] { "\\microsoft\\edge\\" },
            ["brave.exe"]    = new[] { "\\brave software\\", "\\bravesoftware\\" },
            ["opera.exe"]    = new[] { "\\opera\\" },
            ["vivaldi.exe"]  = new[] { "\\vivaldi\\" },
            ["firefox.exe"]  = new[] { "\\mozilla firefox\\", "\\firefox\\" },
            ["acrord32.exe"] = new[] { "\\adobe\\acrobat\\", "\\adobe\\reader\\" },
            ["acrobat.exe"]  = new[] { "\\adobe\\acrobat\\" },
            ["wscript.exe"]  = new[] { "\\system32\\", "\\syswow64\\" },
            ["cscript.exe"]  = new[] { "\\system32\\", "\\syswow64\\" },
        };

        // Map: parent exe name -> child exe names that are suspicious for THIS parent
        private static readonly Dictionary<string, HashSet<string>> ChildrenByParent =
            new(StringComparer.OrdinalIgnoreCase)
        {
            ["winword.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe" },
            ["excel.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe" },
            ["powerpnt.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["outlook.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "regsvr32.exe", "certutil.exe" },
            ["onenote.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["msaccess.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["soffice.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["chrome.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
            ["msedge.exe"]   = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["firefox.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["brave.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["opera.exe"]    = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["vivaldi.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["acrord32.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["acrobat.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe" },
            ["wscript.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe" },
            ["cscript.exe"]  = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe" },
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;
            if (string.IsNullOrEmpty(pt.ParentProcessName)) return null;

            // 1. Does this parent name appear in our map?
            if (!ChildrenByParent.TryGetValue(pt.ParentProcessName, out var suspiciousChildren))
                return null;

            // 2. Is the child one of the suspicious children for this parent?
            if (!suspiciousChildren.Contains(pt.ProcessName))
                return null;

            // 3. PARENT PATH VERIFICATION against a NON-attacker-controllable anchor.
            //    Constraint (docs/constraints.md): a filename alone must never self-authorize.
            //    An attacker can name a binary "winword.exe" and drop it in C:\Temp\, so the
            //    parent NAME matching our map proves nothing. We must confirm the parent binary
            //    actually lives in a legitimate install location - using the image path the OS
            //    recorded at process creation (ancestry cache), NOT the child's command line
            //    (which the attacker controls) and NOT the parent name.
            //
            //    Two outcomes for a parent name we have an expected-path map for:
            //      - Parent's REAL image path is inside a legitimate install dir  -> a genuine
            //        app spawned a shell. Report as a Tier2 observe leg (macro/LOLBin behaviour).
            //      - Parent's real path is NOT in a legitimate dir, OR we cannot resolve it
            //        (spoofed name, unknown provenance) -> this is the exact spoofed-parent case
            //        the rule exists to catch. FAIL CLOSED: report it, with higher confidence,
            //        rather than skipping. (Still Tier2/LogOnly - kill needs chain confirm.)
            bool parentPathSpoofedOrUnknown = false;
            if (ParentExpectedPaths.TryGetValue(pt.ParentProcessName, out var allowedFragments))
            {
                var parentImagePath = ResponsePolicy.ResolveImagePathForPid(pt.ParentProcessId);
                if (string.IsNullOrEmpty(parentImagePath))
                {
                    // Cannot verify the parent's real location -> do not trust the name.
                    parentPathSpoofedOrUnknown = true;
                }
                else
                {
                    var lowered = parentImagePath!.ToLowerInvariant();
                    bool pathLegitimate = allowedFragments.Any(fragment => lowered.Contains(fragment));
                    if (!pathLegitimate)
                        parentPathSpoofedOrUnknown = true;
                }
            }

            double confidence = parentPathSpoofedOrUnknown ? 0.85 : 0.75;
            string provenance = parentPathSpoofedOrUnknown
                ? "Parent binary name matches a known application but its real image path is NOT in a " +
                  "legitimate install location (or could not be verified) - a spoofed-parent / masquerade " +
                  "pattern. Reported (fail-closed); auto-kill still requires chain confirmation."
                : "A legitimate application (Office / browser / PDF reader), verified by its real install " +
                  "path, spawned a shell or scripting engine. Feeding correlation engine; auto-kill " +
                  "requires chain confirmation.";

            return new DetectionEvent
            {
                RuleName          = Name,
                RuleId            = "SENT-003",
                ProcessName       = pt.ProcessName,
                ProcessId         = pt.ProcessId,
                SignalType        = SignalType.SuspiciousProcess,
                Confidence        = confidence,
                Tier              = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                Evidence          = $"'{pt.ParentProcessName}' spawned suspicious child " +
                                    $"'{pt.ProcessName}' (PID {pt.ProcessId}); parent path " +
                                    $"{(parentPathSpoofedOrUnknown ? "UNVERIFIED/spoofed" : "verified")}. " +
                                    $"Command line: {pt.CommandLine ?? "unknown"}",
                Reasoning         = provenance,
                Metadata          = new Dictionary<string, string>
                {
                    { "RuleId",             "SENT-003" },
                    { "ParentProcess",      pt.ParentProcessName },
                    { "ChildProcess",       pt.ProcessName },
                    { "ParentPathVerified", (!parentPathSpoofedOrUnknown).ToString() }
                }
            };
        }
    }
}
