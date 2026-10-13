using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 - Structured MITRE ATT&amp;CK technique mapping for detections.
    /// Rule-name fragments map to technique IDs for explainability and reporting.
    /// Not a substitute for behavioral proof - metadata only.
    /// </summary>
    public static class AttackTechniqueMap
    {
        private static readonly (string Fragment, string[] Techniques)[] Map =
        {
            ("LSASS", new[] { "T1003.001" }),
            ("Credential Dump", new[] { "T1003" }),
            ("Credential Theft", new[] { "T1003" }),
            ("Mimikatz", new[] { "T1003.001", "T1003" }),
            ("SAM hive", new[] { "T1003.002" }),
            ("DCSync", new[] { "T1003.006" }),
            ("Token Theft", new[] { "T1134" }),
            ("Impersonat", new[] { "T1134.001" }),
            ("SeImpersonate", new[] { "T1134.001" }),
            ("Potato", new[] { "T1134.001", "T1068" }),
            ("Reverse Shell", new[] { "T1059", "T1105" }),
            ("Beacon", new[] { "T1071", "T1573" }),
            ("C2", new[] { "T1071" }),
            ("Named Pipe", new[] { "T1559", "T1071" }),
            ("Ransomware", new[] { "T1486", "T1490" }),
            ("Shadow Copy", new[] { "T1490" }),
            ("Process Injection", new[] { "T1055" }),
            ("Unbacked RWX", new[] { "T1055" }),
            ("Hollowing", new[] { "T1055.012" }),
            ("DLL Sideload", new[] { "T1574.002" }),
            ("DLL Injection", new[] { "T1055.001" }),
            ("Scheduled Task", new[] { "T1053.005" }),
            ("WMI Persistence", new[] { "T1546.003" }),
            ("Hostile Event Subscription", new[] { "T1546.003" }),
            ("WMI Policy Rewrite", new[] { "T1112", "T1546.003" }),
            ("WMI-Activity", new[] { "T1047", "T1546.003" }),
            ("Run Key", new[] { "T1547.001" }),
            ("Autorun", new[] { "T1547" }),
            ("Persistence", new[] { "T1547" }),
            ("UAC Bypass", new[] { "T1548.002" }),
            ("Privilege Escalation", new[] { "T1068" }),
            ("BYOVD", new[] { "T1068", "T1562.001" }),
            ("Vulnerable Driver", new[] { "T1068" }),
            ("AMSI", new[] { "T1562.001" }),
            ("ETW", new[] { "T1562.006" }),
            ("Security Evasion", new[] { "T1562" }),
            ("Exfil", new[] { "T1041", "T1048" }),
            ("DNS Tunnel", new[] { "T1071.004", "T1048" }),
            ("DNS Exfil", new[] { "T1071.004" }),
            ("Lateral", new[] { "T1021" }),
            ("WMI", new[] { "T1047" }),
            ("PsExec", new[] { "T1569.002", "T1021.002" }),
            ("RDP", new[] { "T1021.001" }),
            ("PowerShell", new[] { "T1059.001" }),
            ("MSHTA", new[] { "T1218.005" }),
            ("Rundll32", new[] { "T1218.011" }),
            ("LNK", new[] { "T1204.002", "T1547.009" }),
            ("Browser", new[] { "T1555.003", "T1185" }),
            ("CDP", new[] { "T1185" }),
            ("Webcam", new[] { "T1125" }),
            ("Screen Capture", new[] { "T1113" }),
            ("Desktop Duplication", new[] { "T1113" }),
            ("Keystroke", new[] { "T1056.001" }),
            ("Stalkerware", new[] { "T1113", "T1056", "T1547" }),
            ("Surveillance", new[] { "T1113", "T1125" }),
            ("Supply Chain", new[] { "T1195" }),
            ("npm", new[] { "T1195.001" }),
            ("Package", new[] { "T1195" }),
            ("Agentic", new[] { "T1059", "T1106" }),
            ("MCP", new[] { "T1059", "T1106" }),
            ("PPID Spoof", new[] { "T1134.004" }),
            ("Parent PID", new[] { "T1134.004" }),
            ("Unsigned", new[] { "T1036" }),
            ("File Reputation", new[] { "T1204.002" }),
            ("Malicious Binary", new[] { "T1204.002" }),
            ("Weighted Correlation", new[] { "TA0002", "TA0011" }),
            ("Dream Job", new[] { "T1204.002", "T1574.002", "T1068", "T1071" }),
            ("Lazarus", new[] { "T1204.002", "T1068", "T1071" }),
            ("FudModule", new[] { "T1068", "T1562.001" }),
            ("SecurityPDF", new[] { "T1204.002", "T1574.002" }),
            ("MuPDF sideload", new[] { "T1574.002" }),
            ("LegacyHive", new[] { "T1068", "T1574.005" }),
            ("Cloud Files", new[] { "T1562.001", "T1574" }),
            ("KEV unpatched", new[] { "T1190" }),
            ("Kernel Exploit Loader", new[] { "T1068" }),
            ("Installer EoP", new[] { "T1068", "T1548.002" }),
            ("AlwaysInstallElevated", new[] { "T1548.002" }),
            ("Package Manager EoP", new[] { "T1068", "T1195" }),
            ("Mark-of-the-Web", new[] { "T1553.005", "T1204.002" }),
            ("Disk Image in Delivery", new[] { "T1553.005", "T1204.002" }),
            ("ClickFix Encoded", new[] { "T1204", "T1059.001" }),
            ("VS Code Encoded", new[] { "T1059.001", "T1218" }),
            ("Isolation Filter Driver", new[] { "T1068", "T1611" }),
            ("Missed Patch Tuesday", new[] { "T1190" }),
            ("Network UDP", new[] { "T1071", "T1095" }),
            ("Network ICMP", new[] { "T1095", "T1046" }),
            ("Network WFP", new[] { "T1095", "T1562" }),
            ("Unusual IP Protocol", new[] { "T1095" }),
            ("Network VoIP", new[] { "T1071", "T1123" }),
            ("SIP from Unexpected", new[] { "T1071", "T1123" }),
            ("Covert Mesh", new[] { "T1071", "T1095", "T1572" }),
            ("Userspace Overlay", new[] { "T1095", "T1572" }),
            ("DERP Relay", new[] { "T1090", "T1095" }),
            ("Covert Webhook", new[] { "T1041", "T1567.004" }),
            ("Disposable Sink", new[] { "T1041", "T1567" }),
        };

        /// <summary>
        /// Resolve ATT&amp;CK technique IDs for a rule name (ordered, distinct).
        /// </summary>
        public static IReadOnlyList<string> Resolve(string? ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName))
                return Array.Empty<string>();

            var found = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (fragment, techniques) in Map)
            {
                if (ruleName!.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                foreach (var t in techniques)
                {
                    if (seen.Add(t))
                        found.Add(t);
                }
            }

            return found;
        }

        /// <summary>
        /// Attach AttackTechniques + AttackTechniquesCsv to detection metadata.
        /// </summary>
        public static void Enrich(DetectionEvent detection)
        {
            if (detection == null) return;
            detection.Metadata ??= new Dictionary<string, string>();

            var techniques = Resolve(detection.RuleName);
            if (techniques.Count == 0 && detection.SignalType != SignalType.Generic)
                techniques = ResolveFromSignal(detection.SignalType);

            if (techniques.Count == 0) return;

            detection.Metadata["AttackTechniques"] = string.Join(",", techniques);
            detection.Metadata["AttackTechniquesCsv"] = detection.Metadata["AttackTechniques"];
            detection.Metadata["AttackTechniqueCount"] = techniques.Count.ToString();
        }

        private static IReadOnlyList<string> ResolveFromSignal(SignalType signal)
        {
            return signal switch
            {
                SignalType.LsassAccess => new[] { "T1003.001" },
                SignalType.Ransomware => new[] { "T1486" },
                SignalType.ReverseShell => new[] { "T1059" },
                SignalType.NetworkC2 => new[] { "T1071" },
                SignalType.CredentialTheft => new[] { "T1003" },
                SignalType.ProcessInjection => new[] { "T1055" },
                SignalType.AmsiTampering => new[] { "T1562.001" },
                SignalType.EtwTampering => new[] { "T1562.006" },
                SignalType.SecurityEvasion => new[] { "T1562" },
                SignalType.AntiTamper => new[] { "T1562" },
                _ => Array.Empty<string>()
            };
        }
    }
}
