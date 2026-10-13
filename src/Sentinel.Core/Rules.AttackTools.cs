using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.SecurityEvasion)]
    public class AttackToolsRule : IDetectionRule
    {
        public string Name => "AttackToolsRule";

        // Plain tool/LOLBin pattern literals. Split-string Concat was removed: ML AV
        // (Kaspersky, Defender) scores runtime string assembly as evasion, not hygiene.
        private static readonly (string Pattern, string Category)[] ToolSignatures = new[]
        {
            // C2 frameworks. Plaintext: the C# spec folds "co" + "balt" back to "cobalt"
            // in the compiled PE anyway, so source-splitting is cosmetic - and the split
            // PATTERN itself is what ML AV (Kaspersky/Defender) scores as evasion. Plaintext
            // in a signed binary reads as a security product; obfuscation reads as malware.
            ("cobalt", "C2"), ("cobeacon", "C2"), ("beacon.dll", "C2"),
            ("meterpreter", "C2"), ("msfvenom", "C2"), ("msfconsole", "C2"),
            ("sliver", "C2"), ("havoc", "C2"),

            // Credential tools
            ("mimikatz", "CredTool"), ("sekurlsa", "CredTool"), ("kerberos::list", "CredTool"),
            ("lazagne", "CredTool"), ("pypykatz", "CredTool"),
            ("rubeus", "CredTool"), ("asreproast", "CredTool"), ("kerberoast", "CredTool"),

            // AD attack tools
            ("bloodhound", "ADTool"), ("sharphound", "ADTool"),
            ("crackmapexec", "ADTool"), ("impacket", "ADTool"),
            ("psexec", "ADTool"), ("wmiexec", "ADTool"),

            // === LOLBin abuse (behavioral: binary + suspicious arguments) ===
            // Download/execute
            ("certutil -urlcache", "LOLBin:certutil"), ("certutil -decode", "LOLBin:certutil"),
            ("certutil -encode", "LOLBin:certutil"), ("certutil -verifyctl", "LOLBin:certutil"),
            ("bitsadmin /transfer", "LOLBin:bitsadmin"), ("bitsadmin /create", "LOLBin:bitsadmin"),
            ("msiexec /q /i http", "LOLBin:msiexec"), ("msiexec /q /i \\\\", "LOLBin:msiexec"),
            // Script execution via proxy
            ("mshta vbscript", "LOLBin:mshta"), ("mshta javascript", "LOLBin:mshta"),
            ("mshta http", "LOLBin:mshta"), ("mshta \\\\", "LOLBin:mshta"),
            ("regsvr32 /s /n /u /i:", "LOLBin:regsvr32"), ("regsvr32 /s /n /i:", "LOLBin:regsvr32"),
            ("regsvr32 /i:http", "LOLBin:regsvr32"),
            ("rundll32 javascript:", "LOLBin:rundll32"), ("rundll32 vbscript:", "LOLBin:rundll32"),
            ("rundll32.exe shell32.dll,control_rundll", "LOLBin:rundll32"),
            // WMI lateral movement
            ("wmic process call create", "LOLBin:wmic"), ("wmic /node:", "LOLBin:wmic"),
            // MSBuild inline task execution (T1127.001)
            ("msbuild.exe /p:", "LOLBin:msbuild"),
            // InstallUtil bypass (T1218.004)
            ("installutil /logfile= /logtoconsole=false", "LOLBin:installutil"),
            // Compiler abuse (drop & compile on target)
            ("csc.exe /target:library /out:", "LOLBin:csc"),
            // Forfiles proxy execution
            ("forfiles /p c:\\windows", "LOLBin:forfiles"),
            // SyncAppvPublishingServer (PowerShell execution proxy)
            ("syncappvpublishingserver", "LOLBin:syncappv"),
            // PresentationHost (XAML execution)
            ("presentationhost.exe", "LOLBin:presentationhost"),
            // CMSTP INF-based execution
            ("cmstp.exe /s /ns", "LOLBin:cmstp"), ("cmstp.exe /ni", "LOLBin:cmstp"),

            // === LOLScripts (suspicious interpreter usage) ===
            ("powershell -enc", "LOLScript:PowerShell"), ("powershell -e ", "LOLScript:PowerShell"),
            ("powershell -nop -w hidden", "LOLScript:PowerShell"),
            ("powershell -nop -exec bypass", "LOLScript:PowerShell"),
            ("powershell iex(", "LOLScript:PowerShell"), ("powershell iex (", "LOLScript:PowerShell"),
            ("powershell -command \"iex", "LOLScript:PowerShell"),
            ("powershell downloadstring", "LOLScript:PowerShell"),
            ("pwsh -enc", "LOLScript:PowerShell"), ("pwsh -e ", "LOLScript:PowerShell"),
            ("cscript //nologo //e:jscript", "LOLScript:cscript"),
            ("wscript //nologo //e:jscript", "LOLScript:wscript"),
            ("cscript //b //nologo", "LOLScript:cscript"),

            // === LOLLibs (DLL abuse via rundll32 or direct load) ===
            ("comsvcs.dll,minidump", "LOLLib:comsvcs"), ("comsvcs.dll,#24", "LOLLib:comsvcs"),
            ("comsvcs.dll,minitump", "LOLLib:comsvcs"),
            ("dbgcore.dll", "LOLLib:dbgcore"),
            ("pcwutl.dll,launchapplication", "LOLLib:pcwutl"),
            ("advpack.dll,launchinfection", "LOLLib:advpack"),
            ("advpack.dll,registerocx", "LOLLib:advpack"),
            ("zipfldr.dll,routethepackage", "LOLLib:zipfldr"),
            ("url.dll,filereprotocolhandler", "LOLLib:url"),
            ("url.dll,openurl", "LOLLib:url"),
            ("ieadvpack.dll,registerocx", "LOLLib:ieadvpack"),
            ("shdocvw.dll,openurl", "LOLLib:shdocvw"),
            ("shell32.dll,shellexec_rundll", "LOLLib:shell32"),
            // === Chinese APT / Earth Lamia / StrikeShark Toolsets ===
            // Short names require exact filename or word-boundary matching to avoid
            // false positives from substring matches (e.g. "fscan" in "filesystem_scanner")
            ("fscan", "APTTool:fscan"),
            ("kscan", "APTTool:kscan"),
            ("stowaway", "APTTool:stowaway"),
            ("rakshasa", "APTTool:rakshasa"),
            ("supershell", "APTTool:supershell"),
            ("pillager", "APTTool:pillager"),
            ("searchall", "APTTool:searchall"),
            ("ntdsutil", "APTTool:ntdsutil"),
            ("ntds.dit", "APTTool:ntds.dit"),

            // === Exfiltration endpoints ===
            ("pastebin.com/raw", "Exfil:Pastebin"),
            ("discord.com/api/webhooks", "Exfil:Discord"),
            ("discordapp.com/api/webhooks", "Exfil:Discord"),
            ("api.telegram.org/bot", "Exfil:Telegram"),
            ("hooks.slack.com", "Exfil:Slack"),
            ("webhook.site", "Exfil:WebhookSink"),
            ("interact.sh", "Exfil:WebhookSink"),
            (".onion.", "Exfil:Tor"),
            ("tor2web", "Exfil:Tor"),
        };

        /// <summary>
        /// Checks if a pattern appears in the text at a word boundary (preceded/followed by
        /// non-alphanumeric characters or string start/end). Prevents substring false positives
        /// where e.g. "fscan" matches inside "filesystem_scanner.exe".
        /// </summary>
        private static bool HasWordBoundaryMatch(string text, string pattern)
        {
            int idx = -1;
            while ((idx = text.IndexOf(pattern, idx + 1)) >= 0)
            {
                bool leftBound = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
                int endIdx = idx + pattern.Length;
                bool rightBound = endIdx >= text.Length || !char.IsLetterOrDigit(text[endIdx]);
                if (leftBound && rightBound) return true;
            }
            return false;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
                var image = pt.ImagePath;

                // Custom check for symlink/junction abuse targeting system folders (BlueHammer, etc.)
                if ((cmd.Contains("mklink") || 
                     cmd.Contains("junction")) &&
                    (cmd.Contains(@"\system32\config") ||
                     cmd.Contains(@"\windows defender") ||
                     cmd.Contains(@"\config\system") ||
                     cmd.Contains(@"\config\sam") ||
                     cmd.Contains(@"\config\security")))
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.SuspiciousProcess,
                        Confidence = 0.98,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Junction LPE attempt detected: '{cmd}'",
                        Reasoning = "Process attempted to create an NTFS directory junction or symlink targeting sensitive Windows configuration or Defender update directories. " +
                                    "This is a signature pattern of local privilege escalation exploits like BlueHammer."
                    };
                }

                foreach (var (pattern, category) in ToolSignatures)
                {
                    if (cmd.Contains(pattern) ||
                        image.Contains(pattern))
                    {
                        // For short APT tool names, require word-boundary or filename-exact match
                        // to avoid false positives from substring matches
                        if (category.StartsWith("APTTool:"))
                        {
                            var fileName = Path.GetFileNameWithoutExtension(pt.ImagePath).ToLowerInvariant();
                            bool isExactFilename = fileName.Equals(pattern);
                            // Check for word boundary in command line: pattern preceded/followed by non-alphanumeric
                            bool hasWordBoundary = HasWordBoundaryMatch(cmd, pattern);
                            if (!isExactFilename && !hasWordBoundary)
                                continue; // Substring match without boundary - skip
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = category.Equals("C2") ? SignalType.NetworkC2 : SignalType.SuspiciousProcess,
                            // Only C2-category tool hits are a terminal C2Beacon; other tool
                            // categories (CredTool/ADTool/LOLBin) are not tagged terminal here
                            // and continue to classify via the existing substring path.
                            Family = category.Equals("C2") ? TerminalFamily.C2Beacon : (TerminalFamily?)null,
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Attack tool detected: {category} (pattern: '{pattern}') in {pt.ProcessName} (PID {pt.ProcessId})",
                            Reasoning = $"Process command line or image path matches a known offensive security tool ({category}). Kill authorized."
                        };
                    }
                }
            }
            return null;
        }
    }

}
