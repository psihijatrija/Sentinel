using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// Global response posture: every monitor is observe-only until a multi-signal chain
    /// points at a real terminal attack. Kill-grade Tier1 is reserved for high-confidence
    /// token theft, credential dump, reverse shell, or C2 beaconing (or multi-signal composites
    /// that prove those). DLL unload remediations are exempt and may act immediately.
    /// </summary>
    public static class ResponsePolicy
    {
        /// <summary>Metadata key set when a detection is authorized for full destructive response.</summary>
        public const string ChainConfirmedKey = "ChainConfirmed";

        /// <summary>Metadata key: which terminal outcome family authorized the nuke.</summary>
        public const string TerminalOutcomeKey = "TerminalOutcome";

        /// <summary>
        /// The only single-signal families that may carry Tier1 (kill-grade) labels.
        /// Everything else is Tier2 observe fuel for correlation / composites.
        /// v2.6: derived from the typed <see cref="TerminalFamily"/> taxonomy so a
        /// mistyped string literal can no longer silently drop a family from kill-grade.
        /// </summary>
        public static readonly HashSet<string> KillGradeTerminalFamilies =
            new(TerminalFamilies.KillGradeCanonicalStrings(), StringComparer.OrdinalIgnoreCase);

        /// <summary>Minimum confidence for a kill-grade family to stay Tier1 (default 0.85).</summary>
        public const double DefaultMinTier1Confidence = 0.85;

        private static readonly ConcurrentDictionary<int, PidSignalBuffer> PidBuffers = new();

        // v2.6.0: Cross-PID ancestry buffer - catches staged attacks that spawn a fresh
        // process per malicious action so each PID starts at zero per-PID signals.
        // Keyed by the non-system root ancestor PID; all children sharing that root
        // contribute to the same buffer.  System/browser/IDE hosts are excluded as roots
        // to avoid cross-contamination between unrelated processes under explorer.exe.
        private static readonly ConcurrentDictionary<int, PidSignalBuffer> RootBuffers = new();

        /// <summary>
        /// Injected once at service start-up by the DI container.
        /// Static so RegisterAndEvaluateChain (also static) can read ancestry without
        /// a per-call parameter change that would touch every call-site.
        /// </summary>
        private static ProcessAncestryCache? _ancestryCache;

        public static void SetAncestryCache(ProcessAncestryCache? cache) => _ancestryCache = cache;

        /// <summary>
        /// Resolves the authoritative image path for a PID from the ancestry cache
        /// (captured at process-start from ETW/WMI, retained 60s after exit). Returns null
        /// when the cache is unwired or has no record. This is a NON-attacker-controllable
        /// anchor: unlike a command line, a process cannot forge the image path the OS
        /// recorded for it at creation. Used by trust-anchor rules that must verify a
        /// parent binary really lives in a legitimate install location.
        /// </summary>
        public static string? ResolveImagePathForPid(int pid)
        {
            if (pid <= 0) return null;
            var cache = _ancestryCache;
            if (cache == null) return null;
            try
            {
                var (_, _, imagePath) = cache.GetProcessInfo(pid);
                return string.IsNullOrEmpty(imagePath) ? null : imagePath;
            }
            catch { return null; }
        }

        /// <summary>
        /// Excluded ancestry root names.  Processes with these names are so widely shared
        /// that keying a root buffer on them would cross-contaminate unrelated processes.
        /// </summary>
        private static readonly HashSet<string> ExcludedAncestryRoots = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass",
            "winlogon", "explorer", "svchost", "dwm", "sihost",
        };

        private static readonly string[] DllUnloadRuleFragments =
        {
            "DLL Sideloading",
            "DLL Injection",
            "DllUnload",
            "DLL Unload",
            "FreeLibrary",
            "Sideload",
            "Injected Module",
            "Hostile Module",
            "Proven Load",
            "Foreign Module Unloaded",
            "Foreign Module Remediated",
        };

        /// <summary>
        /// Terminal attack families that authorize chain-confirmed nuke.
        /// Normal software (Steam DirectX/redist System32 writes, GPU drivers, installers) is NOT here.
        /// </summary>
        private static readonly (string Outcome, string[] Fragments)[] TerminalOutcomes =
        {
            ("BYOVD", new[]
            {
                "BYOVD", "Vulnerable Driver", "kdmapper", "DBUtil",
                "RTCore", "AsIO.sys", "AsIO64", "AsIO2", "WinRing0", "capcom.sys", "gdrv.sys", "iqvw64e",
                "Vulnerable Kernel", "Bring Your Own",
                "NSecKrnl", "ensrvr64", "encase", "PoisonX",
            }),
            ("CredentialDump", new[]
            {
                "LSASS", "Credential Dump", "Credential Theft", "Mimikatz", "sekurlsa",
                "procdump", "comsvcs", "MiniDump", "DumpCred", "SAM hive", "SECURITY hive",
                "ntds.dit", "DCSync", "secretsdump", "Credential Canary",
            }),
            ("TokenTheft", new[]
            {
                "Token Theft", "Token Stealing", "SYSTEM Token", "Impersonat",
                "SeImpersonate", "DuplicateToken", "MakeToken", "GodPotato", "PrintSpoofer",
                "Potato", "JuicyPotato", "RoguePotato", "SharpEfsPotato",
                "FudModule", "LegacyHive",
                "Kernel Exploit Loader", "Installer EoP", "AlwaysInstallElevated",
                "LPE Scaffold: Privilege Escalation Tool",
            }),
            ("ReverseShell", new[]
            {
                "Reverse Shell", "Bind Shell", "Interactive Shell", "pty.spawn",
                "socket.dup", "nc -e", "ncat", "revshell", "meterpreter",
                "ClickFix Encoded",
            }),
            ("Exfil", new[]
            {
                "Exfil", "Exfiltration", "Data Staging", "Cloud Sync Exfil",
                "Bulk Upload", "Outbound Transfer", "WorkFolders Exfil",
                "AppDnsExfil", "DNS Tunnel", "DNS Exfil",
            }),
            ("C2Beacon", new[]
            {
                "C2 Beacon", "C2 Beaconing", "Beaconing", "Beacon Detector",
                "Command-and-Control", "Command and Control", "NetworkC2",
                "Injected C2", "Confirmed C2", "Covert C2", "C2 Channel",
                "Periodic Callback", "Statistical Beacon",
                "Lazarus Dream Job", "Dream Job: C2",
                "Covert Mesh", "Covert Webhook",
                "Classic Malware Port",
                "Named Pipe: Known C2",
                "Tunneling Tool Detected",
            }),
            // v2.5.3 - attributed AMSI/ETW patch, Hell's Gate, unmapped thread (the 10)
            ("Evasion", new[]
            {
                "AMSI Bypass Detected",
                "Indirect Syscall",
                "Hell's Gate",
                "Unmapped Thread Start Address",
                "ETW/Event Log Manipulation",
            }),
            ("Injection", new[]
            {
                "ThreatIntelInjectionRule",
                "Remote Memory Injection",
                "ALLOCVM_REMOTE",
            }),
            // v2.2.8 - executable WMI consumers / policy rewrite via provider host
            ("WmiPersistence", new[]
            {
                "Hostile Event Subscription",
                "CommandLineEventConsumer",
                "ActiveScriptEventConsumer",
                "FilterToConsumerBinding",
                "WMI Policy Rewrite",
                "WMI-Activity: Permanent",
                "WMI Persistence + Policy Rewrite",
            }),
        };

        /// <summary>
        /// System-directory write rules that are almost always installer/redist life
        /// (Steam DirectX, GPU runtimes). Logged as Tier2 observe; never chain-seed.
        /// </summary>
        private static readonly string[] BenignNoiseRuleFragments =
        {
            "Unauthorized Write to System Directory",
            "System Integrity: Unauthorized Write",
            "Write to System Directory",
        };

        /// <summary>
        /// Pure UX / ambient noise - excluded from BOTH chain buffer and multi-signal composites.
        /// (Cast observe, module-count growth, screen capture, BitLocker status, whitelist noise, ...)
        /// </summary>
        private static readonly string[] PureUxObserveRuleFragments =
        {
            "Cast Device Guard",
            "Module Count Growth",
            "NeuroBehavior",
            "Visual Anomaly",
            "Cursor:",
            "Takeover Movement",
            "Hardware Security: BitLocker",
            "Self-Protection: Unexpected Module",
            "Outbound Whitelist",
            "Connection to Non-Whitelisted",
            "Network Policy: Unusual Destination",
            "Attack Tool: Connection from Suspicious Path",
            "Traffic Anomaly: Upload Volume",
            "Traffic Anomaly: Outbound Volume Spike",
            "Traffic Anomaly: Bulk Transfer",
            "Privacy:",
            "Network: New Local TCP Listener",
            "Network Share: Inbound SMB",
            "Browser Extension: New Extension",
            "Boot Integrity: BCD",
            "Boot Integrity: New Boot Driver",
            "Firewall Integrity: Bulk Rule",
            "Anti-Tamper: IPSec Policy Deleted",
            "Anti-Tamper: Hosts File Modification",
            "C2 Pairing: Failover",
        };

        /// <summary>
        /// Weak attack-adjacent heuristics - may still feed composites, but never alone complete
        /// a ResponsePolicy PID chain nuke (need a real high-confidence terminal leg).
        /// Includes surveillance legs (screen/webcam) so stalkerware composites can fire (v1.9.4).
        /// </summary>
        private static readonly string[] WeakChainOnlyRuleFragments =
        {
            "PPID Spoofing",
            "Parent PID Mismatch",
            "Ephemeral Process",
            "Self-Deleting",
            "Privilege Escalation: Elevated Process from User Path",
            "Persistence: New Scheduled Task",
            "Token Theft: SeImpersonatePrivilege",
            "Named Pipe: High-Entropy Name",
            // v2.1.2: browse/play heuristics - observe fuel only, never a chain seed
            "Suspicious Outbound Connection",
            "Application-Level DoH",
            "DNS Bypass:",
            "C2 Pairing: Defensive Process Spawn",
            "Image File Missing",
            "Clickjacking",
            "Junction/Symlink",
            // v2.5.3: LPE named tools, kernel EoP loader, ClickFix, unmapped thread,
            // classic malware ports, Known-C2 pipes are kill-grade. High-entropy
            // pipes, MOTW/disk-image/VSIX delivery, DoH, SSH-from-shell stay weak.
            "CVE Class: PE Missing Mark-of-the-Web",
            "CVE Class: Disk Image in Delivery",
            "CVE Class: AppInstaller Package",
            "CVE Class: VSIX in Delivery",
            "CVE Class: RDP File in Delivery",
            "CVE Class: Package Manager EoP",
            "CVE Class: VS Code Encoded",
            "Patch Posture: Missed Patch Tuesday",
            // v2.4.8: ambient protocol noise - never a chain seed
            "Network UDP:",
            "Network ICMP:",
            "Network WFP:",
            "Network VoIP:",
            // DNS lookups with no PID stay observe (PID 0). Process-attributed
            // Covert Mesh / Covert Webhook are kill-grade C2 as of v2.5.2.
            // Surveillance: composite fuel for coercion toolkit; never sole chain seed
            "Screen Capture",
            "DXGI Desktop Duplication",
            "Desktop Duplication",
            "Webcam",
        };

        /// <summary>
        /// Secondary weak rules that are benign ONLY when the process/path is a known
        /// DirectX / VC++ / installer redistributable (not for arbitrary processes).
        /// </summary>
        private static readonly string[] InstallerContextWeakRuleFragments =
        {
            "Ephemeral Process",
            "Self-Deleting",
            "Parent PID Spoof",
            "PPID Spoof",
            "Unsigned Binary in Temp",
            "High Entropy",
        };

        /// <summary>
        /// Composites that already encode multi-signal proof toward a terminal outcome.
        /// </summary>
        private static readonly string[] NukeCompositeFragments =
        {
            "Credential Dump + Exfiltration",
            "Token Theft + Lateral Movement",
            "Injected C2 Beacon",
            "In-Memory Implant Active",
            "Fileless Attack Chain",
            "Named Pipe C2 + Network Beaconing",
            "Spoofed Process Phoning Home",
            "Escalation + C2 Channel",
            "Active Mass-Encryption Chain",
            "Covert RAT",
            "Confirmed C2 Beacon",
            "Covert C2",
            "Dropped Payload Active",
            "DGA + C2 Beaconing",
            // v1.9.4 - digital coercion / stalkerware / remote-control abuse (platform-agnostic)
            "Covert Surveillance + Remote Channel",
            "Remote Control Abuse Toolkit",
            "Session Theft + Abuse Channel",
            "Stalkerware Persistence Chain",
            // v2.0 - explainable weighted multi-signal composite
            "Weighted Correlation",
            "Multi-Signal Threat",
            // v2.0 - signed disk rule packs
            "Rule Pack:",
            "[COMPOSITE]",
            // v2.2.4 - generic CVE-class chains
            "Kernel Exploit Loader Chain",
            "Installer / Package Manager EoP Chain",
            "MOTW Bypass Execution Chain",
            "VS Code Workspace Abuse Chain",
            "WMI Persistence + Policy Rewrite",
        };

        public static bool IsDllUnloadExempt(DetectionEvent? detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            foreach (var f in DllUnloadRuleFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true;
            }

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("DllUnloadExempt", out var flag) &&
                string.Equals(flag, "true"))
                return true;

            return false;
        }

        /// <summary>
        /// Standing product law: system-wide module identity unload already remediates
        /// in <c>DllUnloadEngine</c>. The detection must remain Tier1 forever - never
        /// demoted by observe-until-chain or kill-grade filtering.
        /// </summary>
        public static bool IsPermanentModuleIdentityUnload(DetectionEvent? detection)
        {
            if (detection == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("PermanentRule", out var flag) &&
                string.Equals(flag, "ModuleIdentityUnload", StringComparison.OrdinalIgnoreCase))
                return true;

            var r = detection.RuleName ?? "";
            return r.IndexOf("Foreign Module Unloaded", StringComparison.OrdinalIgnoreCase) >= 0
                   || r.IndexOf("Foreign Module Remediated", StringComparison.OrdinalIgnoreCase) >= 0
                   || r.IndexOf("Hijack-Name Plant Quarantined", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Standing tier law: Tier1 only when the act is kill-grade and confident enough -
        /// token theft, credential dump, reverse shell, C2 beaconing - or a multi-signal
        /// composite / chain-confirmed detection that proves one of those.
        /// All other signals become Tier2 + LogOnly (still feed correlation).
        /// Module-identity unload remediations are a permanent Tier1 exception (already acted;
        /// do not promote to kill). Other DLL-unload-exempt observe plants stay observe-only.
        /// </summary>
        public static void ApplyTierLaw(DetectionEvent detection, double minConfidence = DefaultMinTier1Confidence)
        {
            if (detection == null) return;

            detection.Metadata ??= new Dictionary<string, string>();

            // v2.3.1 ALWAYS-ON: DLL Unload policy - never demote, never gate.
            // Checks both the legacy IsPermanentModuleIdentityUnload and the new
            // AlwaysOnPolicies.IsDllUnloadAlwaysOn (which also reads metadata markers).
            if (IsPermanentModuleIdentityUnload(detection) || AlwaysOnPolicies.IsDllUnloadAlwaysOn(detection))
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                detection.Metadata["TierLaw"] = "ModuleIdentityUnload";
                detection.Metadata["PermanentRule"] = "ModuleIdentityUnload";
                detection.Metadata["AlwaysOnPolicy"] = "DllUnload";
                return;
            }

            // Multi-signal composites already encode independent proof -> keep Tier1 kill intent.
            if (IsNukeComposite(detection))
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                // v2.6.0: A network-tamper composite authors the non-kill VPN-shield remediation
                // (SYSTEM/PID 0 origin, no process to terminate). Do NOT rewrite it into a
                // process nuke - preserve the author action so the response engine can raise the
                // protective tunnel instead of quarantine-and-kill.
                if (detection.AuthorizedResponse != ResponseAction.VpnShieldUp &&
                    detection.AuthorizedResponse < ResponseAction.KillProcessTree)
                    detection.AuthorizedResponse = ResponseAction.QuarantineAndKill;
                detection.Metadata["TierLaw"] = "Composite";
                return;
            }

            // Already chain-confirmed (correlation path) -> Tier1.
            if (detection.Metadata.TryGetValue(ChainConfirmedKey, out var chain) &&
                string.Equals(chain, "true"))
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                detection.Metadata["TierLaw"] = "ChainConfirmed";
                return;
            }

            // Benign installer / DirectX / System32 redist noise is never Tier1.
            if (IsBenignInstallerNoise(detection))
            {
                DemoteToObserve(detection, "BenignInstallerNoise");
                return;
            }

            var outcome = ClassifyTerminalOutcome(detection);
            bool killGrade = outcome != null && KillGradeTerminalFamilies.Contains(outcome);
            double conf = detection.Confidence;
            if (conf <= 0 && detection.Metadata.TryGetValue("ThreatScore", out var scoreStr) &&
                double.TryParse(scoreStr, out var score))
            {
                // ScoringEngine uses 0-100; map roughly to 0-1 when Confidence unset.
                conf = score > 1.0 ? score / 100.0 : score;
            }

            if (killGrade && conf >= minConfidence)
            {
                detection.Tier = DetectionTier.Tier1Behavioral;
                detection.Metadata["TierLaw"] = outcome!;
                detection.Metadata[TerminalOutcomeKey] = outcome!;
                // Recommended action may be kill-grade; ObserveUntilChain still gates execution
                // until a second independent signal / composite confirms.
                return;
            }

            // Weak / non-terminal / low-confidence -> observe only. Still logs + correlates.
            DemoteToObserve(detection, killGrade ? "LowConfidenceTerminal" : "NonKillGrade");
        }

        private static void DemoteToObserve(DetectionEvent detection, string reason)
        {
            detection.Tier = DetectionTier.Tier2Indicator;
            if (detection.AuthorizedResponse >= ResponseAction.NetworkIsolate)
                detection.AuthorizedResponse = ResponseAction.LogOnly;
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata["TierLaw"] = reason;
            detection.Metadata["ObserveOnly"] = "true";
        }

        public static bool IsKillGradeTerminal(DetectionEvent detection)
        {
            var outcome = ClassifyTerminalOutcome(detection);
            return outcome != null && KillGradeTerminalFamilies.Contains(outcome);
        }

        /// <summary>
        /// Weak observe heuristics that must never classify as terminal or fill the chain buffer.
        /// Pure UX noise is also excluded from multi-signal composites.
        /// </summary>
        public static bool IsWeakObserveSeed(DetectionEvent? detection)
        {
            if (detection == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("WeakObserveSeed", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return true;

            // Explicit observe-only Cast mode must never be NetworkC2 terminal fuel.
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("Mode", out var mode) &&
                string.Equals(mode, "observe-only", StringComparison.OrdinalIgnoreCase) &&
                (detection.RuleName?.IndexOf("Cast Device Guard", StringComparison.OrdinalIgnoreCase) ?? -1) >= 0)
                return true;

            var r = detection.RuleName ?? "";
            foreach (var f in PureUxObserveRuleFragments)
            {
                if (r.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            foreach (var f in WeakChainOnlyRuleFragments)
            {
                if (r.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Pure UX / ambient noise only - excluded from multi-signal composites.
        /// Attack-adjacent weak signals (SeImpersonate, PPID, ...) still feed composites.
        /// </summary>
        public static bool IsPureUxObserveNoise(DetectionEvent? detection)
        {
            if (detection == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("WeakObserveSeed", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return true;

            var r = detection.RuleName ?? "";
            foreach (var f in PureUxObserveRuleFragments)
            {
                if (r.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Classify terminal outcome family from rule/evidence/signal type, or null if not terminal.
        /// </summary>
        public static string? ClassifyTerminalOutcome(DetectionEvent detection)
        {
            if (detection == null) return null;

            // Installer / DirectX / GPU redistributable noise is never terminal.
            if (IsBenignInstallerNoise(detection))
                return null;

            // Weak observe seeds never become terminal families (even if mis-tagged NetworkC2).
            if (IsWeakObserveSeed(detection))
                return null;

            // v2.6: An explicitly-declared typed family is authoritative - a migrated monitor
            // stated its outcome directly, so we don't guess from substrings. This is checked
            // AFTER the benign-noise / weak-seed safety demotions above (those always win) but
            // BEFORE the SignalType switch and rule-name matching below.
            if (detection.Family.HasValue)
                return detection.Family.Value.ToCanonicalString();

            switch (detection.SignalType)
            {
                case SignalType.LsassAccess:
                case SignalType.CredentialTheft:
                    return TerminalFamily.CredentialDump.ToCanonicalString();
                case SignalType.ReverseShell:
                    return TerminalFamily.ReverseShell.ToCanonicalString();
                case SignalType.NetworkC2:
                    return TerminalFamily.C2Beacon.ToCanonicalString();
            }

            var haystack = string.Join(" ",
                detection.RuleName ?? "",
                detection.Evidence ?? "",
                detection.Reasoning ?? "");

            foreach (var (outcome, fragments) in TerminalOutcomes)
            {
                foreach (var f in fragments)
                {
                    if (haystack.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
                        return outcome;
                }
            }

            return null;
        }

        /// <summary>
        /// v2.6: Typed classification of a detection into its <see cref="TerminalFamily"/>,
        /// or null if the detection is not terminal. This is the typed counterpart to
        /// <see cref="ClassifyTerminalOutcome"/> and is implemented directly in terms of it,
        /// so the two can never disagree. Prefer this in new code; the string method remains
        /// for the existing metadata/evidence contracts.
        /// </summary>
        public static TerminalFamily? ClassifyTerminalFamily(DetectionEvent detection)
            => TerminalFamilies.FromCanonicalString(ClassifyTerminalOutcome(detection));

        public static bool IsBenignInstallerNoise(DetectionEvent detection)
        {
            if (detection == null) return false;

            // Explicit metadata from monitors (FileActivityMonitor DirectX path, etc.)
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("BenignInstallerNoise", out var flag) &&
                string.Equals(flag, "true"))
                return true;

            string? imagePath = null;
            string? filePath = null;
            if (detection.Metadata != null)
            {
                detection.Metadata.TryGetValue("ImagePath", out imagePath);
                detection.Metadata.TryGetValue("FilePath", out filePath);
            }

            // Any signal from a DirectX/redist process is observe-only noise (never Tier1/composite).
            if (InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, imagePath) ||
                InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, filePath))
                return true;

            var r = detection.RuleName ?? "";
            foreach (var f in BenignNoiseRuleFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true; // System32 integrity writes are never kill-grade alone
            }

            // Weak secondary rules only when process is installer/redist context.
            bool installerContext =
                InstallerHeuristics.IsInstallerExtractor(detection.ProcessName, imagePath) ||
                InstallerHeuristics.LooksLikeInstallerName(detection.ProcessName, imagePath);
            if (installerContext)
            {
                foreach (var f in InstallerContextWeakRuleFragments)
                {
                    if (r.IndexOf(f) >= 0)
                        return true;
                }
            }

            // System32/SysWOW64 writes of GPU/DirectX/runtime names = Steam/driver redist race.
            var path = filePath ?? (detection.Evidence ?? "");
            if (path.IndexOf(@"\System32\") >= 0 ||
                path.IndexOf(@"\SysWOW64\") >= 0)
            {
                if (InstallerHeuristics.IsDirectXOrRuntimeRedist(detection.ProcessName, path))
                    return true;

                string[] redistHints =
                {
                    "vulkan", "nvcuda", "nvEncode", "nvapi", "d3d", "dxgi", "xinput",
                    "xaudio", "d3dx", "D3DCompiler", "vcomp", "vcruntime", "msvcp",
                    "ucrtbase", "api-ms-win", "openal", "physx", "x3daudio", "xact",
                    "xapofx", "dsetup", "dxsetup",
                };
                foreach (var h in redistHints)
                {
                    if (path.IndexOf(h) >= 0)
                        return true;
                }

                // Unattributed System32 PE write (PID <= 4) during redist races - never kill-grade.
                if (detection.ProcessId <= 4 &&
                    (r.IndexOf("System Directory") >= 0 ||
                     r.IndexOf("Unauthorized Write") >= 0))
                    return true;
            }

            // Low-confidence System32 write signals are observe fuel only - not composite legs.
            if (detection.Confidence > 0 && detection.Confidence < 0.70 &&
                (r.IndexOf("Unauthorized Write") >= 0 ||
                 r.IndexOf("System Directory") >= 0))
                return true;

            return false;
        }

        /// <summary>
        /// True when this signal must not count toward multi-signal composites.
        /// DirectX / pure UX observe noise never satisfy composite legs. Attack-adjacent weak
        /// seeds (SeImpersonate, PPID, ...) still feed composites but not ResponsePolicy chain nukes.
        /// </summary>
        public static bool IsNonCorrelatingObserveNoise(DetectionEvent detection)
            => detection == null || IsBenignInstallerNoise(detection) || IsPureUxObserveNoise(detection);

        /// <summary>
        /// Tailcat / userspace WG overlay / webhook-sink stealers attributed to a
        /// real PID. Not Discord.exe, not Chrome, not official Tailscale - those
        /// never emit these rule names. Solo chain-confirm when confidence is kill-grade.
        /// </summary>
        public static bool IsCovertChannelTerminal(DetectionEvent? detection)
        {
            if (detection == null || detection.ProcessId <= 4)
                return false;
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("WeakObserveSeed", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return false;

            var r = detection.RuleName ?? "";
            return r.StartsWith("Covert Mesh:", StringComparison.OrdinalIgnoreCase)
                || r.StartsWith("Covert Webhook:", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// v2.5.3: the 10 - attributed attack-class rules that are the act, not
        /// ambient noise. Discord/Chrome/games/official Tailscale never emit these.
        /// PID <= 4 stays observe. High-entropy pipes, SSH-from-shell, DoH, MOTW
        /// delivery, SeImpersonate-alone, TeamViewer presence are not this list.
        /// </summary>
        public static bool IsAttackClassTerminal(DetectionEvent? detection)
        {
            if (detection == null || detection.ProcessId <= 4)
                return false;
            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("WeakObserveSeed", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return false;

            if (IsCovertChannelTerminal(detection))
                return true;

            var r = detection.RuleName ?? "";
            return r.StartsWith("LPE Scaffold: Privilege Escalation Tool", StringComparison.OrdinalIgnoreCase)
                || r.StartsWith("CVE Class: Kernel Exploit Loader", StringComparison.OrdinalIgnoreCase)
                || r.StartsWith("CVE Class: ClickFix Encoded", StringComparison.OrdinalIgnoreCase)
                || r.IndexOf("Unmapped Thread Start Address", StringComparison.OrdinalIgnoreCase) >= 0
                || r.IndexOf("Network Indicator: Classic Malware Port", StringComparison.OrdinalIgnoreCase) >= 0
                || r.StartsWith("Named Pipe: Known C2", StringComparison.OrdinalIgnoreCase)
                || r.StartsWith("Remote Access: Tunneling Tool", StringComparison.OrdinalIgnoreCase)
                || r.IndexOf("Indirect Syscall", StringComparison.OrdinalIgnoreCase) >= 0
                || r.IndexOf("Hell's Gate", StringComparison.OrdinalIgnoreCase) >= 0
                || r.IndexOf("AMSI Bypass Detected", StringComparison.OrdinalIgnoreCase) >= 0
                || r.IndexOf("ETW/Event Log Manipulation", StringComparison.OrdinalIgnoreCase) >= 0
                || r.Equals("ThreatIntelInjectionRule", StringComparison.OrdinalIgnoreCase)
                || r.IndexOf("Remote Memory Injection", StringComparison.OrdinalIgnoreCase) >= 0
                || r.IndexOf("ALLOCVM_REMOTE", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsNukeComposite(DetectionEvent detection)
        {
            if (detection == null) return false;
            var r = detection.RuleName ?? "";
            var e = detection.Evidence ?? "";
            if (e.IndexOf("[COMPOSITE]") >= 0)
                return true;
            foreach (var f in NukeCompositeFragments)
            {
                if (r.IndexOf(f) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Record this detection for PID-level multi-signal correlation.
        /// Returns true when enough distinct rules accumulate AND at least one is a terminal outcome
        /// (or a nuke composite already fired).
        /// </summary>
        public static bool RegisterAndEvaluateChain(DetectionEvent detection, SentinelConfig config)
        {
            if (detection == null || config == null) return false;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue(ChainConfirmedKey, out var already) &&
                string.Equals(already, "true", StringComparison.OrdinalIgnoreCase))
            {
                PromoteChainConfirmedFields(detection);
                return true;
            }

            if (IsBenignInstallerNoise(detection))
                return false;

            // Weak observe seeds never fill the chain buffer (Cast, module growth, UX noise, ...).
            if (IsWeakObserveSeed(detection))
                return false;

            if (IsNukeComposite(detection))
            {
                TagChainConfirmed(detection, "Composite");
                return true;
            }

            int pid = detection.ProcessId;
            if (pid <= 4)
            {
                // No reliable process attribution - never authorize host mutation from PID 0 noise
                // (this is exactly how Steam DirectX / dxsetup races look).
                return false;
            }

            // v2.5.2/2.5.3: the 10 (mesh, webhook, potato, kernel EoP loader,
            // ClickFix, Hell's Gate, unmapped thread, CS pipes, classic RAT
            // ports, ngrok/chisel, impostor AMSI) ARE the attack. Civilians
            // stay skipped in the monitors. One high-confidence hit is enough.
            if (IsAttackClassTerminal(detection) &&
                detection.Confidence >= (config.MinTier1Confidence > 0
                    ? config.MinTier1Confidence
                    : DefaultMinTier1Confidence))
            {
                TagChainConfirmed(detection, ClassifyTerminalOutcome(detection) ?? "C2Beacon");
                return true;
            }

            int minSignals = Math.Max(2, config.ChainConfirmMinSignals);
            int windowSec = Math.Max(30, config.ChainConfirmWindowSeconds);
            double minTerminalConf = config.MinTier1Confidence > 0
                ? config.MinTier1Confidence
                : DefaultMinTier1Confidence;
            var window = TimeSpan.FromSeconds(windowSec);

            // v2.0.3: lazy sweep to evict stale PID buffers (prevents recycled-PID false chains)
            TryLazySweep(windowSec);

            var signalEntry = BuildSignalEntry(detection, minTerminalConf);

            //  Per-PID buffer (original path) 
            if (EvaluateBuffer(PidBuffers, pid, signalEntry, window, minSignals, minTerminalConf,
                    detection, out var pidOutcome))
            {
                TagChainConfirmed(detection, pidOutcome!);
                return true;
            }

            //  v2.6.0: Cross-PID ancestry buffer 
            // Catches staged attacks that spawn a fresh process per malicious action.
            // Each fresh child PID starts at zero in the per-PID buffer, but all children
            // that share a non-system root ancestor accumulate in the root buffer.
            // Example: loader.exe (pid=100) spawns stage1.exe (pid=200) then stage2.exe
            // (pid=201). Each child's signals land in loader.exe's root buffer; when the
            // buffer hits minSignals + terminal, the CURRENT detection is chain-confirmed.
            int rootPid = GetAttackRootPid(pid);
            if (rootPid > 4 && rootPid != pid)
            {
                if (EvaluateBuffer(RootBuffers, rootPid, signalEntry, window, minSignals, minTerminalConf,
                        detection, out var rootOutcome))
                {
                    TagChainConfirmed(detection, rootOutcome!);
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// When ObserveUntilChain is on: may we take kill/quarantine/isolate/host mutation?
        /// DLL unload path is always allowed (callers still use DllUnloadEngine).
        /// </summary>
        public static bool MayPerformDestructiveResponse(DetectionEvent detection, SentinelConfig config)
        {
            if (config == null || !config.ActiveResponse)
                return false;

            if (!config.ObserveUntilChain)
                return true;

            if (IsDllUnloadExempt(detection))
                return true;

            return RegisterAndEvaluateChain(detection, config);
        }

        /// <summary>
        /// Inline monitor host mutations (hosts rewrite, SUBST kill, USB disable, cuckoo restore)
        /// when ObserveUntilChain is on - never, unless a detection is already chain-confirmed.
        /// Prefer routing through DetectionEngine so chain logic applies.
        /// </summary>
        public static bool MayPerformInlineHostMutation(SentinelConfig config, DetectionEvent? chainContext = null)
        {
            if (config == null || !config.ActiveResponse)
                return false;

            if (!config.ObserveUntilChain)
                return true;

            if (chainContext != null && MayPerformDestructiveResponse(chainContext, config))
                return true;

            // MitmDefense does not unlock USB / admin / registry / volume mutations.
            // Those callers must use AllowsMitmDefenseMutations / IsMitmDefenseAction.
            return false;
        }

        /// <summary>
        /// True when a detection is part of the MITM suite and MitmDefense is enabled
        /// (cert remove / cast block / FCM). Used by AdvancedResponseEngine to act under
        /// ObserveUntilChain without requiring a multi-signal kill chain.
        /// </summary>
        public static bool IsMitmDefenseAction(DetectionEvent detection, SentinelConfig config)
        {
            if (detection == null || config == null)
                return false;

            // v2.6.0: The protective VPN-shield remediation is a network-integrity action in the
            // same MITM family, but gated on its OWN posture switch (VpnShield.Enabled), NOT on
            // MitmDefense.Enabled. Check it before the MitmDefense gate so enabling VpnShield
            // alone is sufficient to exempt it from the multi-signal chain gate. Still non-kill;
            // the response engine Tier1-guards it and re-checks ProductPosture.AllowsVpnShield.
            if (detection.AuthorizedResponse == ResponseAction.VpnShieldUp)
                return ProductPosture.AllowsVpnShield(config);

            if (!ProductPosture.AllowsMitmDefenseMutations(config))
                return false;

            if (detection.AuthorizedResponse == ResponseAction.RemoveCert ||
                detection.AuthorizedResponse == ResponseAction.RemoveCertAndKillAdder)
                return config.MitmDefense.RemovePlantedCerts;

            if (detection.Metadata != null &&
                detection.Metadata.TryGetValue("MitmDefense", out var flag) &&
                string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase))
                return true;

            var rule = detection.RuleName ?? "";
            return rule.Contains("Cast Device Guard", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("FCM Push", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("MitM", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("MITM", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Phantom Device", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("TLS Certificate", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("TLS:", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Certificate", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Ghost Process", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Fake Chromecast", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Rogue Cast", StringComparison.OrdinalIgnoreCase)
                   // Classic LAN MitM surface (same suite as June chain)
                   || rule.Contains("ARP Spoof", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Proxy", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Route Table", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("Persistent Route", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("DNS Poison", StringComparison.OrdinalIgnoreCase)
                   || rule.Contains("DNS Hijack", StringComparison.OrdinalIgnoreCase);
        }

        public static bool ShouldNotifyUser(DetectionEvent detection, SentinelConfig config)
        {
            if (config == null) return false;
            if (!config.SilentObserve)
                return true;
            if (detection?.Metadata == null) return false;
            return detection.Metadata.TryGetValue(ChainConfirmedKey, out var v) &&
                   string.Equals(v, "true");
        }

        public static bool ShouldAutoReportIncident(DetectionEvent detection, SentinelConfig config)
        {
            // Same gate as user notify when silent observe is on.
            if (config == null) return true;
            if (!config.SilentObserve)
                return true;
            return ShouldNotifyUser(detection, config);
        }

        private static void TagChainConfirmed(DetectionEvent detection, string outcome)
        {
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata[ChainConfirmedKey] = "true";
            detection.Metadata[TerminalOutcomeKey] = outcome;
            PromoteChainConfirmedFields(detection);
        }

        /// <summary>
        /// Write kill-grade fields back onto the detection so AutoIncidentReporter /
        /// orchestrator see the same authority the response engine used for the nuke.
        /// </summary>
        public static void PromoteChainConfirmedFields(DetectionEvent detection)
        {
            if (detection == null) return;
            detection.Tier = DetectionTier.Tier1Behavioral;
            // v2.6.0: The protective VPN-shield action is a non-kill network-integrity
            // remediation (SYSTEM/PID 0 origin, no malicious process to terminate). Chain
            // confirmation must NOT rewrite it into a process nuke - preserve the author action.
            if (detection.AuthorizedResponse == ResponseAction.VpnShieldUp)
            {
                detection.Metadata ??= new Dictionary<string, string>();
                detection.Metadata[ChainConfirmedKey] = "true";
                return;
            }
            // KillAuthorized is derived from AuthorizedResponse >= KillProcess
            if (detection.AuthorizedResponse < ResponseAction.KillProcessTree)
                detection.AuthorizedResponse = ResponseAction.QuarantineAndKill;
            detection.Metadata ??= new Dictionary<string, string>();
            detection.Metadata[ChainConfirmedKey] = "true";
        }

        private sealed class PidSignalBuffer
        {
            public List<SignalEntry> Entries { get; } = new();
            public DateTime LastActivity { get; set; } = DateTime.UtcNow;
        }

        private readonly record struct SignalEntry(string RuleName, string? Outcome, double Confidence, DateTime When);

        // v2.0.3: TTL sweep state - prevents stale PID buffers from accumulating
        // and false-positive chain-nukes on recycled PIDs.
        private static long _lastSweepTicks = Environment.TickCount;
        private const int SweepIntervalMs = 120_000; // sweep every 2 minutes

        /// <summary>
        /// v2.0.3: Evict PID buffers whose last activity exceeds the chain window + grace.
        /// Called lazily from RegisterAndEvaluateChain and explicitly from SentinelHealthCheck.
        /// Prevents recycled PIDs from inheriting stale signals from dead processes.
        /// </summary>
        public static int SweepStalePidBuffers(int chainWindowSeconds = 300)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-(chainWindowSeconds + 60));
            int removed = 0;
            foreach (var dict in new[] { PidBuffers, RootBuffers })
            {
                foreach (var kvp in dict)
                {
                    var buffer = kvp.Value;
                    bool stale;
                    lock (buffer)
                    {
                        stale = buffer.LastActivity < cutoff && buffer.Entries.Count == 0
                                || buffer.LastActivity < cutoff;
                        if (stale)
                        {
                            buffer.Entries.RemoveAll(e => e.When < cutoff);
                            stale = buffer.Entries.Count == 0;
                        }
                    }
                    if (stale && dict.TryRemove(kvp.Key, out _))
                        removed++;
                }
            }
            return removed;
        }

        /// <summary>
        /// Lazy sweep: called within RegisterAndEvaluateChain to bound dictionary growth
        /// without requiring external periodic invocation.
        /// </summary>
        /// <summary>
        /// Builds a <see cref="SignalEntry"/> from a detection, capping low-confidence
        /// terminal labels to observe-fuel only (no terminal outcome stored).
        /// </summary>
        private static SignalEntry BuildSignalEntry(DetectionEvent detection, double minTerminalConf)
        {
            var outcome = ClassifyTerminalOutcome(detection);
            double conf = detection.Confidence;
            if (conf <= 0 && detection.Metadata != null &&
                detection.Metadata.TryGetValue("ThreatScore", out var scoreStr) &&
                double.TryParse(scoreStr, out var score))
            {
                conf = score > 1.0 ? score / 100.0 : score;
            }
            if (outcome != null && conf < minTerminalConf)
                outcome = null;
            return new SignalEntry(detection.RuleName ?? "unknown", outcome, conf, DateTime.UtcNow);
        }

        /// <summary>
        /// Adds <paramref name="entry"/> to the buffer keyed by <paramref name="bufferKey"/>
        /// and evaluates whether the chain threshold is met.
        /// Returns true when confirmed; <paramref name="outcome"/> carries the terminal family.
        /// </summary>
        private static bool EvaluateBuffer(
            ConcurrentDictionary<int, PidSignalBuffer> buffers,
            int bufferKey,
            SignalEntry entry,
            TimeSpan window,
            int minSignals,
            double minTerminalConf,
            DetectionEvent detection,
            out string? outcome)
        {
            outcome = null;
            var buffer = buffers.GetOrAdd(bufferKey, _ => new PidSignalBuffer());
            lock (buffer)
            {
                var now = DateTime.UtcNow;
                buffer.Entries.RemoveAll(e => now - e.When > window);
                buffer.LastActivity = now;
                buffer.Entries.Add(entry);

                var distinctRules = buffer.Entries
                    .Select(e => e.RuleName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                var terminal = buffer.Entries
                    .Where(e => e.Outcome != null && e.Confidence >= minTerminalConf)
                    .Select(e => e.Outcome)
                    .FirstOrDefault(o => o != null);

                if (distinctRules >= minSignals && terminal != null)
                {
                    outcome = terminal;
                    return true;
                }

                // Two+ distinct terminal families - still require min confidence each.
                var terminalFamilies = buffer.Entries
                    .Where(e => e.Outcome != null && e.Confidence >= minTerminalConf)
                    .Select(e => e.Outcome!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (terminalFamilies.Count >= 2)
                {
                    outcome = string.Join("+", terminalFamilies);
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Walks the ancestry cache upward from <paramref name="pid"/> to find the
        /// highest non-system, non-excluded ancestor within a depth limit of 8.
        /// Returns the root PID, or 0 if no suitable root is found.
        ///
        /// This root PID is used as the key for the cross-PID ancestry buffer so that
        /// all sibling / cousin processes spawned by the same attacker-controlled loader
        /// accumulate their signals together.
        /// </summary>
        private static int GetAttackRootPid(int startPid)
        {
            var cache = _ancestryCache;
            if (cache == null) return 0;

            int current = startPid;
            int candidate = 0;
            var visited = new HashSet<int> { current };

            for (int depth = 0; depth < 8; depth++)
            {
                var (parentId, parentName) = cache.GetParent(current);
                if (parentId <= 4) break;
                if (visited.Contains(parentId)) break; // cycle guard
                visited.Add(parentId);

                // Stop walking at widely-shared system ancestors - these would cross-
                // contaminate unrelated processes.
                if (ExcludedAncestryRoots.Contains(parentName))
                    break;

                // Accept this as a candidate root (non-excluded, non-trivial PID).
                candidate = parentId;
                current = parentId;
            }

            return candidate;
        }

        private static void TryLazySweep(int chainWindowSeconds)
        {
            long now = Environment.TickCount;
            long last = Interlocked.Read(ref _lastSweepTicks);
            // Avoid sweep storms - only one sweep per interval
            if (unchecked(now - last) >= SweepIntervalMs)
            {
                if (Interlocked.CompareExchange(ref _lastSweepTicks, now, last) == last)
                {
                    SweepStalePidBuffers(chainWindowSeconds);
                }
            }
        }

        /// <summary>Test helper - clear PID buffers between tests.</summary>
        internal static void ResetForTests()
        {
            PidBuffers.Clear();
            RootBuffers.Clear();
        }
    }
}
