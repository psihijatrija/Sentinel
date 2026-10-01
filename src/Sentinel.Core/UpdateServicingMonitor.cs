using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Update / servicing-surface behavioral observer (v2.6.3).
    ///
    /// Answers the honest question "can something malicious ride in through the Windows
    /// update / CAB servicing path?" WITHOUT pretending to validate whether an update is
    /// genuine - that is impossible from userland, and a truly Microsoft-signed CDN-delivered
    /// payload (Flame-tier cert forgery) is invisible to any userland tool. Per the
    /// behavioral-signals-only constraint, this monitor watches what the servicing surface
    /// DOES, not what it IS:
    ///
    ///   1. A servicing actor (TrustedInstaller/tiworker/wusa/dism/dismhost/expand/extrac32/
    ///      pkgmgr) spawning a shell / LOLBin / credential tool.
    ///   2. CAB/MSU extraction to a path OUTSIDE the legitimate WinSxS/servicing/Temp staging
    ///      (the CVE-2021-40444 "..\" path-traversal class).
    ///   3. A binary NAMED as a servicing actor that is unsigned or not Microsoft-signed
    ///      (impostor / BYOVD staging), confidence folded through SignerTrustService.
    ///   4. A non-Microsoft or plain-HTTP WSUS / AutoConfigURL-style update source
    ///      (the WSUSpect on-path class).
    ///
    /// EVERY signal is Tier2 / ResponseAction.LogOnly - this monitor NEVER self-authorizes a
    /// destructive action. Its value is composition: it does not re-observe file writes or
    /// service registration (FileActivityMonitor and RegistryMonitor already emit those and
    /// are servicing-path-aware). It contributes the servicing-context observe leg that the
    /// correlation layer chains with a RegistryMonitor driver/service drop or a subsequent
    /// beacon/credential-access leg to reach a confirmed composite.
    ///
    /// Legitimate servicing (a clean cumulative update via TrustedInstaller, NTLite/DISM
    /// offline image work, a UUP dump conversion) produces no anomalous child, no abnormal
    /// extraction path, and Microsoft-signed binaries - so it emits nothing.
    /// </summary>
    public sealed class UpdateServicingMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<UpdateServicingMonitor> _logger;

        // Per-key cooldown so a single servicing event does not storm alerts.
        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts =
            new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(12);

        // The servicing actors we treat as high-trust servicing context. Names are compared
        // case-insensitively WITHOUT the .exe suffix (as Process.ProcessName returns them).
        private static readonly HashSet<string> ServicingActors = new(StringComparer.OrdinalIgnoreCase)
        {
            "trustedinstaller", "tiworker", "wusa", "dism", "dismhost",
            "expand", "extrac32", "pkgmgr", "poqexec", "drvinst",
        };

        // Children that a servicing actor should never legitimately spawn. A cumulative
        // update does not open an interactive shell, a download cradle, or a cred tool.
        private static readonly HashSet<string> AnomalousChildren = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "powershell_ise", "pwsh", "wscript", "cscript",
            "mshta", "bash", "curl", "certutil", "bitsadmin", "rundll32",
            "regsvr32", "reg", "net", "net1", "whoami", "nltest", "rundll",
            "installutil", "msbuild", "mshtml", "hh",
        };

        // Legitimate destinations for CAB/MSU expansion. Anything OUTSIDE these (that a
        // servicing actor writes to) is the CVE-2021-40444 abnormal-extraction shape.
        private static readonly string[] LegitStagingFragments =
        {
            @"\windows\winsxs\",
            @"\windows\servicing\",
            @"\windows\softwaredistribution\",
            @"\windows\temp\",
            @"\windows\logs\cbs\",
            @"\windows\logs\dism\",
            @"\windows\system32\",
            @"\windows\syswow64\",
        };

        // Microsoft signer-CN fragments. A servicing-named binary whose signer does not
        // contain one of these is treated as non-Microsoft (impostor / BYOVD staging).
        private static readonly string[] MicrosoftSignerFragments =
        {
            "microsoft", "windows",
        };

        public UpdateServicingMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ILogger<UpdateServicingMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[UpdateServicingMonitor] Started - observing update/servicing surface " +
                "(actor children, abnormal CAB/MSU extraction, unsigned servicing binaries, update source)");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(PollInterval, ct).ConfigureAwait(false);

                    await CheckServicingActorChildren(ct).ConfigureAwait(false);
                    await CheckServicingBinarySignatures(ct).ConfigureAwait(false);
                    await CheckUpdateSource(ct).ConfigureAwait(false);

                    PruneRecentAlerts();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UpdateServicingMonitor] Error"); }
            }
        }

        /// <summary>
        /// Check 1 &amp; 2: enumerate live servicing actors; flag anomalous children and any
        /// CAB/MSU extraction whose target lands outside legitimate staging.
        /// </summary>
        private async Task CheckServicingActorChildren(CancellationToken ct)
        {
            Process[] all;
            try { all = Process.GetProcesses(); }
            catch (Exception ex) { _logger.LogDebug(ex, "[UpdateServicingMonitor] GetProcesses failed"); return; }

            // Map pid -> process name once (parent lookups reuse this).
            var nameByPid = new Dictionary<int, string>();
            foreach (var p in all)
            {
                try { nameByPid[p.Id] = p.ProcessName; } catch { }
            }

            try
            {
                foreach (var child in all)
                {
                    if (ct.IsCancellationRequested) break;

                    string childName;
                    int childPid;
                    try { childName = child.ProcessName; childPid = child.Id; }
                    catch { continue; }

                    if (!AnomalousChildren.Contains(childName)) continue;

                    int parentPid = GetParentProcessId(childPid);
                    if (parentPid <= 0) continue;

                    if (!nameByPid.TryGetValue(parentPid, out var parentName)) continue;
                    if (!ServicingActors.Contains(parentName)) continue;

                    // Anomalous child of a servicing actor.
                    var alertKey = $"ServicingChild:{parentPid}:{childPid}";
                    if (!TryMarkAlert(alertKey)) continue;

                    string childCmd = GetProcessCommandLine(childPid);
                    await EmitServicingChild(parentName, parentPid, childName, childPid, childCmd)
                        .ConfigureAwait(false);
                }

                // Check 2: abnormal-path extraction driven by expand/extrac32.
                foreach (var actor in all)
                {
                    if (ct.IsCancellationRequested) break;
                    string actorName;
                    int actorPid;
                    try { actorName = actor.ProcessName; actorPid = actor.Id; }
                    catch { continue; }

                    if (!actorName.Equals("expand", StringComparison.OrdinalIgnoreCase) &&
                        !actorName.Equals("extrac32", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string cmd = GetProcessCommandLine(actorPid);
                    if (string.IsNullOrEmpty(cmd)) continue;

                    var target = ExtractDestinationPath(cmd);
                    if (string.IsNullOrEmpty(target)) continue;

                    if (IsLegitStagingPath(target!)) continue;

                    var alertKey = $"AbnormalExtract:{actorPid}";
                    if (!TryMarkAlert(alertKey)) continue;

                    await EmitAbnormalExtraction(actorName, actorPid, cmd, target!)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                foreach (var p in all)
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }

        /// <summary>
        /// Check 3: a running process NAMED as a servicing actor whose on-disk image is
        /// unsigned or not Microsoft-signed - an impostor or BYOVD staging binary wearing a
        /// servicing name to blend into the update surface.
        /// </summary>
        private async Task CheckServicingBinarySignatures(CancellationToken ct)
        {
            Process[] all;
            try { all = Process.GetProcesses(); }
            catch (Exception ex) { _logger.LogDebug(ex, "[UpdateServicingMonitor] GetProcesses failed"); return; }

            try
            {
                foreach (var p in all)
                {
                    if (ct.IsCancellationRequested) break;

                    string name;
                    int pid;
                    try { name = p.ProcessName; pid = p.Id; }
                    catch { continue; }

                    if (!ServicingActors.Contains(name)) continue;
                    if (pid <= 4) continue;

                    string? imagePath = SecurityValidation.GetProcessImagePath(pid);
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    bool signed = _signerTrust.IsSignedFile(imagePath!);
                    string? signer = signed ? _signerTrust.GetSignerName(imagePath!) : null;
                    bool microsoftSigned = signed && IsMicrosoftSigner(signer);

                    if (microsoftSigned) continue; // Genuine servicing binary - nothing to say.

                    var alertKey = $"ServicingSig:{imagePath}";
                    if (!TryMarkAlert(alertKey)) continue;

                    await EmitUnsignedServicingBinary(name, pid, imagePath!, signed, signer)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                foreach (var p in all)
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }

        /// <summary>
        /// Check 4: the machine's configured update source. A WSUS server reached over plain
        /// HTTP (WSUSpect on-path class) or a non-Microsoft WSUS host is observe fuel.
        /// </summary>
        private Task CheckUpdateSource(CancellationToken ct)
        {
            try
            {
                using var wu = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", writable: false);
                if (wu == null) return Task.CompletedTask;

                string? wuServer = wu.GetValue("WUServer") as string;
                if (string.IsNullOrWhiteSpace(wuServer)) return Task.CompletedTask;

                bool plainHttp = wuServer!.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                bool nonMicrosoft = !LooksMicrosoftUpdateHost(wuServer!);

                if (!plainHttp && !nonMicrosoft) return Task.CompletedTask;

                var alertKey = $"UpdateSource:{wuServer}";
                if (!TryMarkAlert(alertKey)) return Task.CompletedTask;

                return EmitSuspiciousUpdateSource(wuServer!, plainHttp, nonMicrosoft);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[UpdateServicingMonitor] Update-source check error");
                return Task.CompletedTask;
            }
        }

        //  Emit helpers - all Tier2 / LogOnly, Family null (never kill-grade) 

        private Task EmitServicingChild(string parentName, int parentPid, string childName, int childPid, string childCmd)
        {
            string cmdSnippet = Truncate(childCmd, 300);
            return _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = $"Servicing: Anomalous Child ({parentName}->{childName})",
                Evidence = $"Servicing actor '{parentName}' (PID {parentPid}) spawned '{childName}' (PID {childPid})." +
                           (string.IsNullOrEmpty(cmdSnippet) ? "" : $" CommandLine: {cmdSnippet}"),
                Reasoning = "A Windows servicing actor (TrustedInstaller/wusa/dism/expand/...) launched a shell, " +
                            "download cradle, or credential/LOLBin tool. Genuine servicing installs components; it does " +
                            "not open interactive shells. This is the WSUSpect / servicing-abuse and CVE-2021-40444 " +
                            "post-detonation shape. Observe-only leg - chains with a service/driver drop or callback.",
                Confidence = 0.6,
                Tier = DetectionTier.Tier2Indicator,
                SignalType = SignalType.SuspiciousProcess,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = childName,
                ProcessId = childPid,
                Metadata = new Dictionary<string, string>
                {
                    { "ParentName", parentName },
                    { "ParentPid", parentPid.ToString() },
                    { "ChildCommandLine", cmdSnippet },
                    { "Surface", "UpdateServicing" },
                },
            });
        }

        private Task EmitAbnormalExtraction(string actorName, int actorPid, string cmd, string target)
        {
            return _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Servicing: CAB/MSU Extraction to Abnormal Path",
                Evidence = $"'{actorName}' (PID {actorPid}) extracting to '{target}', outside legitimate " +
                           $"WinSxS/servicing/Temp staging. CommandLine: {Truncate(cmd, 300)}",
                Reasoning = "expand/extrac32 unpacking a CAB/MSU to a user-writable or otherwise abnormal path is the " +
                            "CVE-2021-40444 (MSHTML) path-traversal delivery class: a malicious CAB writes a payload " +
                            "outside its expected extraction directory. Legitimate servicing only expands into WinSxS/" +
                            "servicing/Temp. Observe-only leg - chains with subsequent execution of the dropped file.",
                Confidence = 0.65,
                Tier = DetectionTier.Tier2Indicator,
                SignalType = SignalType.SuspiciousProcess,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = actorName,
                ProcessId = actorPid,
                Metadata = new Dictionary<string, string>
                {
                    { "ExtractedPath", target },
                    { "CommandLine", Truncate(cmd, 300) },
                    { "Surface", "UpdateServicing" },
                },
            });
        }

        private Task EmitUnsignedServicingBinary(string name, int pid, string imagePath, bool signed, string? signer)
        {
            // Fold the signing state into confidence: an unsigned impostor scores higher than
            // a validly-but-non-Microsoft-signed one. Never zero (behavioral fire preserved).
            double baseConfidence = signed ? 0.55 : 0.7;
            double confidence = _signerTrust.AdjustConfidence(baseConfidence, imagePath);

            string signerDesc = signed
                ? $"signed by '{signer}' (not a Microsoft signer)"
                : "unsigned";

            return _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Servicing: Non-Microsoft Servicing Binary",
                Evidence = $"Process '{name}' (PID {pid}) runs image '{imagePath}' which is {signerDesc}.",
                Reasoning = "A binary wearing a servicing-actor name (TrustedInstaller/dism/wusa/...) that is unsigned or " +
                            "not Microsoft-signed is an impostor or BYOVD-staging binary blending into the update surface. " +
                            "Genuine servicing binaries are Microsoft-signed and live under \\Windows. Observe-only leg - " +
                            "chains with a driver/service drop (RegistryMonitor) to a BYOVD composite; never a solo kill.",
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator,
                SignalType = SignalType.SuspiciousProcess,
                // Terminal family is BYOVD-adjacent but NEVER solo kill-grade; left null so
                // ResponsePolicy does not treat this observe leg as a terminal outcome.
                Family = null,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                Metadata = new Dictionary<string, string>
                {
                    { "ImagePath", imagePath },
                    { "Signed", signed.ToString() },
                    { "SignerCN", signer ?? "" },
                    { "Surface", "UpdateServicing" },
                },
            });
        }

        private Task EmitSuspiciousUpdateSource(string wuServer, bool plainHttp, bool nonMicrosoft)
        {
            var reasons = new List<string>();
            if (plainHttp) reasons.Add("plain-HTTP (unencrypted, on-path tamperable)");
            if (nonMicrosoft) reasons.Add("non-Microsoft host");

            return _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Servicing: Suspicious Update Source (WSUS)",
                Evidence = $"WUServer policy points at '{wuServer}' - {string.Join(", ", reasons)}.",
                Reasoning = "A WSUS update source reached over plain HTTP can be man-in-the-middled (the WSUSpect class): " +
                            "an on-path attacker injects attacker-chosen 'updates'. A non-Microsoft WSUS host may be a " +
                            "rogue/compromised update server. Corporate WSUS over HTTPS is legitimate, so this is " +
                            "observe-only fuel that escalates only when correlated with a suspicious servicing install.",
                Confidence = plainHttp && nonMicrosoft ? 0.7 : 0.55,
                Tier = DetectionTier.Tier2Indicator,
                SignalType = SignalType.SecurityEvasion,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "system",
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    { "WUServer", wuServer },
                    { "PlainHttp", plainHttp.ToString() },
                    { "NonMicrosoft", nonMicrosoft.ToString() },
                    { "Surface", "UpdateServicing" },
                },
            });
        }

        //  Pure helpers 

        internal static bool IsLegitStagingPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string lower = path.ToLowerInvariant();
            foreach (var frag in LegitStagingFragments)
                if (lower.Contains(frag)) return true;
            return false;
        }

        internal static bool IsMicrosoftSigner(string? signerCn)
        {
            if (string.IsNullOrWhiteSpace(signerCn)) return false;
            string lower = signerCn!.ToLowerInvariant();
            foreach (var frag in MicrosoftSignerFragments)
                if (lower.Contains(frag)) return true;
            return false;
        }

        internal static bool LooksMicrosoftUpdateHost(string wuServer)
        {
            if (string.IsNullOrWhiteSpace(wuServer)) return false;
            string lower = wuServer.ToLowerInvariant();
            return lower.Contains("microsoft.com") ||
                   lower.Contains("windowsupdate.com") ||
                   lower.Contains(".microsoft.") ||
                   lower.Contains("msftconnecttest") ||
                   lower.Contains("update.microsoft");
        }

        /// <summary>
        /// Extract the destination path from an expand/extrac32 command line. expand supports
        /// "expand src.cab -F:* dest" (dest is the last non-switch token); extrac32 uses
        /// "/E &lt;dir&gt;" or a trailing directory. Returns the best-effort destination or null.
        /// </summary>
        internal static string? ExtractDestinationPath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return null;

            var tokens = Tokenize(commandLine);
            if (tokens.Count <= 1) return null;

            // Drop the executable token.
            tokens.RemoveAt(0);

            string? lastPathLike = null;
            foreach (var t in tokens)
            {
                if (t.StartsWith("/") || t.StartsWith("-")) continue; // switch
                // A path-like token: has a directory separator or a drive letter.
                if (t.Contains("\\") || (t.Length >= 2 && t[1] == ':'))
                    lastPathLike = t;
            }

            if (lastPathLike == null) return null;

            // If the destination token is a file (e.g. the source .cab), strip to its directory
            // only when it clearly has an archive extension; otherwise treat as the dest path.
            return lastPathLike.Trim('"');
        }

        private static List<string> Tokenize(string commandLine)
        {
            var result = new List<string>();
            bool inQuotes = false;
            var current = new System.Text.StringBuilder();

            foreach (char c in commandLine)
            {
                if (c == '"') { inQuotes = !inQuotes; continue; }
                if (char.IsWhiteSpace(c) && !inQuotes)
                {
                    if (current.Length > 0) { result.Add(current.ToString()); current.Clear(); }
                    continue;
                }
                current.Append(c);
            }
            if (current.Length > 0) result.Add(current.ToString());
            return result;
        }

        private static string Truncate(string? s, int max)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s!.Length <= max ? s : s.Substring(0, max) + "...";
        }

        private bool TryMarkAlert(string key)
        {
            var now = DateTime.UtcNow;
            if (_recentAlerts.TryGetValue(key, out var last) && (now - last) < AlertCooldown)
                return false;
            _recentAlerts[key] = now;
            return true;
        }

        private void PruneRecentAlerts()
        {
            var cutoff = DateTime.UtcNow - AlertCooldown;
            foreach (var key in _recentAlerts.Keys.ToArray())
            {
                if (_recentAlerts.TryGetValue(key, out var t) && t < cutoff)
                    _recentAlerts.TryRemove(key, out _);
            }
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static int GetParentProcessId(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return -1;
        }
    }
}
