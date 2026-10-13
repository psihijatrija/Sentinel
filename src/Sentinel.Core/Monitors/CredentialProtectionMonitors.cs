// Credential Protection Monitor Group - canary files, browser credential guards, account guards, and password rotation

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // Canary File Monitor - honeypot files in sensitive directories
    // 
    public sealed class CanaryFileMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CanaryFileMonitor> _logger;
        private readonly List<string> _canaryPaths = new();

        public CanaryFileMonitor(DetectionEngine de, ILogger<CanaryFileMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CanaryFileMonitor] Started");
            PlantCanaryFiles();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);
                    // Iterate a snapshot to avoid mutating the list while enumerating it
                    var toRemove = new List<string>();
                    foreach (var path in _canaryPaths.ToArray())
                    {
                        if (!File.Exists(path))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Canary File: Deleted",
                                Evidence = $"Canary file was deleted: {path}",
                                Reasoning = "A honeypot canary file planted in a sensitive directory was deleted, indicating possible ransomware or unauthorized file manipulation.",
                                Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            toRemove.Add(path);
                        }
                    }
                    foreach (var path in toRemove)
                        _canaryPaths.Remove(path);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CanaryFileMonitor] Error"); }
            }
        }

        private void PlantCanaryFiles()
        {
            var dirs = new[] { Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                               Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) };
            foreach (var dir in dirs)
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                try
                {
                    var canary = Path.Combine(dir, ".~sentinel_canary.tmp");
                    if (!File.Exists(canary))
                    {
                        File.WriteAllText(canary, "SENTINEL_CANARY");
                        File.SetAttributes(canary, FileAttributes.Hidden | FileAttributes.System);
                    }
                    _canaryPaths.Add(canary);
                }
                catch { }
            }
        }
    }


    // 
    // Browser Credential Guard - unified monitor for browser credential/session theft
    // Covers Chrome, Edge, and Firefox credential stores and cookie databases
    // 
    public sealed class BrowserCredentialGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserCredentialGuard> _logger;
        private readonly Dictionary<string, DateTime> _baselines = new();

        public BrowserCredentialGuard(DetectionEngine de, ILogger<BrowserCredentialGuard> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserCredentialGuard] Started");

            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Define all browser targets: (BrowserName, FilePath, ProcessName, Description)
            var targets = new List<(string BrowserName, string FilePath, string ProcessName, string Description)>();

            // Chrome Login Data (credential theft)
            if (!string.IsNullOrEmpty(localAppData))
            {
                targets.Add(("Chrome", Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Login Data"), "chrome", "credential theft"));
                targets.Add(("Chrome", Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Network\Cookies"), "chrome", "session theft"));
                targets.Add(("Edge", Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Login Data"), "msedge", "credential theft"));
                targets.Add(("Edge", Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Network\Cookies"), "msedge", "session theft"));
            }

            // Firefox logins.json - multiple profiles possible
            if (!string.IsNullOrEmpty(roamingAppData))
            {
                var profilesDir = Path.Combine(roamingAppData, @"Mozilla\Firefox\Profiles");
                if (Directory.Exists(profilesDir))
                {
                    foreach (var prof in Directory.GetDirectories(profilesDir))
                    {
                        var loginJson = Path.Combine(prof, "logins.json");
                        targets.Add(("Firefox", loginJson, "firefox", "credential theft"));
                    }
                }
            }

            // Baseline all existing files
            foreach (var (_, filePath, _, _) in targets)
            {
                if (File.Exists(filePath))
                    _baselines[filePath] = File.GetLastWriteTimeUtc(filePath);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    foreach (var (browserName, filePath, processName, description) in targets)
                    {
                        if (!File.Exists(filePath)) continue;

                        var current = File.GetLastWriteTimeUtc(filePath);
                        if (_baselines.TryGetValue(filePath, out var prev) && current != prev)
                        {
                            var browserRunning = Process.GetProcessesByName(processName).Length > 0;
                            if (!browserRunning)
                            {
                                var dataType = description == "session theft" ? "Session" : "Credential";
                                var fileName = Path.GetFileName(filePath);
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = $"Browser {dataType} Theft: {browserName} {fileName} Modified While Browser Closed",
                                    Evidence = $"{browserName} {fileName} modified at {current:O} while {processName}.exe is not running",
                                    Reasoning = $"{browserName} {description} store was modified while the browser was not running, indicating {description}. " +
                                                "No browser process is running to attribute the access - check recent process history for credential theft tools.",
                                    Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                    // Cannot kill PID 0 - the accessor process has already exited or was not identified.
                                    // Log the event for correlation; the analyst or a follow-up scan should identify the stealer.
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = "SYSTEM", ProcessId = 0
                                });
                            }
                        }
                        _baselines[filePath] = current;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserCredentialGuard] Error"); }
            }
        }
    }


    // 
    // 
    // Microsoft Account Guard - watches for token files
    // 
    public sealed class MicrosoftAccountGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MicrosoftAccountGuardMonitor> _logger;
        private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);

        public MicrosoftAccountGuardMonitor(DetectionEngine de, ILogger<MicrosoftAccountGuardMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MicrosoftAccountGuardMonitor] Started");
            var tokenCachePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\TokenBroker\Cache");
            DateTime lastScan = DateTime.UtcNow;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (!Directory.Exists(tokenCachePath)) continue;

                    foreach (var file in Directory.EnumerateFiles(tokenCachePath, "*.tbres"))
                    {
                        var fi = new FileInfo(file);
                        if (fi.LastWriteTimeUtc > lastScan)
                        {
                            // Check which process has the token file open
                            // If a non-browser, non-system process is touching token files, alert
                            var fileName = Path.GetFileName(file);
                            if (_alertedFiles.Contains(fileName)) continue;

                            // Look for processes that might be reading token files
                            foreach (var proc in Process.GetProcesses())
                            {
                                try
                                {
                                    var name = proc.ProcessName;
                                    // Skip known legitimate token consumers
                                    if (name.Contains("RuntimeBroker") ||
                                        name.Contains("svchost") ||
                                        name.Contains("TokenBroker") ||
                                        name.Contains("msedge") ||
                                        name.Contains("chrome") ||
                                        name.Contains("Teams") ||
                                        name.Contains("OneDrive") ||
                                        name.Contains("explorer"))
                                        continue;

                                    // Check if process is from temp/suspicious path
                                    string? imagePath = null;
                                    try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                                    if (!string.IsNullOrEmpty(imagePath) &&
                                        (imagePath!.Contains(@"\Temp\") ||
                                         imagePath.Contains(@"\Downloads\")))
                                    {
                                        _alertedFiles.Add(fileName);
                                        await _detectionEngine.EmitAsync(new DetectionEvent
                                        {
                                            RuleName = "Credential Theft: Microsoft Token Cache Accessed",
                                            Evidence = $"Token cache file '{fileName}' modified while suspicious process '{name}' (PID {proc.Id}) from '{imagePath}' is running",
                                            Reasoning = "The Microsoft TokenBroker cache was accessed while a process from a suspicious path is active, which may indicate token theft.",
                                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                                            AuthorizedResponse = ResponseAction.KillProcessTree,
                                            ProcessName = name, ProcessId = proc.Id
                                        });
                                        break;
                                    }
                                }
                                catch { }
                                finally { proc.Dispose(); }
                            }
                        }
                    }
                    lastScan = DateTime.UtcNow;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[MicrosoftAccountGuardMonitor] Error"); }
            }
        }
    }


    // 
    // Null Session Guard - actively blocks blank-password network logon exposure
    // by enforcing security policy that restricts network access without credentials.
    // Also hardens against FCM push-triggered tab opens following MitM cert attacks.
    // 
    public sealed class NullSessionGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<NullSessionGuard> _logger;
        private bool _policyApplied;
        private bool _fcmBlocked;
        private bool _fcmCleanupDone;

        private const string LimitBlankPasswordUseKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
        private const string LimitBlankPasswordUseValue = "LimitBlankPasswordUse";
        private const string RestrictNullSessAccessValue = "RestrictAnonymous";
        private const string EveryoneIncludesAnonValue = "EveryoneIncludesAnonymous";
        private const string RestrictRemoteSamKey = @"SYSTEM\CurrentControlSet\Control\Lsa";

        // Google FCM/GCM IPs use port 5228. Blocking this port via Windows Firewall
        // prevents push-triggered tab opens ("Send Tab to Self") that attackers can
        // abuse after stealing Chrome session tokens via MitM cert interception.
        // v1.8.3: only when Sentinel:BlockFcmPushChannel=true (post-incident opt-in).
        private const string FcmFirewallRuleName = "Sentinel-FCM-Push-Block";
        private const int FcmPort = 5228;

        public NullSessionGuard(DetectionEngine de, SentinelConfig config, ILogger<NullSessionGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            // MitmDefense.Enabled implies FCM block (Send Tab to Self after token theft)
            bool fcmOn = _config.BlockFcmPushChannel
                         || (ProductPosture.AllowsMitmDefenseMutations(_config)
                             && (_config.MitmDefense?.BlockFcmPushChannel ?? true));

            _logger.LogInformation(
                "[NullSessionGuard] Started - blank-password network restrictions; FCM block={Fcm} (MitmDefense={Mitm})",
                fcmOn ? "ON (post-incident / MitM suite)" : "OFF (observe-only default)",
                ProductPosture.AllowsMitmDefenseMutations(_config));

            // Initial delay to let other monitors start
            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await EnforceNullSessionProtection(ct);
                    fcmOn = _config.BlockFcmPushChannel
                            || (ProductPosture.AllowsMitmDefenseMutations(_config)
                                && (_config.MitmDefense?.BlockFcmPushChannel ?? true));
                    if (fcmOn)
                        await EnforceFcmPushBlock(ct);
                    else if (!_fcmCleanupDone)
                        RemoveFcmPushBlockIfPresent();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NullSessionGuard] Error"); }

                // Re-check every 60s (policy may be reverted by attacker/GPO)
                await Task.Delay(60000, ct);
            }
        }

        /// <summary>
        /// v1.8.3: When BlockFcmPushChannel is false, remove leftover FCM firewall rules
        /// from older installs so Chrome push works again for normal users.
        /// </summary>
        private void RemoveFcmPushBlockIfPresent()
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType != null)
                {
                    dynamic? policy = Activator.CreateInstance(policyType);
                    if (policy != null)
                    {
                        bool removed = false;
                        try
                        {
                            policy.Rules.Remove(FcmFirewallRuleName);
                            removed = true;
                        }
                        catch { /* rule may not exist */ }

                        if (removed)
                            _logger.LogWarning(
                                "[NullSessionGuard] Removed leftover {Rule} (BlockFcmPushChannel=false - no preemptive FCM block)",
                                FcmFirewallRuleName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NullSessionGuard] FCM rule cleanup failed");
            }
            finally
            {
                _fcmCleanupDone = true;
                _fcmBlocked = false;
            }
        }

        /// <summary>
        /// Enforces Windows security policies that prevent blank-password accounts from
        /// being accessed over the network. This is the ACTIVE protection:
        /// 
        /// 1. LimitBlankPasswordUse = 1 - blocks network logon for accounts with empty passwords
        ///    (prevents SMB null-session, RDP without password, WinRM without password)
        /// 2. RestrictAnonymous = 1 - prevents anonymous enumeration of SAM accounts and shares
        /// 3. EveryoneIncludesAnonymous = 0 - anonymous tokens excluded from Everyone group
        ///
        /// If an attacker reverts these, the monitor detects and re-applies within 60s.
        /// </summary>
        private async Task EnforceNullSessionProtection(CancellationToken ct)
        {
            bool anyChanged = false;

            try
            {
                using var lsaKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(LimitBlankPasswordUseKey, true);
                if (lsaKey != null)
                {
                    // Enforce LimitBlankPasswordUse = 1
                    var current = lsaKey.GetValue(LimitBlankPasswordUseValue);
                    if (current == null || (int)current != 1)
                    {
                        lsaKey.SetValue(LimitBlankPasswordUseValue, 1, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced LimitBlankPasswordUse=1 (was {Old})", current);
                    }

                    // Enforce RestrictAnonymous = 1
                    var restrictAnon = lsaKey.GetValue(RestrictNullSessAccessValue);
                    if (restrictAnon == null || (int)restrictAnon < 1)
                    {
                        lsaKey.SetValue(RestrictNullSessAccessValue, 1, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced RestrictAnonymous=1 (was {Old})", restrictAnon);
                    }

                    // Enforce EveryoneIncludesAnonymous = 0
                    var everyoneAnon = lsaKey.GetValue(EveryoneIncludesAnonValue);
                    if (everyoneAnon != null && (int)everyoneAnon != 0)
                    {
                        lsaKey.SetValue(EveryoneIncludesAnonValue, 0, Microsoft.Win32.RegistryValueKind.DWord);
                        anyChanged = true;
                        _logger.LogWarning("[NullSessionGuard] Enforced EveryoneIncludesAnonymous=0 (was {Old})", everyoneAnon);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NullSessionGuard] Failed to enforce LSA policy");
            }

            if (anyChanged && !_policyApplied)
            {
                _policyApplied = true;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Hardening: Null Session Network Access Blocked",
                    Evidence = "Enforced LimitBlankPasswordUse=1, RestrictAnonymous=1, EveryoneIncludesAnonymous=0",
                    Reasoning = "Active protection applied: blank-password accounts are now blocked from network logon " +
                                "(SMB, RDP, WinRM). Anonymous enumeration of user accounts and shares is restricted. " +
                                "This prevents attackers from exploiting the blank local password via null-session authentication, " +
                                "pass-the-hash with the well-known empty NTLM hash (31D6CFE0D16AE931B73C59D7E0C089C0), " +
                                "or anonymous share/user enumeration for lateral movement.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        { "Action", "PolicyEnforced" },
                        { "LimitBlankPasswordUse", "1" },
                        { "RestrictAnonymous", "1" }
                    }
                });
            }
            else if (anyChanged)
            {
                // Policy was reverted by something - attacker or GPO. Re-applied.
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Null Session Policy Reverted and Re-Applied",
                    Evidence = "Null-session restriction policy was found reverted and has been re-enforced",
                    Reasoning = "The LimitBlankPasswordUse or RestrictAnonymous policy was found in a weakened state. " +
                                "This could indicate an attacker disabling the protection to enable null-session access, " +
                                "or a Group Policy override. Sentinel has re-applied the hardened settings.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion
                });
            }
        }

        /// <summary>
        /// Blocks outbound traffic to Google FCM port 5228 via Windows Firewall.
        ///
        /// Attack chain:
        ///   1. Attacker plants MitM root cert -> intercepts HTTPS -> steals Chrome sync tokens
        ///   2. With stolen tokens, attacker uses "Send Tab to Self" via FCM push
        ///   3. Chrome receives FCM push on port 5228 -> opens attacker-controlled URL
        ///   4. URL exploits browser or phishes credentials
        ///
        /// By blocking port 5228, we sever the FCM push channel completely.
        /// Chrome still functions normally (browsing, sync of bookmarks/passwords works
        /// via HTTPS on 443). Only real-time push notifications are lost.
        ///
        /// This is acceptable because:
        ///   - No AV/EDR is installed (Defender removed on debloated Windows)
        ///   - MitM certs WERE detected and removed, but token theft may have already occurred
        ///   - The user's Google account is "well secured" but tokens can outlive password changes
        ///   - Better to lose push notifications than allow remote tab injection
        /// </summary>
        private async Task EnforceFcmPushBlock(CancellationToken ct)
        {
            if (_fcmBlocked) return;

            try
            {
                // Check if the firewall rule already exists
                bool ruleExists = false;
                try
                {
                    var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                    if (policyType == null) throw new InvalidOperationException("COM type not found");
                    dynamic? policy = Activator.CreateInstance(policyType);
                    if (policy == null) throw new InvalidOperationException("COM instance failed");

                    foreach (dynamic rule in policy.Rules)
                    {
                        if ((string)rule.Name == FcmFirewallRuleName)
                        {
                            ruleExists = true;
                            break;
                        }
                    }

                    if (!ruleExists)
                    {
                        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                        if (ruleType == null) throw new InvalidOperationException("COM rule type not found");
                        dynamic? newRule = Activator.CreateInstance(ruleType);
                        if (newRule == null) throw new InvalidOperationException("COM rule instance failed");

                        newRule.Name = FcmFirewallRuleName;
                        newRule.Description = "Sentinel: Blocks Google FCM push notifications (port 5228) " +
                                              "to prevent remote tab injection via stolen sync tokens";
                        newRule.Protocol = 6; // TCP
                        newRule.RemotePorts = FcmPort.ToString();
                        newRule.Direction = 2; // Outbound
                        newRule.Action = 0; // Block
                        newRule.Enabled = true;
                        newRule.Profiles = 0x7FFFFFFF; // All profiles

                        policy.Rules.Add(newRule);

                        _logger.LogWarning("[NullSessionGuard] BLOCKED outbound port {Port} (Google FCM push) - prevents remote tab injection", FcmPort);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: FCM Push Channel Blocked",
                            Evidence = $"Firewall rule '{FcmFirewallRuleName}' created blocking outbound TCP port {FcmPort}",
                            Reasoning = "Blocked Google Firebase Cloud Messaging (FCM) port 5228 outbound. " +
                                        "Attack chain: MitM cert -> HTTPS intercept -> Chrome token theft -> FCM 'Send Tab to Self' -> " +
                                        "arbitrary URL opens on this machine. Blocking FCM severs this attack vector permanently. " +
                                        "Chrome browsing, bookmark sync, and password sync continue to work normally via HTTPS (port 443). " +
                                        "Only real-time push notifications are disabled.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.NetworkC2,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Action", "FirewallBlock" },
                                { "Port", FcmPort.ToString() },
                                { "RuleName", FcmFirewallRuleName },
                                { "Impact", "Push notifications disabled; browsing unaffected" }
                            }
                        });
                    }
                    else
                    {
                        _logger.LogInformation("[NullSessionGuard] FCM block rule already exists");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[NullSessionGuard] Failed to create FCM block via COM, falling back to netsh");

                    // Fallback: use netsh directly
                    var psi = new ProcessStartInfo("netsh",
                        $"advfirewall firewall add rule name=\"{FcmFirewallRuleName}\" " +
                        $"dir=out action=block protocol=tcp remoteport={FcmPort}")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(5000);

                    if (proc?.ExitCode == 0)
                    {
                        _logger.LogWarning("[NullSessionGuard] BLOCKED FCM port {Port} via netsh fallback", FcmPort);
                    }
                }

                _fcmBlocked = true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NullSessionGuard] FCM block enforcement failed");
            }
        }
    }


    // 
    // Builtin Admin Guard - detects and disables the built-in Administrator account.
    // The built-in Administrator account (RID 500) should NEVER be active on a
    // personal workstation. Attackers enable it for backdoor access because it:
    //   1. Has a blank password by default on many installs
    //   2. Bypasses UAC entirely (no elevation prompts)
    //   3. Survives user profile deletion
    //   4. Is visible on the login screen, inviting interactive logon
    // v1.4.1: Introduced after an active intrusion enabled it to establish persistence.
    // 
    public sealed class BuiltinAdminGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<BuiltinAdminGuard> _logger;

        public BuiltinAdminGuard(DetectionEngine de, SentinelConfig config, ILogger<BuiltinAdminGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BuiltinAdminGuard] Started - monitoring built-in Administrator account state");

            // Check immediately at startup
            await CheckAndDisableBuiltinAdmin("Startup", ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct); // Check every 15 seconds
                    await CheckAndDisableBuiltinAdmin("PeriodicCheck", ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BuiltinAdminGuard] Error"); }
            }
        }

        private async Task CheckAndDisableBuiltinAdmin(string trigger, CancellationToken ct)
        {
            try
            {
                // Query the built-in Administrator account state via SAM registry
                // HKLM\SAM\SAM\Domains\Account\Users\000001F4 (RID 500 = 0x1F4)
                // The "F" binary value at offset 0x38 contains account flags.
                // Bit 0x0002 = Account Disabled. If NOT set, account is active.
                //
                bool isActive = IsBuiltinAdminActive();

                if (isActive)
                {
                    _logger.LogWarning("[BuiltinAdminGuard] Built-in Administrator account is ENABLED (trigger: {Trigger}) - disabling immediately", trigger);

                    // Disable it
                    if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                    {
                        DisableBuiltinAdmin();
                    }

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Account Tampering: Built-in Administrator Enabled",
                        Evidence = $"The built-in Administrator account (RID 500) was found ACTIVE (trigger: {trigger}). " +
                                   (ResponsePolicy.MayPerformInlineHostMutation(_config) ? "Account has been disabled." : "Active response is off - account remains enabled."),
                        Reasoning = "The built-in Administrator account should never be active on a personal workstation. " +
                                    "It has no UAC restrictions, may have a blank password, and is a common attacker backdoor. " +
                                    "An attacker with admin/SYSTEM access enables it via 'net user Administrator /active:yes' " +
                                    "to establish a persistent, stealthy backdoor that survives user profile changes. " +
                                    "This was detected during an active intrusion where the account was enabled alongside a system freeze.",
                        Confidence = 0.97,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.SecurityEvasion,
                        Metadata = new Dictionary<string, string>
                        {
                            ["Trigger"] = trigger,
                            ["Action"] = ResponsePolicy.MayPerformInlineHostMutation(_config) ? "Disabled" : "AlertOnly",
                            ["AccountSID"] = "S-1-5-21-*-500"
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BuiltinAdminGuard] CheckAndDisableBuiltinAdmin failed");
            }
        }

        private static bool IsBuiltinAdminActive() => BuiltinAdminAccount.IsActive();

        private void DisableBuiltinAdmin()
        {
            if (BuiltinAdminAccount.TryDisable(out var error))
                _logger.LogWarning("[BuiltinAdminGuard] DISABLED built-in Administrator account");
            else
                _logger.LogError("[BuiltinAdminGuard] Failed to disable Administrator account (NetUser={Error})", error);
        }
    }

    /// <summary>
    /// SAM query/set for RID 500 via NetUser APIs - no net.exe.
    /// USER_INFO_1008 updates flags only (does not touch the password).
    /// </summary>
    internal static class BuiltinAdminAccount
    {
        private const int UfAccountDisable = 0x0002;
        private const int NerrSuccess = 0;

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserGetInfo(string? serverName, string userName, int level, out IntPtr bufPtr);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetUserSetInfo(string? serverName, string userName, int level, IntPtr buf, out int parmErr);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_1
        {
            public string usri1_name;
            public string usri1_password;
            public int usri1_password_age;
            public int usri1_priv;
            public string usri1_home_dir;
            public string usri1_comment;
            public int usri1_flags;
            public string usri1_script_path;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct USER_INFO_1008
        {
            public int usri1008_flags;
        }

        public static bool IsActive()
        {
            if (!TryGetFlags(out var flags))
                return false;
            return (flags & UfAccountDisable) == 0;
        }

        public static bool TryDisable(out int error)
        {
            error = -1;
            if (!TryGetFlags(out var flags))
                return false;
            if ((flags & UfAccountDisable) != 0)
            {
                error = NerrSuccess;
                return true;
            }

            var info = new USER_INFO_1008 { usri1008_flags = flags | UfAccountDisable };
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<USER_INFO_1008>());
            try
            {
                Marshal.StructureToPtr(info, ptr, false);
                error = NetUserSetInfo(null, "Administrator", 1008, ptr, out _);
                return error == NerrSuccess;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        internal static bool TryGetFlags(out int flags)
        {
            flags = 0;
            int rc = NetUserGetInfo(null, "Administrator", 1, out var buf);
            if (rc != NerrSuccess || buf == IntPtr.Zero)
                return false;
            try
            {
                var info = Marshal.PtrToStructure<USER_INFO_1>(buf);
                flags = info.usri1_flags;
                return true;
            }
            finally
            {
                NetApiBufferFree(buf);
            }
        }
    }


    // NOTE: PasswordRotationGuard was removed in v2.7.6. It rotated local account
    // passwords on a timer and, to avoid lockout, configured silent auto-logon
    // (AutoAdminLogon + LSA DefaultPassword secret), disabled Ctrl+Alt+Del, disabled the
    // screen-lock timeout, and pinned UAC to consent-only. That combination removed the
    // interactive authentication boundary rather than strengthening it and conflicts with
    // Sentinel's userland / no-persistence / no-self-hiding constraints. Remote-logon
    // exposure is handled by NullSessionGuard, RemoteSessionGuard, and BuiltinAdminGuard
    // plus OS-level "deny network/RDP logon" hardening - not by rotating the local password.


    // 
    // Remote Logon Hardening Guard (v2.7.6) - the constructive replacement for the removed
    // PasswordRotationGuard. It does NOT touch any account password. Instead it closes the
    // remote-logon surface for privileged local accounts and removes any auto-logon leak:
    //
    //   1. Deny network + RDP logon for local admin-class accounts by assigning
    //      SeDenyNetworkLogonRight + SeDenyRemoteInteractiveLogonRight (via LGPO if present,
    //      else secedit). This makes those accounts unusable over SMB / WinRM / RDP.
    //   2. Ensure no auto-logon leak: AutoAdminLogon=0, delete Winlogon\DefaultPassword,
    //      and clear the LSA "DefaultPassword" private-data secret if present.
    //
    // Enforced on startup and re-checked on an interval so an attacker cannot silently
    // re-grant the right or re-arm auto-logon. Standing proactive OS hardening, so it is
    // gated on ProductPosture.AllowsProactiveHostLockdown (always-on in current posture).
    // MayEnforce is exposed for the default-deny test required by docs/constraints.md.
    // 
    public sealed class RemoteLogonHardeningGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<RemoteLogonHardeningGuard> _logger;

        private static readonly TimeSpan RecheckInterval = TimeSpan.FromMinutes(5);

        public RemoteLogonHardeningGuard(DetectionEngine de, SentinelConfig config, ILogger<RemoteLogonHardeningGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        /// <summary>
        /// Posture gate for this guard's host mutation. Exposed for the default-deny test.
        /// Follows the always-on proactive-hardening posture (a null/default config still
        /// authorizes it), matching the other credential/hardening guards.
        /// </summary>
        internal static bool MayEnforce(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RemoteLogonHardeningGuard] Started - deny network/RDP logon for local admin accounts; no auto-logon leak");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    Enforce();
                    await Task.Delay(RecheckInterval, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RemoteLogonHardeningGuard] Error"); }
            }
        }

        private void Enforce()
        {
            // Default-deny: never mutate the host unless posture authorizes it.
            if (!MayEnforce(_config))
            {
                _logger.LogInformation("[RemoteLogonHardeningGuard] Skipped - proactive host lockdown not authorized by posture");
                return;
            }

            ClearAutoLogonLeak();

            var admins = GetLocalAdminAccountSids();
            if (admins.Count == 0)
            {
                _logger.LogDebug("[RemoteLogonHardeningGuard] No local admin accounts resolved to deny");
                return;
            }
            DenyRemoteLogon(admins);
        }

        // 
        // 1. No auto-logon leak
        // 
        private void ClearAutoLogonLeak()
        {
            try
            {
                using var winlogon = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", writable: true);
                if (winlogon != null)
                {
                    var auto = winlogon.GetValue("AutoAdminLogon") as string;
                    if (auto != null && auto != "0")
                    {
                        winlogon.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
                        _logger.LogWarning("[RemoteLogonHardeningGuard] Disabled AutoAdminLogon (was '{Old}')", auto);
                    }

                    if (winlogon.GetValue("DefaultPassword") != null)
                    {
                        winlogon.DeleteValue("DefaultPassword", throwOnMissingValue: false);
                        _logger.LogWarning("[RemoteLogonHardeningGuard] Removed plaintext Winlogon DefaultPassword");
                    }

                    if (winlogon.GetValue("ForceAutoLogon") != null)
                        winlogon.DeleteValue("ForceAutoLogon", throwOnMissingValue: false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RemoteLogonHardeningGuard] ClearAutoLogonLeak (registry) failed");
            }

            // Clear the LSA "DefaultPassword" private-data secret if present.
            ClearLsaDefaultPasswordSecret();
        }

        private void ClearLsaDefaultPasswordSecret()
        {
            var objectAttributes = new LSA_OBJECT_ATTRIBUTES { Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
            var systemName = new LSA_UNICODE_STRING();

            uint status = LsaOpenPolicy(ref systemName, ref objectAttributes, POLICY_CREATE_SECRET, out IntPtr policyHandle);
            if (status != 0 || policyHandle == IntPtr.Zero)
            {
                _logger.LogDebug("[RemoteLogonHardeningGuard] LsaOpenPolicy failed: 0x{Status:X8}", status);
                return;
            }

            try
            {
                var keyName = CreateLsaString("DefaultPassword");
                try
                {
                    // Storing null private-data deletes the secret.
                    status = LsaStorePrivateData(policyHandle, ref keyName, IntPtr.Zero);
                    if (status == 0)
                        _logger.LogDebug("[RemoteLogonHardeningGuard] Cleared LSA DefaultPassword secret");
                }
                finally
                {
                    if (keyName.Buffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(keyName.Buffer);
                }
            }
            finally
            {
                LsaClose(policyHandle);
            }
        }

        // 
        // 2. Deny network + RDP logon for local admin-class accounts
        // 
        private void DenyRemoteLogon(List<string> sids)
        {
            var tmpDir = Path.Combine(Path.GetTempPath(), "sentinel-rlhg");
            try { Directory.CreateDirectory(tmpDir); } catch { /* best effort */ }

            var infPath = Path.Combine(tmpDir, "deny-remote.inf");
            var dbPath = Path.Combine(tmpDir, "deny-remote.sdb");
            var logPath = Path.Combine(tmpDir, "deny-remote.log");

            // Build the two deny-right lines. secedit expects SIDs prefixed with '*'.
            var accountList = string.Join(",", sids.Select(s => "*" + s));

            var inf = new StringBuilder();
            inf.AppendLine("[Unicode]");
            inf.AppendLine("Unicode=yes");
            inf.AppendLine("[Version]");
            inf.AppendLine("signature=\"$CHICAGO$\"");
            inf.AppendLine("Revision=1");
            inf.AppendLine("[Privilege Rights]");
            inf.AppendLine("SeDenyNetworkLogonRight = " + accountList);
            inf.AppendLine("SeDenyRemoteInteractiveLogonRight = " + accountList);

            try
            {
                File.WriteAllText(infPath, inf.ToString(), new UTF8Encoding(true));

                // net48 has no ProcessStartInfo.ArgumentList; build a quoted argument string.
                // All path values are Sentinel-controlled temp paths (no untrusted input), and
                // each is wrapped in double quotes to survive spaces.
                string args = string.Join(" ", new[]
                {
                    "/configure",
                    "/db",    Quote(dbPath),
                    "/cfg",   Quote(infPath),
                    "/areas", "USER_RIGHTS",
                    "/log",   Quote(logPath),
                    "/quiet"
                });

                var psi = new ProcessStartInfo
                {
                    FileName = "secedit.exe",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    proc.WaitForExit(30000);
                    if (proc.ExitCode == 0)
                        _logger.LogWarning("[RemoteLogonHardeningGuard] Denied network + RDP logon for {Count} local admin account(s)", sids.Count);
                    else
                        _logger.LogDebug("[RemoteLogonHardeningGuard] secedit exit code {Code}", proc.ExitCode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RemoteLogonHardeningGuard] DenyRemoteLogon (secedit) failed");
            }
            finally
            {
                try { if (File.Exists(infPath)) File.Delete(infPath); } catch { }
                try { if (File.Exists(dbPath)) File.Delete(dbPath); } catch { }
                try { if (File.Exists(logPath)) File.Delete(logPath); } catch { }
            }
        }

        /// <summary>
        /// Resolves SIDs of enabled local accounts that are members of the local
        /// Administrators group, plus the built-in Administrator (RID 500). Domain accounts
        /// and Microsoft-linked accounts are still local admins here if group members; we deny
        /// remote logon for any local admin-class principal.
        /// </summary>
        private List<string> GetLocalAdminAccountSids()
        {
            var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var machine = new System.DirectoryServices.DirectoryEntry("WinNT://.");
                foreach (System.DirectoryServices.DirectoryEntry child in machine.Children)
                {
                    try
                    {
                        if (child.SchemaClassName != "User") continue;

                        if (child.Properties["objectSid"].Value is not byte[] sidBytes) continue;
                        var sid = new System.Security.Principal.SecurityIdentifier(sidBytes, 0).Value;

                        // Built-in Administrator (RID 500) is always in scope.
                        bool isBuiltinAdmin = sid.EndsWith("-500", StringComparison.Ordinal);

                        // Enabled?
                        bool disabled = false;
                        if (child.Properties["UserFlags"].Value is int flags)
                            disabled = (flags & 0x0002) != 0;

                        if (isBuiltinAdmin || (!disabled && IsLocalAdmin(child.Name)))
                            sids.Add(sid);
                    }
                    catch { }
                    finally { child.Dispose(); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RemoteLogonHardeningGuard] GetLocalAdminAccountSids failed");
            }
            return sids.ToList();
        }

        private bool IsLocalAdmin(string userName)
        {
            try
            {
                // Well-known Administrators group SID S-1-5-32-544 -> resolve local name.
                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var adminsName = ((System.Security.Principal.NTAccount)adminsSid.Translate(
                    typeof(System.Security.Principal.NTAccount))).Value;
                var groupLeaf = adminsName.Contains('\\') ? adminsName.Split('\\')[1] : adminsName;

                using var group = new System.DirectoryServices.DirectoryEntry($"WinNT://./{groupLeaf},group");
                var members = (System.Collections.IEnumerable?)group.Invoke("Members");
                if (members == null) return false;
                foreach (var m in members)
                {
                    using var member = new System.DirectoryServices.DirectoryEntry(m);
                    if (string.Equals(member.Name, userName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
        }

        // 
        // LSA interop (scoped to this guard; used only to clear the DefaultPassword secret)
        // 
        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        // PrivateData = IntPtr.Zero deletes the secret.
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaStorePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            IntPtr PrivateData);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        private const uint POLICY_CREATE_SECRET = 0x00000020;

        private static LSA_UNICODE_STRING CreateLsaString(string value)
        {
            var lsaStr = new LSA_UNICODE_STRING
            {
                Length = (ushort)(value.Length * 2),
                MaximumLength = (ushort)((value.Length + 1) * 2),
                Buffer = Marshal.StringToHGlobalUni(value)
            };
            return lsaStr;
        }

        // Wrap a path in double quotes and escape any embedded quotes for a safe command line.
        private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";
    }
}
