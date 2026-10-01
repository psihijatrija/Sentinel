using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Self-protection against tampering:
    ///
    /// 1. Binary integrity - alerts if Sentinel's own executable is deleted/replaced while running
    /// 2. Anti-suspend detection - monitors execution timing; fires if a gap exceeds threshold
    ///    (indicates NtSuspendProcess was used to freeze Sentinel while attacker operates)
    /// 3. Service reinstall - if Sentinel's service registry key is deleted, re-registers via native SCM P/Invoke
    /// 4. Last-gasp logging - on unexpected exit, writes final state to last_gasp.jsonl
    /// 5. FIPS Algorithm Policy enforcement - detects and disables GP-reenabled FIPS every check cycle
    ///
    /// Scan interval: 2 seconds for timing (anti-suspend), 10 seconds for binary/service/FIPS checks.
    /// </summary>
    public sealed class AntiTamperGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<AntiTamperGuard> _logger;
        private readonly SentinelConfig _config;

        private const string ServiceName = "Sentinel";
        // HARDENING: Lowered from 10s to 4s (2x tick interval). An attacker suspending
        // Sentinel for 9s had a full operating window undetected. Now any suspension
        // beyond 4s (double the expected 2s tick) triggers the alert.
        private const int SuspendThresholdMs = 4_000;
        private readonly int _timingTickMs;
        private readonly int _integrityTickMs;

        private DateTimeOffset _lastTick = DateTimeOffset.UtcNow;
        private readonly string? _ownExePath;
        private readonly string _lastGaspPath;
        private bool _exitHandlerRegistered;
        private bool _serviceAlertSuppressed; // Only alert once about missing service registration
        private bool _systemJustResumed;
        // HARDENING v1.5.9: Track ActiveResponse state to detect tampering.
        // If ActiveResponse transitions from true to false at runtime, fire anti-tamper.
        private bool _activeResponseLastKnown;
        // v1.6.0: Boot-time ActiveResponse=false was force-enabled; alert pending on first integrity tick
#pragma warning disable CS0169
        private bool _bootActiveResponseForcePending;
        private bool _bootActiveResponseAlerted;
#pragma warning restore CS0169
        private string? _encryptedConfigHash;

        // v2.1.7 RT-2026-H3: SHA-256 hash of own binary at startup for replacement detection
        private readonly string? _ownBinaryBaselineHash;

        // HARDENING: QueryPerformanceCounter as secondary time source.
        // DateTime/DateTimeOffset can be manipulated by usermode time adjustment (SetSystemTime).
        // QPC is monotonic and hardware-driven - immune to clock skew attacks.
        private long _lastPerfCount;
        private readonly long _perfFrequency;

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern bool QueryPerformanceFrequency(out long lpFrequency);

        //  Native SCM P/Invoke (replaces sc.exe shelling) 
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(IntPtr hService, uint dwServiceType, uint dwStartType,
            uint dwErrorControl, string? lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword, string? lpDisplayName);

        [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_CHANGE_CONFIG = 0x0002;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x10;
        private const uint SERVICE_AUTO_START = 0x02;
        private const uint SERVICE_ERROR_NORMAL = 0x01;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

        public AntiTamperGuard(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            SentinelConfig config,
            ILogger<AntiTamperGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _config = config;
            _logger = logger;
            _ownExePath = System.Net48Environment.ProcessPath;
            _lastGaspPath = Path.Combine(
                Path.GetDirectoryName(_eventLogger.LogFilePath) ?? AppContext.BaseDirectory,
                "last_gasp.jsonl");
            
            _timingTickMs = config.AntiTamperTimingTickMs > 0 ? config.AntiTamperTimingTickMs : 2000;
            _integrityTickMs = config.AntiTamperIntegrityTickMs > 0 ? config.AntiTamperIntegrityTickMs : 10000;
            _activeResponseLastKnown = config.ActiveResponse;

            // Initialize QPC baseline
            QueryPerformanceFrequency(out _perfFrequency);
            QueryPerformanceCounter(out _lastPerfCount);

            // v2.0.4: Capture initial encrypted config hash for integrity monitoring
            _encryptedConfigHash = TryHashEncryptedConfig();

            // v2.1.7 RT-2026-H3: Capture SHA-256 hash of own binary at startup
            _ownBinaryBaselineHash = TryHashOwnBinary();
        }

        public override Task StartAsync(CancellationToken cancellationToken)
        {
            try
            {
                Microsoft.Win32.SystemEvents.PowerModeChanged += OnPowerModeChanged;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Failed to subscribe to PowerModeChanged events");
            }

            // v1.6.0: Enforce ActiveResponse at process start (closes reboot/config-file bypass)
            EnforceActiveResponseAtStartup();

            return base.StartAsync(cancellationToken);
        }

        /// <summary>
        /// v2.0.4: ActiveResponse is always true (compile-time constant). This method is now a no-op
        /// retained for structural compatibility. The property cannot be disabled.
        /// </summary>
        private void EnforceActiveResponseAtStartup()
        {
            // v2.0.4: ActiveResponse has no off switch - nothing to enforce.
            _activeResponseLastKnown = true;
        }

        public override void Dispose()
        {
            try
            {
                Microsoft.Win32.SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            }
            catch { }
            base.Dispose();
        }

        private void OnPowerModeChanged(object sender, Microsoft.Win32.PowerModeChangedEventArgs e)
        {
            if (e.Mode == Microsoft.Win32.PowerModes.Resume)
            {
                _logger.LogInformation("[AntiTamperGuard] System resume detected; suppressing anti-suspend alarm for next tick");
                _systemJustResumed = true;
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[AntiTamperGuard] Started - monitoring binary integrity, timing, and service registration");

            // Register exit handler for last-gasp logging
            RegisterExitHandler();

            int tickCounter = 0;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_timingTickMs, stoppingToken);
                    tickCounter++;

                    // === Anti-Suspend Detection ===
                    var now = DateTimeOffset.UtcNow;
                    var elapsed = (now - _lastTick).TotalMilliseconds;
                    _lastTick = now;

                    // HARDENING: Use QPC as secondary/authoritative time source.
                    // An attacker might manipulate system clock to hide the gap from
                    // DateTimeOffset, but QPC is hardware-monotonic and unaffected.
                    double qpcElapsedMs = 0;
                    if (_perfFrequency > 0)
                    {
                        QueryPerformanceCounter(out long currentPerfCount);
                        qpcElapsedMs = (currentPerfCount - _lastPerfCount) * 1000.0 / _perfFrequency;
                        _lastPerfCount = currentPerfCount;
                    }

                    // Use the LARGER of DateTime and QPC elapsed - prevents clock manipulation
                    elapsed = Math.Max(elapsed, qpcElapsedMs);

                    if (_systemJustResumed)
                    {
                        _systemJustResumed = false;
                        elapsed = 0;
                    }

                    // If elapsed time is significantly more than expected, we were suspended
                    if (elapsed > SuspendThresholdMs)
                    {
                        var gapSeconds = elapsed / 1000.0;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Process Suspended",
                            Evidence = $"Execution gap of {gapSeconds:F1}s detected (expected ~{_timingTickMs / 1000.0:F1}s). " +
                                       $"Sentinel was likely suspended via NtSuspendProcess.",
                            Reasoning = "The Sentinel service experienced a timing gap far exceeding its " +
                                        $"expected tick interval ({gapSeconds:F1}s actual). This indicates the process was " +
                                        "suspended by an external actor using NtSuspendProcess/NtSuspendThread. " +
                                        "Attackers suspend EDR processes to operate undetected during the freeze window. " +
                                        "This is a high-confidence indicator of active compromise.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Can't kill ourselves; alert is the response
                            ProcessName = "Sentinel.Service",
                            ProcessId = System.Net48Environment.ProcessId,
                            Metadata = new Dictionary<string, string>
                            {
                                ["GapSeconds"] = gapSeconds.ToString("F1"),
                                ["ExpectedTickMs"] = _timingTickMs.ToString()
                            }
                        });
                    }

                    // === Binary & Service Checks (dynamic check based on integrity / timing ratio) ===
                    int ticksPerCheck = Math.Max(1, _integrityTickMs / _timingTickMs);
                    if (tickCounter % ticksPerCheck == 0)
                    {
                        await CheckBinaryIntegrity();
                        await CheckServiceRegistration();
                        await CheckActiveResponseConfig();
                        await CheckEncryptedConfigIntegrity();
                        await CheckAndEnforceQosPolicies();
                        // v2.0.4 HIGH-4: Removed EnforceFipsDisabled() - an EDR must not
                        // weaken system cryptographic posture.
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[AntiTamperGuard] Error");
                    try { await Task.Delay(5000, stoppingToken); } catch { break; }
                }
            }
        }

        /// <summary>
        /// v2.1.7 RT-2026-H3 FIX: Checks if our own binary still exists AND hasn't been replaced.
        /// Uses SHA-256 hash comparison against the startup-time baseline hash.
        /// If the binary is deleted or its hash changes, it's a tampering attempt.
        /// </summary>
        private async Task CheckBinaryIntegrity()
        {
            if (_ownExePath == null) return;

            if (!File.Exists(_ownExePath))
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Sentinel Binary Deleted",
                    Evidence = $"Sentinel executable no longer exists at: {_ownExePath}",
                    Reasoning = "The Sentinel service binary has been deleted from disk while the service " +
                                "is still running. This is a direct tampering attempt - the attacker wants " +
                                "to ensure Sentinel cannot restart after a reboot or service crash.",
                    Confidence = 0.99,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });
                return;
            }

            // v2.1.7: Hash-based binary replacement detection
            try
            {
                if (_ownBinaryBaselineHash != null)
                {
                    using var stream = new FileStream(_ownExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    var currentHash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();

                    if (!string.Equals(currentHash, _ownBinaryBaselineHash, StringComparison.Ordinal))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Sentinel Binary Replaced",
                            Evidence = $"Sentinel binary hash has changed since startup. " +
                                       $"Path: {_ownExePath}. Expected: {_ownBinaryBaselineHash?.Substring(0, 16)}..., " +
                                       $"Got: {currentHash.Substring(0, 16)}...",
                            Reasoning = "The on-disk Sentinel service binary has been replaced while the service " +
                                        "is still running in memory. An attacker has modified the binary so that " +
                                        "on next restart, their malicious version runs as SYSTEM. This is a critical " +
                                        "persistence mechanism - the attacker replaces the EDR with their own code.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new System.Collections.Generic.Dictionary<string, string>
                            {
                                ["ExpectedHash"] = _ownBinaryBaselineHash ?? "unknown",
                                ["ActualHash"] = currentHash,
                                ["BinaryPath"] = _ownExePath
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Error hashing binary for integrity check");
            }
        }

        /// <summary>
        /// v2.0.4: ActiveResponse is a compile-time constant (always true). This check is now
        /// a no-op. Retained as a stub for structural compatibility with the tick loop.
        /// </summary>
        private Task CheckActiveResponseConfig()
        {
            // v2.0.4: ActiveResponse has no off switch - nothing to check.
            _activeResponseLastKnown = true;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Monitors DPAPI config.enc hash. Disk JSON host files are not loaded
        /// and are not a config source.
        /// </summary>
        private async Task CheckEncryptedConfigIntegrity()
        {
            try
            {
                var currentHash = TryHashEncryptedConfig();
                if (currentHash == null) return;

                if (_encryptedConfigHash == null)
                {
                    _encryptedConfigHash = currentHash;
                    return;
                }

                if (!string.Equals(_encryptedConfigHash, currentHash))
                {
                    _logger.LogWarning("[AntiTamperGuard] config.enc hash changed (encrypted config modified on disk).");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Anti-Tamper: Encrypted Config Modified",
                        Evidence = $"config.enc hash changed from {_encryptedConfigHash[..Math.Min(16, _encryptedConfigHash.Length)]}... to {currentHash[..Math.Min(16, currentHash.Length)]}...",
                        Reasoning = "Sentinel DPAPI-encrypted configuration was modified while the service is running. " +
                                    "If not initiated by an administrator via --set-config, this may indicate tampering.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            ["TamperType"] = "EncryptedConfigModified",
                            ["PreviousHashPrefix"] = _encryptedConfigHash[..Math.Min(16, _encryptedConfigHash.Length)],
                            ["CurrentHashPrefix"] = currentHash[..Math.Min(16, currentHash.Length)]
                        }
                    });

                    _encryptedConfigHash = currentHash;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Config integrity check failed");
            }
        }

        private static string? TryHashEncryptedConfig()
        {
            try
            {
                var path = EncryptedConfigStore.DefaultConfigPath;
                if (!File.Exists(path)) return null;
                var bytes = File.ReadAllBytes(path);
                return ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(bytes));
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// v2.1.7 RT-2026-H3: Computes SHA-256 of the running Sentinel binary at startup.
        /// Used as baseline for periodic integrity checks (detects binary replacement).
        /// </summary>
        private string? TryHashOwnBinary()
        {
            try
            {
                if (_ownExePath == null || !File.Exists(_ownExePath)) return null;
                using var stream = new FileStream(_ownExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sha = System.Security.Cryptography.SHA256.Create();
                var hash = sha.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Failed to hash own binary at startup");
                return null;
            }
        }

        /// <summary>
        /// Checks if the Sentinel Windows service is still registered.
        /// If the service registry key was deleted, re-register it via SCM.
        /// Attackers delete services to prevent auto-restart.
        /// </summary>
        private async Task CheckServiceRegistration()
        {
            if (_serviceAlertSuppressed) return;

            try
            {
                // Check if service exists via ServiceController
                using var sc = new ServiceController(ServiceName);
                _ = sc.Status; // Throws InvalidOperationException if service doesn't exist

                // Enforce start type is Automatic so attackers cannot disable it
                if (sc.StartType != ServiceStartMode.Automatic)
                {
                    try
                    {
                        // v1.5.4: Native SCM P/Invoke - no sc.exe dependency
                        SetServiceStartTypeNative(ServiceName, SERVICE_AUTO_START);
                        _logger.LogWarning("[AntiTamperGuard] Enforced service '{Service}' StartType back to Automatic.", ServiceName);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[AntiTamperGuard] Failed to enforce service StartType");
                    }
                }
            }
            catch (InvalidOperationException)
            {
                _serviceAlertSuppressed = true; // Only alert once

                // Service registration is gone - attempt re-register
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Service Registration Deleted",
                    Evidence = $"Windows service '{ServiceName}' is no longer registered in SCM",
                    Reasoning = "The Sentinel service registration was removed from the Service Control Manager " +
                                "while the service is still running. This prevents automatic restart on boot. " +
                                "Attempting to re-register.",
                    Confidence = 0.98,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });

                // Attempt to re-register using native SCM P/Invoke (no LOLBin dependency)
                if (_ownExePath != null)
                {
                    try
                    {
                        CreateServiceNative(ServiceName, "Sentinel", _ownExePath);
                        _logger.LogWarning("[AntiTamperGuard] Re-registered service '{Service}' via native SCM API", ServiceName);
                        // Reset the suppression flag so we can detect and fix subsequent deletions
                        _serviceAlertSuppressed = false;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[AntiTamperGuard] Failed to re-register service");
                    }
                }
            }
            catch { } // Service exists - all good
        }

        /// <summary>
        /// Registers handlers that write a last-gasp log entry on unexpected exit.
        /// This captures final state before crash/kill for forensic analysis.
        /// </summary>
        private void RegisterExitHandler()
        {
            if (_exitHandlerRegistered) return;
            _exitHandlerRegistered = true;

            AppDomain.CurrentDomain.ProcessExit += (_, _) => WriteLastGasp("ProcessExit");
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                WriteLastGasp($"UnhandledException: {(args.ExceptionObject as Exception)?.Message ?? "unknown"}");
        }

        private void WriteLastGasp(string reason)
        {
            // Uptime is best-effort; a dying process may already have lost access to its own
            // Process handle, so guard it independently of the rest of the record.
            string uptime;
            try
            {
                uptime = (DateTimeOffset.UtcNow - Process.GetCurrentProcess().StartTime.ToUniversalTime()).ToString();
            }
            catch { uptime = "unknown"; }

            var pid = System.Net48Environment.ProcessId;

            // Always write the raw last-gasp line (unchanged forensic behavior).
            try
            {
                var entry = System.Text.Json.JsonSerializer.Serialize(new
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Reason = reason,
                    ProcessId = pid,
                    Uptime = uptime,
                    LastTick = _lastTick
                });
                File.AppendAllText(_lastGaspPath, entry + Environment.NewLine);
            }
            catch { } // Best-effort - we're dying

            // B1: classify the stop and record it durably in the append-only audit trail.
            // Expected (cooperative SCM stop / OS shutdown / upgrade / uninstall) -> lifecycle event.
            // Otherwise -> suspected tamper suppression (alert-before-suppression).
            try
            {
                if (ShutdownContext.IsExpected)
                {
                    _eventLogger.LogServiceStopExpected(
                        reason: $"{reason}; expected={ShutdownContext.Reason}",
                        processId: pid,
                        uptime: uptime);
                }
                else
                {
                    var classification =
                        "Sentinel exited without a cooperative shutdown signal (no SCM Stop, OS " +
                        "shutdown, upgrade, or uninstall was recorded). Consistent with a possible " +
                        "tamper stop or process kill while the service was still registered.";

                    _eventLogger.LogServiceStopSuspected(
                        reason: reason,
                        processId: pid,
                        uptime: uptime,
                        lastTick: _lastTick,
                        classification: classification);

                    // Emit a Tier1 LogOnly AntiTamper detection IF the engine is still reachable.
                    // On a dying process this is best-effort; the audit-log write above is the
                    // durable fallback. Fire-and-forget so we never block the exit hook.
                    try
                    {
                        _ = _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Service Stopped Unexpectedly",
                            Evidence = $"Process exit '{reason}' with no expected-shutdown signal (pid {pid}, uptime {uptime}).",
                            Reasoning = classification,
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            SignalType = SignalType.AntiTamper,
                            ProcessName = "SYSTEM",
                            ProcessId = 0
                        });
                    }
                    catch { /* engine may be gone - audit record already written */ }
                }
            }
            catch { } // Best-effort - never throw out of the exit path.
        }

        /// <summary>
        /// Scans Policies\Microsoft\Windows\QoS registry subkeys to detect and delete
        /// any bandwidth throttling rules targeting Sentinel binaries.
        /// </summary>
        private async Task CheckAndEnforceQosPolicies()
        {
            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\QoS", true);
                if (baseKey == null) return;

                foreach (var subkeyName in baseKey.GetSubKeyNames())
                {
                    using var subKey = baseKey.OpenSubKey(subkeyName);
                    if (subKey == null) continue;

                    var appName = subKey.GetValue("App Name") as string;
                    // Match product name
                    if (!string.IsNullOrEmpty(appName) &&
                        appName!.Contains("Sentinel"))
                    {
                        // Found a policy targeting Sentinel! Delete it.
                        baseKey.DeleteSubKeyTree(subkeyName);
                        
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Network QoS Throttling Detected",
                            Evidence = $"Rogue QoS policy '{subkeyName}' targeting '{appName}' was found in registry.",
                            Reasoning = "An attacker attempted to throttle or block Sentinel's network traffic " +
                                        "by writing a policy-based QoS rule to HKLM\\Software\\Policies\\Microsoft\\Windows\\QoS. " +
                                        "This is a common EDR evasion technique to prevent alerts from reaching the cloud. " +
                                        "Sentinel has removed the registry key to restore full network bandwidth.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Healed in-line
                            ProcessName = "SYSTEM",
                            ProcessId = 0
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[AntiTamperGuard] Error checking QoS policies");
            }
        }

        // 
        // Native SCM Helpers (v1.5.4 - replaces sc.exe)
        // 

        /// <summary>
        /// Creates a Windows service via native advapi32 CreateService.
        /// Replaces Process.Start("sc.exe", "create ...") to eliminate LOLBin dependency.
        /// </summary>
        private static void CreateServiceNative(string serviceName, string displayName, string binaryPath)
        {
            var scmHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var serviceHandle = CreateService(
                    scmHandle,
                    serviceName,
                    displayName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binaryPath,
                    null,
                    IntPtr.Zero,
                    null,
                    null, // LocalSystem
                    null);

                if (serviceHandle == IntPtr.Zero)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

                CloseServiceHandle(serviceHandle);
            }
            finally
            {
                CloseServiceHandle(scmHandle);
            }
        }

        /// <summary>
        /// Changes a service's start type via native advapi32 ChangeServiceConfig.
        /// Replaces Process.Start("sc.exe", "config ... start=auto").
        /// </summary>
        private static void SetServiceStartTypeNative(string serviceName, uint startType)
        {
            var scmHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var serviceHandle = OpenService(scmHandle, serviceName, SERVICE_CHANGE_CONFIG);
                if (serviceHandle == IntPtr.Zero)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

                try
                {
                    if (!ChangeServiceConfig(
                        serviceHandle,
                        SERVICE_NO_CHANGE,
                        startType,
                        SERVICE_NO_CHANGE,
                        null, null, IntPtr.Zero, null, null, null, null))
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
                finally
                {
                    CloseServiceHandle(serviceHandle);
                }
            }
            finally
            {
                CloseServiceHandle(scmHandle);
            }
        }
    }
}
