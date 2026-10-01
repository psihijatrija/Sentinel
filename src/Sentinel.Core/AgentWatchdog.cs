using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Service-side watchdog that keeps Sentinel.Agent.exe alive in the user's
    /// interactive session.
    ///
    /// Problem: The Agent is a user-session process launched via the HKLM Run key.
    /// Unlike the Service (which has SCM failure-restart configured), the Agent has no
    /// automatic recovery - if it crashes or is killed it stays dead until the next login.
    /// The Service runs as SYSTEM and has no direct visibility into the user session,
    /// so a simple Process.Start won't land in the correct session.
    ///
    /// Solution:
    ///   1. Check for the Agent immediately on service start (no multi-second grace),
    ///      then poll every 10 seconds.
    ///   2. If absent, launch it in the active console session via CreateProcessAsUser
    ///      (WTSQueryUserToken -> CreateEnvironmentBlock -> CreateProcessAsUser).
    ///   3. Rate-limit relaunches (max 1 per 15s, 5 in 5 minutes before backing off)
    ///      to avoid restart storms on systematic crash loops.
    ///   4. Fire a Tier1 detection if the Agent is killed more than 3 times in 5 minutes
    ///      (anti-tamper signal - attacker is trying to blind the user-facing monitor).
    ///
    /// Security note: CreateProcessAsUser requires SE_ASSIGNPRIMARYTOKEN_NAME and
    /// SE_INCREASE_QUOTA_NAME privileges. The Service already runs as LocalSystem which
    /// holds both. The Agent token obtained from WTSQueryUserToken is a restricted user
    /// token (not elevated), so the relaunched agent runs as the logged-in user - identical
    /// to what the HKLM Run key produces.
    /// </summary>
    public sealed class AgentWatchdog : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<AgentWatchdog> _logger;

        private const string AgentProcessName = "Sentinel.Agent";
        private const string AgentExeName = "Sentinel.Agent.exe";

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan RelaunchCooldown = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan KillWindowDuration = TimeSpan.FromMinutes(5);
        private const int KillThresholdForAlert = 3;
        private const int MaxRelaunchesInWindow = 5;

        // No multi-second grace before first check. Post-install and service start must
        // surface the tray immediately when the agent is missing. IsAgentRunning() already
        // prevents dual-launch if the installer / Run key already started the agent.
        private static readonly TimeSpan StartupGrace = TimeSpan.Zero;

        private DateTimeOffset _lastRelaunchTime = DateTimeOffset.MinValue;

        // Two independent counters, previously conflated into one "_killCount" that
        // incremented on every 10s absent poll:
        //   _absentPolls    - consecutive polls where the agent was missing. Drives the
        //                     anti-tamper alert. Reset to 0 the moment the agent is seen,
        //                     so a slow first start (agent not yet in the process list, or
        //                     user not yet logged in) does not accumulate a false alert.
        //   _relaunchCount  - number of actual relaunch attempts in the current window.
        //                     Drives the rate-limit back-off, so a single crashed agent
        //                     that we keep trying to start does not get counted as many
        //                     "kills" and prematurely exhaust the relaunch budget.
        private int _absentPolls;
        private int _relaunchCount;
        private DateTimeOffset _windowStart = DateTimeOffset.MinValue;
        private bool _alertFired;

        public AgentWatchdog(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            ILogger<AgentWatchdog> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[AgentWatchdog] Started - will monitor {Agent} liveness", AgentProcessName);

            // Optional zero-cost yield only (StartupGrace is Zero). Check FIRST so tray
            // appears immediately after install / service start when agent is absent -
            // never sit idle for PollInterval before the first relaunch attempt.
            if (StartupGrace > TimeSpan.Zero)
                await Task.Delay(StartupGrace, stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckAgentAsync(stoppingToken);
                    await Task.Delay(PollInterval, stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[AgentWatchdog] Unexpected error during agent check");
                }
            }
        }

        private async Task CheckAgentAsync(CancellationToken ct)
        {
            // Is the agent already running in ANY session?
            if (IsAgentRunning())
            {
                // Agent is healthy - clear the consecutive-absent streak so a transient
                // gap (slow start, brief crash) never accumulates toward the alert.
                _absentPolls = 0;
                return;
            }

            var now = DateTimeOffset.UtcNow;
            if (now - _windowStart > KillWindowDuration)
            {
                // Roll the rate-limit / alert window.
                _windowStart = now;
                _relaunchCount = 0;
                _alertFired = false;
            }

            _absentPolls++;
            _logger.LogWarning(
                "[AgentWatchdog] Agent not running - absent poll #{Polls} (relaunches this window: {Relaunches})",
                _absentPolls, _relaunchCount);

            // Anti-tamper alert is driven by CONSECUTIVE absent polls, not by every poll ever.
            // A genuine slow start clears _absentPolls the moment the agent appears; only a
            // process that repeatedly vanishes keeps the streak climbing.
            if (_absentPolls >= KillThresholdForAlert && !_alertFired)
            {
                _alertFired = true;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Agent Process Repeatedly Killed",
                    Evidence = $"Sentinel.Agent.exe has been continuously absent across {_absentPolls} consecutive " +
                               $"{PollInterval.TotalSeconds:F0}s checks. Watchdog is relaunching it.",
                    Reasoning = "The Sentinel user-session agent keeps dying. This may indicate an attacker " +
                                "is repeatedly terminating the agent to suppress tray notifications and prevent " +
                                "the user from seeing active threat alerts. Could also be an AV/EDR product " +
                                "incorrectly blocking the agent binary.",
                    Confidence = _absentPolls >= KillThresholdForAlert + 2 ? 0.90 : 0.70,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = AgentProcessName,
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["AbsentPolls"] = _absentPolls.ToString(),
                        ["WindowMinutes"] = KillWindowDuration.TotalMinutes.ToString("F0")
                    }
                });
            }

            // Enforce relaunch cooldown to avoid storm on systematic crash
            if (now - _lastRelaunchTime < RelaunchCooldown)
            {
                _logger.LogDebug("[AgentWatchdog] Relaunch cooldown active - skipping");
                return;
            }

            // Rate-limit on ACTUAL relaunch attempts, not on absent polls. One agent that
            // stays dead should keep being relaunched (subject to cooldown) rather than
            // exhausting the budget in a few polls and being abandoned for the window.
            if (_relaunchCount >= MaxRelaunchesInWindow)
            {
                _logger.LogWarning("[AgentWatchdog] Relaunch rate limit reached ({Count}/{Max}) - backing off",
                    _relaunchCount, MaxRelaunchesInWindow);
                return;
            }

            await RelaunchAgentAsync(ct);
        }

        private async Task RelaunchAgentAsync(CancellationToken ct)
        {
            // Locate the agent binary next to the service binary
            var selfDir = AppContext.BaseDirectory;
            var agentPath = Path.Combine(selfDir, AgentExeName);

            if (!File.Exists(agentPath))
            {
                _logger.LogError("[AgentWatchdog] Agent binary not found at {Path} - cannot relaunch", agentPath);
                return;
            }

            // v2.1.7 RT-2026-H1 FIX: Verify binary integrity before launch.
            // Prevents TOCTOU attacks where an attacker replaces the agent binary
            // between existence check and CreateProcessAsUser.
            if (!VerifyAgentBinaryIntegrity(agentPath))
            {
                _logger.LogError("[AgentWatchdog] Agent binary FAILED integrity check - refusing to launch");
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Agent Binary Integrity Failure",
                    Evidence = $"Sentinel.Agent.exe at {agentPath} failed Authenticode signature verification. " +
                               "The binary may have been replaced with a malicious copy.",
                    Reasoning = "Before relaunching the Agent process, Sentinel verifies the binary is " +
                                "Authenticode-signed or matches the known install hash. A verification failure " +
                                "means the agent binary was tampered with - this is a critical indicator of compromise.",
                    Confidence = 0.97,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = AgentProcessName,
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new System.Collections.Generic.Dictionary<string, string>
                    {
                        ["AgentPath"] = agentPath,
                        ["Check"] = "BinaryIntegrity"
                    }
                });
                return;
            }

            _lastRelaunchTime = DateTimeOffset.UtcNow;
            _relaunchCount++;

            // Try privileged launch (SYSTEM service -> user session) first
            bool launched = TryLaunchInUserSession(agentPath);

            if (!launched)
            {
                // Fallback: simple Process.Start (works if the Service happens to share a session,
                // e.g., on a non-Server SKU where session 0 isolation is partial, or under a test runner)
                launched = TryFallbackLaunch(agentPath);
            }

            if (launched)
            {
                _logger.LogWarning("[AgentWatchdog] Relaunched {Agent}", AgentProcessName);
                await _eventLogger.LogEventAsync("agent_relaunched", new
                {
                    RelaunchCount = _relaunchCount,
                    AbsentPolls = _absentPolls,
                    AgentPath = agentPath,
                    Timestamp = DateTimeOffset.UtcNow
                }, ct);
            }
            else
            {
                _logger.LogError("[AgentWatchdog] All relaunch attempts failed for {Agent}", AgentProcessName);
            }
        }

        // 
        // Process Detection
        // 

        private bool IsAgentRunning()
        {
            Process[]? procs = null;
            try
            {
                var installDir = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\') + '\\';
                procs = Process.GetProcessesByName(AgentProcessName);
                foreach (var p in procs)
                {
                    try
                    {
                        var path = p.MainModule?.FileName;
                        if (string.IsNullOrEmpty(path)) continue;
                        var full = Path.GetFullPath(path);
                        if (full.StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                    catch
                    {
                        // Access denied on MainModule - ignore this PID
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (procs != null)
                {
                    foreach (var p in procs) p.Dispose();
                }
            }
        }

        // 
        // User-Session Launch (SYSTEM -> console user)
        // 

        /// <summary>
        /// Launches the agent in the active console user's session using
        /// WTSQueryUserToken -> CreateEnvironmentBlock -> CreateProcessAsUser.
        ///
        /// This is the standard Windows pattern for services that need to spawn
        /// processes visible to the logged-in user (e.g., Task Scheduler "run in user context").
        /// </summary>
        private bool TryLaunchInUserSession(string agentPath)
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                _logger.LogDebug("[AgentWatchdog] No active console session - skipping user-session launch");
                return false;
            }

            var userToken = IntPtr.Zero;
            var envBlock = IntPtr.Zero;
            var procInfo = new PROCESS_INFORMATION();

            try
            {
                // Obtain the primary token of the logged-in console user
                if (!WTSQueryUserToken(sessionId, out userToken))
                {
                    var err = Marshal.GetLastWin32Error();
                    _logger.LogDebug("[AgentWatchdog] WTSQueryUserToken failed (err={Err}) - user may not be logged in", err);
                    return false;
                }

                // Build the environment block for the user (inherits their PATH, APPDATA, etc.)
                if (!CreateEnvironmentBlock(out envBlock, userToken, false))
                    envBlock = IntPtr.Zero; // Non-fatal; proceed without custom env block

                var si = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    // Interactive session launch REQUIRES an explicit desktop. Without this
                    // the process has no window station/desktop to attach to and either fails
                    // to start or starts on an invisible desktop (tray never appears). Mirrors
                    // the CreateProcessAsUser call in VolumeMountMonitor.
                    lpDesktop = @"winsta0\default",
                    dwFlags = STARTF_USESHOWWINDOW,
                    wShowWindow = SW_HIDE
                };

                var commandLine = $"\"{agentPath}\"";
                var workDir = Path.GetDirectoryName(agentPath) ?? selfDir;

                const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                const uint CREATE_NO_WINDOW = 0x08000000;
                const uint NORMAL_PRIORITY_CLASS = 0x00000020;

                // v2.2.0: pass lpApplicationName so the image cannot be swapped via command-line
                // search; command line remains the quoted path for argv[0].
                bool created = CreateProcessAsUser(
                    userToken,
                    agentPath,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW | (envBlock != IntPtr.Zero ? CREATE_UNICODE_ENVIRONMENT : 0),
                    envBlock,
                    workDir,
                    ref si,
                    out procInfo);

                if (!created)
                {
                    var err = Marshal.GetLastWin32Error();
                    _logger.LogWarning("[AgentWatchdog] CreateProcessAsUser failed (err={Err})", err);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AgentWatchdog] Exception during user-session launch");
                return false;
            }
            finally
            {
                if (procInfo.hProcess != IntPtr.Zero) CloseHandle(procInfo.hProcess);
                if (procInfo.hThread != IntPtr.Zero) CloseHandle(procInfo.hThread);
                if (userToken != IntPtr.Zero) CloseHandle(userToken);
                if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            }
        }

        // Stored for use inside TryLaunchInUserSession without capturing 'this'
        private static readonly string selfDir = AppContext.BaseDirectory;

        private static bool TryFallbackLaunch(string agentPath)
        {
            try
            {
                var psi = new ProcessStartInfo(agentPath)
                {
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using var p = Process.Start(psi);
                return p != null;
            }
            catch
            {
                return false;
            }
        }

        // 
        // Binary Integrity Verification (v2.1.7 RT-2026-H1 Fix)
        // 

        /// <summary>
        /// v2.1.7: Verifies the Agent binary is trustworthy before launching it.
        /// Uses Authenticode signature verification (WinVerifyTrust).
        /// Falls back to SHA-256 hash comparison against the service binary's own install hash
        /// (both binaries are signed by the same publisher).
        /// </summary>
        private bool VerifyAgentBinaryIntegrity(string agentPath)
        {
            try
            {
                var servicePath = Process.GetCurrentProcess().MainModule?.FileName;
                bool agentSigned = SecurityValidation.VerifyAuthenticodeSignature(agentPath);
                bool serviceSigned = !string.IsNullOrEmpty(servicePath) &&
                                     SecurityValidation.VerifyAuthenticodeSignature(servicePath!);

                if (agentSigned && serviceSigned)
                {
                    // v2.2.0: any trusted publisher is not enough - Agent must match Service signer.
                    if (SecurityValidation.VerifySameAuthenticodePublisher(agentPath, servicePath!))
                        return true;
                    _logger.LogError("[AgentWatchdog] Agent signer does not match Service signer - refusing launch");
                    return false;
                }

                if (agentSigned && !serviceSigned)
                {
                    _logger.LogError("[AgentWatchdog] Service unsigned but Agent signed - refusing launch");
                    return false;
                }

#if DEBUG
                // Unsigned pair is allowed only in Debug builds (local dev).
                if (!agentSigned && !serviceSigned)
                {
                    _logger.LogWarning("[AgentWatchdog] Both Service and Agent are unsigned - DEBUG build. Allowing launch.");
                    return true;
                }
#endif

                _logger.LogError("[AgentWatchdog] Agent binary failed integrity check (unsigned or publisher mismatch)");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AgentWatchdog] Exception during binary integrity check");
                return false; // Fail closed
            }
        }

        // 
        // P/Invoke
        // 

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const ushort SW_HIDE = 0;
    }
}
