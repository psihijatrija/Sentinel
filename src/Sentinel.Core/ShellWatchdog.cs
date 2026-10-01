using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors the Windows shell (explorer.exe) for hangs, crashes, and injection.
    ///
    /// Malware often kills or freezes explorer.exe to:
    ///   - Hide its activity (no taskbar notifications)
    ///   - Prevent user from launching Task Manager via Start menu
    ///   - Cause confusion during cleanup to buy time for C2 exfiltration
    ///   - Inject into explorer for persistence (T1055)
    ///
    /// PlugX specifically can cause cross-process hangs in explorer when it injects
    /// into svchost groups that explorer communicates with (e.g., TokenBroker).
    ///
    /// This watchdog:
    ///   1. Monitors explorer.exe responsiveness via SendMessageTimeout
    ///   2. Detects explorer.exe process termination/absence
    ///   3. Auto-restarts explorer.exe if it dies (user shell recovery)
    ///   4. Detects sustained unresponsiveness and emits high-confidence alerts
    ///   5. Tracks crash frequency - repeated crashes suggest active attack
    ///
    /// Scan interval: 5 seconds (fast response to shell death).
    /// </summary>
    public sealed class ShellWatchdog : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<ShellWatchdog> _logger;

        private int _consecutiveHangs;
        private int _crashCount;
        private DateTimeOffset _lastCrashTime = DateTimeOffset.MinValue;
        private DateTimeOffset _lastRestartTime = DateTimeOffset.MinValue;
        private DateTimeOffset _lastHangEmitUtc = DateTimeOffset.MinValue;
        private int _explorerPid;
        private bool _shellAbsent;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        // Short timeout - SMTO_BLOCK freezes *this* thread for the full timeout when the shell is busy.
        // Under CPU storms, a 3s block every 5s made the agent (and tray) feel dead.
        private static readonly TimeSpan HangTimeout = TimeSpan.FromMilliseconds(800);
        private static readonly TimeSpan RestartCooldown = TimeSpan.FromSeconds(15);
        private static readonly TimeSpan CrashWindowReset = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan HangEmitCooldown = TimeSpan.FromMinutes(5);

        // If explorer crashes more than this in the window, something is actively attacking it
        private const int CrashThresholdForAlert = 3;
        // Consecutive hang checks before alerting (~25s of unresponsiveness at 5s interval)
        private const int HangThresholdForAlert = 5;

        public ShellWatchdog(
            DetectionEngine detectionEngine,
            JsonlEventLogger eventLogger,
            ILogger<ShellWatchdog> logger)
        {
            _detectionEngine = detectionEngine;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ShellWatchdog] Started - waiting for shell initialization");

            // Wait for the shell to fully initialize before monitoring.
            // Explorer's shell window may not exist immediately at logon or agent startup.
            // Without this delay, the watchdog falsely concludes explorer is dead and
            // launches a new instance - which opens a File Explorer window instead of the shell.
            await Task.Delay(TimeSpan.FromSeconds(30), ct);

            // Initial baseline
            _explorerPid = GetExplorerPid();
            if (_explorerPid > 0)
                _logger.LogInformation("[ShellWatchdog] Monitoring explorer.exe PID {Pid}", _explorerPid);
            else
                _logger.LogWarning("[ShellWatchdog] Explorer not found after startup delay - will monitor for appearance");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await CheckShellHealthAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ShellWatchdog] Check error"); }
            }
        }

        private async Task CheckShellHealthAsync(CancellationToken ct)
        {
            var currentPid = GetExplorerPid();

            // === Case 1: Explorer is missing entirely ===
            if (currentPid == 0)
            {
                if (!_shellAbsent)
                {
                    _shellAbsent = true;
                    _crashCount++;
                    _lastCrashTime = DateTimeOffset.UtcNow;

                    _logger.LogWarning("[ShellWatchdog] Explorer.exe not found - shell is dead");

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Shell Watchdog: Explorer Process Terminated",
                        Evidence = $"Explorer.exe (previously PID {_explorerPid}) is no longer running. " +
                                   $"Crash #{_crashCount} in current window.",
                        Reasoning = "The Windows shell process (explorer.exe) has terminated. " +
                                    "This leaves the user without a taskbar, Start menu, or desktop. " +
                                    "Malware may kill explorer to prevent the user from seeing alerts, " +
                                    "opening Task Manager, or noticing suspicious activity.",
                        Confidence = _crashCount >= CrashThresholdForAlert ? 0.85 : 0.55,
                        Tier = _crashCount >= CrashThresholdForAlert
                            ? DetectionTier.Tier1Behavioral
                            : DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "explorer",
                        ProcessId = _explorerPid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CrashCount"] = _crashCount.ToString(),
                            ["PreviousPid"] = _explorerPid.ToString()
                        }
                    });

                    // Auto-restart explorer after cooldown
                    await TryRestartExplorerAsync(ct);
                }
                return;
            }

            // === Case 2: Explorer reappeared (self-restarted or we restarted it) ===
            if (_shellAbsent)
            {
                _shellAbsent = false;
                _explorerPid = currentPid;
                _consecutiveHangs = 0;
                _logger.LogInformation("[ShellWatchdog] Explorer.exe recovered, new PID {Pid}", currentPid);
                return;
            }

            // === Case 3: Explorer PID changed (crash + auto-restart by Windows) ===
            if (currentPid != _explorerPid && _explorerPid > 0)
            {
                _crashCount++;
                _lastCrashTime = DateTimeOffset.UtcNow;
                _logger.LogWarning("[ShellWatchdog] Explorer PID changed {Old} -> {New} (crash #{Count})",
                    _explorerPid, currentPid, _crashCount);

                if (_crashCount >= CrashThresholdForAlert)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Shell Watchdog: Repeated Explorer Crashes",
                        Evidence = $"Explorer.exe has crashed {_crashCount} times in the last " +
                                   $"{CrashWindowReset.TotalMinutes} minutes. PIDs: {_explorerPid} -> {currentPid}",
                        Reasoning = "Repeated explorer.exe crashes indicate possible DLL injection failure, " +
                                    "cross-process manipulation, or malware actively targeting the shell. " +
                                    "PlugX and similar RATs can cause cascading failures in shell-dependent " +
                                    "services (TokenBroker, ShellExperienceHost) through svchost injection.",
                        Confidence = 0.82,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "explorer",
                        ProcessId = currentPid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CrashCount"] = _crashCount.ToString(),
                            ["PreviousPid"] = _explorerPid.ToString(),
                            ["NewPid"] = currentPid.ToString()
                        }
                    });
                }

                _explorerPid = currentPid;
                _consecutiveHangs = 0;
                return;
            }

            // === Case 4: Check if explorer is responsive ===
            bool isResponsive = IsExplorerResponsive(currentPid);

            if (!isResponsive)
            {
                _consecutiveHangs++;
                _logger.LogDebug("[ShellWatchdog] Explorer not responding (hang #{Count})", _consecutiveHangs);

                if (_consecutiveHangs >= HangThresholdForAlert)
                {
                    // Rate-limit: under load SendMessageTimeout fails often; do not flood events.jsonl
                    // (flood -> agent log watcher -> tray STA pressure -> worse shell lag).
                    if (DateTimeOffset.UtcNow - _lastHangEmitUtc >= HangEmitCooldown)
                    {
                        _lastHangEmitUtc = DateTimeOffset.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Shell Watchdog: Explorer Unresponsive",
                            Evidence = $"Explorer.exe (PID {currentPid}) has been unresponsive for " +
                                       $"{_consecutiveHangs * ScanInterval.TotalSeconds}s " +
                                       $"({_consecutiveHangs} consecutive failed message checks).",
                            Reasoning = "Explorer.exe is not responding to window messages. " +
                                        "This indicates a deadlock, cross-process hang (AppHangXProcB1), " +
                                        "or thread injection that blocked the UI thread. " +
                                        "Cross-process hangs occur when explorer calls into an injected/corrupted " +
                                        "COM server (e.g., TokenBroker) that never returns.",
                            Confidence = 0.72,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "explorer",
                            ProcessId = currentPid,
                            Metadata = new Dictionary<string, string>
                            {
                                ["HangDurationSec"] = (_consecutiveHangs * ScanInterval.TotalSeconds).ToString("F0"),
                                ["ConsecutiveHangs"] = _consecutiveHangs.ToString()
                            }
                        });
                    }

                    // Floor so we re-check soon without full threshold reset storms
                    _consecutiveHangs = HangThresholdForAlert - 1;
                }
            }
            else
            {
                _consecutiveHangs = 0;
            }

            // Reset crash counter if window expired
            if (DateTimeOffset.UtcNow - _lastCrashTime > CrashWindowReset)
            {
                _crashCount = 0;
            }
        }

        private async Task TryRestartExplorerAsync(CancellationToken ct)
        {
            if (DateTimeOffset.UtcNow - _lastRestartTime < RestartCooldown)
            {
                _logger.LogDebug("[ShellWatchdog] Restart cooldown active, skipping");
                return;
            }

            _lastRestartTime = DateTimeOffset.UtcNow;

            // Do NOT launch explorer.exe directly - launching it from a background service
            // context without arguments opens a File Explorer window instead of restarting
            // the shell. Windows has its own shell restart mechanism (Winlogon will restart
            // the shell if it detects the user's shell process has died). We just log and wait.
            _logger.LogWarning("[ShellWatchdog] Explorer.exe is dead - waiting for Windows shell auto-recovery");

            await _eventLogger.LogEventAsync("shell_death", new
            {
                CrashCount = _crashCount,
                Timestamp = DateTime.UtcNow,
                Note = "Relying on Windows shell auto-recovery (Winlogon). No manual restart."
            }, ct);
        }

        /// <summary>
        /// Only the shell-window owner counts as the desktop shell.
        /// Never fall back to a random File Explorer window - that caused dual-explorer
        /// PID thrash (false "crashes") and bad hang targeting.
        /// </summary>
        private static int GetExplorerPid()
        {
            try
            {
                var shellWindow = GetShellWindow();
                if (shellWindow == IntPtr.Zero)
                    return 0;

                GetWindowThreadProcessId(shellWindow, out uint shellPid);
                return shellPid == 0 ? 0 : (int)shellPid;
            }
            catch
            {
                return 0;
            }
        }

        private static bool IsExplorerResponsive(int pid)
        {
            try
            {
                var shellWindow = GetShellWindow();
                if (shellWindow == IntPtr.Zero)
                {
                    // No shell window - explorer might be starting up
                    return true;
                }

                GetWindowThreadProcessId(shellWindow, out uint ownerPid);
                if (ownerPid != (uint)pid)
                    return true; // Different process, skip check

                // SMTO_ABORTIFHUNG only - avoid SMTO_BLOCK so a sluggish shell does not
                // freeze the agent thread for the full timeout (tray freeze under load).
                IntPtr result;
                var success = SendMessageTimeout(
                    shellWindow,
                    0x0000, // WM_NULL
                    IntPtr.Zero,
                    IntPtr.Zero,
                    SMTO_ABORTIFHUNG | SMTO_NORMAL,
                    (uint)HangTimeout.TotalMilliseconds,
                    out result);

                return success != IntPtr.Zero;
            }
            catch
            {
                return true;
            }
        }

        #region P/Invoke

        [DllImport("user32.dll")]
        private static extern IntPtr GetShellWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
            uint fuFlags, uint uTimeout, out IntPtr lpdwResult);

        private const uint SMTO_NORMAL = 0x0000;
        private const uint SMTO_ABORTIFHUNG = 0x0002;

        #endregion
    }
}
