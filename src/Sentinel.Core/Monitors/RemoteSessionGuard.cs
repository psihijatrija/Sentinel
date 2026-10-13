// Ported from Credentials/ES.ps1 - terminate unauthorized non-console remote sessions.
// AV-safe: WTS APIs only (no keyboard hooks, no shelling rwinsta/qwinsta when possible).

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Enumerates Terminal Services sessions via WTS and logs off non-console remote
    /// sessions (RDP, ICA, etc.). Complements service disablement of TermService:
    /// if RDP is re-enabled and someone connects, the session is cut within ~5s.
    ///
    /// Never touches:
    ///   - Session 0 (services)
    ///   - The active console session (local interactive user)
    ///   - WTSListen listener stubs (not real user sessions)
    /// </summary>
    public sealed class RemoteSessionGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<RemoteSessionGuard> _logger;

        // Dedup: SessionId -> last alert time
        private readonly ConcurrentDictionary<int, DateTime> _alertedSessions = new();

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        public RemoteSessionGuard(DetectionEngine de, SentinelConfig config, ILogger<RemoteSessionGuard> logger)
        {
            _detectionEngine = de;
            _config = config ?? new SentinelConfig();
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            // v2.5.5: Hardening is always-on - always enforce remote session termination.
            _logger.LogInformation(
                "[RemoteSessionGuard] Active - polling Terminal Services sessions every 5s");

            try { await Task.Delay(TimeSpan.FromSeconds(10), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAndTerminateAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[RemoteSessionGuard] Scan error");
                }

                try { await Task.Delay(PollInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        /// <summary>
        /// Classifies whether a session should be force-logged-off.
        /// Exposed for unit tests (no WTS required).
        /// </summary>
        internal static bool ShouldTerminateSession(
            int sessionId,
            string? winStationName,
            WtsConnectState state,
            uint consoleSessionId)
        {
            // Session 0 = services isolation
            if (sessionId == 0) return false;

            // Local interactive console
            if (sessionId == (int)consoleSessionId) return false;

            // Listener / protocol stubs are not user sessions
            if (state == WtsConnectState.WTSListen) return false;
            if (state == WtsConnectState.WTSInit) return false;
            if (state == WtsConnectState.WTSDown) return false;
            if (state == WtsConnectState.WTSReset) return false;

            var name = (winStationName ?? string.Empty).Trim();
            if (name.Equals("Console")) return false;
            if (name.Equals("Services")) return false;

            // Active/connected/disconnected remote sessions (rdp-tcp#N, ica-tcp#N, etc.)
            return state is WtsConnectState.WTSActive
                or WtsConnectState.WTSConnected
                or WtsConnectState.WTSConnectQuery
                or WtsConnectState.WTSShadow
                or WtsConnectState.WTSDisconnected
                or WtsConnectState.WTSIdle;
        }

        private async Task ScanAndTerminateAsync(CancellationToken ct)
        {
            var consoleId = WTSGetActiveConsoleSessionId();
            if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, out var pSessionInfo, out var count))
                return;

            try
            {
                int structSize = Marshal.SizeOf<WtsSessionInfo>();
                for (int i = 0; i < count; i++)
                {
                    if (ct.IsCancellationRequested) break;

                    var ptr = IntPtr.Add(pSessionInfo, i * structSize);
                    var info = Marshal.PtrToStructure<WtsSessionInfo>(ptr);
                    string? station = info.pWinStationName != IntPtr.Zero
                        ? Marshal.PtrToStringAuto(info.pWinStationName)
                        : null;

                    if (!ShouldTerminateSession(info.SessionId, station, info.State, consoleId))
                        continue;

                    bool loggedOff = WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, info.SessionId, false);
                    _logger.LogWarning(
                        "[RemoteSessionGuard] Terminated remote session {Id} ({Station}, state={State}) success={Ok}",
                        info.SessionId, station ?? "?", info.State, loggedOff);

                    // Alert with cooldown per session id
                    var now = DateTime.UtcNow;
                    if (_alertedSessions.TryGetValue(info.SessionId, out var last) && now - last < AlertCooldown)
                        continue;
                    _alertedSessions[info.SessionId] = now;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Remote Session: Unauthorized Non-Console Session Terminated",
                        Evidence = $"Session {info.SessionId} station '{station ?? "?"}' state={info.State} " +
                                   $"was force-logged-off (console session={consoleId}). Logoff API success={loggedOff}.",
                        Reasoning = "Sentinel only permits the local console interactive session. " +
                                    "RDP/remote sessions are an unauthorized remote-access path (MITRE T1021.001). " +
                                    "TermService is disabled at install; this guard cuts sessions if RDP is re-enabled.",
                        Confidence = 0.92,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            ["SessionId"] = info.SessionId.ToString(),
                            ["WinStation"] = station ?? "",
                            ["State"] = info.State.ToString(),
                            ["LogoffSucceeded"] = loggedOff.ToString(),
                            ["ConsoleSessionId"] = consoleId.ToString()
                        }
                    });
                }

                // Prune stale alert keys (sessions that no longer appear)
                // Keep map small: drop entries older than cooldown * 2
                foreach (var kv in _alertedSessions)
                {
                    if (DateTime.UtcNow - kv.Value > AlertCooldown + AlertCooldown)
                        _alertedSessions.TryRemove(kv.Key, out _);
                }
            }
            finally
            {
                WTSFreeMemory(pSessionInfo);
            }
        }

        #region WTS P/Invoke

        public enum WtsConnectState
        {
            WTSActive = 0,
            WTSConnected = 1,
            WTSConnectQuery = 2,
            WTSShadow = 3,
            WTSDisconnected = 4,
            WTSIdle = 5,
            WTSListen = 6,
            WTSReset = 7,
            WTSDown = 8,
            WTSInit = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WtsSessionInfo
        {
            public int SessionId;
            public IntPtr pWinStationName;
            public WtsConnectState State;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int reserved,
            int version,
            out IntPtr ppSessionInfo,
            out int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WTSLogoffSession(IntPtr hServer, int sessionId, bool bWait);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        #endregion
    }
}
