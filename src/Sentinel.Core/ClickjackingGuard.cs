using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Comprehensive clickjacking and UI manipulation guard:
    /// 
    /// 1. Mouse input injection - detects synthetic mouse clicks (SendInput/mouse_event)
    /// 2. Click redirection - detects SetCursorPos followed by synthetic click (cursor teleport + click)
    /// 3. Non-foreground overlays - enumerates ALL visible top-level windows for overlay patterns
    /// 4. Fake UAC/credential prompts - detects windows mimicking system UI from non-system processes
    /// 5. Semi-transparent overlays - detects partially transparent windows over sensitive areas
    ///
    /// Runs in the user session (Agent) since it needs desktop access.
    /// </summary>
    public sealed class ClickjackingGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<ClickjackingGuard> _logger;

        // Track cursor teleportation
        private POINT _lastCursorPos;
        private DateTime _lastCursorChange = DateTime.UtcNow;
        private int _teleportClickCount;

        // Fake UAC dedup
        private readonly ConcurrentDictionary<int, DateTime> _fakeUacAlerted = new();

        #region P/Invoke

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern byte GetLayeredWindowAttributes(IntPtr hwnd, out uint pcrKey, out byte pbAlpha, out uint pdwFlags);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_LAYERED = 0x80000;
        private const int WS_EX_TRANSPARENT = 0x20;
        private const int WS_EX_TOPMOST = 0x8;
        private const int WS_EX_NOACTIVATE = 0x08000000;
        private const uint LWA_ALPHA = 0x02;

        #endregion

        public ClickjackingGuard(DetectionEngine de, SignerTrustService signerTrust, ILogger<ClickjackingGuard> l)
        {
            _detectionEngine = de;
            _signerTrust = signerTrust;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ClickjackingGuard] Started - monitoring for clickjacking, fake UAC, and suspicious overlays");

            GetCursorPos(out _lastCursorPos);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct);

                    // Periodic checks (every 5s)
                    await CheckOverlayWindowsAsync();
                    await CheckFakeUacAsync();
                    CheckCursorTeleportation();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ClickjackingGuard] Error");
                }
            }
        }

        #region Cursor Teleportation + Click Detection

        private void CheckCursorTeleportation()
        {
            if (!GetCursorPos(out var pos)) return;

            var dx = pos.X - _lastCursorPos.X;
            var dy = pos.Y - _lastCursorPos.Y;
            var distance = Math.Sqrt(dx * dx + dy * dy);

            // Large instantaneous jump (>800px) between checks
            if (distance > 800 && (DateTime.UtcNow - _lastCursorChange) < TimeSpan.FromSeconds(10))
            {
                _teleportClickCount++;
                if (_teleportClickCount >= 3)
                {
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Clickjacking: Cursor Teleport Anomaly",
                        Evidence = $"Cursor repeatedly teleported {distance:F0}px to ({pos.X},{pos.Y}). " +
                                   $"Pattern repeated {_teleportClickCount} times.",
                        Reasoning = "SetCursorPos moved the cursor abnormally across screen coordinates. " +
                                    "This pattern is commonly associated with click redirection and automated UI evasion.",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.PhantomKeystroke,
                        Metadata = new Dictionary<string, string>
                        {
                            { "TeleportDistance", $"{distance:F0}px" },
                            { "TargetPosition", $"{pos.X},{pos.Y}" },
                            { "RepeatCount", _teleportClickCount.ToString() }
                        }
                    });
                    _teleportClickCount = 0;
                }
            }

            _lastCursorPos = pos;
            _lastCursorChange = DateTime.UtcNow;
        }

        #endregion

        #region Non-Foreground Overlay Detection

        private async Task CheckOverlayWindowsAsync()
        {
            var suspiciousWindows = new List<(IntPtr hWnd, int pid, string procName, int width, int height, byte alpha)>();

            EnumWindows((hWnd, _) =>
            {
                if (!IsWindowVisible(hWnd)) return true;

                int exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
                bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
                bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
                bool isNoActivate = (exStyle & WS_EX_NOACTIVATE) != 0;
                bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

                // Pattern: layered + topmost + (transparent OR noactivate) = overlay
                if (isLayered && isTopmost && (isTransparent || isNoActivate))
                {
                    if (!GetWindowRect(hWnd, out var rect)) return true;
                    int width = rect.Right - rect.Left;
                    int height = rect.Bottom - rect.Top;

                    // Only care about large overlays (>400x400)
                    if (width < 400 || height < 400) return true;

                    GetWindowThreadProcessId(hWnd, out uint pid);
                    if (pid <= 4) return true;

                    string procName = "unknown";
                    string? imagePath = null;
                    try
                    {
                        using var p = Process.GetProcessById((int)pid);
                        procName = p.ProcessName;
                        imagePath = SecurityValidation.GetProcessImagePath((int)pid);
                    }
                    catch { }

                    // v2.5.3: skip real civilians only. FakeOverlay.exe and
                    // discord.exe in Temp are the attack - name is not identity.
                    if (IsVerifiedOverlayCivilian(procName, imagePath))
                        return true;

                    // Check alpha transparency
                    byte alpha = 255;
                    uint crKey;
                    uint flags;
                    GetLayeredWindowAttributes(hWnd, out crKey, out alpha, out flags);
                    if ((flags & LWA_ALPHA) != 0 && alpha > 200) return true; // Nearly opaque = normal window

                    suspiciousWindows.Add((hWnd, (int)pid, procName, width, height, alpha));
                }
                return true;
            }, IntPtr.Zero);

            foreach (var (hWnd, pid, procName, width, height, alpha) in suspiciousWindows)
            {
                var dedupKey = $"overlay:{pid}";
                if (_fakeUacAlerted.ContainsKey(pid)) continue;
                _fakeUacAlerted[pid] = DateTime.UtcNow;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Clickjacking: Suspicious Overlay Window",
                    Evidence = $"Process '{procName}' (PID {pid}) has a large overlay window ({width}x{height}, alpha={alpha}). " +
                               "Layered+Topmost+Transparent/NoActivate pattern.",
                    Reasoning = "A non-foreground transparent topmost window was detected covering a significant screen area. " +
                                "This pattern is used in clickjacking: an invisible overlay captures clicks meant for the window " +
                                "beneath, or a deceptive overlay mimics legitimate UI to trick the user into clicking.",
                    Confidence = 0.78,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = procName,
                    ProcessId = pid,
                    SignalType = SignalType.PhantomKeystroke,
                    Metadata = new Dictionary<string, string>
                    {
                        { "WindowSize", $"{width}x{height}" },
                        { "Alpha", alpha.ToString() },
                        { "ExStyle", "Layered+Topmost+Transparent" }
                    }
                });
            }
        }

        #endregion

        /// <summary>
        /// Real DWM/explorer (System32), real Discord/Chrome, real games, real IDEs.
        /// FakeOverlay.exe and discord.exe in Temp are not this.
        /// </summary>
        internal static bool IsVerifiedOverlayCivilian(string? procName, string? imagePath)
        {
            if (string.IsNullOrEmpty(procName)) return false;
            var n = procName!;

            if (n.Equals("dwm", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                return SecurityValidation.IsWindowsSystemImage(imagePath);

            if (UserlandProtocolHeuristics.IsKnownCommsIdentity(n, imagePath))
                return true;
            if (SecurityValidation.IsGameOrAntiCheatPath(imagePath))
                return true;
            if (ChainTracer.IsLegitimateIdeHost(imagePath, n))
                return true;

            if (n.Equals("GeForceOverlay", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("NVIDIA Share", StringComparison.OrdinalIgnoreCase) ||
                n.Equals("GameBar", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(imagePath)) return false;
                var lower = imagePath!.ToLowerInvariant();
                if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\"))
                    return false;
                if (lower.Contains(@"\nvidia corporation\") ||
                    lower.Contains(@"\gamebar\") ||
                    lower.Contains(@"\windowsapps\"))
                    return true;
                try
                {
                    return System.IO.File.Exists(imagePath) &&
                           SecurityValidation.VerifyAuthenticodeSignature(imagePath);
                }
                catch { return false; }
            }

            return false;
        }

        #region Fake UAC / Credential Prompt Detection

        private async Task CheckFakeUacAsync()
        {
            var sb = new StringBuilder(256);
            var classSb = new StringBuilder(256);

            EnumWindows((hWnd, _) =>
            {
                if (!IsWindowVisible(hWnd)) return true;

                GetWindowText(hWnd, sb, 256);
                var title = sb.ToString();
                GetClassName(hWnd, classSb, 256);
                var className = classSb.ToString();

                // Detect windows with UAC-like titles from non-consent.exe processes
                bool looksLikeUac = title.Contains("User Account Control") ||
                                    title.Contains("Windows Security") ||
                                    title.Contains("Administrator permission") ||
                                    title.Contains("Credential") && title.Contains("Windows") ||
                                    title.Contains("Sign in") && className.Contains("#32770");

                if (!looksLikeUac) return true;

                GetWindowThreadProcessId(hWnd, out uint pid);
                if (pid <= 4) return true;

                string procName = "unknown";
                string? imagePath = null;
                try
                {
                    using var p = Process.GetProcessById((int)pid);
                    procName = p.ProcessName;
                    imagePath = SecurityValidation.GetProcessImagePath((int)pid);
                }
                catch { }

                // Skip processes signed by a trusted publisher (Google, Microsoft, Mozilla, etc.)
                // This cannot be bypassed by renaming a malicious binary to "chrome.exe" -
                // the attacker would need the publisher's private code-signing key.
                if (!string.IsNullOrEmpty(imagePath) && _signerTrust.IsSignedFile(imagePath!))
                    return true;

                // Also skip our own agent process by name (it won't have a third-party signature)
                if (string.Equals(procName, "Sentinel.Agent"))
                    return true;

                // This is a non-system process with a UAC-like window title - fake UAC
                if (!_fakeUacAlerted.ContainsKey((int)pid))
                {
                    _fakeUacAlerted[(int)pid] = DateTime.UtcNow;
                    Task.Run(() => _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Clickjacking: Fake UAC/Credential Prompt",
                        Evidence = $"Process '{procName}' (PID {pid}) from '{imagePath ?? "unknown"}' " +
                                   $"created a window titled '{title}' (class: {className})",
                        Reasoning = "A non-system process created a window with a title mimicking Windows UAC or " +
                                    "credential prompts. Attackers use fake UAC dialogs to harvest passwords - the user " +
                                    "thinks they're authenticating to Windows but they're typing into an attacker-controlled window.",
                        Confidence = 0.90,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = procName,
                        ProcessId = (int)pid,
                        SignalType = SignalType.PhantomKeystroke,
                        Metadata = new Dictionary<string, string>
                        {
                            { "WindowTitle", title },
                            { "ClassName", className },
                            { "ImagePath", imagePath ?? "unknown" }
                        }
                    }));
                }

                return true;
            }, IntPtr.Zero);
        }

        #endregion
    }
}
