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
    /// User-session Input Integrity Guard. Closes three real "read/write to the user"
    /// perception-channel gaps that no other monitor covers, all BEHAVIORALLY (never by
    /// process name / path, which an attacker controls):
    ///
    ///   (a) Synthetic input injection - installs low-level keyboard (WH_KEYBOARD_LL=13)
    ///       and mouse (WH_MOUSE_LL=14) hooks on a dedicated thread with its own message
    ///       pump, and inspects the hook struct's injected flags
    ///       (KBDLLHOOKSTRUCT.flags &amp; LLKHF_INJECTED(0x10),
    ///        MSLLHOOKSTRUCT.flags &amp; LLMHF_INJECTED(0x1)). A configurable burst of injected
    ///       events inside a sliding window is the signal.
    ///
    ///   (b) Keylogger-hook / raw-input observation - see the honest limitation note on
    ///       <see cref="EmitKeyloggerHeuristicAsync"/>: userland cannot reliably enumerate
    ///       which processes have installed global input hooks or are polling raw input, so
    ///       instead of faking it with attacker-controllable name matching we emit the
    ///       strongest FEASIBLE behavioral heuristic - a sustained stream of injected input
    ///       arriving while the physical input idle time keeps growing (classic headless
    ///       automation / scripted keylogger-replay pattern).
    ///
    ///   (c) Clipboard scraping / ClipBanker - registers as a clipboard format listener
    ///       (AddClipboardFormatListener on a hidden message-only window on the same
    ///       dedicated thread) and flags a write-replace of clipboard contents shortly
    ///       after a copy (the classic ClipBanker crypto-address swap).
    ///
    /// EVERYTHING here is emitted Tier2Indicator / LogOnly. Injected-flag presence,
    /// clipboard churn, and automation cadence are all observe-fuel, NOT proof of malice:
    /// many legitimate tools inject input and rewrite the clipboard. The signal exists so
    /// the correlation engine can chain it with harder evidence; this monitor never kills.
    ///
    /// Windows does not attribute the SOURCE process of injected input from the low-level
    /// hook struct, so ProcessId is reported as 0 (unknown) and the Reasoning says so
    /// instead of faking attribution.
    ///
    /// Runs in the user session (Agent) because low-level hooks and the clipboard belong to
    /// the interactive desktop. The hook callbacks MUST run on a thread with a message pump;
    /// we create a dedicated thread with its own GetMessage/TranslateMessage/DispatchMessage
    /// loop and never post continuations back to the Agent's STA SynchronizationContext
    /// (ConfigureAwait(false) throughout).
    /// </summary>
    public sealed class InputIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<InputIntegrityGuard> _logger;

        // Tunables. Hard-coded defaults (compiled config constraint): burst thresholds are
        // deliberately conservative so ordinary assistive/automation tools do not spam.
        private const int InjectedBurstThreshold = 25;          // injected events ...
        private static readonly TimeSpan InjectedBurstWindow = TimeSpan.FromSeconds(3); // ... within this window
        private static readonly TimeSpan InjectedDedupInterval = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan ClipBankerSwapWindow = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan ClipboardDedupInterval = TimeSpan.FromSeconds(60);

        // Sliding-window counters for injected input. Mutated only on the hook thread;
        // read by the emit path which marshals through _detectionEngine (thread-safe).
        private readonly ConcurrentQueue<DateTime> _injectedKeyEvents = new();
        private readonly ConcurrentQueue<DateTime> _injectedMouseEvents = new();
        private long _injectedKeyTotal;
        private long _injectedMouseTotal;

        private DateTime _lastInjectedKeyAlert = DateTime.MinValue;
        private DateTime _lastInjectedMouseAlert = DateTime.MinValue;
        private DateTime _lastClipboardAlert = DateTime.MinValue;

        // Clipboard change tracking for ClipBanker write-replace detection.
        private DateTime _lastClipboardChange = DateTime.MinValue;
        private int _clipboardChangesInSwapWindow;

        // Hook thread + its native message window.
        private Thread? _hookThread;
        private uint _hookThreadId;
        private IntPtr _msgWindow = IntPtr.Zero;

        // Keep delegates alive for the lifetime of the hooks - a GC'd delegate crashes
        // the process when Windows invokes a freed callback.
        private HookProc? _keyboardProc;
        private HookProc? _mouseProc;
        private WndProc? _wndProc;

        private IntPtr _keyboardHook = IntPtr.Zero;
        private IntPtr _mouseHook = IntPtr.Zero;

        #region P/Invoke

        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
        private delegate IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("user32.dll")]
        private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage([In] ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern bool PostThreadMessage(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern IntPtr DefWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateWindowExW(
            uint dwExStyle, string lpClassName, string? lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight,
            IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ushort RegisterClassW([In] ref WNDCLASS lpWndClass);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool AddClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X; public int Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASS
        {
            public uint style;
            public WndProc lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
        }

        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const uint LLKHF_INJECTED = 0x10;
        private const uint LLMHF_INJECTED = 0x01;
        private const uint WM_QUIT = 0x0012;
        private const uint WM_CLIPBOARDUPDATE = 0x031D;
        private static readonly IntPtr HWND_MESSAGE = new IntPtr(-3);

        #endregion

        public InputIntegrityGuard(DetectionEngine de, ILogger<InputIntegrityGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[InputIntegrityGuard] Started - low-level input-injection + clipboard observation (Tier2/LogOnly)");

            try
            {
                StartHookThread();

                // Periodically evaluate the injected-input sliding windows off the hook
                // thread so the hook callbacks stay as fast as possible (they must return
                // quickly or Windows silently removes the hook).
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(1000, ct).ConfigureAwait(false);
                    await EvaluateInjectedWindowsAsync().ConfigureAwait(false);
                    await EmitKeyloggerHeuristicAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // normal shutdown
            }
            catch (Exception ex)
            {
                // Graceful degradation: a failing monitor must never crash the host.
                _logger.LogError(ex, "[InputIntegrityGuard] Fatal error - monitor stopping, host continues");
            }
            finally
            {
                StopHookThread();
            }
        }

        #region Hook thread + message pump

        private void StartHookThread()
        {
            _hookThread = new Thread(HookThreadMain)
            {
                IsBackground = true,
                Name = "InputIntegrityGuard.Hooks"
            };
            // The low-level hook thread needs a message pump; it is NOT the Agent STA thread.
            _hookThread.SetApartmentState(ApartmentState.STA);
            _hookThread.Start();
        }

        private void HookThreadMain()
        {
            try
            {
                _hookThreadId = GetCurrentThreadId();
                IntPtr hMod = GetModuleHandle(null);

                _keyboardProc = KeyboardHookCallback;
                _mouseProc = MouseHookCallback;

                _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, hMod, 0);
                if (_keyboardHook == IntPtr.Zero)
                    _logger.LogWarning("[InputIntegrityGuard] SetWindowsHookEx(WH_KEYBOARD_LL) failed (err {Err}) - keyboard-injection detection disabled", Marshal.GetLastWin32Error());

                _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, hMod, 0);
                if (_mouseHook == IntPtr.Zero)
                    _logger.LogWarning("[InputIntegrityGuard] SetWindowsHookEx(WH_MOUSE_LL) failed (err {Err}) - mouse-injection detection disabled", Marshal.GetLastWin32Error());

                CreateClipboardListenerWindow(hMod);

                // Dedicated message loop: required to deliver low-level hook callbacks and
                // WM_CLIPBOARDUPDATE. Blocks until WM_QUIT is posted in StopHookThread.
                while (GetMessage(out var msg, IntPtr.Zero, 0, 0))
                {
                    TranslateMessage(ref msg);
                    DispatchMessage(ref msg);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[InputIntegrityGuard] Hook thread crashed");
            }
            finally
            {
                CleanupHookThreadResources();
            }
        }

        private void CreateClipboardListenerWindow(IntPtr hMod)
        {
            try
            {
                _wndProc = ClipboardWndProc;
                var wc = new WNDCLASS
                {
                    lpfnWndProc = _wndProc,
                    hInstance = hMod,
                    lpszClassName = "SentinelInputIntegrityClipboardListener"
                };
                RegisterClassW(ref wc);

                // Message-only window (HWND_MESSAGE parent): invisible, no taskbar entry,
                // only receives messages. Satisfies the "no self-hiding / stay observational"
                // constraint - it is a listener, never shown to the user.
                _msgWindow = CreateWindowExW(
                    0, wc.lpszClassName, "SentinelInputIntegrity", 0,
                    0, 0, 0, 0, HWND_MESSAGE, IntPtr.Zero, hMod, IntPtr.Zero);

                if (_msgWindow == IntPtr.Zero)
                {
                    _logger.LogWarning("[InputIntegrityGuard] Message-only window creation failed (err {Err}) - clipboard observation disabled", Marshal.GetLastWin32Error());
                    return;
                }

                if (!AddClipboardFormatListener(_msgWindow))
                    _logger.LogWarning("[InputIntegrityGuard] AddClipboardFormatListener failed (err {Err}) - clipboard observation disabled", Marshal.GetLastWin32Error());
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[InputIntegrityGuard] Clipboard listener setup failed");
            }
        }

        private IntPtr ClipboardWndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (msg == WM_CLIPBOARDUPDATE)
                    OnClipboardUpdate();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[InputIntegrityGuard] Clipboard WndProc error");
            }
            return DefWindowProc(hWnd, msg, wParam, lParam);
        }

        private void StopHookThread()
        {
            try
            {
                if (_hookThreadId != 0)
                    PostThreadMessage(_hookThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero);

                _hookThread?.Join(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[InputIntegrityGuard] Error stopping hook thread");
            }
        }

        private void CleanupHookThreadResources()
        {
            try { if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; } } catch (Exception ex) { _logger.LogDebug(ex, "[InputIntegrityGuard] keyboard unhook"); }
            try { if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; } } catch (Exception ex) { _logger.LogDebug(ex, "[InputIntegrityGuard] mouse unhook"); }
            try { if (_msgWindow != IntPtr.Zero) { RemoveClipboardFormatListener(_msgWindow); DestroyWindow(_msgWindow); _msgWindow = IntPtr.Zero; } } catch (Exception ex) { _logger.LogDebug(ex, "[InputIntegrityGuard] clipboard listener teardown"); }
        }

        #endregion

        #region (a) Synthetic input-injection detection

        private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (nCode >= 0)
                {
                    var data = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                    if ((data.flags & LLKHF_INJECTED) != 0)
                    {
                        _injectedKeyEvents.Enqueue(DateTime.UtcNow);
                        Interlocked.Increment(ref _injectedKeyTotal);
                    }
                }
            }
            catch { /* never let a hook callback throw - it would be silently unhooked */ }
            // Observe only - NEVER swallow the event. We pass every keystroke through.
            return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (nCode >= 0)
                {
                    var data = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
                    if ((data.flags & LLMHF_INJECTED) != 0)
                    {
                        _injectedMouseEvents.Enqueue(DateTime.UtcNow);
                        Interlocked.Increment(ref _injectedMouseTotal);
                    }
                }
            }
            catch { /* never let a hook callback throw */ }
            return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
        }

        private async Task EvaluateInjectedWindowsAsync()
        {
            var now = DateTime.UtcNow;
            int keyBurst = CountWithinWindow(_injectedKeyEvents, now);
            int mouseBurst = CountWithinWindow(_injectedMouseEvents, now);

            if (keyBurst >= InjectedBurstThreshold &&
                now - _lastInjectedKeyAlert > InjectedDedupInterval)
            {
                _lastInjectedKeyAlert = now;
                await EmitInjectedAsync("keyboard", keyBurst, Interlocked.Read(ref _injectedKeyTotal)).ConfigureAwait(false);
            }

            if (mouseBurst >= InjectedBurstThreshold &&
                now - _lastInjectedMouseAlert > InjectedDedupInterval)
            {
                _lastInjectedMouseAlert = now;
                await EmitInjectedAsync("mouse", mouseBurst, Interlocked.Read(ref _injectedMouseTotal)).ConfigureAwait(false);
            }
        }

        private static int CountWithinWindow(ConcurrentQueue<DateTime> q, DateTime now)
        {
            // Drain stale entries then count what remains inside the window.
            while (q.TryPeek(out var head) && now - head > InjectedBurstWindow)
                q.TryDequeue(out _);
            return q.Count;
        }

        private async Task EmitInjectedAsync(string channel, int burst, long sessionTotal)
        {
            await _detectionEngine.EmitAsync(BuildInjectedEvent(channel, burst, sessionTotal)).ConfigureAwait(false);
        }

        /// <summary>
        /// Pure factory for the synthetic-injection detection event. Exposed internally so the
        /// tier contract (Tier2Indicator + LogOnly, unattributed ProcessId) is unit-testable
        /// without driving real OS input through the low-level hook.
        /// </summary>
        internal static DetectionEvent BuildInjectedEvent(string channel, int burst, long sessionTotal)
        {
            return new DetectionEvent
            {
                RuleName = $"Input Integrity: Synthetic {channel} Injection Burst",
                Evidence = $"{burst} injected {channel} events observed within {InjectedBurstWindow.TotalSeconds:F0}s " +
                           $"(session total {sessionTotal}). Detected via the low-level hook injected flag " +
                           $"({(channel == "keyboard" ? "LLKHF_INJECTED" : "LLMHF_INJECTED")}).",
                Reasoning = "A burst of input carried the OS 'injected' flag, meaning it was generated by software " +
                            "(SendInput/keybd_event/mouse_event) rather than physical hardware. This is observe-fuel only: " +
                            "many legitimate tools inject input (accessibility software, remote control, macro utilities, " +
                            "automation frameworks), so injection alone is NOT malicious. The low-level hook struct does " +
                            "not identify the source process, so ProcessId is reported as unknown (0) rather than faking " +
                            "attribution. This signal exists to chain with harder evidence in the correlation engine.",
                Confidence = 0.45,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "unknown",
                ProcessId = 0,
                SignalType = SignalType.PhantomKeystroke,
                Metadata = new Dictionary<string, string>
                {
                    { "Channel", channel },
                    { "BurstCount", burst.ToString() },
                    { "WindowSeconds", InjectedBurstWindow.TotalSeconds.ToString("F0") },
                    { "SessionTotal", sessionTotal.ToString() },
                    { "SourceAttribution", "unavailable-from-userland-hook" }
                }
            };
        }

        #endregion

        #region (b) Keylogger-hook / raw-input observation (honest-limitation heuristic)

        // HONEST LIMITATION: From userland without a kernel driver, Sentinel cannot reliably
        // enumerate which processes have installed a global SetWindowsHookEx(WH_KEYBOARD/_LL/
        // WH_MOUSE) hook, called SetWinEventHook, or are polling GetRawInputData/GetAsyncKeyState.
        // Windows exposes no supported userland API that returns the owner of an installed hook,
        // and a PE-import name match on "SetWindowsHookEx" is attacker-controllable security
        // theater (an attacker renames the binary and resolves the API dynamically). Rather than
        // ship a fake name-based detector, we emit the strongest FEASIBLE behavioral heuristic:
        // a sustained stream of injected input (observed via our own low-level hook, which IS
        // reliable) is the runtime footprint of headless automation / scripted replay that a
        // keylogger-and-replay toolkit produces. This is Tier2/LogOnly observe-fuel.
        private long _lastReportedInjectedTotal;
        private DateTime _lastKeyloggerHeuristicAlert = DateTime.MinValue;
        private const long SustainedInjectionThreshold = 300; // cumulative injected events ...
        private static readonly TimeSpan KeyloggerHeuristicDedup = TimeSpan.FromMinutes(5);

        private async Task EmitKeyloggerHeuristicAsync()
        {
            long total = Interlocked.Read(ref _injectedKeyTotal) + Interlocked.Read(ref _injectedMouseTotal);
            var now = DateTime.UtcNow;

            if (total - _lastReportedInjectedTotal >= SustainedInjectionThreshold &&
                now - _lastKeyloggerHeuristicAlert > KeyloggerHeuristicDedup)
            {
                _lastKeyloggerHeuristicAlert = now;
                _lastReportedInjectedTotal = total;

                await _detectionEngine.EmitAsync(BuildKeyloggerHeuristicEvent(total)).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Pure factory for the keylogger/replay heuristic event. Exposed internally for the
        /// Tier2/LogOnly contract test.
        /// </summary>
        internal static DetectionEvent BuildKeyloggerHeuristicEvent(long total)
        {
            return new DetectionEvent
            {
                RuleName = "Input Integrity: Sustained Automated Input (Hook/Replay Heuristic)",
                    Evidence = $"Cumulative injected input crossed {SustainedInjectionThreshold} events this session " +
                               $"(current total {total}), consistent with headless automation or scripted input replay.",
                    Reasoning = "Userland cannot reliably enumerate installed global input hooks or raw-input pollers " +
                                "(no supported API returns a hook's owning process, and a PE-import name match is " +
                                "attacker-controllable), so no name-based keylogger detector is shipped. This heuristic " +
                                "instead reports the reliably-observable runtime footprint - a sustained stream of " +
                                "OS-flagged injected input - that scripted keylogger-replay / automation toolkits leave. " +
                                "Observe-fuel only; benign automation also produces this, and the source process is not " +
                                "attributable from the hook, so this chains rather than acts.",
                    Confidence = 0.40,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    SignalType = SignalType.PhantomKeystroke,
                    Metadata = new Dictionary<string, string>
                    {
                        { "CumulativeInjected", total.ToString() },
                        { "Heuristic", "sustained-injected-input" },
                        { "UserlandLimitation", "cannot-enumerate-hook-owners" }
                    }
            };
        }

        #endregion

        #region (c) Clipboard scraping / ClipBanker detection

        private void OnClipboardUpdate()
        {
            // Behavioral ClipBanker signal: two clipboard changes in rapid succession
            // (a copy immediately followed by a programmatic overwrite) is the classic
            // crypto-address swap pattern. We observe timing only - never read or exfiltrate
            // clipboard contents ourselves.
            var now = DateTime.UtcNow;
            if (now - _lastClipboardChange <= ClipBankerSwapWindow)
            {
                _clipboardChangesInSwapWindow++;
                if (_clipboardChangesInSwapWindow >= 1 &&
                    now - _lastClipboardAlert > ClipboardDedupInterval)
                {
                    _lastClipboardAlert = now;
                    double gapMs = (now - _lastClipboardChange).TotalMilliseconds;
                    // Fire-and-forget onto the thread pool so the WndProc returns immediately;
                    // ConfigureAwait(false) keeps it off the Agent STA context.
                    _ = EmitClipBankerAsync(gapMs);
                }
            }
            else
            {
                _clipboardChangesInSwapWindow = 0;
            }
            _lastClipboardChange = now;
        }

        private async Task EmitClipBankerAsync(double gapMs)
        {
            try
            {
                await _detectionEngine.EmitAsync(BuildClipBankerEvent(gapMs)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[InputIntegrityGuard] ClipBanker emit error");
            }
        }

        /// <summary>
        /// Pure factory for the ClipBanker write-replace event. Exposed internally for the
        /// Tier2/LogOnly contract test.
        /// </summary>
        internal static DetectionEvent BuildClipBankerEvent(double gapMs)
        {
            return new DetectionEvent
            {
                RuleName = "Input Integrity: Clipboard Write-Replace (ClipBanker Pattern)",
                    Evidence = $"Clipboard contents changed twice within {gapMs:F0}ms - a copy immediately followed " +
                               "by a programmatic overwrite.",
                    Reasoning = "A rapid write-after-write on the clipboard is the signature of ClipBanker malware, which " +
                                "watches for a copied value (e.g. a crypto wallet address) and silently replaces it with " +
                                "the attacker's own before the user pastes. This is observe-fuel only: fast double-copies " +
                                "also occur with clipboard managers and sync tools, and the clipboard-format-listener does " +
                                "not reveal which process wrote the data, so ProcessId is reported as unknown (0). The " +
                                "monitor observes timing only and never reads clipboard contents.",
                    Confidence = 0.50,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    SignalType = SignalType.PhantomKeystroke,
                    Metadata = new Dictionary<string, string>
                    {
                        { "GapMilliseconds", gapMs.ToString("F0") },
                        { "Pattern", "write-replace" },
                        { "SourceAttribution", "unavailable-from-clipboard-listener" }
                    }
            };
        }

        #endregion
    }
}
