// Monitors ported from D:\Gorstak\Powershell Detection/ + Grok.ps1 unified EDR.
// LnkUncGuard           <- Detection/LNKProtection.ps1
// ScarewareWindowMonitor <- Detection/RansomwareScarewareDetection.ps1 (+ FakeUAC keywords)
// CursorTakeoverMonitor  <- Detection/CursorTakeoverDetection.ps1
// CookieIntegrityMonitor <- Detection/CookieMonitor.ps1 (alert-only, no Chrome kill)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Removes / quarantines malicious .lnk shortcuts that point at UNC/network paths
    /// (classic delivery vector for phishing + payload drop). Scans Desktop, Public Desktop,
    /// Start Menu, and Taskbar pin folders.
    /// Safe to run from the Service (filesystem only).
    /// </summary>
    public sealed class LnkUncGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly QuarantineManager _quarantine;
        private readonly ILogger<LnkUncGuard> _logger;
        private readonly ConcurrentDictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromHours(1);

        public LnkUncGuard(DetectionEngine de, QuarantineManager quarantine, ILogger<LnkUncGuard> logger)
        {
            _detectionEngine = de;
            _quarantine = quarantine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LnkUncGuard] Started - scanning Desktop/StartMenu/Taskbar for UNC .lnk shortcuts");

            // Initial pass after short settle
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAllAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[LnkUncGuard] Scan error");
                }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        internal async Task<int> ScanAllAsync(CancellationToken ct = default)
        {
            int findings = 0;
            foreach (var dir in GetScanRoots())
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;

                IEnumerable<string> lnks;
                try
                {
                    lnks = Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var lnk in lnks)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        if (await EvaluateLnkAsync(lnk))
                            findings++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[LnkUncGuard] Failed to evaluate {Path}", lnk);
                    }
                }
            }
            return findings;
        }

        /// <summary>
        /// Returns true if the shortcut is malicious (UNC / remote launcher).
        /// Exposed for unit tests.
        /// </summary>
        /// <summary>
        /// Heuristic classifier retained for tests / shared logic.
        /// Prefer <see cref="LnkShortcutMonitor.IsMaliciousShortcut"/> at runtime
        /// (that monitor is the sole registered LNK guard as of v1.7.4).
        /// </summary>
        internal static bool IsMaliciousShortcut(string? targetPath, string? arguments)
            => LnkShortcutMonitor.IsMaliciousShortcut(targetPath, arguments);

        private async Task<bool> EvaluateLnkAsync(string lnkPath)
        {
            if (!TryReadShortcut(lnkPath, out var target, out var args))
                return false;

            if (!IsMaliciousShortcut(target, args))
                return false;

            var now = DateTime.UtcNow;
            if (_alerted.TryGetValue(lnkPath, out var last) && now - last < AlertCooldown)
                return false;
            _alerted[lnkPath] = now;

            string? quarantined = null;
            try
            {
                quarantined = await _quarantine.QuarantineFileAtomicAsync(lnkPath, forceQuarantineSigned: true);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LnkUncGuard] Quarantine failed for {Path}", lnkPath);
            }

            // Fallback delete if quarantine declined
            if (quarantined == null && File.Exists(lnkPath))
            {
                try { File.Delete(lnkPath); } catch { /* best effort */ }
            }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "LNK: UNC/Remote Shortcut Removed",
                Evidence = $"Malicious shortcut '{lnkPath}' -> Target='{target}' Args='{args}'" +
                           (quarantined != null ? $" | Quarantined as {Path.GetFileName(quarantined)}" : " | Deleted"),
                Reasoning = "Attackers plant .lnk files on Desktop/Start Menu/Taskbar that point to UNC " +
                            "network paths or remote launchers. Opening the shortcut executes remote code " +
                            "and is a common phishing/payload-delivery technique.",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.Quarantine,
                ProcessName = "explorer",
                ProcessId = 0,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["LnkPath"] = lnkPath,
                    ["TargetPath"] = target ?? string.Empty,
                    ["Arguments"] = args ?? string.Empty,
                    ["Quarantined"] = (quarantined != null).ToString()
                }
            });

            return true;
        }

        private static IEnumerable<string> GetScanRoots()
        {
            var roots = new List<string>();

            void Add(string? p)
            {
                if (!string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
                    roots.Add(p!);
            }

            // Service runs as SYSTEM - enumerate interactive user profiles for Desktops
            try
            {
                var usersRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"..\Users");
                usersRoot = Path.GetFullPath(usersRoot);
                if (Directory.Exists(usersRoot))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
                    {
                        var name = Path.GetFileName(userDir);
                        if (name is "Public" or "Default" or "Default User" or "All Users" or "desktop.ini")
                            continue;
                        Add(Path.Combine(userDir, "Desktop"));
                        Add(Path.Combine(userDir, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
                        Add(Path.Combine(userDir, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"));
                    }
                }
            }
            catch { /* ignore */ }

            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            Add(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu));

            return roots.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Parse Shell Link (.lnk) without COM - reads LinkInfo / StringData for Target + Args.
        /// Spec: MS-SHLLINK.
        /// </summary>
        internal static bool TryReadShortcut(string path, out string? targetPath, out string? arguments)
        {
            targetPath = null;
            arguments = null;
            try
            {
                var bytes = File.ReadAllBytes(path);
                if (bytes.Length < 0x4C) return false;

                // HeaderSize must be 0x4C, CLSID ShellLink
                if (BitConverter.ToUInt32(bytes, 0) != 0x4Cu) return false;
                // LinkFlags at offset 0x14
                uint linkFlags = BitConverter.ToUInt32(bytes, 0x14);
                int offset = 0x4C;

                // Skip LinkTargetIDList if present (HasLinkTargetIDList = 0x01)
                if ((linkFlags & 0x01) != 0)
                {
                    if (offset + 2 > bytes.Length) return false;
                    ushort idListSize = BitConverter.ToUInt16(bytes, offset);
                    offset += 2 + idListSize;
                }

                // LinkInfo if present (HasLinkInfo = 0x02)
                if ((linkFlags & 0x02) != 0 && offset + 4 <= bytes.Length)
                {
                    uint linkInfoSize = BitConverter.ToUInt32(bytes, offset);
                    if (linkInfoSize >= 0x1C && offset + (int)linkInfoSize <= bytes.Length)
                    {
                        uint linkInfoFlags = BitConverter.ToUInt32(bytes, offset + 8);
                        // VolumeID + LocalBasePath
                        if ((linkInfoFlags & 0x01) != 0) // VolumeIDAndLocalBasePath
                        {
                            uint localBasePathOffset = BitConverter.ToUInt32(bytes, offset + 16);
                            if (localBasePathOffset < linkInfoSize)
                            {
                                targetPath = ReadNullTerminatedAnsi(bytes, offset + (int)localBasePathOffset);
                            }
                        }
                        // CommonNetworkRelativeLink
                        if ((linkInfoFlags & 0x02) != 0) // CommonNetworkRelativeLinkAndPathSuffix
                        {
                            uint netOffset = BitConverter.ToUInt32(bytes, offset + 20);
                            if (netOffset < linkInfoSize && netOffset + 20 <= linkInfoSize)
                            {
                                uint netNameOffset = BitConverter.ToUInt32(bytes, offset + (int)netOffset + 8);
                                if (netNameOffset < linkInfoSize)
                                {
                                    var netName = ReadNullTerminatedAnsi(bytes, offset + (int)netOffset + (int)netNameOffset);
                                    uint suffixOffset = BitConverter.ToUInt32(bytes, offset + 24);
                                    var suffix = suffixOffset < linkInfoSize
                                        ? ReadNullTerminatedAnsi(bytes, offset + (int)suffixOffset)
                                        : string.Empty;
                                    if (!string.IsNullOrEmpty(netName))
                                    {
                                        targetPath = string.IsNullOrEmpty(suffix)
                                            ? @"\\" + netName.TrimStart('\\')
                                            : @"\\" + netName.TrimStart('\\') + @"\" + suffix.TrimStart('\\');
                                    }
                                }
                            }
                        }
                    }
                    offset += (int)linkInfoSize;
                }

                // StringData - NAME, RELATIVE, WORKING DIR, ARGS, ICON
                // HasName=0x04, HasRelativePath=0x08, HasWorkingDir=0x10, HasArguments=0x20, HasIconLocation=0x40
                bool isUnicode = (linkFlags & 0x80) != 0; // IsUnicode
                string? ReadStringData(ref int off)
                {
                    if (off + 2 > bytes.Length) return null;
                    ushort count = BitConverter.ToUInt16(bytes, off);
                    off += 2;
                    if (count == 0) return string.Empty;
                    if (isUnicode)
                    {
                        int byteLen = count * 2;
                        if (off + byteLen > bytes.Length) return null;
                        var s = Encoding.Unicode.GetString(bytes, off, byteLen);
                        off += byteLen;
                        return s.TrimEnd('\0');
                    }
                    else
                    {
                        if (off + count > bytes.Length) return null;
                        var s = Encoding.Default.GetString(bytes, off, count);
                        off += count;
                        return s.TrimEnd('\0');
                    }
                }

                if ((linkFlags & 0x04) != 0) _ = ReadStringData(ref offset); // Name
                if ((linkFlags & 0x08) != 0)
                {
                    var rel = ReadStringData(ref offset);
                    if (string.IsNullOrEmpty(targetPath) && !string.IsNullOrEmpty(rel))
                        targetPath = rel;
                }
                if ((linkFlags & 0x10) != 0) _ = ReadStringData(ref offset); // WorkingDir
                if ((linkFlags & 0x20) != 0) arguments = ReadStringData(ref offset);
                // IconLocation ignored

                // COM fallback for stubborn links
                if (string.IsNullOrEmpty(targetPath))
                {
                    try
                    {
                        var shellType = Type.GetTypeFromProgID("WScript.Shell");
                        if (shellType != null)
                        {
                            dynamic shell = Activator.CreateInstance(shellType)!;
                            dynamic sc = shell.CreateShortcut(path);
                            targetPath = (string?)sc.TargetPath;
                            arguments ??= (string?)sc.Arguments;
                            Marshal.FinalReleaseComObject(sc);
                            Marshal.FinalReleaseComObject(shell);
                        }
                    }
                    catch { /* optional */ }
                }

                return !string.IsNullOrEmpty(targetPath) || !string.IsNullOrEmpty(arguments);
            }
            catch
            {
                return false;
            }
        }

        private static string ReadNullTerminatedAnsi(byte[] bytes, int offset)
        {
            if (offset < 0 || offset >= bytes.Length) return string.Empty;
            int end = offset;
            while (end < bytes.Length && bytes[end] != 0) end++;
            return Encoding.Default.GetString(bytes, offset, end - offset);
        }
    }

    /// <summary>
    /// Detects ransomware/scareware and fake system dialogs via process MainWindowTitle
    /// heuristics. Port of Detection/RansomwareScarewareDetection.ps1 + FakeUacDetection.ps1.
    /// Must run in the user session (Agent) so MainWindowTitle is visible.
    /// </summary>
    public sealed class ScarewareWindowMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScarewareWindowMonitor> _logger;
        private readonly ConcurrentDictionary<int, DateTime> _alerted = new();

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        private static readonly string[] ScarewarePatterns =
        {
            "encrypted", "bitcoin", "decrypt", "ransom", "pay to unlock",
            "your files have been", "restore your files", "microsoft support",
            "pay fine", "your computer has been locked", "all your files",
            "send bitcoin", "crypto locker"
        };

        private static readonly string[] FakeSystemPatterns =
        {
            "user account control", "do you want to allow", "windows security",
            "microsoft defender", "critical update", "windows update required"
        };

        private static readonly HashSet<string> Allowlist = new(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "logonui", "lockapp", "consent", "applicationframehost",
            "steam", "epicgameslauncher", "chrome", "msedge", "firefox", "brave",
            "code", "devenv", "notepad", "notepad++", "securityhealthsystray",
            "securityhealthservice", "msmpeng", "systemsettings", "credentialuibroker",
            "dwm", "shellexperiencehost", "startmenuexperiencehost", "searchhost",
            "runtimebroker", "textinputhost", "Sentinel.Agent", "Sentinel.Service"
        };

        public ScarewareWindowMonitor(DetectionEngine de, ILogger<ScarewareWindowMonitor> logger)
        {
            _detectionEngine = de;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScarewareWindowMonitor] Started - scanning window titles for scareware/fake UAC");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[ScarewareWindowMonitor] Error");
                }

                try { await Task.Delay(PollInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        internal async Task<int> ScanAsync(CancellationToken ct = default)
        {
            int findings = 0;
            var now = DateTime.UtcNow;

            // Prune stale alert entries
            foreach (var kv in _alerted)
            {
                if (now - kv.Value > AlertCooldown)
                    _alerted.TryRemove(kv.Key, out _);
            }

            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    using (proc)
                    {
                        if (proc.Id <= 4) continue;
                        if (Allowlist.Contains(proc.ProcessName)) continue;

                        string title;
                        try { title = proc.MainWindowTitle; }
                        catch { continue; }
                        if (string.IsNullOrWhiteSpace(title)) continue;

                        var titleLower = title.ToLowerInvariant();

                        int scareHits = ScarewarePatterns.Count(p => titleLower.Contains(p));
                        bool fakeSystem = FakeSystemPatterns.Any(p => titleLower.Contains(p));

                        if (scareHits < 2 && !fakeSystem) continue;
                        if (_alerted.ContainsKey(proc.Id)) continue;
                        _alerted[proc.Id] = now;

                        string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "unknown";
                        bool isScareware = scareHits >= 2;
                        findings++;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = isScareware
                                ? "Scareware: Ransomware Window Title"
                                : "Scareware: Fake System/UAC Dialog",
                            Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) from '{imagePath}' " +
                                       $"shows window titled '{title}' (scarewareHits={scareHits}, fakeSystem={fakeSystem})",
                            Reasoning = isScareware
                                ? "Window title matches multiple ransomware/scareware keywords. " +
                                  "Real ransomware and fake tech-support scams present full-screen or " +
                                  "dialog UI demanding payment or credentials."
                                : "Non-system process displayed a window title mimicking Windows UAC, " +
                                  "Defender, or Update prompts - a common credential-harvesting technique.",
                            Confidence = isScareware ? 0.88 : 0.82,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            SignalType = isScareware ? SignalType.Ransomware : SignalType.CredentialTheft,
                            Metadata = new Dictionary<string, string>
                            {
                                ["WindowTitle"] = title,
                                ["ImagePath"] = imagePath,
                                ["ScarewareHits"] = scareHits.ToString(),
                                ["FakeSystem"] = fakeSystem.ToString()
                            }
                        });
                    }
                }
                catch { /* process exited */ }
            }

            return findings;
        }
    }

    /// <summary>
    /// Detects automated / remote-takeover style cursor movement via low velocity variance.
    /// Port of Detection/CursorTakeoverDetection.ps1. Complements ClickjackingGuard
    /// (which focuses on injected clicks / teleports). User-session only (Agent).
    /// </summary>
    public sealed class CursorTakeoverMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CursorTakeoverMonitor> _logger;

        private readonly List<(int X, int Y, long Ticks)> _samples = new(24);
        private DateTime _lastAlert = DateTime.MinValue;

        private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(3);
        // v2.7.3: 1 min was too chatty for a LogOnly indicator (hundreds of repeats during
        // sustained automation/RDP use). 10 min keeps the signal without flooding the log.
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        // Tuned from original PS script: var &lt; 0.005 with mean velocity &gt; 0.01
        private const double VarianceThreshold = 0.005;
        private const double MeanVelocityThreshold = 0.01;
        private const int MinSamples = 12;

        public CursorTakeoverMonitor(DetectionEngine de, ILogger<CursorTakeoverMonitor> logger)
        {
            _detectionEngine = de;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CursorTakeoverMonitor] Started - sampling cursor velocity variance");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    SampleAndEvaluate();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CursorTakeoverMonitor] Error");
                }

                try { await Task.Delay(SampleInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        internal bool SampleAndEvaluate()
        {
            if (!GetCursorPos(out var pt)) return false;

            long ticks = DateTime.UtcNow.Ticks;
            _samples.Add((pt.X, pt.Y, ticks));
            while (_samples.Count > 20)
                _samples.RemoveAt(0);

            if (_samples.Count < MinSamples) return false;

            var velocities = new List<double>(_samples.Count - 1);
            for (int i = 1; i < _samples.Count; i++)
            {
                var a = _samples[i - 1];
                var b = _samples[i];
                double dtMs = Math.Max((b.Ticks - a.Ticks) / 10_000.0, 1.0);
                double dist = Math.Sqrt((b.X - a.X) * (b.X - a.X) + (b.Y - a.Y) * (b.Y - a.Y));
                velocities.Add(dist / dtMs);
            }

            double mean = velocities.Average();
            double variance = velocities.Sum(v => (v - mean) * (v - mean)) / velocities.Count;

            if (variance >= VarianceThreshold || mean <= MeanVelocityThreshold)
                return false;

            var now = DateTime.UtcNow;
            if (now - _lastAlert < AlertCooldown)
                return false;
            _lastAlert = now;

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Cursor: Automated / Takeover Movement",
                Evidence = $"Low-variance continuous cursor movement detected (variance={variance:F6}, meanVel={mean:F4} px/ms, samples={_samples.Count})",
                Reasoning = "Human cursor movement has high velocity variance. Sustained low-variance " +
                            "movement while the cursor keeps moving is characteristic of bot/automation " +
                            "scripts or remote desktop takeover tools driving the pointer programmatically.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "user32",
                ProcessId = 0,
                SignalType = SignalType.PhantomKeystroke,
                Metadata = new Dictionary<string, string>
                {
                    ["Variance"] = variance.ToString("F6"),
                    ["MeanVelocity"] = mean.ToString("F4"),
                    ["SampleCount"] = _samples.Count.ToString()
                }
            });

            return true;
        }

        // Expose thresholds for tests
        internal static bool IsTakeoverPattern(IReadOnlyList<double> velocities)
        {
            if (velocities.Count < MinSamples - 1) return false;
            double mean = velocities.Average();
            double variance = velocities.Sum(v => (v - mean) * (v - mean)) / velocities.Count;
            return variance < VarianceThreshold && mean > MeanVelocityThreshold;
        }

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }
    }

    /// <summary>
    /// Alert-only browser cookie DB integrity monitor.
    /// Port of Detection/CookieMonitor.ps1 - does NOT kill browsers or force-restore
    /// (those behaviors caused more damage than they prevented). User-session (Agent).
    /// </summary>
    public sealed class CookieIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CookieIntegrityMonitor> _logger;
        private readonly ConcurrentDictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

        public CookieIntegrityMonitor(DetectionEngine de, ILogger<CookieIntegrityMonitor> logger)
        {
            _detectionEngine = de;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CookieIntegrityMonitor] Started - hashing browser cookie DBs");

            // Baseline first without alerting
            try { await ScanAsync(alert: false, ct); } catch { /* ignore */ }

            while (!ct.IsCancellationRequested)
            {
                try { await Task.Delay(PollInterval, ct); }
                catch (OperationCanceledException) { break; }

                try { await ScanAsync(alert: true, ct); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[CookieIntegrityMonitor] Error");
                }
            }
        }

        internal async Task<int> ScanAsync(bool alert, CancellationToken ct = default)
        {
            int changes = 0;
            foreach (var path in EnumerateCookiePaths())
            {
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(path)) continue;

                string hash;
                try { hash = ComputeSha256(path); }
                catch { continue; }

                if (_hashes.TryGetValue(path, out var prev) && !string.Equals(prev, hash))
                {
                    changes++;
                    if (alert)
                    {
                        var now = DateTime.UtcNow;
                        if (!_alerted.TryGetValue(path, out var last) || now - last >= AlertCooldown)
                        {
                            _alerted[path] = now;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Browser: Cookie Database Modified",
                                Evidence = $"Cookie DB hash changed: {path}",
                                Reasoning = "Browser cookie databases changing outside normal browser " +
                                            "activity can indicate session-hijacking malware copying or " +
                                            "tampering with cookies. This is alert-only (no restore/kill).",
                                Confidence = 0.45,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "browser",
                                ProcessId = 0,
                                SignalType = SignalType.CredentialTheft,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["CookiePath"] = path,
                                    ["PreviousHash"] = prev,
                                    ["CurrentHash"] = hash
                                }
                            });
                        }
                    }
                }

                _hashes[path] = hash;
            }
            return changes;
        }

        private static IEnumerable<string> EnumerateCookiePaths()
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) yield break;

            string[] rel =
            {
                @"Google\Chrome\User Data\Default\Network\Cookies",
                @"Google\Chrome\User Data\Default\Cookies",
                @"Microsoft\Edge\User Data\Default\Network\Cookies",
                @"Microsoft\Edge\User Data\Default\Cookies",
                @"BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies",
            };

            foreach (var r in rel)
                yield return Path.Combine(local, r);
        }

        private static string ComputeSha256(string path)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sha = SHA256.Create();
            return ConvertHex.ToHexString(sha.ComputeHash(fs));
        }
    }
}
