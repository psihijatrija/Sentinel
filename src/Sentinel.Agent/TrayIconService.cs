using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Sentinel.Core;

namespace Sentinel.Agent
{
    public class TrayIconService : IHostedService, IDisposable
    {
        // Native show/restore for Settings when the form HWND exists but is not WS_VISIBLE
        // (classic side-effect of Application.Run main form being WindowState=Minimized).
        private const int SwRestore = 9;
        private const int SwShow = 5;

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool BringWindowToTop(IntPtr hWnd);

        private readonly QuarantineManager _quarantine;
        private NotifyIcon? _notifyIcon;
        private ContextMenuStrip? _contextMenu;
        private Thread? _uiThread;
        private readonly CancellationTokenSource _cts = new();
        private readonly string _version;
        private (string RuleName, string ProcessName, double Confidence, string Evidence)? _pendingDetection;
        private AgentDashboardForm? _settingsForm;

        public TrayIconService(QuarantineManager quarantine)
        {
            _quarantine = quarantine ?? new QuarantineManager();
            _version = LoadVersion();
        }

        private static string LoadVersion()
        {
            var exeDir = AppContext.BaseDirectory;
            var versionFile = Path.Combine(exeDir, "version.txt");
            if (File.Exists(versionFile))
            {
                var text = File.ReadAllText(versionFile).Trim();
                if (!string.IsNullOrEmpty(text)) return text;
            }

            return typeof(TrayIconService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _uiThread = new Thread(RunUiThread);
            _uiThread.SetApartmentState(ApartmentState.STA);
            _uiThread.Start();
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
            }
            Application.Exit();
            return Task.CompletedTask;
        }

        private void RunUiThread()
        {
            _contextMenu = new ContextMenuStrip();
            var openItem = new ToolStripMenuItem("Settings", null, OnOpenDashboard)
            {
                Font = new System.Drawing.Font(System.Drawing.SystemFonts.MenuFont!, System.Drawing.FontStyle.Bold)
            };
            _contextMenu.Items.Add(openItem);
            _contextMenu.Items.Add(new ToolStripSeparator());
            _contextMenu.Items.Add("Open Quarantine Folder", null, OnOpenQuarantine);
            _contextMenu.Items.Add("Open Event Log", null, OnOpenEventLog);
            _contextMenu.Items.Add("Open Data Folder", null, OnOpenDataFolder);
            // No Exit Agent - service owns lifetime; tray exit was a soft self-stop that confused users.
            // No Report to Police on tray - filing stays under Settings -> Report to Police.

            System.Drawing.Icon? appIcon = null;
            try
            {
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                {
                    appIcon = new System.Drawing.Icon(icoPath);
                }
                else
                {
                    appIcon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                }
            }
            catch { }

            _notifyIcon = new NotifyIcon
            {
                Icon = appIcon ?? System.Drawing.SystemIcons.Shield,
                ContextMenuStrip = _contextMenu,
                Text = $"Sentinel v{_version} - Protection Active",
                Visible = true
            };

            _notifyIcon.DoubleClick += OnOpenDashboard;

            var watchThread = new Thread(() => WatchLogFileSync(_cts.Token))
            {
                IsBackground = true,
                Name = "SentinelLogWatcher"
            };
            watchThread.Start();

            Application.Run(new HiddenForm(_notifyIcon));
        }

        private class HiddenForm : Form
        {
            private readonly NotifyIcon _notifyIcon;
            private readonly int _taskbarCreatedMsg;

            [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            private static extern int RegisterWindowMessage(string lpString);

            public HiddenForm(NotifyIcon notifyIcon)
            {
                _notifyIcon = notifyIcon;
                _taskbarCreatedMsg = RegisterWindowMessage("TaskbarCreated");

                // Do NOT use WindowState=Minimized for the Application.Run main form.
                // A minimized main form can leave modeless Settings windows in a
                // "handle exists but WS_VISIBLE off" ghost state (Settings appears
                // not to open after tray click / shell recovery).
                ShowInTaskbar = false;
                FormBorderStyle = FormBorderStyle.FixedToolWindow;
                StartPosition = FormStartPosition.Manual;
                Location = new System.Drawing.Point(-10000, -10000);
                Size = new System.Drawing.Size(1, 1);
                Opacity = 0;
                ShowIcon = false;
                Text = "Sentinel Agent";

                _ = this.Handle;
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == _taskbarCreatedMsg)
                {
                    try
                    {
                        _notifyIcon.Visible = false;
                        _notifyIcon.Visible = true;
                    }
                    catch { }
                }
                base.WndProc(ref m);
            }
        }

        private void OnOpenDashboard(object? sender, EventArgs e)
        {
            ShowDashboard();
        }

        private void ShowDashboard()
        {
            if (_settingsForm == null || _settingsForm.IsDisposed)
            {
                _settingsForm = new AgentDashboardForm(_version, WebDashboardService.DashboardLaunchUrl);
                _settingsForm.FormClosed += (_, _) => _settingsForm = null;
            }

            if (_settingsForm.WindowState == FormWindowState.Minimized)
                _settingsForm.WindowState = FormWindowState.Normal;

            _settingsForm.Show();
            try
            {
                ShowWindow(_settingsForm.Handle, SwRestore);
                ShowWindow(_settingsForm.Handle, SwShow);
                BringWindowToTop(_settingsForm.Handle);
                SetForegroundWindow(_settingsForm.Handle);
            }
            catch { }
            _settingsForm.Activate();
            _settingsForm.BringToFront();
        }

        private static string ProgramDataRoot =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        private void OnOpenQuarantine(object? sender, EventArgs e)
        {
            try
            {
                var qDir = Path.Combine(ProgramDataRoot, "Quarantine");
                if (!Directory.Exists(qDir))
                {
                    MessageBox.Show(
                        "Quarantine folder does not exist yet. It is created by the Sentinel service when the first file is quarantined.",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // net48: ProcessStartInfo.ArgumentList is not available
                AgentDashboardForm.OpenFolder(qDir);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open quarantine: {ex.Message}");
            }
        }

        private void OnOpenEventLog(object? sender, EventArgs e)
        {
            try
            {
                var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");
                if (File.Exists(logFile))
                {
                    // net48: ProcessStartInfo.ArgumentList is not available
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "notepad.exe",
                        UseShellExecute = true,
                        Arguments = "\"" + logFile + "\""
                    });
                }
                else
                {
                    MessageBox.Show("Event log not found yet.", "Sentinel",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open event log: {ex.Message}");
            }
        }

        private void OnOpenDataFolder(object? sender, EventArgs e)
        {
            AgentDashboardForm.OpenFolder(ProgramDataRoot);
        }

        public void Dispose()
        {
            try { _settingsForm?.Dispose(); } catch { }
            _settingsForm = null;
            _notifyIcon?.Dispose();
            _contextMenu?.Dispose();
            _cts.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Synchronous log watcher on a dedicated background thread.
        /// Never touches the STA message pump.
        /// </summary>
        private void WatchLogFileSync(CancellationToken cancellationToken)
        {
            var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");

            while (!File.Exists(logFile) && !cancellationToken.IsCancellationRequested)
            {
                Thread.Sleep(1000);
            }

            long lastOffset = 0;
            try
            {
                if (File.Exists(logFile))
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    lastOffset = fs.Length;
                }
            }
            catch { }

            var shownCache = new System.Collections.Generic.Dictionary<string, DateTime>();

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var now = DateTime.UtcNow;
                    var keysToRemove = new System.Collections.Generic.List<string>();
                    foreach (var kvp in shownCache)
                    {
                        if (now - kvp.Value > TimeSpan.FromSeconds(30))
                            keysToRemove.Add(kvp.Key);
                    }
                    foreach (var k in keysToRemove)
                        shownCache.Remove(k);

                    if (File.Exists(logFile))
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);
                        if (fs.Length < lastOffset)
                            lastOffset = 0;

                        if (fs.Length > lastOffset)
                        {
                            fs.Seek(lastOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, System.Text.Encoding.UTF8, false, 4096, true);
                            string? line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (line.Contains("\"type\":\"detection\"", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        using var doc = JsonDocument.Parse(line);
                                        var data = doc.RootElement.GetProperty("data");
                                        var ruleName = data.GetProperty("RuleName").GetString() ?? "Threat Detected";
                                        var processName = data.GetProperty("ProcessName").GetString() ?? "unknown";
                                        var confidence = data.GetProperty("Confidence").GetDouble();
                                        var evidence = data.GetProperty("Evidence").GetString() ?? "";

                                        int tierVal = 1;
                                        if (data.TryGetProperty("Tier", out var tierProp))
                                            tierVal = tierProp.GetInt32();

                                        if (tierVal == 0)
                                            _pendingDetection = (ruleName, processName, confidence, evidence);
                                    }
                                    catch { }
                                }
                                else if (line.Contains("\"type\":\"response\"", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        using var doc = JsonDocument.Parse(line);
                                        var data = doc.RootElement.GetProperty("data");
                                        var actionTaken = data.GetProperty("ActionTaken").GetString() ?? "";

                                        if (_pendingDetection.HasValue &&
                                            (actionTaken == "KILL" || actionTaken == "QUARANTINE_AND_KILL" ||
                                             actionTaken == "NETWORK_ISOLATE" || actionTaken == "REMOVE_CERT_AND_KILL_ADDER"))
                                        {
                                            var (ruleName, processName, confidence, evidence) = _pendingDetection.Value;

                                            var cacheKey = $"{ruleName}:{processName}";
                                            if (shownCache.TryGetValue(cacheKey, out var lastShown))
                                            {
                                                if (DateTime.UtcNow - lastShown < TimeSpan.FromSeconds(30))
                                                {
                                                    _pendingDetection = null;
                                                    continue;
                                                }
                                            }
                                            shownCache[cacheKey] = DateTime.UtcNow;

                                            try
                                            {
                                                if (_notifyIcon != null)
                                                {
                                                    var tip = $"Sentinel v{_version} - last: {ruleName}";
                                                    if (tip.Length > 63) tip = tip[..63];
                                                    _notifyIcon.Text = tip;
                                                }
                                            }
                                            catch { }
                                        }
                                        _pendingDetection = null;
                                    }
                                    catch { _pendingDetection = null; }
                                }
                            }
                            lastOffset = fs.Position;
                        }
                    }
                }
                catch { }

                Thread.Sleep(1000);
            }
        }
    }
}
