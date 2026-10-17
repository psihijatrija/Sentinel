using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Sentinel.Agent
{
    /// <summary>
    /// Thin shell form hosting an embedded browser that displays the Sentinel web dashboard
    /// served by <see cref="WebDashboardService"/> on localhost.
    ///
    /// v3.0.6: prefers the Edge/Chromium WebView2 control (modern CSS/JS, no IE11 quirks) and
    /// falls back to the legacy WinForms <see cref="WebBrowser"/> (IE11 emulation) when the Edge
    /// WebView2 Runtime is not installed - so a host without the runtime still gets a working
    /// Settings window instead of a crash (graceful degradation, NFR-2).
    ///
    /// v3.2.7: WebView2 types are isolated in <see cref="WebView2Host"/> so the CLR never
    /// JIT-compiles WebView2 method bodies when the assemblies are absent. Previously a
    /// TypeLoadException during JIT of TryStartWebView2() would escape the try/catch and crash
    /// the STA thread before the tray icon appeared.
    ///
    /// No async/await is used on the Agent STA thread (NFR-6): WebView2 initialization is driven
    /// via the CoreWebView2InitializationCompleted event, not awaited.
    /// </summary>
    public sealed class AgentDashboardForm : Form
    {
        private readonly string _launchUrl;
        private readonly string _version;
        private WebBrowser? _legacyBrowser;

        public AgentDashboardForm(string version, string launchUrl)
        {
            _launchUrl = launchUrl;
            _version = version;

            Text = $"Sentinel Dashboard \u2014 v{version}";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(980, 640);
            Size = new Size(1200, 780);
            BackColor = Color.FromArgb(0x0D, 0x11, 0x17);
            ShowInTaskbar = true;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;

            try
            {
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                    Icon = new Icon(icoPath);
                else
                    Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch { /* icon optional */ }

            Load += OnFormLoad;
        }

        private void OnFormLoad(object? sender, EventArgs e)
        {
            // v3.2.7: WebView2Host is a separately-compiled helper class. Calling it through a
            // method boundary means the CLR only JIT-compiles WebView2 method bodies if the
            // assemblies actually load. A TypeLoadException / BadImageFormatException raised here
            // is caught and degrades cleanly to the legacy browser — previously the exception
            // escaped the try/catch in TryStartWebView2 because it fired during JIT of that very
            // method, before execution reached the try block.
            bool webViewStarted = false;
            try
            {
                webViewStarted = WebView2Host.TryStart(this, _launchUrl, _version, OnFallbackRequested);
            }
            catch (Exception ex) when (IsWebView2AssemblyException(ex))
            {
                // WebView2 managed assemblies or native loader are absent. Degrade immediately.
                ReportWebView2Unavailable("assembly load failed: " + ex.GetBaseException().Message);
                MarkLegacyMode();
            }

            if (!webViewStarted)
                StartLegacyBrowser();
        }

        // Called by WebView2Host on the STA thread when WebView2 init fails at runtime.
        private void OnFallbackRequested(string reason)
        {
            if (_fellBack) return;
            _fellBack = true;
            ReportWebView2Unavailable(reason);
            MarkLegacyMode();
            StartLegacyBrowser();
        }

        private bool _fellBack;

        /// <summary>
        /// Returns true for exceptions that indicate the WebView2 managed assemblies or native
        /// loader could not be found or loaded — distinct from runtime-absent errors which
        /// ProbeWebView2Runtime inside WebView2Host handles separately.
        /// </summary>
        private static bool IsWebView2AssemblyException(Exception ex)
        {
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (e is System.IO.FileNotFoundException ||
                    e is System.IO.FileLoadException ||
                    e is BadImageFormatException ||
                    e is TypeLoadException)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Records that WebView2 is unavailable and the dashboard is falling back to IE11.
        /// Written to agent_runtime.log (not agent_crash.log — this is a status notice, not a crash).
        /// </summary>
        private void ReportWebView2Unavailable(string reason)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var logPath = Path.Combine(programData, "Sentinel", "agent_runtime.log");
                var msg = $"[{DateTime.UtcNow:o}] [Info] WebView2 unavailable: {reason}. " +
                          "Dashboard using the legacy IE11 WebBrowser control. " +
                          "Install the Microsoft Edge WebView2 Runtime (Evergreen) to enable the modern dashboard." +
                          Environment.NewLine;
                File.AppendAllText(logPath, msg);
                System.Diagnostics.Trace.TraceWarning(
                    "Sentinel: WebView2 unavailable ({0}); using legacy IE11 browser for dashboard.", reason);
            }
            catch { /* logging is best-effort */ }
        }

        private void MarkLegacyMode()
        {
            try { Text = $"Sentinel Dashboard \u2014 v{_version} (legacy browser \u2014 WebView2 unavailable)"; }
            catch { /* cosmetic */ }
        }

        /// <summary>
        /// Legacy WinForms WebBrowser (IE11 emulation) path. Used when WebView2 / its runtime is
        /// unavailable so Settings always renders something usable.
        /// </summary>
        private void StartLegacyBrowser()
        {
            SetBrowserEmulationMode();

            var browser = new WebBrowser
            {
                Dock = DockStyle.Fill,
                ScriptErrorsSuppressed = true,
                IsWebBrowserContextMenuEnabled = false,
                AllowWebBrowserDrop = false,
                WebBrowserShortcutsEnabled = true
            };
            Controls.Add(browser);
            _legacyBrowser = browser;

            try
            {
                browser.Navigate(_launchUrl);
            }
            catch (Exception ex)
            {
                browser.DocumentText = $@"
                    <html><body style='background:#0d1117;color:#e6edf3;font-family:Segoe UI,sans-serif;padding:40px'>
                    <h2>Dashboard Unavailable</h2>
                    <p>Could not connect to the embedded dashboard server.</p>
                    <p style='color:#8b949e'>{System.Net.WebUtility.HtmlEncode(ex.Message)}</p>
                    <p style='color:#8b949e'>URL: {System.Net.WebUtility.HtmlEncode(_launchUrl)}</p>
                    </body></html>";
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _legacyBrowser?.Dispose(); } catch { }
                _legacyBrowser = null;
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// Opens the specified folder in Explorer. Used by TrayIconService context menu.
        /// </summary>
        internal static void OpenFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    MessageBox.Show(
                        $"Folder does not exist yet:\n{path}",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true,
                    Verb = "open"
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not open folder:\n{path}\n\n{ex.Message}",
                    "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        /// <summary>
        /// Sets the FEATURE_BROWSER_EMULATION registry key for this process so the legacy
        /// WebBrowser control renders in IE11 Edge mode (CSS grid/flexbox). Only relevant on the
        /// fallback path; harmless otherwise.
        /// </summary>
        private static void SetBrowserEmulationMode()
        {
            try
            {
                var exeName = Path.GetFileName(Application.ExecutablePath);
                using var key = Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION",
                    RegistryKeyPermissionCheck.ReadWriteSubTree);
                // 11001 = IE11 Edge mode
                key?.SetValue(exeName, 11001, RegistryValueKind.DWord);
            }
            catch
            {
                // Best effort - dashboard still works in quirks mode, just uglier
            }
        }
    }
}
