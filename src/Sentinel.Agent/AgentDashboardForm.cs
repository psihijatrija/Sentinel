using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Web.WebView2.Core;

namespace Sentinel.Agent
{
    /// <summary>
    /// Thin shell form hosting an embedded browser that displays the Sentinel web dashboard
    /// served by <see cref="WebDashboardService"/> on localhost.
    ///
    /// v3.0.6: prefers the Edge/Chromium <see cref="WebView2"/> control (modern CSS/JS, no IE11
    /// quirks) and falls back to the legacy WinForms <see cref="WebBrowser"/> (IE11 emulation)
    /// when the Edge WebView2 Runtime is not installed - so a host without the runtime still gets
    /// a working Settings window instead of a crash (graceful degradation, NFR-2).
    ///
    /// No async/await is used on the Agent STA thread (NFR-6): WebView2 initialization is driven
    /// via the CoreWebView2InitializationCompleted event, not awaited.
    /// </summary>
    public sealed class AgentDashboardForm : Form
    {
        private readonly string _launchUrl;
        private readonly string _version;
        private WebView2? _webView;
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
            if (!TryStartWebView2())
                StartLegacyBrowser();
        }

        /// <summary>
        /// Attempt to host the dashboard in WebView2. Returns true if the control was created and
        /// initialization was kicked off; the actual navigate happens in the init-completed handler,
        /// which also falls back to the legacy browser on failure. Returns false if the control
        /// could not even be constructed (assemblies/loader missing), so the caller falls back.
        /// </summary>
        private bool TryStartWebView2()
        {
            try
            {
                // WebView2 keeps a per-user browser profile; it must be a writable location.
                // The install dir may be read-only for the interactive user, so use LocalAppData.
                var userDataFolder = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Sentinel", "WebView2");
                Directory.CreateDirectory(userDataFolder);

                var env = CoreWebView2Environment.CreateAsync(
                    browserExecutableFolder: null,
                    userDataFolder: userDataFolder,
                    options: null);

                var webView = new WebView2
                {
                    Dock = DockStyle.Fill,
                    DefaultBackgroundColor = Color.FromArgb(0x0D, 0x11, 0x17),
                };
                webView.CoreWebView2InitializationCompleted += OnWebViewInitCompleted;

                Controls.Add(webView);
                _webView = webView;

                // Initialize against the environment once it is ready. No await on the STA thread:
                // attach a continuation that marshals back to the UI thread.
                env.ContinueWith(t =>
                {
                    if (t.IsFaulted || t.Result == null)
                    {
                        BeginInvokeFallback();
                        return;
                    }
                    try
                    {
                        if (IsDisposed || _webView == null) return;
                        BeginInvoke((Action)(() =>
                        {
                            try { _webView.EnsureCoreWebView2Async(t.Result); }
                            catch { StartLegacyBrowserOnce(); }
                        }));
                    }
                    catch { BeginInvokeFallback(); }
                });

                return true;
            }
            catch
            {
                // Assemblies or native loader not present - construction itself failed.
                DisposeWebView();
                return false;
            }
        }

        private void OnWebViewInitCompleted(object? sender, CoreWebView2InitializationCompletedEventArgs e)
        {
            if (!e.IsSuccess || _webView?.CoreWebView2 == null)
            {
                // Runtime missing or init failed - swap in the legacy browser.
                StartLegacyBrowserOnce();
                return;
            }

            try
            {
                var core = _webView.CoreWebView2;
                // Lock the embedded host down: no devtools, no context menu, no new windows.
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.IsStatusBarEnabled = false;
                core.Settings.AreBrowserAcceleratorKeysEnabled = false;
                // Keep navigation inside the loopback dashboard; open nothing in a popup.
                core.NewWindowRequested += (_, args) => args.Handled = true;

                _webView.Source = new Uri(_launchUrl);
            }
            catch
            {
                StartLegacyBrowserOnce();
            }
        }

        private void BeginInvokeFallback()
        {
            try
            {
                if (IsDisposed) return;
                BeginInvoke((Action)StartLegacyBrowserOnce);
            }
            catch { /* form gone */ }
        }

        private bool _fellBack;

        private void StartLegacyBrowserOnce()
        {
            if (_fellBack) return;
            _fellBack = true;
            DisposeWebView();
            StartLegacyBrowser();
        }

        private void DisposeWebView()
        {
            try
            {
                if (_webView != null)
                {
                    _webView.CoreWebView2InitializationCompleted -= OnWebViewInitCompleted;
                    Controls.Remove(_webView);
                    _webView.Dispose();
                    _webView = null;
                }
            }
            catch { /* best effort */ }
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
                DisposeWebView();
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
