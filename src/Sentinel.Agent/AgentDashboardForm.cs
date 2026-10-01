using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Sentinel.Agent
{
    /// <summary>
    /// Thin shell form hosting an embedded WebBrowser control that displays the
    /// Sentinel web dashboard served by <see cref="WebDashboardService"/> on localhost.
    /// This replaces the previous complex WinForms sidebar dashboard (v2.2.2) with
    /// the richer HTML/CSS/JS UI while avoiding the broken-http-protocol-handler
    /// problem that affected external browser launches.
    /// </summary>
    public sealed class AgentDashboardForm : Form
    {
        private readonly WebBrowser _browser;
        private readonly string _launchUrl;

        public AgentDashboardForm(string version, string launchUrl)
        {
            _launchUrl = launchUrl;

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

            // Force the embedded WebBrowser to use Edge mode (IE11 standards)
            // rather than IE7 compatibility. This enables CSS grid/flexbox support.
            SetBrowserEmulationMode();

            _browser = new WebBrowser
            {
                Dock = DockStyle.Fill,
                ScriptErrorsSuppressed = true,
                IsWebBrowserContextMenuEnabled = false,
                AllowWebBrowserDrop = false,
                WebBrowserShortcutsEnabled = true
            };

            Controls.Add(_browser);

            Load += OnFormLoad;
        }

        private void OnFormLoad(object? sender, EventArgs e)
        {
            try
            {
                _browser.Navigate(_launchUrl);
            }
            catch (Exception ex)
            {
                _browser.DocumentText = $@"
                    <html><body style='background:#0d1117;color:#e6edf3;font-family:Segoe UI,sans-serif;padding:40px'>
                    <h2>Dashboard Unavailable</h2>
                    <p>Could not connect to the embedded dashboard server.</p>
                    <p style='color:#8b949e'>{System.Net.WebUtility.HtmlEncode(ex.Message)}</p>
                    <p style='color:#8b949e'>URL: {System.Net.WebUtility.HtmlEncode(_launchUrl)}</p>
                    </body></html>";
            }
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
        /// Sets the FEATURE_BROWSER_EMULATION registry key for this process so the
        /// embedded WebBrowser control renders in IE11 Edge mode (supports CSS grid,
        /// flexbox, and modern JS features available in IE11).
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
