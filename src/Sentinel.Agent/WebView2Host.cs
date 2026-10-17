using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Sentinel.Agent
{
    /// <summary>
    /// Isolates every reference to Microsoft.Web.WebView2 types into a single class so the CLR
    /// never JIT-compiles WebView2 method bodies until this class is first used.
    ///
    /// Prior to v3.2.7 the WebView2 usings lived directly in AgentDashboardForm.cs. On machines
    /// without the WebView2 managed assemblies (or with a mismatched native loader), the CLR threw
    /// TypeLoadException / FileNotFoundException during JIT of TryStartWebView2(), which happened
    /// BEFORE execution reached the try block — so the catch never fired and the STA thread
    /// crashed, taking the tray icon with it.
    ///
    /// Callers (AgentDashboardForm) catch TypeLoadException / FileNotFoundException at the
    /// call-site boundary of <see cref="TryStart"/>, ensuring the form always degrades cleanly.
    /// </summary>
    internal static class WebView2Host
    {
        /// <summary>
        /// Attempts to create and attach a WebView2 control to <paramref name="owner"/>.
        /// </summary>
        /// <param name="owner">The form that will host the control.</param>
        /// <param name="launchUrl">Dashboard URL to navigate to on successful init.</param>
        /// <param name="version">Agent version string (used in fallback title).</param>
        /// <param name="onFallback">
        ///   Called on the STA thread when WebView2 initialisation fails at runtime (after this
        ///   method returns true). The delegate receives a human-readable reason string.
        ///   The caller should degrade to the legacy browser at that point.
        /// </param>
        /// <returns>
        ///   <c>true</c>  — WebView2 was probed as available and the control was attached;
        ///                  the dashboard will navigate once the async init completes.
        ///   <c>false</c> — the runtime is absent (probe says no); the caller should fall back
        ///                  to the legacy browser immediately. <paramref name="onFallback"/> is
        ///                  NOT invoked in this case.
        /// </returns>
        /// <remarks>
        /// Exceptions from missing assemblies / native loader bubble out — the caller wraps this
        /// call in a try/catch for <see cref="TypeLoadException"/>, <see cref="FileNotFoundException"/>,
        /// etc. and treats them as "unavailable".
        /// </remarks>
        internal static bool TryStart(
            Form owner,
            string launchUrl,
            string version,
            Action<string> onFallback)
        {
            // Probe for a compatible Edge WebView2 Runtime before constructing the control.
            // GetAvailableBrowserVersionString() returns null/empty when no compatible runtime
            // exists; it does NOT throw in that case. This avoids the UnobservedTaskException
            // spam that the optimistic CreateAsync path produced when the runtime was missing.
            string? runtimeVersion;
            try
            {
                runtimeVersion = CoreWebView2Environment.GetAvailableBrowserVersionString();
            }
            catch (Exception ex)
            {
                // COM or loader issue - treat as unavailable; bubble nothing.
                onFallback("runtime probe failed: " + ex.Message);
                return true; // we handled it; don't double-fallback
            }

            if (string.IsNullOrWhiteSpace(runtimeVersion))
            {
                // Runtime absent - let the caller's false branch start the legacy browser.
                return false;
            }

            // Runtime is present. Build the environment and attach the control.
            var userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Sentinel", "WebView2");
            Directory.CreateDirectory(userDataFolder);

            var webView = new WebView2
            {
                Dock = DockStyle.Fill,
                DefaultBackgroundColor = Color.FromArgb(0x0D, 0x11, 0x17),
            };

            // Wire init-completed BEFORE adding to the form so we never miss the event.
            webView.CoreWebView2InitializationCompleted += (s, e) =>
                OnInitCompleted(owner, webView, launchUrl, e, onFallback);

            owner.Controls.Add(webView);

            // Create the environment asynchronously and then initialize the control on the
            // STA thread. No await — marshalled via BeginInvoke per NFR-6.
            var envTask = CoreWebView2Environment.CreateAsync(
                browserExecutableFolder: null,
                userDataFolder: userDataFolder,
                options: null);

            envTask.ContinueWith(t =>
            {
                if (t.IsFaulted || t.IsCanceled)
                {
                    if (t.IsFaulted)
                        System.Diagnostics.Trace.TraceWarning(
                            "Sentinel WebView2 environment unavailable: {0}", t.Exception);
                    BeginInvokeFallback(owner, webView, onFallback,
                        t.Exception?.GetBaseException().Message ?? "environment task cancelled");
                    return;
                }

                try
                {
                    if (owner.IsDisposed) return;
                    owner.BeginInvoke((Action)(() =>
                    {
                        try
                        {
                            if (owner.IsDisposed) return;
                            var initTask = webView.EnsureCoreWebView2Async(t.Result);
                            initTask.ContinueWith(completed =>
                            {
                                if (completed.IsFaulted)
                                    System.Diagnostics.Trace.TraceWarning(
                                        "Sentinel WebView2 initialization failed: {0}", completed.Exception);
                                if (completed.IsFaulted || completed.IsCanceled)
                                    BeginInvokeFallback(owner, webView, onFallback,
                                        completed.Exception?.GetBaseException().Message ?? "init cancelled");
                            }, System.Threading.Tasks.TaskScheduler.Default);
                        }
                        catch (Exception ex)
                        {
                            DisposeControl(owner, webView);
                            onFallback("STA init dispatch failed: " + ex.Message);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    BeginInvokeFallback(owner, webView, onFallback,
                        "env continuation failed: " + ex.Message);
                }
            });

            return true;
        }

        private static void OnInitCompleted(
            Form owner,
            WebView2 webView,
            string launchUrl,
            CoreWebView2InitializationCompletedEventArgs e,
            Action<string> onFallback)
        {
            if (!e.IsSuccess || webView.CoreWebView2 == null)
            {
                var reason = e.InitializationException?.Message ?? "init reported failure";
                DisposeControl(owner, webView);
                onFallback(reason);
                return;
            }

            try
            {
                var core = webView.CoreWebView2;
                // Lock the embedded host down: no devtools, no context menu, no new windows.
                core.Settings.AreDevToolsEnabled = false;
                core.Settings.AreDefaultContextMenusEnabled = false;
                core.Settings.IsStatusBarEnabled = false;
                core.Settings.AreBrowserAcceleratorKeysEnabled = false;
                core.NewWindowRequested += (_, args) => args.Handled = true;

                webView.Source = new Uri(launchUrl);
            }
            catch (Exception ex)
            {
                DisposeControl(owner, webView);
                onFallback("post-init navigation failed: " + ex.Message);
            }
        }

        private static void BeginInvokeFallback(
            Form owner,
            WebView2 webView,
            Action<string> onFallback,
            string reason)
        {
            try
            {
                if (owner.IsDisposed) return;
                owner.BeginInvoke((Action)(() =>
                {
                    DisposeControl(owner, webView);
                    onFallback(reason);
                }));
            }
            catch { /* form gone */ }
        }

        private static void DisposeControl(Form owner, WebView2 webView)
        {
            try
            {
                owner.Controls.Remove(webView);
                webView.Dispose();
            }
            catch { /* best effort */ }
        }
    }
}
