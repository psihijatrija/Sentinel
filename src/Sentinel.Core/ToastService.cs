using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Displays Windows toast notifications for Sentinel detections.
    /// Falls back to logging if the service lacks a desktop session or
    /// the AppUserModelID is not registered.
    /// </summary>
    public class ToastService
    {
        private readonly ILogger<ToastService> _logger;
        private static readonly Guid CLSID_ShellLink = new("00021401-0000-0000-C000-000000000046");
        private bool _hasAppId = false;

        /// <summary>
        /// When true, only ShowCriticalToast calls produce notifications.
        /// Regular ShowToast calls are suppressed (log only).
        /// </summary>
        public bool CriticalOnly { get; set; } = true;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string appId);

        public ToastService(ILogger<ToastService> logger)
        {
            _logger = logger;
            try
            {
                SetCurrentProcessExplicitAppUserModelID("Gorstak.Sentinel");
                _hasAppId = true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ToastService: Could not set AppUserModelID");
            }
        }

        /// <summary>
        /// Shows a toast only if CriticalOnly is false. Used for informational detections.
        /// </summary>
        public void ShowToast(string title, string message, string? tag = null)
        {
            if (CriticalOnly)
            {
                _logger.LogDebug("ToastService: Suppressed non-critical toast - {Title}", title);
                return;
            }
            ShowToastInternal(title, message);
        }

        /// <summary>
        /// Always shows a toast regardless of CriticalOnly setting. Used for kills, blocks, quarantine.
        /// </summary>
        public void ShowCriticalToast(string title, string message)
        {
            ShowToastInternal(title, message);
        }

        private void ShowToastInternal(string title, string message)
        {
            try
            {
                if (!_hasAppId)
                {
                    _logger.LogDebug("ToastService: No AppUserModelID registered; skipping toast. Detection: {Title}", title);
                    return;
                }

                var toastXml = $@"
<toast>
    <visual>
        <binding template=""ToastGeneric"">
            <text>{System.Security.SecurityElement.Escape(title)}</text>
            <text>{System.Security.SecurityElement.Escape(message)}</text>
        </binding>
    </visual>
</toast>";

                var xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.LoadXml(toastXml);

                // Use reflection to call Windows.UI.Notifications APIs since they may not
                // be available on all build configurations.
                var toastNotifMgrType = Type.GetType("Windows.UI.Notifications.ToastNotificationManager, Windows.UI, ContentType=WindowsRuntime", throwOnError: false);
                if (toastNotifMgrType == null)
                {
                    _logger.LogDebug("ToastService: ToastNotificationManager type not available");
                    return;
                }

                var createNotifier = toastNotifMgrType.GetMethod("CreateToastNotifier", new[] { typeof(string) });
                if (createNotifier == null)
                {
                    _logger.LogDebug("ToastService: CreateToastNotifier method not found");
                    return;
                }

                var notifier = createNotifier.Invoke(null, new object[] { "Gorstak.Sentinel" });
                if (notifier == null)
                {
                    _logger.LogDebug("ToastService: Could not create toast notifier");
                    return;
                }

                var toastNotifType = Type.GetType("Windows.UI.Notifications.ToastNotification, Windows.UI, ContentType=WindowsRuntime", throwOnError: false);
                if (toastNotifType == null)
                {
                    _logger.LogDebug("ToastService: ToastNotification type not available");
                    return;
                }

                var toast = Activator.CreateInstance(toastNotifType, xmlDoc);
                if (toast == null)
                {
                    _logger.LogDebug("ToastService: Could not create ToastNotification");
                    return;
                }

                var showMethod = notifier.GetType().GetMethod("Show", new[] { toastNotifType });
                if (showMethod == null)
                {
                    _logger.LogDebug("ToastService: Show method not found on notifier");
                    return;
                }

                showMethod.Invoke(notifier, new[] { toast });
                _logger.LogDebug("ToastService: Shown toast - {Title}", title);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ToastService: Failed to show toast");
            }
        }
    }
}
