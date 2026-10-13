using System;
using System.Management;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core.Infrastructure
{
    /// <summary>
    /// Probes optional OS capabilities (WMI, ETW, EventLog) at startup.
    /// Allows the host to disable monitors when the underlying service is missing.
    /// </summary>
    public interface ISystemCapabilityProvider
    {
        bool WmiAvailable { get; }
        bool EtwAvailable { get; }
        bool EventLogAvailable { get; }
    }

    public class SystemCapabilityProvider : ISystemCapabilityProvider
    {
        private readonly ILogger<SystemCapabilityProvider> _log;
        public SystemCapabilityProvider(ILogger<SystemCapabilityProvider> log)
        {
            _log = log;
            WmiAvailable = CheckWmi();
            EtwAvailable = CheckEtw();
            EventLogAvailable = CheckEventLog();
        }

        public bool WmiAvailable { get; private set; }
        public bool EtwAvailable { get; private set; }
        public bool EventLogAvailable { get; private set; }

        private bool CheckWmi()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (var _ in searcher.Get()) { break; }
                return true;
            }
            catch (Exception ex)
            {
                _log?.LogWarning(ex, "WMI not available – related monitors will be disabled.");
                return false;
            }
        }

        private bool CheckEtw()
        {
            // ETW detection is disabled in this build to avoid missing assembly references.
            // Returning false ensures ETW‑dependent monitors are gracefully skipped.
            _log?.LogInformation("ETW capability check disabled – returning false.");
            return false;
        }


        private bool CheckEventLog()
        {
            try
            {
                return System.Diagnostics.EventLog.SourceExists("SentinelService");
            }
            catch (Exception ex)
            {
                _log?.LogWarning(ex, "Event Log not available – logger will be disabled.");
                return false;
            }
        }
    }
}
