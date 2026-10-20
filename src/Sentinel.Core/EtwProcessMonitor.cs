using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>Checks the process provider and ETW consumer continuously. Falls back to
    /// WMI/process snapshots when unavailable, reporting the resulting coverage reduction.</summary>
    public sealed class EtwProcessMonitor : IMonitor, ISensorProgressSource, IMonitorHealthCheck
    {
        public string Name => "EtwProcessMonitor";
        public SensorProgress Progress { get; } = new(TimeSpan.FromSeconds(20))
            { Scope = "Kernel process provider enabled and ETW consumer alive; this check alone does not prove process-start delivery." };

        private readonly UnifiedEtwSession _unifiedSession;
        private readonly WmiProcessMonitor? _wmiProcessMonitor;
        private readonly ILogger<EtwProcessMonitor> _logger;

        public EtwProcessMonitor(
            UnifiedEtwSession unifiedSession,
            ILogger<EtwProcessMonitor> logger,
            WmiProcessMonitor? wmiProcessMonitor = null)
        {
            _unifiedSession = unifiedSession;
            _wmiProcessMonitor = wmiProcessMonitor;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken ct)
        {
            CheckHealth();

            return Task.CompletedTask;
        }

        public void CheckHealth()
        {
            if (_unifiedSession.IsProviderActive(UnifiedEtwSession.Providers.KernelProcess))
            {
                _wmiProcessMonitor?.Disable();
                Progress.Succeeded();
            }
            else
            {
                _wmiProcessMonitor?.Enable();
                // A snapshot fallback is useful but not equivalent to event telemetry:
                // it misses processes shorter than the polling interval and has no command line.
                Progress.Failed(_wmiProcessMonitor?.IsSnapshotHealthy == true
                    ? "Kernel process ETW unavailable; process snapshots active with reduced coverage (short-lived processes/command lines)."
                    : "Kernel process ETW unavailable; no verified process snapshot fallback.");
            }
        }

        public Task StopAsync()
        {
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
