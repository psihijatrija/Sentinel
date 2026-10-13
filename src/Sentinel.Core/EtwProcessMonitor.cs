using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Process monitoring via ETW - delegates to UnifiedEtwSession when active.
    /// 
    /// When UnifiedEtwSession.IsActive is true:
    ///   - ETW provides process events at ~50ms latency
    ///   - WmiProcessMonitor is disabled to prevent duplicate events
    /// 
    /// When UnifiedEtwSession.IsActive is false (current state):
    ///   - WmiProcessMonitor provides fallback telemetry (~1-2s latency)
    ///   - All detection rules and correlation still function identically
    ///   - Only difference is detection latency, not coverage
    /// </summary>
    public sealed class EtwProcessMonitor : IMonitor
    {
        public string Name => "EtwProcessMonitor";

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
            if (_unifiedSession.IsActive)
            {
                _wmiProcessMonitor?.Disable();
                _logger.LogInformation(
                    "[{Monitor}] UnifiedEtwSession active - process events at ~50ms. WMI disabled.", Name);
            }
            else
            {
                _logger.LogInformation(
                    "[{Monitor}] UnifiedEtwSession inactive - WmiProcessMonitor provides fallback (~1-2s).", Name);
            }

            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _logger.LogInformation("[{Monitor}] Stopped", Name);
            return Task.CompletedTask;
        }
    }
}
