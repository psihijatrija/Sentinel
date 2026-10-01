using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;

namespace Sentinel.Core.Monitors
{
    /// <summary>
    /// Placeholder monitor for hardware performance monitoring unit (PMU) telemetry.
    /// Currently a no‑op implementation; future work will surface hardware counters.
    /// </summary>
    public class HardwarePmuMonitor : IMonitor
    {
        public string Name => nameof(HardwarePmuMonitor);

        public Task StartAsync(CancellationToken ct)
        {
            // No‑op: return completed task. In a real implementation this would
            // subscribe to hardware counters when the capability flag is enabled.
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            // No‑op cleanup.
            return Task.CompletedTask;
        }
    }
}
