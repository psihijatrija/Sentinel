using Microsoft.Extensions.Logging;

namespace Sentinel.Core.Monitors
{
    /// <summary>
    /// Marker for an <see cref="IMonitor"/> that is intentionally not running - an optional
    /// feature switched off by config, or a genuinely-absent OS capability. The service
    /// registers these in the terminal <c>Disabled</c> state so the watchdog never evaluates
    /// them and the dashboard reports them honestly as "disabled", never as running or failed.
    /// </summary>
    public interface IDisabledMonitor
    {
        /// <summary>Human-readable reason the monitor is not running (shown on the dashboard).</summary>
        string DisabledReason { get; }
    }

    /// <summary>
    /// Generic no‑op monitor used when an optional feature is off or a required platform
    /// capability is missing. It implements <see cref="IMonitor"/> so the DI container can
    /// resolve the type, and <see cref="IDisabledMonitor"/> so the service records it as an
    /// honest "disabled" rather than letting the watchdog flag a non-heartbeating no-op.
    /// </summary>
    public class DisabledMonitor<T> : IMonitor, IDisabledMonitor where T : class
    {
        private readonly ILogger<DisabledMonitor<T>> _log;
        public DisabledMonitor(ILogger<DisabledMonitor<T>> log, string reason = "No disable reason supplied; configuration requires investigation.")
        {
            _log = log;
            DisabledReason = reason;
        }
        public string Name => typeof(T).Name;
        public string DisabledReason { get; }
        public Task StartAsync(CancellationToken ct)
        {
            _log?.LogInformation(
                "{Monitor} is disabled by configuration/capability - not started (this is expected, not a failure).",
                typeof(T).Name);
            return Task.CompletedTask;
        }
        public Task StopAsync() => Task.CompletedTask;
    }
}
