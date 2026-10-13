using Microsoft.Extensions.Logging;

namespace Sentinel.Core.Monitors
{
    /// <summary>
    /// Generic no‑op monitor used when a required platform capability is missing.
    /// It implements <see cref="IMonitor"/> so the DI container can resolve the type,
    /// but its <c>StartAsync</c> simply logs a warning and returns.
    /// </summary>
    public class DisabledMonitor<T> : IMonitor where T : class
    {
        private readonly ILogger<DisabledMonitor<T>> _log;
        public DisabledMonitor(ILogger<DisabledMonitor<T>> log) => _log = log;
        public string Name => typeof(T).Name;
        public Task StartAsync(CancellationToken ct)
        {
            _log?.LogWarning("{Monitor} disabled – required OS capability is unavailable.", typeof(T).Name);
            return Task.CompletedTask;
        }
        public Task StopAsync() => Task.CompletedTask;
    }
}
