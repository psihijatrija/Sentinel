using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Configuration for a monitor group - controls startup timing, restart policy,
    /// and resource budget for a set of related monitors.
    /// </summary>
    public sealed class MonitorGroupConfig
    {
        /// <summary>Human-readable group name for logging.</summary>
        public string Name { get; set; } = "Unnamed";

        /// <summary>Delay before starting this group (allows priority groups to stabilize first).</summary>
        public TimeSpan StartDelay { get; set; } = TimeSpan.Zero;

        /// <summary>Stagger between individual monitor starts within the group.</summary>
        public TimeSpan StaggerDelay { get; set; } = TimeSpan.FromMilliseconds(200);

        /// <summary>Maximum restart attempts for a failed monitor before giving up.</summary>
        public int MaxRestartAttempts { get; set; } = 3;

        /// <summary>Cooldown between restart attempts.</summary>
        public TimeSpan RestartCooldown { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Health check interval - how often to verify monitors are alive.</summary>
        public TimeSpan HealthCheckInterval { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>If true, restart indefinitely (critical monitors).</summary>
        public bool RestartIndefinitely { get; set; }

        /// <summary>
        /// Category reported to the MonitorRegistry for the dashboard health view.
        /// Defaults to SystemIntegrity; set per-group for accurate categorization.
        /// </summary>
        public MonitorCategory Category { get; set; } = MonitorCategory.SystemIntegrity;
    }

    /// <summary>
    /// Groups related background monitors into a single managed unit with:
    ///   - Staggered startup (avoids thundering herd on boot)
    ///   - Independent failure restart (one monitor crash doesn't kill others)
    ///   - Priority-based start ordering (critical groups start first)
    ///   - Health monitoring with configurable restart policy
    ///
    /// Replaces the flat 60+ AddHostedService registrations with ~7 logical groups.
    /// Each group controls its own lifecycle independently.
    /// </summary>
    public sealed class MonitorGroup : BackgroundService
    {
        private readonly MonitorGroupConfig _config;
        private readonly IReadOnlyList<IHostedService> _monitors;
        private readonly ILogger _logger;
        private readonly MonitorRegistry? _registry;
        private readonly Dictionary<IHostedService, MonitorState> _states = new();

        public MonitorGroup(
            MonitorGroupConfig config,
            IReadOnlyList<IHostedService> monitors,
            ILogger logger,
            MonitorRegistry? registry = null)
        {
            _config = config;
            _monitors = monitors;
            _logger = logger;
            _registry = registry;

            foreach (var monitor in _monitors)
            {
                _states[monitor] = new MonitorState();
                // Register with the health registry up front so the dashboard reflects
                // the full monitor roster even before staggered startup completes.
                _registry?.Register(GetMonitorName(monitor), _config.Category, monitor);
            }
        }

        /// <summary>Group name for diagnostics.</summary>
        public string GroupName => _config.Name;

        /// <summary>Number of monitors in this group.</summary>
        public int MonitorCount => _monitors.Count;

        /// <summary>Number of monitors currently running.</summary>
        public int RunningCount
        {
            get
            {
                int count = 0;
                foreach (var state in _states.Values)
                    if (state.IsRunning) count++;
                return count;
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[MonitorGroup:{Group}] Starting ({Count} monitors, delay={Delay}ms)",
                _config.Name, _monitors.Count, _config.StartDelay.TotalMilliseconds);

            // Respect group start delay (lets higher-priority groups stabilize first)
            if (_config.StartDelay > TimeSpan.Zero)
            {
                try { await Task.Delay(_config.StartDelay, stoppingToken); }
                catch (OperationCanceledException) { return; }
            }

            // Start monitors sequentially with stagger to avoid resource burst
            foreach (var monitor in _monitors)
            {
                if (stoppingToken.IsCancellationRequested) break;

                await StartMonitorAsync(monitor, stoppingToken);

                if (_config.StaggerDelay > TimeSpan.Zero)
                {
                    try { await Task.Delay(_config.StaggerDelay, stoppingToken); }
                    catch (OperationCanceledException) { break; }
                }
            }

            _logger.LogInformation("[MonitorGroup:{Group}] All monitors started ({Running}/{Total} running)",
                _config.Name, RunningCount, _monitors.Count);

            // Health check loop - restart failed monitors per group policy
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_config.HealthCheckInterval, stoppingToken);
                }
                catch (OperationCanceledException) { break; }

                foreach (var monitor in _monitors)
                {
                    if (stoppingToken.IsCancellationRequested) break;

                    var state = _states[monitor];
                    if (state.IsRunning)
                    {
                        // Piggyback a heartbeat onto the group health check so the
                        // MonitorRegistry watchdog sees running monitors as alive.
                        _registry?.Heartbeat(GetMonitorName(monitor));
                        continue;
                    }
                    if (state.Failed && !ShouldRestart(state)) continue;

                    _logger.LogWarning("[MonitorGroup:{Group}] Monitor {Monitor} is not running - attempting restart (attempt {Attempt})",
                        _config.Name, GetMonitorName(monitor), state.RestartAttempts + 1);

                    await RestartMonitorAsync(monitor, state, stoppingToken);
                }
            }

            // Shutdown: stop all monitors in reverse order
            _logger.LogInformation("[MonitorGroup:{Group}] Stopping all monitors", _config.Name);
            for (int i = _monitors.Count - 1; i >= 0; i--)
            {
                await StopMonitorAsync(_monitors[i]);
            }
        }

        private async Task StartMonitorAsync(IHostedService monitor, CancellationToken ct)
        {
            var state = _states[monitor];
            try
            {
                await monitor.StartAsync(ct);
                state.IsRunning = true;
                state.StartedAt = DateTimeOffset.UtcNow;
                state.Failed = false;
                _registry?.MarkStarted(GetMonitorName(monitor));
                _logger.LogDebug("[MonitorGroup:{Group}] Started {Monitor}",
                    _config.Name, GetMonitorName(monitor));
            }
            catch (Exception ex)
            {
                state.IsRunning = false;
                state.Failed = true;
                state.LastError = ex;
                _registry?.MarkFailed(GetMonitorName(monitor), ex);
                _logger.LogError(ex, "[MonitorGroup:{Group}] Failed to start {Monitor}",
                    _config.Name, GetMonitorName(monitor));
            }
        }

        private async Task RestartMonitorAsync(IHostedService monitor, MonitorState state, CancellationToken ct)
        {
            state.RestartAttempts++;
            state.LastRestartAttempt = DateTimeOffset.UtcNow;

            // Stop first (in case it's in a partial state)
            await StopMonitorAsync(monitor);

            // Cooldown
            try { await Task.Delay(_config.RestartCooldown, ct); }
            catch (OperationCanceledException) { return; }

            // Restart
            await StartMonitorAsync(monitor, ct);
        }

        private async Task StopMonitorAsync(IHostedService monitor)
        {
            var state = _states[monitor];
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await monitor.StopAsync(cts.Token);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MonitorGroup:{Group}] Error stopping {Monitor}",
                    _config.Name, GetMonitorName(monitor));
            }
            finally
            {
                state.IsRunning = false;
                _registry?.MarkStopped(GetMonitorName(monitor));

                if (monitor is IDisposable disposable)
                {
                    try { disposable.Dispose(); }
                    catch { }
                }
            }
        }

        private bool ShouldRestart(MonitorState state)
        {
            if (_config.RestartIndefinitely) return true;
            if (state.RestartAttempts >= _config.MaxRestartAttempts) return false;

            // Enforce cooldown between attempts
            if (state.LastRestartAttempt.HasValue)
            {
                var elapsed = DateTimeOffset.UtcNow - state.LastRestartAttempt.Value;
                if (elapsed < _config.RestartCooldown) return false;
            }

            return true;
        }

        private static string GetMonitorName(IHostedService monitor)
        {
            return monitor.GetType().Name;
        }

        private sealed class MonitorState
        {
            public bool IsRunning { get; set; }
            public bool Failed { get; set; }
            public DateTimeOffset? StartedAt { get; set; }
            public int RestartAttempts { get; set; }
            public DateTimeOffset? LastRestartAttempt { get; set; }
            public Exception? LastError { get; set; }
        }
    }
}
