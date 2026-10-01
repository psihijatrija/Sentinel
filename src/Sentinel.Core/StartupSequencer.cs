using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Dependency-ordered startup with readiness gates and verification.
    ///
    /// Problem solved: Previously, all monitors started in arbitrary DI registration order.
    /// FileVerdictScanner could start before HashReputationService was ready.
    /// BeaconingDetector could start before NetworkMonitor was feeding it connections.
    /// ProcessAncestryCache might not be populated before monitors that depend on it.
    ///
    /// StartupSequencer provides:
    ///   - Phased startup: Infrastructure -> Engines -> Monitors -> Validators
    ///   - Readiness gates: each phase waits for the prior phase to report ready
    ///   - Timeout enforcement: phases that don't complete in time get logged and skipped
    ///   - Startup report: complete manifest of what started, what failed, total boot time
    /// </summary>
    public sealed class StartupSequencer
    {
        private readonly MonitorRegistry _registry;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<StartupSequencer> _logger;

        private readonly List<StartupPhase> _phases = new();
        private StartupReport? _lastReport;

        public StartupSequencer(
            MonitorRegistry registry,
            JsonlEventLogger eventLogger,
            ILogger<StartupSequencer> logger)
        {
            _registry = registry;
            _eventLogger = eventLogger;
            _logger = logger;
        }

        /// <summary>
        /// Defines the startup phases in dependency order.
        /// Call this once during service initialization to declare the boot sequence.
        /// </summary>
        public void DefinePhases(IReadOnlyList<StartupPhase> phases)
        {
            _phases.Clear();
            _phases.AddRange(phases);
        }

        /// <summary>
        /// Executes all startup phases in order. Each phase completes before the next begins.
        /// Returns a report of what succeeded, failed, and how long it took.
        /// </summary>
        public async Task<StartupReport> ExecuteAsync(CancellationToken ct)
        {
            var report = new StartupReport { StartTime = DateTimeOffset.UtcNow };
            var totalSw = Stopwatch.StartNew();

            _logger.LogInformation("[StartupSequencer] Beginning phased startup ({Count} phases)...", _phases.Count);

            foreach (var phase in _phases)
            {
                var phaseSw = Stopwatch.StartNew();
                var phaseResult = new PhaseResult { PhaseName = phase.Name, Order = phase.Order };

                _logger.LogInformation("[StartupSequencer] Phase {Order}: {Name} ({Count} components)...",
                    phase.Order, phase.Name, phase.Components.Count);

                // Execute all components in this phase (parallel within phase, sequential between phases)
                var tasks = new List<Task<ComponentResult>>();
                foreach (var component in phase.Components)
                {
                    tasks.Add(StartComponentAsync(component, phase.TimeoutSeconds, ct));
                }

                try
                {
                    var results = await Task.WhenAll(tasks);
                    phaseResult.Components.AddRange(results);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[StartupSequencer] Phase {Name} had unhandled errors", phase.Name);
                }

                phaseSw.Stop();
                phaseResult.DurationMs = phaseSw.ElapsedMilliseconds;
                phaseResult.Success = phaseResult.Components.All(c => c.Success);

                report.Phases.Add(phaseResult);

                if (!phaseResult.Success && phase.Required)
                {
                    _logger.LogError("[StartupSequencer] REQUIRED phase '{Name}' FAILED - continuing with degraded operation",
                        phase.Name);
                    report.DegradedMode = true;
                }

                _logger.LogInformation("[StartupSequencer] Phase {Order}: {Name} completed in {Ms}ms ({Passed}/{Total} OK)",
                    phase.Order, phase.Name, phaseResult.DurationMs,
                    phaseResult.Components.Count(c => c.Success), phaseResult.Components.Count);

                // Readiness gate: brief pause between phases to let components stabilize
                if (!ct.IsCancellationRequested && phase.StabilizationDelayMs > 0)
                {
                    await Task.Delay(phase.StabilizationDelayMs, ct);
                }
            }

            totalSw.Stop();
            report.TotalDurationMs = totalSw.ElapsedMilliseconds;
            report.EndTime = DateTimeOffset.UtcNow;
            report.TotalComponents = report.Phases.Sum(p => p.Components.Count);
            report.SuccessfulComponents = report.Phases.Sum(p => p.Components.Count(c => c.Success));
            report.FailedComponents = report.TotalComponents - report.SuccessfulComponents;

            _lastReport = report;

            // Log startup report
            await _eventLogger.LogEventAsync("startup_complete", new
            {
                TotalMs = report.TotalDurationMs,
                Phases = report.Phases.Count,
                report.TotalComponents,
                report.SuccessfulComponents,
                report.FailedComponents,
                report.DegradedMode,
                Timestamp = report.EndTime
            });

            _logger.LogInformation(
                "[StartupSequencer] Startup COMPLETE in {Ms}ms - {OK}/{Total} components running{Degraded}",
                report.TotalDurationMs, report.SuccessfulComponents, report.TotalComponents,
                report.DegradedMode ? " [DEGRADED MODE]" : "");

            return report;
        }

        private async Task<ComponentResult> StartComponentAsync(
            StartupComponent component, int phaseTimeoutSeconds, CancellationToken ct)
        {
            var result = new ComponentResult { Name = component.Name, Category = component.Category };
            var sw = Stopwatch.StartNew();

            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(phaseTimeoutSeconds));

                // Register with MonitorRegistry before starting
                _registry.Register(component.Name, component.Category, component.Instance);

                // Execute the startup action
                await component.StartAction(timeoutCts.Token);

                sw.Stop();
                result.Success = true;
                result.DurationMs = sw.ElapsedMilliseconds;

                _registry.MarkStarted(component.Name);
                _logger.LogDebug("[StartupSequencer]    {Name} started ({Ms}ms)", component.Name, result.DurationMs);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                sw.Stop();
                result.Success = false;
                result.DurationMs = sw.ElapsedMilliseconds;
                result.Error = $"Timeout after {phaseTimeoutSeconds}s";

                _registry.MarkFailed(component.Name);
                _logger.LogWarning("[StartupSequencer]    {Name} TIMEOUT after {Sec}s", component.Name, phaseTimeoutSeconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                result.Success = false;
                result.DurationMs = sw.ElapsedMilliseconds;
                result.Error = ex.Message;

                _registry.MarkFailed(component.Name, ex);
                _logger.LogError(ex, "[StartupSequencer]    {Name} FAILED", component.Name);
            }

            return result;
        }

        /// <summary>
        /// Returns the last startup report for health monitoring.
        /// </summary>
        public StartupReport? GetLastReport() => _lastReport;
    }

    // 
    // Data Models
    // 

    public sealed class StartupPhase
    {
        public int Order { get; set; }
        public string Name { get; set; } = "";
        public bool Required { get; set; } = true;
        public int TimeoutSeconds { get; set; } = 30;
        public int StabilizationDelayMs { get; set; } = 500;
        public List<StartupComponent> Components { get; set; } = new();
    }

    public sealed class StartupComponent
    {
        public string Name { get; set; } = "";
        public MonitorCategory Category { get; set; }
        public object? Instance { get; set; }
        public Func<CancellationToken, Task> StartAction { get; set; } = _ => Task.CompletedTask;
    }

    public sealed class StartupReport
    {
        public DateTimeOffset StartTime { get; set; }
        public DateTimeOffset EndTime { get; set; }
        public long TotalDurationMs { get; set; }
        public int TotalComponents { get; set; }
        public int SuccessfulComponents { get; set; }
        public int FailedComponents { get; set; }
        public bool DegradedMode { get; set; }
        public List<PhaseResult> Phases { get; set; } = new();
    }

    public sealed class PhaseResult
    {
        public string PhaseName { get; set; } = "";
        public int Order { get; set; }
        public long DurationMs { get; set; }
        public bool Success { get; set; }
        public List<ComponentResult> Components { get; set; } = new();
    }

    public sealed class ComponentResult
    {
        public string Name { get; set; } = "";
        public MonitorCategory Category { get; set; }
        public bool Success { get; set; }
        public long DurationMs { get; set; }
        public string? Error { get; set; }
    }
}
