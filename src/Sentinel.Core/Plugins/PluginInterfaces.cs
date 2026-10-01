using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Plugins
{
    /// <summary>
    /// v2.0 - Detector plugin contract. New detections should implement this
    /// (or IDetectionRule) rather than growing god-files indefinitely.
    /// </summary>
    public interface IDetector
    {
        string Name { get; }
        /// <summary>Optional MITRE ATT&amp;CK technique IDs (e.g. T1003.001).</summary>
        IReadOnlyList<string> AttackTechniques { get; }
        Task StartAsync(CancellationToken ct);
        Task StopAsync();
    }

    /// <summary>
    /// v2.0 - Telemetry source plugin (ETW/WMI/poll/custom).
    /// </summary>
    public interface ITelemetryProvider
    {
        string Name { get; }
        event Action<TelemetryEvent>? OnTelemetry;
        Task StartAsync(CancellationToken ct);
        Task StopAsync();
    }

    /// <summary>
    /// v2.0 - External correlation rule (composite pattern as plugin).
    /// Returns confidence in [0,1] or 0 when no match.
    /// </summary>
    public interface ICorrelationRule
    {
        string Name { get; }
        double MinConfidence { get; }
        /// <summary>
        /// Evaluate buffered signals for one process. Return null when no match.
        /// </summary>
        DetectionEvent? Evaluate(int processId, string processName, IReadOnlyList<DetectionEvent> signals);
    }

    /// <summary>
    /// v2.0 - Response action plugin (custom remediation beyond built-in engine).
    /// </summary>
    public interface IResponsePlugin
    {
        string Name { get; }
        bool CanHandle(DetectionEvent detection);
        Task ExecuteAsync(DetectionEvent detection, CancellationToken ct);
    }

    /// <summary>
    /// Registry for optional 2.0 plugins. Built-in monitors remain HostedServices;
    /// plugins are an extension surface for rule packs and third-party detectors.
    /// </summary>
    public sealed class PluginRegistry
    {
        private readonly List<IDetector> _detectors = new();
        private readonly List<ITelemetryProvider> _telemetry = new();
        private readonly List<ICorrelationRule> _correlationRules = new();
        private readonly List<IResponsePlugin> _responsePlugins = new();
        private readonly object _gate = new();

        public void Register(IDetector detector)
        {
            if (detector == null) return;
            lock (_gate) _detectors.Add(detector);
        }

        public void Register(ITelemetryProvider provider)
        {
            if (provider == null) return;
            lock (_gate) _telemetry.Add(provider);
        }

        public void Register(ICorrelationRule rule)
        {
            if (rule == null) return;
            lock (_gate) _correlationRules.Add(rule);
        }

        public void Register(IResponsePlugin plugin)
        {
            if (plugin == null) return;
            lock (_gate) _responsePlugins.Add(plugin);
        }

        public IReadOnlyList<IDetector> Detectors
        {
            get { lock (_gate) return _detectors.ToArray(); }
        }

        public IReadOnlyList<ITelemetryProvider> TelemetryProviders
        {
            get { lock (_gate) return _telemetry.ToArray(); }
        }

        public IReadOnlyList<ICorrelationRule> CorrelationRules
        {
            get { lock (_gate) return _correlationRules.ToArray(); }
        }

        public IReadOnlyList<IResponsePlugin> ResponsePlugins
        {
            get { lock (_gate) return _responsePlugins.ToArray(); }
        }

        public int TotalCount
        {
            get
            {
                lock (_gate)
                    return _detectors.Count + _telemetry.Count + _correlationRules.Count + _responsePlugins.Count;
            }
        }
    }
}
