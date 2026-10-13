using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Writes critical Sentinel lifecycle / response events to the Windows Event Log
    /// (Application log, source "Sentinel" by default).
    ///
    /// Graceful degradation (barebone / custom / stripped Windows):
    ///   - Event Log service missing, CreateEventSource denied, WriteEntry throws ->
    ///     permanently disable for this process and continue. Never throws to callers.
    ///   - No dependency on custom channels, wevtutil, or PowerShell.
    ///   - Rate-limited so stripped hosts with a broken log stack are not hammered.
    /// JSONL remains the primary product log; this is a durable secondary trail for SIEM/LE.
    /// </summary>
    public sealed class SentinelEventLogWriter : IDisposable
    {
        public const int EventIdServiceStart = 1000;
        public const int EventIdServiceStop = 1001;
        public const int EventIdChainResponse = 1100;
        public const int EventIdEvidencePack = 1200;
        public const int EventIdQuarantine = 1300;
        public const int EventIdAntiTamper = 1400;
        public const int EventIdHeartbeat = 1500;
        public const int EventIdWriterDisabled = 1900;

        private readonly WindowsEventLogConfig _config;
        private readonly ILogger<SentinelEventLogWriter>? _logger;
        private readonly object _gate = new();
        private readonly ConcurrentQueue<long> _writeTimestampsMs = new();

        private volatile bool _available;
        private volatile bool _disabledPermanently;
        private string? _disableReason;
        private EventLog? _eventLog;
        private int _writesSucceeded;
        private int _writesFailed;
        private int _disableLogged;

        public SentinelEventLogWriter(
            WindowsEventLogConfig? config = null,
            ILogger<SentinelEventLogWriter>? logger = null)
        {
            _config = config ?? new WindowsEventLogConfig();
            _logger = logger;
            TryInitialize();
        }

        /// <summary>True when Event Log writes are currently possible.</summary>
        public bool IsAvailable => _available && !_disabledPermanently && _config.Enabled;

        public bool IsPermanentlyDisabled => _disabledPermanently;
        public string? DisableReason => _disableReason;
        public int WritesSucceeded => _writesSucceeded;
        public int WritesFailed => _writesFailed;

        /// <summary>Probe-only: can this process use Event Log APIs at all?</summary>
        public static bool ProbeEventLogInfrastructureAvailable()
        {
            try
            {
                // Exists is cheap; on heavily stripped images may still throw.
                _ = EventLog.Exists("Application");
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void TryInitialize()
        {
            if (!_config.Enabled)
            {
                _available = false;
                _disableReason = "disabled_by_config";
                return;
            }

            try
            {
                if (!ProbeEventLogInfrastructureAvailable())
                {
                    DisablePermanently("event_log_infrastructure_unavailable");
                    return;
                }

                var source = SanitizeName(_config.SourceName, "Sentinel");
                var logName = SanitizeName(_config.LogName, "Application");

                // Creating a source requires admin the first time; under SYSTEM it usually works.
                // On locked-down / stripped hosts this often fails - fall back to write-without-create
                // only if source already exists; otherwise disable.
                bool sourceReady = false;
                try
                {
                    if (EventLog.SourceExists(source))
                    {
                        sourceReady = true;
                    }
                    else
                    {
                        try
                        {
                            EventLog.CreateEventSource(source, logName);
                            sourceReady = true;
                        }
                        catch (Exception createEx)
                        {
                            // Race: another process created it; or ACL denied.
                            try
                            {
                                sourceReady = EventLog.SourceExists(source);
                            }
                            catch
                            {
                                sourceReady = false;
                            }

                            if (!sourceReady)
                            {
                                _logger?.LogDebug(createEx,
                                    "[SentinelEventLog] CreateEventSource failed - Windows Event Log trail disabled");
                                DisablePermanently("create_event_source_failed: " + createEx.GetType().Name);
                                return;
                            }
                        }
                    }
                }
                catch (Exception probeEx)
                {
                    DisablePermanently("source_probe_failed: " + probeEx.GetType().Name);
                    _logger?.LogDebug(probeEx, "[SentinelEventLog] SourceExists probe failed");
                    return;
                }

                if (!sourceReady)
                {
                    DisablePermanently("source_not_ready");
                    return;
                }

                _eventLog = new EventLog(logName)
                {
                    Source = source,
                    // MachineName defaults to local; do not set remote
                };

                // Smoke write is optional - some policies allow create but block write.
                // We do not smoke-write at init (noise); first real write decides.
                _available = true;
                _logger?.LogInformation(
                    "[SentinelEventLog] Available - log={Log} source={Source} criticalOnly={CriticalOnly}",
                    logName, source, _config.CriticalOnly);
            }
            catch (Exception ex)
            {
                DisablePermanently("init_exception: " + ex.GetType().Name);
                _logger?.LogDebug(ex, "[SentinelEventLog] Init failed - feature disabled for process lifetime");
            }
        }

        public void WriteServiceStart(string version)
        {
            Write(EventIdServiceStart, EventLogEntryType.Information,
                $"Sentinel service started. Version={version}. Machine={Environment.MachineName}.");
        }

        public void WriteServiceStop(string version)
        {
            Write(EventIdServiceStop, EventLogEntryType.Information,
                $"Sentinel service stopping. Version={version}.");
        }

        public void WriteChainResponse(DetectionEvent detection, string actionTaken, string reason)
        {
            if (detection == null) return;
            var coercion = CoercionAbusePolicy.IsDigitalCoercionToolkit(detection) ? " coercionToolkit=true" : "";
            Write(EventIdChainResponse, EventLogEntryType.Warning,
                $"Chain-confirmed response. Rule={Safe(detection.RuleName)} Action={Safe(actionTaken)} " +
                $"Process={Safe(detection.ProcessName)} PID={detection.ProcessId} Conf={detection.Confidence:F2}{coercion} " +
                $"Reason={Safe(Truncate(reason, 400))}");
        }

        public void WriteEvidencePack(DetectionEvent detection, string packPath)
        {
            if (detection == null) return;
            var coercion = CoercionAbusePolicy.IsDigitalCoercionToolkit(detection) ? " coercionToolkit=true" : "";
            Write(EventIdEvidencePack, EventLogEntryType.Warning,
                $"Evidence pack sealed. Rule={Safe(detection.RuleName)} Process={Safe(detection.ProcessName)} " +
                $"PID={detection.ProcessId} Path={Safe(Truncate(packPath, 260))}{coercion}");
        }

        public void WriteAntiTamper(string detail)
        {
            Write(EventIdAntiTamper, EventLogEntryType.Warning,
                $"Anti-tamper action. {Safe(Truncate(detail, 500))}");
        }

        public void WriteHeartbeat(string version, bool etwActive)
        {
            if (!_config.HeartbeatEnabled) return;
            Write(EventIdHeartbeat, EventLogEntryType.Information,
                $"Sentinel heartbeat. Version={version} EtwActive={etwActive} " +
                $"EventLogWrites={_writesSucceeded} EventLogFails={_writesFailed}.");
        }

        /// <summary>
        /// Core write path. Never throws. Disables permanently after repeated hard failures.
        /// </summary>
        public void Write(int eventId, EventLogEntryType type, string message)
        {
            if (!_config.Enabled || _disabledPermanently || !_available || _eventLog == null)
                return;

            if (_config.CriticalOnly &&
                eventId != EventIdServiceStart &&
                eventId != EventIdServiceStop &&
                eventId != EventIdChainResponse &&
                eventId != EventIdEvidencePack &&
                eventId != EventIdQuarantine &&
                eventId != EventIdAntiTamper &&
                eventId != EventIdHeartbeat)
            {
                return;
            }

            if (!TryAcquireRateLimitSlot())
            {
                _logger?.LogDebug("[SentinelEventLog] Rate limited - drop event {Id}", eventId);
                return;
            }

            try
            {
                var msg = Truncate(message ?? string.Empty, 7000); // Event Log practical limit
                if (string.IsNullOrWhiteSpace(msg))
                    msg = "(empty)";

                lock (_gate)
                {
                    if (_disabledPermanently || _eventLog == null)
                        return;
                    _eventLog.WriteEntry(msg, type, eventId);
                }

                Interlocked.Increment(ref _writesSucceeded);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _writesFailed);
                // First hard failure on stripped host -> stop forever (no retry storms).
                DisablePermanently("write_failed: " + ex.GetType().Name);
                _logger?.LogDebug(ex, "[SentinelEventLog] Write failed - disabling Windows Event Log trail");
            }
        }

        private bool TryAcquireRateLimitSlot()
        {
            int limit = _config.MaxWritesPerMinute;
            if (limit <= 0) return true;

            long now = System.Net48Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_writeTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _writeTimestampsMs.TryDequeue(out _);

            if (_writeTimestampsMs.Count >= limit)
                return false;

            _writeTimestampsMs.Enqueue(now);
            // Soft cap queue growth under pathological clocks
            while (_writeTimestampsMs.Count > limit * 2)
                _writeTimestampsMs.TryDequeue(out _);
            return true;
        }

        private void DisablePermanently(string reason)
        {
            _disabledPermanently = true;
            _available = false;
            _disableReason = reason;
            try { _eventLog?.Dispose(); } catch { /* ignore */ }
            _eventLog = null;

            if (Interlocked.Exchange(ref _disableLogged, 1) == 0)
            {
                _logger?.LogInformation(
                    "[SentinelEventLog] Permanently disabled for this process: {Reason}. JSONL logging continues.",
                    reason);
            }
        }

        private static string SanitizeName(string? name, string fallback)
        {
            if (string.IsNullOrWhiteSpace(name)) return fallback;
            var sb = new StringBuilder(name!.Length);
            foreach (var c in name.Trim())
            {
                if (char.IsLetterOrDigit(c) || c is '-' or '_' or ' ')
                    sb.Append(c);
            }
            var s = sb.ToString().Trim();
            return string.IsNullOrEmpty(s) ? fallback : s;
        }

        private static string Safe(string? s) =>
            string.IsNullOrEmpty(s) ? "" : s!.Replace("\r", " ").Replace("\n", " ");

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s) || s.Length <= max) return s ?? "";
            return s.Substring(0, max) + "...";
        }

        public void Dispose()
        {
            try { _eventLog?.Dispose(); } catch { /* ignore */ }
            _eventLog = null;
            _available = false;
        }
    }

    /// <summary>
    /// Optional low-frequency heartbeat to Windows Event Log so absence of heartbeats
    /// can indicate service death / log wipe. Never crashes the host if Event Log is gone.
    /// </summary>
    public sealed class SentinelEventLogHeartbeatService : Microsoft.Extensions.Hosting.BackgroundService
    {
        private readonly SentinelEventLogWriter _writer;
        private readonly WindowsEventLogConfig _config;
        private readonly UnifiedEtwSession? _etw;
        private readonly string _version;

        public SentinelEventLogHeartbeatService(
            SentinelEventLogWriter writer,
            WindowsEventLogConfig config,
            UnifiedEtwSession? etw = null)
        {
            _writer = writer;
            _config = config;
            _etw = etw;
            _version = typeof(SentinelEventLogHeartbeatService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        protected override async Task ExecuteAsync(System.Threading.CancellationToken stoppingToken)
        {
            if (!_config.Enabled || !_config.HeartbeatEnabled)
                return;

            int minutes = Math.Max(15, _config.HeartbeatMinutes);
            // Stagger first beat so startup storms don't coincide
            try { await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (_writer.IsAvailable)
                        _writer.WriteHeartbeat(_version, _etw?.IsActive == true);
                }
                catch
                {
                    // Absolute fail-soft - never kill the host loop
                }

                try { await Task.Delay(TimeSpan.FromMinutes(minutes), stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }
}
