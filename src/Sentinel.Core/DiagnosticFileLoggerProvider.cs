using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Core
{
    /// <summary>Independent bounded diagnostic trail; failures never enter the logging pipeline again.</summary>
    public sealed class DiagnosticFileLoggerProvider : ILoggerProvider
    {
        private readonly string _path;
        private readonly object _gate = new();
        private const long MaximumBytes = 5 * 1024 * 1024;
        public DiagnosticFileLoggerProvider(string path) { _path = path; }
        public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);
        public void Dispose() { }

        private void Write(string category, LogLevel level, EventId id, string message, Exception? error)
        {
            try
            {
                lock (_gate)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                    if (File.Exists(_path) && new FileInfo(_path).Length >= MaximumBytes)
                    {
                        if (File.Exists(_path + ".1")) File.Delete(_path + ".1");
                        File.Move(_path, _path + ".1");
                    }
                    using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read | FileShare.Delete);
                    using var writer = new StreamWriter(stream);
                    writer.WriteLine(JsonSerializer.Serialize(new { timestamp = DateTimeOffset.UtcNow, category,
                        level = level.ToString(), eventId = id.Id, message = Clip(message), exception = Clip(error?.ToString()) }));
                }
            }
            catch (Exception ex)
            {
                // Do not recursively log a sink failure, and do not lose the initiating error silently.
                try { Trace.WriteLine("Sentinel diagnostic sink unavailable: " + ex.GetType().Name + "; " + Clip(message)); }
                catch (Exception) { /* A broken trace listener must not terminate a detection thread. */ }
            }
        }

        private static string? Clip(string? text) => text?.Length > 32768 ? text.Substring(0, 32768) : text;
        private sealed class FileLogger : ILogger
        {
            private readonly DiagnosticFileLoggerProvider _owner;
            private readonly string _category;
            public FileLogger(DiagnosticFileLoggerProvider owner, string category) { _owner = owner; _category = category; }
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information && logLevel != LogLevel.None;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel)) return;
                try { _owner.Write(_category, logLevel, eventId, formatter(state, exception), exception); }
                catch (Exception ex) { _owner.Write(_category, LogLevel.Error, eventId, "Diagnostic formatting failed", ex); }
            }
        }
        private sealed class NullScope : IDisposable
        {
            internal static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
