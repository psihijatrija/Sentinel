using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class JsonlEventLogger : IAsyncDisposable
    {
        private string _logFilePath = null!;
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private readonly BurstRateLimiter _rateLimiter = new(1000, 5000);
        private FileStream? _fileStream;
        private StreamWriter? _writer;
        private bool _isDegraded;
        private bool _diskSpaceDegraded;
        private bool _disposed;

        //  Pre-action audit log (Improvement #5 from GorstaksProtection) 
        // Separate append-only file guaranteed to be written BEFORE any kill/block
        // action fires. Daily rotation, 90 days retained.  ACLs: SYSTEM + Admins only.
        private string _auditLogFilePath = null!;
        private readonly SemaphoreSlim _auditSemaphore = new(1, 1);
        private FileStream? _auditFileStream;
        private StreamWriter? _auditWriter;
        private bool _auditDegraded;

        public string LogFilePath => _logFilePath;
        private long _droppedEvents;
        public long DroppedEvents => Interlocked.Read(ref _droppedEvents);

        public JsonlEventLogger(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _logFilePath = customPath!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _logFilePath = Path.Combine(programData, "Sentinel", "events.jsonl");
            }

            // Ensure directory exists
            var directory = Path.GetDirectoryName(_logFilePath);
            if (directory != null)
            {
                try
                {
                    if (!Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    // Only apply production ACLs if this is the default production path in CommonApplicationData
                    var prodDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
                    if (directory.StartsWith(prodDir))
                    {
                        // v2.0.8: SYSTEM + Admins full; Interactive Users read (tray Agent UI).
                        // Not Builtin\Users - service accounts / non-interactive malware must not
                        // harvest detection history for recon of what Sentinel is watching.
                        var dirInfo = new DirectoryInfo(directory);
                        var security = dirInfo.GetAccessControl();
                        security.SetAccessRuleProtection(true, false);
                        var systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(systemSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        var adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(adminSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        var interactiveSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.InteractiveSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(interactiveSid, System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        dirInfo.SetAccessControl(security);
                    }
                }
                catch
                {
                    _isDegraded = true;
                }
            }

            TryOpenFileInternal();

            //  Audit log setup (Improvement #5 from GorstaksProtection) 
            // Daily-rotated, SYSTEM+Admins-only append file written BEFORE any kill/block.
            // Lives in the same directory as the events log (ProgramData\Sentinel in production,
            // or a custom directory when one is supplied) so the audit trail travels with the log.
            var sentinelDir = Path.GetDirectoryName(_logFilePath)
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
            _auditLogFilePath = Path.Combine(sentinelDir,
                $"audit-{DateTime.UtcNow:yyyy-MM-dd}.jsonl");
            TryOpenAuditFileInternal();
        }

        private void TryOpenAuditFileInternal()
        {
            try
            {
                // Rotate to today's file if the date has changed
                var todayPath = Path.Combine(
                    Path.GetDirectoryName(_auditLogFilePath)!,
                    $"audit-{DateTime.UtcNow:yyyy-MM-dd}.jsonl");
                if (todayPath != _auditLogFilePath)
                {
                    _auditWriter?.Dispose();
                    _auditWriter = null;
                    _auditFileStream?.Dispose();
                    _auditFileStream = null;
                    _auditLogFilePath = todayPath;
                }

                if (_auditWriter != null) return; // already open for today

                _auditFileStream = new FileStream(_auditLogFilePath, FileMode.Append, FileAccess.Write,
                    FileShare.Read | FileShare.Delete);
                _auditWriter = new StreamWriter(_auditFileStream) { AutoFlush = true };
                _auditDegraded = false;

                // Prune audit files older than 90 days
                PruneOldAuditFiles();
            }
            catch
            {
                _auditDegraded = true;
            }
        }

        private void PruneOldAuditFiles()
        {
            try
            {
                var dir = Path.GetDirectoryName(_auditLogFilePath);
                if (dir == null || !Directory.Exists(dir)) return;
                var cutoff = DateTime.UtcNow.AddDays(-90);
                foreach (var file in Directory.GetFiles(dir, "audit-*.jsonl"))
                {
                    if (File.GetLastWriteTimeUtc(file) < cutoff)
                        try { File.Delete(file); } catch { /* best-effort */ }
                }
            }
            catch { /* best-effort */ }
        }

        /// <summary>
        /// MANDATORY pre-action audit entry. MUST be called and awaited before any
        /// kill or block action executes. Writes to the dedicated audit log (not the
        /// main events.jsonl). Ported from GorstaksProtection GorstaksLogger.LogAuditBeforeAction.
        /// </summary>
        public async Task LogAuditBeforeActionAsync(
            string detectionId,
            string ruleId,
            string ruleName,
            ResponseAction proposedAction,
            double confidence,
            string processName,
            int processId,
            string justification)
        {
            TryOpenAuditFileInternal();
            if (_auditDegraded || _auditWriter == null) return;

            var entry = new
            {
                AuditType       = "PRE_ACTION",
                Timestamp       = DateTime.UtcNow,
                DetectionId     = detectionId,
                RuleId          = ruleId,
                RuleName        = ruleName,
                ProposedAction  = proposedAction.ToString(),
                Confidence      = confidence,
                ProcessName     = processName,
                ProcessId       = processId,
                Justification   = justification
            };

            var json = JsonSerializer.Serialize(entry);

            await _auditSemaphore.WaitAsync();
            try
            {
                await _auditWriter.WriteLineAsync(json);
            }
            catch
            {
                _auditDegraded = true;
            }
            finally
            {
                _auditSemaphore.Release();
            }
        }

        /// <summary>Records the outcome of a response action to the audit log.</summary>
        public async Task LogAuditActionOutcomeAsync(
            string detectionId,
            ResponseAction action,
            bool succeeded,
            string? errorMessage = null)
        {
            TryOpenAuditFileInternal();
            if (_auditDegraded || _auditWriter == null) return;

            var entry = new
            {
                AuditType    = "ACTION_OUTCOME",
                Timestamp    = DateTime.UtcNow,
                DetectionId  = detectionId,
                Action       = action.ToString(),
                Succeeded    = succeeded,
                ErrorMessage = errorMessage
            };

            var json = JsonSerializer.Serialize(entry);

            await _auditSemaphore.WaitAsync();
            try
            {
                await _auditWriter.WriteLineAsync(json);
            }
            catch
            {
                _auditDegraded = true;
            }
            finally
            {
                _auditSemaphore.Release();
            }
        }

        /// <summary>
        /// B1 (durable evidence survival): records that the Sentinel process is exiting under
        /// circumstances that were NOT marked as an expected/cooperative stop - i.e. a possible
        /// tamper suppression. Written to the append-only audit trail (SYSTEM+Admins ACL) so the
        /// coverage gap is itself evidence.
        ///
        /// This is the <b>synchronous, best-effort</b> variant intended for the process-exit hook,
        /// where awaiting is unsafe (the runtime is tearing down). It performs a single append and
        /// swallows all failures.
        /// </summary>
        public void LogServiceStopSuspected(
            string reason,
            int processId,
            string uptime,
            DateTimeOffset lastTick,
            string classification)
        {
            try
            {
                TryOpenAuditFileInternal();
                if (_auditDegraded || _auditWriter == null) return;

                var entry = new
                {
                    AuditType      = "SERVICE_STOP_SUSPECTED",
                    Timestamp      = DateTime.UtcNow,
                    Reason         = reason,
                    Classification = classification,
                    ProcessId      = processId,
                    Uptime         = uptime,
                    LastTick       = lastTick
                };

                var json = JsonSerializer.Serialize(entry);

                // Best-effort synchronous write - cannot await on a dying process. The audit
                // writer is AutoFlush, so the line hits disk immediately.
                _auditWriter.WriteLine(json);
                _auditWriter.Flush();
            }
            catch
            {
                // Best-effort - we're dying. Never throw out of the exit path (NFR-2).
            }
        }

        /// <summary>
        /// Records a normal, expected service-stop lifecycle event to the append-only audit trail.
        /// Synchronous/best-effort for use from the exit hook.
        /// </summary>
        public void LogServiceStopExpected(
            string reason,
            int processId,
            string uptime)
        {
            try
            {
                TryOpenAuditFileInternal();
                if (_auditDegraded || _auditWriter == null) return;

                var entry = new
                {
                    AuditType = "SERVICE_STOP_EXPECTED",
                    Timestamp = DateTime.UtcNow,
                    Reason    = reason,
                    ProcessId = processId,
                    Uptime    = uptime
                };

                _auditWriter.WriteLine(JsonSerializer.Serialize(entry));
                _auditWriter.Flush();
            }
            catch
            {
                // Best-effort.
            }
        }

        private void TryOpenFileInternal()
        {
            try
            {
                if (_writer != null)
                {
                    _writer.Dispose();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    _fileStream.Dispose();
                    _fileStream = null;
                }

                _fileStream = new FileStream(_logFilePath, FileMode.Append, FileAccess.Write,
                    FileShare.ReadWrite | FileShare.Delete);
                _writer = new StreamWriter(_fileStream) { AutoFlush = true };
                _isDegraded = false;
            }
            catch (IOException)
            {
                // Stale file handling: try renaming locked/inaccessible file to .stale.<timestamp>
                try
                {
                    var stalePath = $"{_logFilePath}.stale.{DateTime.UtcNow:yyyyMMddHHmmss}";
                    if (File.Exists(_logFilePath))
                    {
                        File.Move(_logFilePath, stalePath);
                    }
                    _fileStream = new FileStream(_logFilePath, FileMode.Create, FileAccess.Write,
                        FileShare.ReadWrite | FileShare.Delete);
                    _writer = new StreamWriter(_fileStream) { AutoFlush = true };
                    _isDegraded = false;
                }
                catch
                {
                    _isDegraded = true;
                }
            }
            catch
            {
                _isDegraded = true;
            }
        }

        public async Task LogEventAsync<T>(string type, T data, CancellationToken cancellationToken = default)
        {
            if (!_rateLimiter.AllowRequest())
            {
                Interlocked.Increment(ref _droppedEvents);
                return;
            }

            if (_disposed)
                return;

            try
            {
                await _semaphore.WaitAsync(cancellationToken);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (OperationCanceledException)
            {
                throw;
            }

            try
            {
                if (_disposed)
                    return;

                if (_isDegraded || _writer == null)
                {
                    // Self-healing attempt
                    TryOpenFileInternal();
                    if (_isDegraded || _writer == null)
                    {
                        // Still degraded
                        return;
                    }
                }

                // Check file size for rotation (20 MB - keep I/O and dashboard reads lighter)
                try
                {
                    if (_fileStream != null && _fileStream.Length > 20L * 1024 * 1024)
                    {
                        RotateLogsInternal();
                    }
                }
                catch
                {
                    // Ignore rotation failure, continue writing
                }

                // v2.0.3: Disk space guard - degrade gracefully if volume is critically low.
                // Prevents Sentinel from filling the last remaining disk space with event logs.
                if (!CheckDiskSpaceInternal())
                {
                    Interlocked.Increment(ref _droppedEvents);
                    return;
                }

                var entry = new
                {
                    type,
                    timestamp = DateTime.UtcNow,
                    data
                };

                string jsonLine;
                try
                {
                    jsonLine = JsonSerializer.Serialize(entry);
                }
                catch
                {
                    // Fallback: serialize with type name and error indicator
                    jsonLine = JsonSerializer.Serialize(new { type, timestamp = DateTime.UtcNow, data = $"<unserializable:{typeof(T).Name}>" });
                }

                if (_writer != null)
                {
                    await _writer.WriteLineAsync(jsonLine);
                }
            }
            finally
            {
                try { _semaphore.Release(); } catch (ObjectDisposedException) { }
            }
        }

        /// <summary>
        /// v2.0.3: Check available disk space on the log volume.
        /// Returns false (skip write) when free space is below 100 MB.
        /// Also triggers cleanup of oldest rotated logs to reclaim space.
        /// </summary>
        private bool CheckDiskSpaceInternal()
        {
            try
            {
                var logDir = Path.GetDirectoryName(_logFilePath);
                if (string.IsNullOrEmpty(logDir)) return true;

                var driveRoot = Path.GetPathRoot(logDir);
                if (string.IsNullOrEmpty(driveRoot)) return true;

                var driveInfo = new DriveInfo(driveRoot);
                if (!driveInfo.IsReady) return true;

                long freeBytes = driveInfo.AvailableFreeSpace;
                const long MinFreeBytes = 100L * 1024 * 1024; // 100 MB floor
                const long WarnFreeBytes = 200L * 1024 * 1024; // 200 MB -> prune old logs

                if (freeBytes < WarnFreeBytes)
                {
                    // Proactively delete oldest rotated logs to reclaim space
                    PruneOldestRotatedLogs();
                }

                if (freeBytes < MinFreeBytes)
                {
                    // Critical: stop writing to prevent disk exhaustion
                    if (!_isDegraded)
                    {
                        _isDegraded = true;
                        _diskSpaceDegraded = true;
                    }
                    return false;
                }

                // Recover from disk-space degradation if space freed up
                if (_diskSpaceDegraded && freeBytes >= MinFreeBytes)
                {
                    _diskSpaceDegraded = false;
                    if (_isDegraded)
                    {
                        TryOpenFileInternal();
                    }
                }

                return true;
            }
            catch
            {
                // Cannot determine disk space - allow write (fail-open for logging)
                return true;
            }
        }

        /// <summary>
        /// v2.0.3: Delete the oldest rotated log files when disk space is low.
        /// Deletes from .5 down to .3 (keeps .1 and .2 as recent context).
        /// </summary>
        private void PruneOldestRotatedLogs()
        {
            try
            {
                for (int i = 5; i >= 3; i--)
                {
                    var rotatedPath = $"{_logFilePath}.{i}";
                    if (File.Exists(rotatedPath))
                    {
                        File.Delete(rotatedPath);
                    }
                }
            }
            catch { /* best effort */ }
        }

        private void RotateLogsInternal()
        {
            try
            {
                if (_writer != null)
                {
                    _writer.Dispose();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    _fileStream.Dispose();
                    _fileStream = null;
                }

                // Rotate events.jsonl.4 -> events.jsonl.5, etc.
                for (int i = 4; i >= 1; i--)
                {
                    var oldPath = $"{_logFilePath}.{i}";
                    var newPath = $"{_logFilePath}.{i + 1}";
                    if (File.Exists(oldPath))
                    {
                        if (File.Exists(newPath)) File.Delete(newPath);
                        File.Move(oldPath, newPath);
                    }
                }

                if (File.Exists(_logFilePath))
                {
                    var backupPath = $"{_logFilePath}.1";
                    if (File.Exists(backupPath)) File.Delete(backupPath);
                    File.Move(_logFilePath, backupPath);
                }

                TryOpenFileInternal();
            }
            catch
            {
                _isDegraded = true;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            // Hold both locks so in-flight event/audit writers finish before we tear down streams.
            // Releasing _auditSemaphore without WaitAsync caused SemaphoreFullException (max=1)
            // and cascaded into ~100 xUnit Dispose failures on CI.
            try
            {
                await _semaphore.WaitAsync();
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            var auditHeld = false;
            try
            {
                try
                {
                    await _auditSemaphore.WaitAsync();
                    auditHeld = true;
                }
                catch (ObjectDisposedException) { }

                _disposed = true;
                if (_writer != null)
                {
                    await _writer.DisposeAsync();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    await _fileStream.DisposeAsync();
                    _fileStream = null;
                }
                if (_auditWriter != null)
                {
                    await _auditWriter.DisposeAsync();
                    _auditWriter = null;
                }
                if (_auditFileStream != null)
                {
                    await _auditFileStream.DisposeAsync();
                    _auditFileStream = null;
                }
            }
            finally
            {
                if (auditHeld)
                {
                    try { _auditSemaphore.Release(); }
                    catch (ObjectDisposedException) { }
                    catch (SemaphoreFullException) { }
                }
                try { _auditSemaphore.Dispose(); } catch (ObjectDisposedException) { }

                try { _semaphore.Release(); }
                catch (ObjectDisposedException) { }
                catch (SemaphoreFullException) { }
                try { _semaphore.Dispose(); } catch (ObjectDisposedException) { }
            }
            GC.SuppressFinalize(this);
        }
    }
}
