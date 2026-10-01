using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class ConsultantSignalIngestor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ConsultantSignalIngestor> _logger;
        private readonly string? _customWatchDirectory;
        private readonly ConcurrentDictionary<string, long> _fileOffsets = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _fileLocks = new(StringComparer.OrdinalIgnoreCase);
        private string? _watchDirectory;

        public ConsultantSignalIngestor(
            DetectionEngine detectionEngine,
            ILogger<ConsultantSignalIngestor> logger,
            string? customWatchDirectory = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _customWatchDirectory = customWatchDirectory;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _watchDirectory = _customWatchDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Sentinel",
                "consultants"
            );

            try
            {
                var dirInfo = new DirectoryInfo(_watchDirectory);
                if (!dirInfo.Exists)
                {
                    dirInfo.Create();
                }

                try
                {
                    // Apply secure ACLs to prevent low-privileged users from dropping files
                    var security = dirInfo.GetAccessControl();
                    security.SetAccessRuleProtection(true, false);

                    var systemSid = new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        systemSid,
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));

                    var adminsSid = new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                    security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                        adminsSid,
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                        System.Security.AccessControl.PropagationFlags.None,
                        System.Security.AccessControl.AccessControlType.Allow));

                    if (_customWatchDirectory != null)
                    {
                        var currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                        if (currentUserSid != null)
                        {
                            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                                currentUserSid,
                                System.Security.AccessControl.FileSystemRights.FullControl,
                                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                                System.Security.AccessControl.PropagationFlags.None,
                                System.Security.AccessControl.AccessControlType.Allow));
                        }
                    }
                    else
                    {
                        var usersSid = new System.Security.Principal.SecurityIdentifier(
                            System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            usersSid,
                            System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                            System.Security.AccessControl.PropagationFlags.None,
                            System.Security.AccessControl.AccessControlType.Allow));
                    }

                    dirInfo.SetAccessControl(security);
                }
                catch (UnauthorizedAccessException uae)
                {
                    _logger.LogWarning(uae, "Access denied setting permissions on consultants directory {Path}. Existing permissions will be used.", _watchDirectory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create/secure consultants directory: {Path}", _watchDirectory);
                return;
            }

            _logger.LogInformation("[ConsultantSignalIngestor] Starting monitoring on directory: {Path}", _watchDirectory);

            // 1. Process existing files first to tail any historical data
            try
            {
                var existingFiles = Directory.GetFiles(_watchDirectory, "*.jsonl");
                foreach (var file in existingFiles)
                {
                    await ProcessFileAsync(file, stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error scanning existing files in {Path}", _watchDirectory);
            }

            // 2. Setup FileSystemWatcher to monitor new writes/changes
            using var watcher = new FileSystemWatcher(_watchDirectory, "*.jsonl")
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                IncludeSubdirectories = false
            };

            watcher.Created += (s, e) => { _ = Task.Run(() => ProcessFileAsync(e.FullPath, stoppingToken)); };
            watcher.Changed += (s, e) => { _ = Task.Run(() => ProcessFileAsync(e.FullPath, stoppingToken)); };
            watcher.Renamed += (s, e) => { _ = Task.Run(() => ProcessFileAsync(e.FullPath, stoppingToken)); };

            watcher.EnableRaisingEvents = true;

            // Keep the service alive and handle updates gracefully
            try
            {
                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            finally
            {
                watcher.EnableRaisingEvents = false;
            }
        }

        private async Task ProcessFileAsync(string filePath, CancellationToken ct)
        {
            if (string.IsNullOrEmpty(filePath) || !filePath.EndsWith(".jsonl"))
            {
                return;
            }

            // Verify file owner is Administrator or SYSTEM before processing
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Exists)
                {
                    var fileSecurity = fileInfo.GetAccessControl();
                    var ownerSid = fileSecurity.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier;
                    
                    bool isTestMode = _customWatchDirectory != null;
                    var currentUserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;

                    bool isOwnerAdminOrSystem = ownerSid != null && (
                        ownerSid.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid) ||
                        ownerSid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid) ||
                        (isTestMode && currentUserSid != null && ownerSid.Equals(currentUserSid))
                    );

                    if (!isOwnerAdminOrSystem)
                    {
                        _logger.LogWarning("[ConsultantSignalIngestor] Rejecting file {FilePath} because owner is not Administrator or SYSTEM.", filePath);
                        try { File.Delete(filePath); } catch { }
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[ConsultantSignalIngestor] Failed to check owner for file {FilePath}", filePath);
                return;
            }

            var fileLock = _fileLocks.GetOrAdd(filePath, _ => new SemaphoreSlim(1, 1));
            await fileLock.WaitAsync(ct);

            try
            {
                if (!File.Exists(filePath))
                {
                    _fileOffsets.TryRemove(filePath, out _);
                    return;
                }

                // Add a backoff retry loop in case the file is briefly locked by the writer
                int retries = 5;
                FileStream? fs = null;
                while (retries > 0)
                {
                    try
                    {
                        fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        break;
                    }
                    catch (IOException)
                    {
                        retries--;
                        if (retries == 0) throw;
                        await Task.Delay(100, ct);
                    }
                }

                if (fs == null) return;

                using (fs)
                {
                    long offset = _fileOffsets.GetOrAdd(filePath, 0);

                    // If file was truncated or recreated
                    if (fs.Length < offset)
                    {
                        offset = 0;
                    }

                    if (fs.Length == offset)
                    {
                        return;
                    }

                    fs.Seek(offset, SeekOrigin.Begin);

                    using (var reader = new StreamReader(fs))
                    {
                        string? line;
                        while ((line = await reader.ReadLineAsync()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            try
                            {
                                var options = new JsonSerializerOptions
                                {
                                    PropertyNameCaseInsensitive = true
                                };
                                var detection = JsonSerializer.Deserialize<DetectionEvent>(line, options);
                                if (detection != null)
                                {
                                    await _detectionEngine.SubmitConsultantSignalAsync(detection);
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, "Failed to parse jsonl line in {FilePath}: {Line}", filePath, line);
                            }
                        }
                        _fileOffsets[filePath] = fs.Position;
                    }
                }
            }
            catch (IOException)
            {
                // Exceeded retries, we expect another Changed event to trigger soon
            }
            catch (OperationCanceledException)
            {
                // Normal cancellation
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error tailing consultant file: {FilePath}", filePath);
            }
            finally
            {
                fileLock.Release();
            }
        }
    }
}
