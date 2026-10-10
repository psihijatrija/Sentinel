using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// One-time system scan engine. Performs a comprehensive point-in-time security audit
    /// of the local system without continuous monitoring. Designed to be triggered on-demand
    /// from the web dashboard or IPC.
    ///
    /// Scan categories:
    ///   1. Running processes - hash reputation + unsigned in staging paths
    ///   2. Persistence - Run/RunOnce keys, scheduled tasks, startup folder, services, IFEO
    ///   3. Certificate store - non-public-CA entries in TrustedPublisher/Root
    ///   4. LNK files - malicious shortcut patterns (UNC, protocol abuse, LOLBin+remote)
    ///   5. Staging paths - unsigned executables in Temp, AppData, Downloads, ProgramData
    ///   6. Network - listening ports from suspicious paths, connections to known-bad IPs
    /// </summary>
    public sealed class ScanEngine
    {
        private readonly IoCScanner _iocScanner;
        private readonly FileReputationEngine? _fileReputation;
        private readonly ILogger<ScanEngine> _logger;

        private int _isRunning;

        public ScanEngine(
            IoCScanner iocScanner,
            ILogger<ScanEngine> logger,
            FileReputationEngine? fileReputation = null)
        {
            _iocScanner = iocScanner;
            _logger = logger;
            _fileReputation = fileReputation;
        }

        public bool IsRunning => Interlocked.CompareExchange(ref _isRunning, 0, 0) == 1;

        /// <summary>
        /// Performs a full system scan. Returns structured results. Thread-safe - only one scan at a time.
        /// </summary>
        public async Task<ScanResult> RunFullScanAsync(CancellationToken ct = default)
        {
            if (Interlocked.CompareExchange(ref _isRunning, 1, 0) != 0)
                return new ScanResult { Error = "Scan already in progress" };

            var sw = Stopwatch.StartNew();
            var result = new ScanResult { StartTime = DateTime.UtcNow };

            try
            {
                _logger.LogInformation("[ScanEngine] One-time full system scan started");

                // Run scan categories in parallel where safe
                var processTask = Task.Run(() => ScanRunningProcesses(result, ct), ct);
                var persistenceTask = Task.Run(() => ScanPersistence(result, ct), ct);
                var certTask = Task.Run(() => ScanCertificateStores(result, ct), ct);
                var lnkTask = Task.Run(() => ScanLnkFiles(result, ct), ct);
                var stagingTask = Task.Run(() => ScanStagingPaths(result, ct), ct);
                var networkTask = Task.Run(() => ScanNetworkState(result, ct), ct);

                await Task.WhenAll(processTask, persistenceTask, certTask, lnkTask, stagingTask, networkTask)
                    .ConfigureAwait(false);

                sw.Stop();
                result.DurationMs = sw.ElapsedMilliseconds;
                result.EndTime = DateTime.UtcNow;
                result.Completed = true;

                _logger.LogInformation("[ScanEngine] Scan completed in {Ms}ms - {Findings} findings, {Critical} critical",
                    result.DurationMs, result.Findings.Count, result.Findings.Count(f => f.Severity == ScanSeverity.Critical));

                return result;
            }
            catch (OperationCanceledException)
            {
                result.Error = "Scan cancelled";
                result.Completed = false;
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[ScanEngine] Scan failed");
                result.Error = ex.Message;
                result.Completed = false;
                return result;
            }
            finally
            {
                Interlocked.Exchange(ref _isRunning, 0);
            }
        }

        #region Process Scan

        private void ScanRunningProcesses(ScanResult result, CancellationToken ct)
        {
            try
            {
                var processes = Process.GetProcesses();
                int scanned = 0;

                foreach (var proc in processes)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        string? imagePath = null;
                        try { imagePath = proc.MainModule?.FileName; } catch { }
                        if (string.IsNullOrEmpty(imagePath)) continue;

                        scanned++;

                        // Skip Windows system binaries
                        var lower = imagePath!.ToLowerInvariant();
                        if (lower.Contains(@"\windows\system32\") ||
                            lower.Contains(@"\windows\syswow64\") ||
                            lower.Contains(@"\windows\winsxs\") ||
                            lower.Contains(@"\windows\servicing\"))
                            continue;

                        // Check if in staging path and unsigned
                        bool inStaging = IsStagingPath(imagePath);
                        bool isSigned = false;

                        if (inStaging || IsUnusualProcessPath(imagePath))
                        {
                            isSigned = SecurityValidation.VerifyAuthenticodeSignature(imagePath);
                            if (!isSigned && inStaging)
                            {
                                result.AddFinding(new ScanFinding
                                {
                                    Category = ScanCategory.Process,
                                    Severity = ScanSeverity.High,
                                    Title = "Unsigned process running from staging path",
                                    Description = $"PID {proc.Id} ({proc.ProcessName}) is unsigned and running from a staging directory.",
                                    Path = imagePath,
                                    ProcessId = proc.Id,
                                    ProcessName = proc.ProcessName,
                                });
                            }
                        }

                        // Hash check against IoC database
                        if (File.Exists(imagePath))
                        {
                            var hash = ComputeSha256(imagePath);
                            if (!string.IsNullOrEmpty(hash) && _iocScanner.IsKnownBadHash(hash!))
                            {
                                result.AddFinding(new ScanFinding
                                {
                                    Category = ScanCategory.Process,
                                    Severity = ScanSeverity.Critical,
                                    Title = "Process matches known-bad hash (IoC)",
                                    Description = $"PID {proc.Id} ({proc.ProcessName}) matches a known malicious hash.",
                                    Path = imagePath,
                                    Hash = hash,
                                    ProcessId = proc.Id,
                                    ProcessName = proc.ProcessName,
                                });
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        try { proc.Dispose(); } catch { }
                    }
                }

                result.Stats.ProcessesScanned = scanned;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] Process scan error");
            }
        }

        #endregion

        #region Persistence Scan

        private void ScanPersistence(ScanResult result, CancellationToken ct)
        {
            try
            {
                // Run keys (HKLM + HKCU)
                ScanRunKeys(result, Registry.LocalMachine, "HKLM", ct);
                ScanRunKeys(result, Registry.CurrentUser, "HKCU", ct);

                // Scheduled tasks
                ScanScheduledTasks(result, ct);

                // Startup folder
                ScanStartupFolder(result, ct);

                // Services with suspicious paths
                ScanServices(result, ct);

                // IFEO debugger keys
                ScanIfeo(result, ct);

                // Winlogon keys
                ScanWinlogon(result, ct);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] Persistence scan error");
            }
        }

        private void ScanRunKeys(ScanResult result, RegistryKey hive, string hiveName, CancellationToken ct)
        {
            string[] runPaths =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var path in runPaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var name in key.GetValueNames())
                    {
                        var value = key.GetValue(name)?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(value)) continue;

                        var executable = ExtractExecutablePath(value);
                        if (string.IsNullOrEmpty(executable)) continue;

                        bool suspicious = false;
                        string reason = "";

                        if (IsStagingPath(executable!))
                        {
                            suspicious = true;
                            reason = "Persistence target is in a staging/temp path";
                        }
                        else if (!string.IsNullOrEmpty(executable) && File.Exists(executable) &&
                                 !SecurityValidation.VerifyAuthenticodeSignature(executable!))
                        {
                            // Unsigned binary in Run key - worth flagging
                            if (!IsKnownGoodRunEntry(name, executable!))
                            {
                                suspicious = true;
                                reason = "Unsigned binary registered for auto-start";
                            }
                        }

                        if (suspicious)
                        {
                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Persistence,
                                Severity = IsStagingPath(executable!) ? ScanSeverity.Critical : ScanSeverity.Medium,
                                Title = reason,
                                Description = $"{hiveName}\\{path}\\{name} -> {value}",
                                Path = executable,
                                RegistryKey = $"{hiveName}\\{path}",
                                RegistryValue = name,
                            });
                        }

                        result.Stats.PersistenceEntriesScanned++;
                    }
                }
                catch { }
            }
        }

        private void ScanScheduledTasks(ScanResult result, CancellationToken ct)
        {
            try
            {
                var taskDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "Tasks");

                if (!Directory.Exists(taskDir)) return;

                var files = Directory.GetFiles(taskDir, "*", SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        var content = File.ReadAllText(file);
                        // Look for suspicious task commands
                        if (ContainsSuspiciousTaskCommand(content, out string? cmdPath))
                        {
                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Persistence,
                                Severity = ScanSeverity.High,
                                Title = "Suspicious scheduled task",
                                Description = $"Task '{Path.GetFileName(file)}' executes from staging path: {cmdPath}",
                                Path = cmdPath ?? file,
                            });
                        }
                        result.Stats.PersistenceEntriesScanned++;
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanStartupFolder(ScanResult result, CancellationToken ct)
        {
            string[] startupPaths =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            };

            foreach (var startupDir in startupPaths)
            {
                if (string.IsNullOrEmpty(startupDir) || !Directory.Exists(startupDir)) continue;
                try
                {
                    foreach (var file in Directory.GetFiles(startupDir))
                    {
                        if (ct.IsCancellationRequested) return;
                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext == ".lnk" || ext == ".exe" || ext == ".bat" || ext == ".cmd" ||
                            ext == ".vbs" || ext == ".js" || ext == ".ps1")
                        {
                            // Any script or unsigned exe in startup is worth noting
                            bool isScript = ext != ".exe" && ext != ".lnk";
                            bool isUnsignedExe = ext == ".exe" && !SecurityValidation.VerifyAuthenticodeSignature(file);

                            if (isScript || isUnsignedExe)
                            {
                                result.AddFinding(new ScanFinding
                                {
                                    Category = ScanCategory.Persistence,
                                    Severity = ScanSeverity.Medium,
                                    Title = isScript ? "Script in startup folder" : "Unsigned executable in startup folder",
                                    Description = $"File '{Path.GetFileName(file)}' in startup will execute on logon.",
                                    Path = file,
                                });
                            }
                            result.Stats.PersistenceEntriesScanned++;
                        }
                    }
                }
                catch { }
            }
        }

        private void ScanServices(ScanResult result, CancellationToken ct)
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        if (svcKey == null) continue;

                        var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? "";
                        if (string.IsNullOrWhiteSpace(imagePath)) continue;

                        var exePath = ExtractExecutablePath(imagePath);
                        if (string.IsNullOrEmpty(exePath)) continue;

                        if (IsStagingPath(exePath!))
                        {
                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Persistence,
                                Severity = ScanSeverity.Critical,
                                Title = "Service binary in staging path",
                                Description = $"Service '{svcName}' executes from a staging directory: {exePath}",
                                Path = exePath,
                            });
                        }
                        result.Stats.PersistenceEntriesScanned++;
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanIfeo(ScanResult result, CancellationToken ct)
        {
            try
            {
                using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                if (ifeoKey == null) return;

                foreach (var subKeyName in ifeoKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var subKey = ifeoKey.OpenSubKey(subKeyName);
                        var debugger = subKey?.GetValue("Debugger")?.ToString();
                        if (!string.IsNullOrEmpty(debugger))
                        {
                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Persistence,
                                Severity = ScanSeverity.High,
                                Title = "IFEO debugger key set",
                                Description = $"Image hijack on '{subKeyName}': Debugger = {debugger}",
                                Path = debugger,
                                RegistryKey = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subKeyName}",
                                RegistryValue = "Debugger",
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanWinlogon(ScanResult result, CancellationToken ct)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                if (key == null) return;

                var userinit = key.GetValue("Userinit")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(userinit) &&
                    !userinit.Equals(@"C:\Windows\system32\userinit.exe,", StringComparison.OrdinalIgnoreCase) &&
                    !userinit.Equals(@"C:\Windows\system32\userinit.exe", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddFinding(new ScanFinding
                    {
                        Category = ScanCategory.Persistence,
                        Severity = ScanSeverity.Critical,
                        Title = "Winlogon Userinit modified",
                        Description = $"Userinit value is non-default: {userinit}",
                        RegistryKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        RegistryValue = "Userinit",
                    });
                }

                var shell = key.GetValue("Shell")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(shell) &&
                    !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                {
                    result.AddFinding(new ScanFinding
                    {
                        Category = ScanCategory.Persistence,
                        Severity = ScanSeverity.Critical,
                        Title = "Winlogon Shell modified",
                        Description = $"Shell value is non-default: {shell}",
                        RegistryKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        RegistryValue = "Shell",
                    });
                }
            }
            catch { }
        }

        #endregion

        #region Certificate Store Scan

        private void ScanCertificateStores(ScanResult result, CancellationToken ct)
        {
            try
            {
                ScanCertStore(result, StoreName.Root, StoreLocation.LocalMachine, "LocalMachine\\Root", ct);
                ScanCertStore(result, StoreName.Root, StoreLocation.CurrentUser, "CurrentUser\\Root", ct);
                ScanCertStore(result, StoreName.TrustedPublisher, StoreLocation.LocalMachine, "LocalMachine\\TrustedPublisher", ct);
                ScanCertStore(result, StoreName.TrustedPublisher, StoreLocation.CurrentUser, "CurrentUser\\TrustedPublisher", ct);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] Certificate store scan error");
            }
        }

        private void ScanCertStore(ScanResult result, StoreName name, StoreLocation location, string label, CancellationToken ct)
        {
            try
            {
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        var issuer = cert.Issuer;
                        var subject = cert.Subject;
                        var thumbprint = cert.Thumbprint;

                        // Highest priority: thumbprint is on the authoritative distrust list
                        // (StartCom + the roots pinned to Disallowed by Registry\Certificates.reg).
                        // Thumbprint is a non-attacker-controllable identity anchor, so this is a
                        // true positive regardless of what the cert names itself. Offer remediation.
                        var distrustLabel = CertDistrustList.GetLabel(thumbprint);
                        if (distrustLabel != null)
                        {
                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Certificate,
                                Severity = ScanSeverity.High,
                                Title = "Distrusted certificate in trusted store",
                                Description = $"{distrustLabel}. Store: {label}, Subject: {subject}, Thumbprint: {thumbprint}. " +
                                              "Sentinel can remove it from the Root store and pin it to the Disallowed (Untrusted) store.",
                                Path = label,
                                CertThumbprint = CertDistrustList.Normalize(thumbprint),
                                Remediable = true,
                            });
                        }
                        // Otherwise fall back to the name/validity heuristic for unknown non-standard CAs.
                        else if (!IsWellKnownCa(cert))
                        {
                            // Skip common legitimate additions (driver signing, enterprise CAs with long validity)
                            if (IsLikelyLegitimateAddition(cert)) continue;

                            result.AddFinding(new ScanFinding
                            {
                                Category = ScanCategory.Certificate,
                                Severity = ScanSeverity.Medium,
                                Title = "Non-standard certificate in trusted store",
                                Description = $"Store: {label}, Subject: {subject}, Issuer: {issuer}, Thumbprint: {thumbprint}",
                                Path = label,
                                CertThumbprint = CertDistrustList.Normalize(thumbprint),
                            });
                        }
                        result.Stats.CertificatesScanned++;
                    }
                    finally
                    {
                        cert.Dispose();
                    }
                }
            }
            catch { }
        }

        #endregion

        #region LNK Scan

        private void ScanLnkFiles(ScanResult result, CancellationToken ct)
        {
            try
            {
                string[] lnkSearchPaths =
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                };

                foreach (var searchPath in lnkSearchPaths)
                {
                    if (string.IsNullOrEmpty(searchPath) || !Directory.Exists(searchPath)) continue;
                    try
                    {
                        foreach (var lnk in Directory.GetFiles(searchPath, "*.lnk", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) return;
                            AnalyzeLnk(lnk, result);
                            result.Stats.LnkFilesScanned++;
                        }
                    }
                    catch { }
                }

                // Also scan taskbar pins
                var taskbarPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar");
                if (Directory.Exists(taskbarPath))
                {
                    foreach (var lnk in Directory.GetFiles(taskbarPath, "*.lnk"))
                    {
                        if (ct.IsCancellationRequested) return;
                        AnalyzeLnk(lnk, result);
                        result.Stats.LnkFilesScanned++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] LNK scan error");
            }
        }

        private void AnalyzeLnk(string lnkPath, ScanResult result)
        {
            try
            {
                var bytes = File.ReadAllBytes(lnkPath);
                if (bytes.Length < 76) return; // Minimum LNK header size

                // Quick text scan of the LNK content for suspicious patterns
                var text = Encoding.Unicode.GetString(bytes) + Encoding.ASCII.GetString(bytes);
                var lower = text.ToLowerInvariant();

                bool hasUncTarget = lower.Contains(@"\\\\") || lower.Contains(@"\\");
                bool hasProtocolAbuse = lower.Contains("search-ms:") || lower.Contains("ms-msdt:") ||
                                       lower.Contains("ms-officecmd:");
                bool hasLolbinRemote = HasLolbinWithRemoteArgs(lower);

                if (hasProtocolAbuse)
                {
                    result.AddFinding(new ScanFinding
                    {
                        Category = ScanCategory.Lnk,
                        Severity = ScanSeverity.Critical,
                        Title = "LNK with protocol handler abuse",
                        Description = $"Shortcut uses dangerous protocol handler (search-ms/ms-msdt/ms-officecmd): {Path.GetFileName(lnkPath)}",
                        Path = lnkPath,
                    });
                }
                else if (hasLolbinRemote)
                {
                    result.AddFinding(new ScanFinding
                    {
                        Category = ScanCategory.Lnk,
                        Severity = ScanSeverity.High,
                        Title = "LNK targeting LOLBin with remote arguments",
                        Description = $"Shortcut executes a LOLBin with remote/UNC arguments: {Path.GetFileName(lnkPath)}",
                        Path = lnkPath,
                    });
                }
            }
            catch { }
        }

        #endregion

        #region Staging Path Scan

        private void ScanStagingPaths(ScanResult result, CancellationToken ct)
        {
            try
            {
                string[] stagingDirs =
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                };

                foreach (var dir in stagingDirs.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)))
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        // Only scan immediate children + 1 level deep (avoid deep recursion in ProgramData)
                        var exeFiles = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                            .Concat(Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.EnumerateFiles(dir, "*.scr", SearchOption.TopDirectoryOnly))
                            .Concat(Directory.EnumerateFiles(dir, "*.sys", SearchOption.TopDirectoryOnly));

                        foreach (var file in exeFiles)
                        {
                            if (ct.IsCancellationRequested) return;
                            try
                            {
                                if (!File.Exists(file)) continue;
                                var fi = new FileInfo(file);
                                // Skip very small files (likely not real executables) and very old files
                                if (fi.Length < 4096) continue;
                                if (fi.CreationTimeUtc < DateTime.UtcNow.AddDays(-30)) continue;

                                bool signed = SecurityValidation.VerifyAuthenticodeSignature(file);
                                if (!signed)
                                {
                                    var hash = ComputeSha256(file);
                                    bool isIoc = !string.IsNullOrEmpty(hash) && _iocScanner.IsKnownBadHash(hash!);

                                    result.AddFinding(new ScanFinding
                                    {
                                        Category = ScanCategory.StagingPath,
                                        Severity = isIoc ? ScanSeverity.Critical : ScanSeverity.Low,
                                        Title = isIoc ? "Known-bad binary in staging path" : "Unsigned binary in staging path",
                                        Description = $"Unsigned {Path.GetExtension(file)} in {Path.GetDirectoryName(file)}: {Path.GetFileName(file)} ({fi.Length:N0} bytes)",
                                        Path = file,
                                        Hash = hash,
                                    });
                                }
                                result.Stats.FilesScanned++;
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] Staging path scan error");
            }
        }

        #endregion

        #region Network State Scan

        private void ScanNetworkState(ScanResult result, CancellationToken ct)
        {
            try
            {
                // Use netstat-equivalent to find suspicious listeners
                var psi = new ProcessStartInfo
                {
                    FileName = "netstat.exe",
                    Arguments = "-ano -p TCP",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);

                foreach (var line in output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (ct.IsCancellationRequested) return;
                    if (!line.Contains("LISTENING") && !line.Contains("ESTABLISHED")) continue;

                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 5) continue;

                    if (int.TryParse(parts[parts.Length - 1], out int pid) && pid > 0)
                    {
                        try
                        {
                            var p = Process.GetProcessById(pid);
                            string? imagePath = null;
                            try { imagePath = p.MainModule?.FileName; } catch { }

                            if (!string.IsNullOrEmpty(imagePath) && IsStagingPath(imagePath!))
                            {
                                bool isListening = line.Contains("LISTENING");
                                result.AddFinding(new ScanFinding
                                {
                                    Category = ScanCategory.Network,
                                    Severity = isListening ? ScanSeverity.High : ScanSeverity.Medium,
                                    Title = isListening ? "Listening port from staging path" : "Network connection from staging path",
                                    Description = $"PID {pid} ({p.ProcessName}) has network activity from: {imagePath}",
                                    Path = imagePath,
                                    ProcessId = pid,
                                    ProcessName = p.ProcessName,
                                });
                            }
                        }
                        catch { }
                    }
                }
                result.Stats.NetworkConnectionsScanned = output.Split('\n').Length;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ScanEngine] Network scan error");
            }
        }

        #endregion

        #region Helpers

        private static bool IsStagingPath(string path)
        {
            var lower = path.ToLowerInvariant();
            return lower.Contains(@"\temp\") ||
                   lower.Contains(@"\tmp\") ||
                   lower.Contains(@"\appdata\local\temp\") ||
                   lower.Contains(@"\downloads\") ||
                   lower.Contains(@"\desktop\") && lower.EndsWith(".exe") ||
                   lower.Contains(@"\public\") ||
                   lower.Contains(@"\users\public\");
        }

        private static bool IsUnusualProcessPath(string path)
        {
            var lower = path.ToLowerInvariant();
            return lower.Contains(@"\appdata\") ||
                   lower.Contains(@"\programdata\") && !lower.Contains(@"\programdata\sentinel\");
        }

        private static bool IsKnownGoodRunEntry(string name, string path)
        {
            var lowerName = name.ToLowerInvariant();
            var lowerPath = path.ToLowerInvariant();
            // Skip well-known entries
            return lowerPath.Contains(@"\program files\") ||
                   lowerPath.Contains(@"\program files (x86)\") ||
                   lowerPath.Contains(@"\windows\") ||
                   lowerName.Contains("security") && lowerPath.Contains("sentinel");
        }

        private static bool ContainsSuspiciousTaskCommand(string xmlContent, out string? cmdPath)
        {
            cmdPath = null;
            var lower = xmlContent.ToLowerInvariant();
            // Look for Command elements pointing to staging paths
            var cmdStart = lower.IndexOf("<command>", StringComparison.Ordinal);
            while (cmdStart >= 0)
            {
                var cmdEnd = lower.IndexOf("</command>", cmdStart, StringComparison.Ordinal);
                if (cmdEnd > cmdStart)
                {
                    var cmd = xmlContent.Substring(cmdStart + 9, cmdEnd - cmdStart - 9).Trim();
                    if (IsStagingPath(cmd))
                    {
                        cmdPath = cmd;
                        return true;
                    }
                }
                cmdStart = lower.IndexOf("<command>", cmdEnd > 0 ? cmdEnd : cmdStart + 1, StringComparison.Ordinal);
            }
            return false;
        }

        private static bool IsWellKnownCa(X509Certificate2 cert)
        {
            var issuer = cert.Issuer.ToLowerInvariant();
            // Major CAs and Microsoft roots
            return issuer.Contains("microsoft") ||
                   issuer.Contains("verisign") ||
                   issuer.Contains("digicert") ||
                   issuer.Contains("comodo") ||
                   issuer.Contains("globalsign") ||
                   issuer.Contains("entrust") ||
                   issuer.Contains("geotrust") ||
                   issuer.Contains("thawte") ||
                   issuer.Contains("godaddy") ||
                   issuer.Contains("symantec") ||
                   issuer.Contains("usertrust") ||
                   issuer.Contains("sectigo") ||
                   issuer.Contains("let's encrypt") ||
                   issuer.Contains("letsencrypt") ||
                   issuer.Contains("google trust") ||
                   issuer.Contains("amazon") ||
                   issuer.Contains("starfield") ||
                   issuer.Contains("baltimore") ||
                   issuer.Contains("identrust") ||
                   issuer.Contains("isrg root") ||
                   issuer.Contains("certsign") ||
                   issuer.Contains("certum");
        }

        private static bool IsLikelyLegitimateAddition(X509Certificate2 cert)
        {
            var validity = cert.NotAfter - cert.NotBefore;
            // Absurd validity (>30 years) is an attack indicator (e.g. 1000-year MitM attack roots), never legitimate
            if (validity.TotalDays > 365 * 30) return false;

            // Long validity (5 to 30 years) typically indicates enterprise/vendor CA
            if (validity.TotalDays > 365 * 5) return true;

            // Recently added with very short validity is suspicious (skip legitimacy)
            return false;
        }

        private static bool HasLolbinWithRemoteArgs(string lower)
        {
            string[] lolbins = { "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec" };
            string[] remoteIndicators = { "http:", "https:", @"\\\\", @"\\", "ftp:" };

            foreach (var lb in lolbins)
            {
                if (!lower.Contains(lb)) continue;
                foreach (var ri in remoteIndicators)
                {
                    if (lower.Contains(ri)) return true;
                }
            }
            return false;
        }

        private static string ExtractExecutablePath(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return "";

            var trimmed = commandLine.Trim();
            if (trimmed.StartsWith("\""))
            {
                var end = trimmed.IndexOf('"', 1);
                return end > 0 ? trimmed.Substring(1, end - 1) : "";
            }

            var spaceIdx = trimmed.IndexOf(' ');
            return spaceIdx > 0 ? trimmed.Substring(0, spaceIdx) : trimmed;
        }

        private static string? ComputeSha256(string filePath)
        {
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        #endregion
    }

    #region Scan Result Models

    public enum ScanCategory
    {
        Process,
        Persistence,
        Certificate,
        Lnk,
        StagingPath,
        Network,
    }

    public enum ScanSeverity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
    }

    public sealed class ScanFinding
    {
        public ScanCategory Category { get; set; }
        public ScanSeverity Severity { get; set; }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string? Path { get; set; }
        public string? Hash { get; set; }
        public string? RegistryKey { get; set; }
        public string? RegistryValue { get; set; }
        public int? ProcessId { get; set; }
        public string? ProcessName { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Certificate SHA-1 thumbprint (uppercase hex, no separators) when the finding is a
        /// certificate finding. Null for non-cert findings.
        /// </summary>
        public string? CertThumbprint { get; set; }

        /// <summary>
        /// True when Sentinel can offer a one-click remediation for this finding. For
        /// distrusted certificates this triggers the Root-removal + Disallowed-pin flow.
        /// </summary>
        public bool Remediable { get; set; }
    }

    public sealed class ScanStats
    {
        public int ProcessesScanned { get; set; }
        public int PersistenceEntriesScanned { get; set; }
        public int CertificatesScanned { get; set; }
        public int LnkFilesScanned { get; set; }
        public int FilesScanned { get; set; }
        public int NetworkConnectionsScanned { get; set; }
    }

    public sealed class ScanResult
    {
        public bool Completed { get; set; }
        public string? Error { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public long DurationMs { get; set; }
        public ScanStats Stats { get; set; } = new();
        public List<ScanFinding> Findings { get; set; } = new();

        [System.Text.Json.Serialization.JsonIgnore]
        private readonly object _lock = new();

        public void AddFinding(ScanFinding finding)
        {
            lock (_lock)
            {
                Findings.Add(finding);
            }
        }

        public int CriticalCount => Findings.Count(f => f.Severity == ScanSeverity.Critical);
        public int HighCount => Findings.Count(f => f.Severity == ScanSeverity.High);
        public int MediumCount => Findings.Count(f => f.Severity == ScanSeverity.Medium);
        public int LowCount => Findings.Count(f => f.Severity == ScanSeverity.Low);
    }

    #endregion
}
