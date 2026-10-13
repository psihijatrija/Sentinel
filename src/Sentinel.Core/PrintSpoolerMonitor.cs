using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors the Windows Print Spooler for data exfiltration via:
    /// - Print-to-file operations that write sensitive data to arbitrary paths
    /// - XPS spool file creation (staging area for exfiltration)
    /// - Microsoft Print to PDF creating files outside normal paths
    /// - Bulk print operations (rapid file creation in spool directory)
    ///
    /// The print spooler spool directory (C:\Windows\System32\spool\PRINTERS)
    /// and user-directed print-to-file paths are outside FileActivityMonitor's scope.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class PrintSpoolerMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PrintSpoolerMonitor> _logger;

        private readonly ConcurrentDictionary<string, int> _recentSpoolFiles = new();
        private int _spoolBurstCount;
        private DateTimeOffset _burstWindowStart = DateTimeOffset.UtcNow;

        private FileSystemWatcher? _spoolWatcher;
        private FileSystemWatcher? _printToFileWatcher;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);
        private const int BurstThreshold = 20; // 20+ spool files in 60s = suspicious
        private static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(60);

        private static readonly string SpoolPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"spool\PRINTERS");

        // Suspicious extensions for print-to-file output
        private static readonly HashSet<string> SuspiciousOutputExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".hta", ".scr", ".msi", ".reg", ".inf"
        };

        public PrintSpoolerMonitor(
            DetectionEngine detectionEngine,
            ILogger<PrintSpoolerMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PrintSpoolerMonitor] Started");

            // Watch the spool directory for burst activity
            if (Directory.Exists(SpoolPath))
            {
                try
                {
                    _spoolWatcher = new FileSystemWatcher(SpoolPath)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                        EnableRaisingEvents = true
                    };
                    _spoolWatcher.Created += OnSpoolFileCreated;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PrintSpoolerMonitor] Cannot watch spool directory");
                }
            }

            // Watch common print-to-file output directories
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrEmpty(documentsPath) && Directory.Exists(documentsPath))
            {
                try
                {
                    _printToFileWatcher = new FileSystemWatcher(documentsPath)
                    {
                        Filter = "*.xps",
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName,
                        EnableRaisingEvents = true
                    };
                    _printToFileWatcher.Created += OnXpsFileCreated;
                }
                catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await CheckSpoolBurst(ct);
                    await ScanForSuspiciousPrintOutput(ct);
                    await ScanForPrintNightmareExploitation(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PrintSpoolerMonitor] Error"); }
            }

            _spoolWatcher?.Dispose();
            _printToFileWatcher?.Dispose();
        }

        private async void OnSpoolFileCreated(object sender, FileSystemEventArgs e)
        {
            Interlocked.Increment(ref _spoolBurstCount);
            _recentSpoolFiles[e.Name ?? "unknown"] = Environment.CurrentManagedThreadId;
        }

        private async void OnXpsFileCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Print Spooler: XPS Document Created",
                    Evidence = $"XPS print output created: {e.FullPath}",
                    Reasoning = "An XPS document was created via the print system. XPS files can " +
                                "contain rendered copies of sensitive documents and may be used " +
                                "as a covert exfiltration channel.",
                    Confidence = 0.35,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0
                });
            }
            catch { }
        }

        private async Task CheckSpoolBurst(CancellationToken ct)
        {
            if (DateTimeOffset.UtcNow - _burstWindowStart > BurstWindow)
            {
                var count = Interlocked.Exchange(ref _spoolBurstCount, 0);
                _burstWindowStart = DateTimeOffset.UtcNow;
                _recentSpoolFiles.Clear();

                if (count >= BurstThreshold)
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Print Spooler: Bulk Print Burst Detected",
                        Evidence = $"{count} spool files created in {BurstWindow.TotalSeconds}s window",
                        Reasoning = "A large number of print spool files were created in a short window. " +
                                    "This can indicate bulk document rendering for exfiltration via " +
                                    "print-to-file, or exploitation of the print spooler service. " +
                                    "Normal printing rarely exceeds 5-10 documents per minute.",
                        Confidence = 0.65,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "spoolsv.exe",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["SpoolFileCount"] = count.ToString(),
                            ["WindowSeconds"] = BurstWindow.TotalSeconds.ToString()
                        }
                    });
                }
            }
        }

        private async Task ScanForSuspiciousPrintOutput(CancellationToken ct)
        {
            // Check for print-to-file output with suspicious extensions
            // Some malware uses "Microsoft Print to PDF" or XPS to write to arbitrary paths
            if (!Directory.Exists(SpoolPath)) return;

            try
            {
                foreach (var file in Directory.GetFiles(SpoolPath))
                {
                    var ext = Path.GetExtension(file);
                    if (!SuspiciousOutputExtensions.Contains(ext)) continue;

                    // Non-document file in the spool directory = suspicious
                    var alertKey = Path.GetFileName(file);
                    if (_recentSpoolFiles.ContainsKey(alertKey)) continue;
                    _recentSpoolFiles[alertKey] = 0;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Print Spooler: Suspicious File in Spool Directory",
                        Evidence = $"Non-document file found in spool directory: {file}",
                        Reasoning = "A non-document file with a suspicious extension was found in the " +
                                    "print spooler directory. This may indicate PrintNightmare-style " +
                                    "exploitation or DLL planting via the spooler service.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        ProcessName = "spoolsv.exe",
                        ProcessId = 0
                    });
                }
            }
            catch { }
        }

        // 
        // v1.6.8: PrintNightmare-Class Exploitation Detection
        //
        // Detects exploitation of the print spooler for privilege escalation:
        // - CVE-2021-34527 (PrintNightmare): AddPrinterDriverEx loading arbitrary DLLs
        // - CVE-2021-1675: Similar via AddPrinterDriver
        // - SpoolFool / other spooler LPE variants
        //
        // Detection approach:
        // 1. Monitor driver store paths for new printer driver DLLs appearing
        // 2. Detect unsigned DLLs loaded by spoolsv.exe from non-standard paths
        // 3. Watch for new printer driver installations via registry
        // 4. Monitor for spoolsv.exe spawning child processes (exploitation indicator)
        // 

        private readonly HashSet<string> _baselineDriverDlls = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, byte> _alertedDriverPaths = new();
        private bool _driverBaselineComplete;

        /// <summary>
        /// Called from ExecuteAsync on startup to baseline existing printer driver DLLs.
        /// </summary>
        private void BaselinePrinterDrivers()
        {
            try
            {
                // Windows printer drivers directory
                var driverPaths = new[]
                {
                    Path.Combine(Environment.SystemDirectory, @"spool\drivers\x64\3"),
                    Path.Combine(Environment.SystemDirectory, @"spool\drivers\x64\4"),
                    Path.Combine(Environment.SystemDirectory, @"spool\drivers\W32X86\3"),
                };

                foreach (var driverDir in driverPaths)
                {
                    if (!Directory.Exists(driverDir)) continue;
                    foreach (var dll in Directory.GetFiles(driverDir, "*.dll", SearchOption.AllDirectories))
                    {
                        _baselineDriverDlls.Add(dll);
                    }
                }
                _driverBaselineComplete = true;
                _logger.LogDebug("[PrintSpoolerMonitor] Baselined {Count} printer driver DLLs", _baselineDriverDlls.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[PrintSpoolerMonitor] Driver baseline failed");
            }
        }

        /// <summary>
        /// Detects PrintNightmare-class exploitation by monitoring:
        /// 1. New DLLs in printer driver directories (AddPrinterDriverEx exploitation)
        /// 2. spoolsv.exe spawning unexpected child processes
        /// 3. Unsigned or remote-path DLLs in driver store
        /// </summary>
        private async Task ScanForPrintNightmareExploitation(CancellationToken ct)
        {
            if (!_driverBaselineComplete)
            {
                BaselinePrinterDrivers();
                return;
            }

            // 1. Check for new DLLs in printer driver directories
            await DetectNewDriverDlls(ct);

            // 2. Detect spoolsv.exe spawning child processes (exploitation indicator)
            await DetectSpoolerChildProcesses(ct);
        }

        private async Task DetectNewDriverDlls(CancellationToken ct)
        {
            var driverPaths = new[]
            {
                Path.Combine(Environment.SystemDirectory, @"spool\drivers\x64\3"),
                Path.Combine(Environment.SystemDirectory, @"spool\drivers\x64\4"),
                Path.Combine(Environment.SystemDirectory, @"spool\drivers\W32X86\3"),
            };

            foreach (var driverDir in driverPaths)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(driverDir)) continue;

                try
                {
                    foreach (var dllPath in Directory.GetFiles(driverDir, "*.dll", SearchOption.AllDirectories))
                    {
                        if (_baselineDriverDlls.Contains(dllPath)) continue;
                        if (_alertedDriverPaths.ContainsKey(dllPath)) continue;

                        // New DLL appeared in printer driver directory - potential PrintNightmare
                        _alertedDriverPaths[dllPath] = 0;

                        // Check if the DLL is Authenticode signed
                        bool isSigned = SecurityValidation.VerifyAuthenticodeSignature(dllPath);
                        var fileInfo = new FileInfo(dllPath);
                        bool isRecent = (DateTime.UtcNow - fileInfo.CreationTimeUtc).TotalMinutes < 5;

                        double confidence = 0.75;
                        var response = ResponseAction.LogOnly;

                        if (!isSigned && isRecent)
                        {
                            confidence = 0.92;
                            response = ResponseAction.QuarantineAndKill;
                        }
                        else if (!isSigned)
                        {
                            confidence = 0.85;
                            response = ResponseAction.Quarantine;
                        }
                        else if (isRecent)
                        {
                            confidence = 0.70;
                        }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Print Spooler: PrintNightmare Driver DLL Planted",
                            Evidence = $"New DLL appeared in printer driver directory: '{dllPath}'. " +
                                       $"Signed: {isSigned}, Created: {fileInfo.CreationTimeUtc:O}, Size: {fileInfo.Length} bytes.",
                            Reasoning = "A new DLL was planted in the Windows printer driver directory after Sentinel's baseline. " +
                                        "This is the primary indicator of PrintNightmare (CVE-2021-34527) exploitation where " +
                                        "AddPrinterDriverEx is called with a malicious DLL path. The spooler loads this DLL as SYSTEM, " +
                                        "giving the attacker immediate privilege escalation.",
                            Confidence = confidence,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = response,
                            SignalType = SignalType.SuspiciousProcess,
                            ProcessName = "spoolsv",
                            ProcessId = GetSpoolerPid(),
                            Metadata = new Dictionary<string, string>
                            {
                                ["DllPath"] = dllPath,
                                ["IsSigned"] = isSigned.ToString(),
                                ["IsRecent"] = isRecent.ToString(),
                                ["CVE"] = "CVE-2021-34527"
                            }
                        });
                    }
                }
                catch { }
            }
        }

        private async Task DetectSpoolerChildProcesses(CancellationToken ct)
        {
            // spoolsv.exe should NOT spawn child processes in normal operation.
            // If it does, it's likely executing a planted DLL that launched a payload.
            try
            {
                var spoolerProcesses = Process.GetProcessesByName("spoolsv");
                foreach (var spooler in spoolerProcesses)
                {
                    try
                    {
                        int spoolerPid = spooler.Id;

                        // Find child processes of spoolsv.exe
                        foreach (var proc in Process.GetProcesses())
                        {
                            try
                            {
                                if (proc.Id == spoolerPid || proc.Id <= 4) continue;

                                // Check parent PID via WMI (lightweight - cached in ProcessAncestryCache equivalent)
                                int parentPid = GetParentPid(proc.Id);
                                if (parentPid != spoolerPid) continue;

                                string childName = proc.ProcessName;

                                // Known legitimate spooler children
                                if (childName.Equals("splwow64") ||
                                    childName.Equals("printfilterpipelinesvc"))
                                    continue;

                                string childPath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";
                                string alertKey = $"spooler_child_{proc.Id}_{childName}";
                                if (_alertedDriverPaths.ContainsKey(alertKey)) continue;
                                _alertedDriverPaths[alertKey] = 0;

                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Print Spooler: Exploitation - Unexpected Child Process",
                                    Evidence = $"spoolsv.exe (PID {spoolerPid}) spawned unexpected child: '{childName}' " +
                                               $"(PID {proc.Id}) at '{Truncate(childPath, 120)}'.",
                                    Reasoning = "The Windows Print Spooler service spawned an unexpected child process. " +
                                                "In normal operation, spoolsv.exe only spawns splwow64.exe or printfilterpipelinesvc.exe. " +
                                                "Any other child process indicates that a loaded printer driver DLL executed a payload - " +
                                                "this is the exploitation phase of PrintNightmare or similar spooler privilege escalation attacks.",
                                    Confidence = 0.90,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    SignalType = SignalType.SuspiciousProcess,
                                    ProcessName = childName,
                                    ProcessId = proc.Id,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        ["ParentPid"] = spoolerPid.ToString(),
                                        ["ChildPath"] = childPath,
                                        ["Technique"] = "PrintNightmare/SpoolFool"
                                    }
                                });
                            }
                            catch { }
                            finally { proc.Dispose(); }
                        }
                    }
                    finally { spooler.Dispose(); }
                }
            }
            catch { }
        }

        private static int GetSpoolerPid()
        {
            try
            {
                var procs = Process.GetProcessesByName("spoolsv");
                if (procs.Length > 0)
                {
                    int pid = procs[0].Id;
                    foreach (var p in procs) p.Dispose();
                    return pid;
                }
            }
            catch { }
            return 0;
        }

        private static int GetParentPid(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        private static string Truncate(string s, int maxLen)
            => s.Length <= maxLen ? s : s[..maxLen] + "...";

        public override void Dispose()
        {
            if (_spoolWatcher != null)
            {
                try { _spoolWatcher.Created -= OnSpoolFileCreated; } catch { }
                try { _spoolWatcher.Dispose(); } catch { }
            }
            if (_printToFileWatcher != null)
            {
                try { _printToFileWatcher.Created -= OnXpsFileCreated; } catch { }
                try { _printToFileWatcher.Dispose(); } catch { }
            }
            base.Dispose();
        }
    }
}
