using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors registry for suspicious changes: autorun entries, COM CLSID hijacking,
    /// malicious services, regsvr32 execution, and .reg file imports.
    /// Emits DetectionEvents and optionally removes malicious entries (active response).
    /// Shows toast notifications when registry threats are detected.
    /// </summary>
    public sealed class RegistryMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ToastService _toastService;
        private readonly ILogger<RegistryMonitor> _logger;
        private readonly SentinelConfig _config;

        // WMI watchers
        private ManagementEventWatcher? _runHklmWatcher;
        private ManagementEventWatcher? _runHkcuWatcher;
        private ManagementEventWatcher? _runOnceHklmWatcher;
        private ManagementEventWatcher? _servicesWatcher;
        private ManagementEventWatcher? _processWatcher;

        // Baselines
        private Dictionary<string, string?> _runHklmBaseline = new(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, string?> _runHkcuBaseline = new(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, string?> _servicesBaseline = new(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, string> _clsidBaseline = new(StringComparer.OrdinalIgnoreCase);
        private Dictionary<string, string?> _proxyBaseline = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _extensionBaseline = new(StringComparer.OrdinalIgnoreCase);

        // Whitelist: known-good autorun entry value names
        private static readonly HashSet<string> WhitelistedRunNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "SecurityHealthSystray",
            "WindowsDefender",
            "OneDrive",
            "MicrosoftEdgeAutoLaunch",
            "Discord",
            "Spotify",
            "Steam",
            "GoogleChromeAutoLaunch",
        };

        // Suspicious paths in autorun values
        private static readonly string[] SuspiciousPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
            @"\appdata\local\", @"\appdata\roaming\",
        };

        // Suspicious executable patterns in autorun values
        private static readonly string[] SuspiciousLaunchers = new[]
        {
            "powershell", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe",
        };

        public RegistryMonitor(
            DetectionEngine detectionEngine,
            ToastService toastService,
            ILogger<RegistryMonitor> logger,
            SentinelConfig config)
        {
            _detectionEngine = detectionEngine;
            _toastService = toastService;
            _logger = logger;
            _config = config;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[RegistryMonitor] Starting registry monitoring...");

            // Build baselines before starting watchers
            BuildBaselines();

            bool wmiAvailable = StartWatchers();

            if (!wmiAvailable)
            {
                _logger.LogWarning("[RegistryMonitor] WMI unavailable - falling back to registry polling mode (15s interval)");
            }
            else
            {
                _logger.LogInformation("[RegistryMonitor] WMI watchers active. Baselines captured.");
            }

            // Periodic CLSID scan (every 30 seconds)
            using var clsidTimer = new System.Timers.Timer(30000);
            clsidTimer.Elapsed += async (_, _) => await ScanClsidAsync();
            clsidTimer.AutoReset = true;
            clsidTimer.Start();

            // Initial CLSID scan
            await ScanClsidAsync();

            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    // If WMI failed, poll registry directly as fallback
                    if (!wmiAvailable)
                    {
                        PollRegistryForChanges();
                    }

                    AuditProxySettings();
                    AuditExtensionPolicies();

                    await Task.Delay(wmiAvailable ? 5000 : 15000, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            finally
            {
                StopWatchers();
                clsidTimer.Stop();
                _logger.LogInformation("[RegistryMonitor] Stopped.");
            }
        }

        /// <summary>
        /// Polling fallback: compare current registry state against baseline.
        /// Used when WMI is unavailable (debloated/custom Windows builds).
        /// </summary>
        private void PollRegistryForChanges()
        {
            try
            {
                // Check Run keys
                PollRunKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", true);
                PollRunKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", true);
                PollRunKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", false);

                // Check Services
                PollServicesKey();
            }
            catch { }
        }

        private void PollRunKey(RegistryKey hive, string subPath, bool isHklm)
        {
            try
            {
                var current = SnapshotRegistryValues(hive, subPath);
                var baseline = isHklm ? _runHklmBaseline : _runHkcuBaseline;

                foreach (var (name, value) in current)
                {
                    if (!baseline.ContainsKey(name))
                    {
                        // New entry since baseline
                        _ = EvaluateAutorunEntry(name, value ?? "", isHklm, subPath);
                        baseline[name] = value;
                    }
                }
            }
            catch { }
        }

        private void PollServicesKey()
        {
            try
            {
                var current = SnapshotServiceNames();
                foreach (var (serviceName, imagePath) in current)
                {
                    if (!_servicesBaseline.ContainsKey(serviceName))
                    {
                        // New service since baseline
                        _ = EvaluateNewService(serviceName, imagePath ?? "");
                        _servicesBaseline[serviceName] = imagePath;
                    }
                }
            }
            catch { }
        }

        private void BuildBaselines()
        {
            _runHklmBaseline = SnapshotRegistryValues(Microsoft.Win32.Registry.LocalMachine,
                @"Software\Microsoft\Windows\CurrentVersion\Run");
            _runHkcuBaseline = SnapshotRegistryValues(Microsoft.Win32.Registry.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Run");
            _servicesBaseline = SnapshotServiceNames();
            BuildProxyBaseline();
            BuildExtensionBaseline();
        }

        private static Dictionary<string, string?> SnapshotRegistryValues(Microsoft.Win32.RegistryKey hive, string subPath)
        {
            var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = hive.OpenSubKey(subPath, writable: false);
                if (key == null) return result;
                foreach (var name in key.GetValueNames())
                {
                    result[name] = key.GetValue(name)?.ToString();
                }
            }
            catch
            {
                // Registry access may be denied for some keys
            }
            return result;
        }

        private static Dictionary<string, string?> SnapshotServiceNames()
        {
            var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Services", writable: false);
                if (key == null) return result;
                foreach (var name in key.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = key.OpenSubKey(name);
                        var imagePath = subKey?.GetValue("ImagePath")?.ToString();
                        result[name] = imagePath;
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }

        private bool StartWatchers()
        {
            int successCount = 0;
            try
            {
                _runHklmWatcher = CreateRegistryWatcher("HKEY_LOCAL_MACHINE",
                    @"Software\Microsoft\Windows\CurrentVersion\Run");
                _runHklmWatcher.EventArrived += OnRunKeyChanged;
                _runHklmWatcher.Start();
                successCount++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Failed to start HKLM Run watcher"); }

            try
            {
                _runHkcuWatcher = CreateRegistryWatcher("HKEY_CURRENT_USER",
                    @"Software\Microsoft\Windows\CurrentVersion\Run");
                _runHkcuWatcher.EventArrived += OnRunKeyChanged;
                _runHkcuWatcher.Start();
                successCount++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Failed to start HKCU Run watcher"); }

            try
            {
                _runOnceHklmWatcher = CreateRegistryWatcher("HKEY_LOCAL_MACHINE",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce");
                _runOnceHklmWatcher.EventArrived += OnRunKeyChanged;
                _runOnceHklmWatcher.Start();
                successCount++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Failed to start RunOnce watcher"); }

            try
            {
                _servicesWatcher = CreateRegistryWatcher("HKEY_LOCAL_MACHINE",
                    @"System\CurrentControlSet\Services");
                _servicesWatcher.EventArrived += OnServicesChanged;
                _servicesWatcher.Start();
                successCount++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Failed to start Services watcher"); }

            try
            {
                var processQuery = new WqlEventQuery(
                    "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' " +
                    "AND (TargetInstance.Name = 'regsvr32.exe' OR TargetInstance.Name = 'reg.exe' OR TargetInstance.Name = 'regedit.exe')");
                _processWatcher = new ManagementEventWatcher(processQuery);
                _processWatcher.EventArrived += OnProcessCreated;
                _processWatcher.Start();
                successCount++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Failed to start process watcher"); }

            return successCount > 0; // At least one WMI watcher succeeded
        }

        private static ManagementEventWatcher CreateRegistryWatcher(string hive, string rootPath)
        {
            var query = new WqlEventQuery(
                $"SELECT * FROM RegistryTreeChangeEvent WHERE Hive='{hive}' AND RootPath='{rootPath.Replace("\\", "\\\\")}'");
            return new ManagementEventWatcher(query);
        }

        private void StopWatchers()
        {
            _runHklmWatcher?.Stop();
            _runHkcuWatcher?.Stop();
            _runOnceHklmWatcher?.Stop();
            _servicesWatcher?.Stop();
            _processWatcher?.Stop();
            _runHklmWatcher?.Dispose();
            _runHkcuWatcher?.Dispose();
            _runOnceHklmWatcher?.Dispose();
            _servicesWatcher?.Dispose();
            _processWatcher?.Dispose();
        }

        private void OnRunKeyChanged(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var hive = e.NewEvent.GetPropertyValue("Hive")?.ToString();
                var isHklm = hive?.Contains("LOCAL_MACHINE") == true;
                var baseline = isHklm ? _runHklmBaseline : _runHkcuBaseline;
                var regHive = isHklm ? Microsoft.Win32.Registry.LocalMachine : Microsoft.Win32.Registry.CurrentUser;
                var current = SnapshotRegistryValues(regHive, @"Software\Microsoft\Windows\CurrentVersion\Run");

                // Find new entries
                foreach (var kvp in current)
                {
                    if (baseline.ContainsKey(kvp.Key)) continue; // Already known

                    var valueName = kvp.Key;
                    var valueData = kvp.Value ?? string.Empty;

                    _ = EvaluateAutorunEntry(valueName, valueData, isHklm, @"Software\Microsoft\Windows\CurrentVersion\Run");
                }

                // Update baseline
                if (isHklm) _runHklmBaseline = current;
                else _runHkcuBaseline = current;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Run key change handler error"); }
        }

        private void OnServicesChanged(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var current = SnapshotServiceNames();

                foreach (var kvp in current)
                {
                    if (_servicesBaseline.ContainsKey(kvp.Key)) continue;

                    var serviceName = kvp.Key;
                    var imagePath = kvp.Value ?? string.Empty;

                    _ = EvaluateNewService(serviceName, imagePath);
                }

                _servicesBaseline = current;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Services change handler error"); }
        }

        private async void OnProcessCreated(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var targetInstance = e.NewEvent["TargetInstance"] as ManagementBaseObject;
                if (targetInstance == null) return;

                var name = targetInstance["Name"]?.ToString() ?? "";
                var pid = Convert.ToInt32(targetInstance["ProcessId"]);
                var cmdLine = targetInstance["CommandLine"]?.ToString() ?? "";
                var lowerCmd = cmdLine.ToLowerInvariant();
                var lowerName = name.ToLowerInvariant();

                if (lowerName == "regsvr32.exe")
                {
                    await EvaluateRegsvr32Async(pid, cmdLine);
                }
                else if (lowerName == "reg.exe")
                {
                    if (lowerCmd.Contains("import") || lowerCmd.Contains("add"))
                    {
                        await EvaluateRegExeAsync(pid, cmdLine);
                    }
                }
                else if (lowerName == "regedit.exe")
                {
                    if (lowerCmd.Contains("/s") || lowerCmd.Contains(".reg"))
                    {
                        await EvaluateRegeditAsync(pid, cmdLine);
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RegistryMonitor] Process creation handler error"); }
        }

        private async Task EvaluateRegsvr32Async(int pid, string cmdLine)
        {
            var lower = cmdLine.ToLowerInvariant();
            var confidence = 0.4;
            var reasoning = "regsvr32.exe is used to register COM DLLs. Legitimate installers use it.";

            if (lower.Contains("/i") || lower.Contains("scrobj.dll"))
            {
                confidence = 0.95;
                reasoning = "regsvr32.exe executed with /i (scriptlet execution) or scrobj.dll - a known LOLBAS technique (Squiblydoo) used to execute arbitrary scripts via COM scriptlets.";
            }
            else if (lower.Contains("http://") || lower.Contains("https://"))
            {
                confidence = 0.90;
                reasoning = "regsvr32.exe loading a resource from a remote URL - a known LOLBAS technique for remote script execution.";
            }
            else if (lower.Contains(@"\temp\") || lower.Contains(@"\tmp\") || lower.Contains(@"\appdata\"))
            {
                confidence = 0.75;
                reasoning = "regsvr32.exe registering a DLL from a user-writable temp or appdata directory.";
            }
            else if (lower.Contains(".sct") || lower.Contains(".txt"))
            {
                confidence = 0.85;
                reasoning = "regsvr32.exe loading a non-DLL file (.sct scriptlet or .txt) - suspicious COM registration pattern.";
            }

            if (confidence >= 0.75)
            {
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: Suspicious regsvr32 Execution",
                    Evidence = $"regsvr32.exe (PID {pid}) executed with command line: {cmdLine}",
                    Reasoning = reasoning,
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = "regsvr32",
                    ProcessId = pid,
                    Metadata = new Dictionary<string, string> { { "CommandLine", cmdLine } }
                };
                await _detectionEngine.EmitAsync(detection);
                _toastService.ShowToast("Sentinel Alert: Suspicious regsvr32", $"PID {pid}: {cmdLine}");
            }
            else
            {
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: regsvr32 Execution",
                    Evidence = $"regsvr32.exe (PID {pid}) executed: {cmdLine}",
                    Reasoning = reasoning,
                    Confidence = confidence,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "regsvr32",
                    ProcessId = pid,
                    Metadata = new Dictionary<string, string> { { "CommandLine", cmdLine } }
                };
                await _detectionEngine.EmitAsync(detection);
            }
        }

        private async Task EvaluateRegExeAsync(int pid, string cmdLine)
        {
            var lower = cmdLine.ToLowerInvariant();
            var confidence = 0.5;
            var reasoning = "reg.exe modified the registry. Could be legitimate system administration.";

            if (lower.Contains("import") && (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\") || lower.Contains(@"\desktop\")))
            {
                confidence = 0.85;
                reasoning = "reg.exe imported a .reg file from a user-writable directory (Temp, Downloads, Desktop). This is a common malware persistence technique.";
            }
            else if (lower.Contains("add") && lower.Contains(@"run"))
            {
                confidence = 0.80;
                reasoning = "reg.exe added a value to a Run key - a known persistence mechanism.";
            }
            else if (lower.Contains("add") && lower.Contains("system\\currentcontrolset\\services"))
            {
                confidence = 0.80;
                reasoning = "reg.exe added a new service registry entry - potential malicious service installation.";
            }

            if (confidence >= 0.75)
            {
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: Suspicious reg.exe Operation",
                    Evidence = $"reg.exe (PID {pid}) executed: {cmdLine}",
                    Reasoning = reasoning,
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = "reg",
                    ProcessId = pid,
                    Metadata = new Dictionary<string, string> { { "CommandLine", cmdLine } }
                };
                await _detectionEngine.EmitAsync(detection);
                _toastService.ShowToast("Sentinel Alert: Suspicious reg.exe", $"PID {pid}: {cmdLine}");
            }
            else
            {
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: reg.exe Operation",
                    Evidence = $"reg.exe (PID {pid}) executed: {cmdLine}",
                    Reasoning = reasoning,
                    Confidence = confidence,
                    Tier = DetectionTier.Tier2Indicator,
                    ProcessName = "reg",
                    ProcessId = pid,
                    Metadata = new Dictionary<string, string> { { "CommandLine", cmdLine } }
                };
                await _detectionEngine.EmitAsync(detection);
            }
        }

        private async Task EvaluateRegeditAsync(int pid, string cmdLine)
        {
            var lower = cmdLine.ToLowerInvariant();
            var confidence = 0.5;
            var reasoning = "regedit.exe executed, possibly importing a .reg file.";

            if (lower.Contains("/s"))
            {
                confidence += 0.15;
                reasoning += " Silent mode (/s) suppresses confirmation dialogs - common in automated malware deployment.";
            }
            if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\") || lower.Contains(@"\desktop\"))
            {
                confidence += 0.25;
                reasoning += " .reg file located in a user-writable directory.";
            }

            var detection = new DetectionEvent
            {
                RuleName = "Registry: regedit.exe Execution",
                Evidence = $"regedit.exe (PID {pid}) executed: {cmdLine}",
                Reasoning = reasoning,
                Confidence = Math.Min(confidence, 0.95),
                Tier = confidence >= 0.75 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = confidence >= 0.75 ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                ProcessName = "regedit",
                ProcessId = pid,
                Metadata = new Dictionary<string, string> { { "CommandLine", cmdLine } }
            };
            await _detectionEngine.EmitAsync(detection);

            if (confidence >= 0.75)
            {
                _toastService.ShowToast("Sentinel Alert: regedit.exe detected", $"PID {pid}: {cmdLine}");
            }
        }

        private async Task EvaluateAutorunEntry(string valueName, string valueData, bool isHklm, string keyPath)
        {
            var lowerData = valueData.ToLowerInvariant();
            var lowerName = valueName.ToLowerInvariant();

            if (WhitelistedRunNames.Contains(valueName)) return;

            var confidence = 0.0;
            var reasoning = "New autorun entry detected.";
            var isSuspiciousPath = SuspiciousPaths.Any(p => lowerData.Contains(p));
            var isSuspiciousLauncher = SuspiciousLaunchers.Any(l => lowerData.Contains(l));

            if (isSuspiciousPath) { confidence += 0.40; reasoning += " Points to a user-writable directory."; }
            if (isSuspiciousLauncher) { confidence += 0.35; reasoning += " Uses a suspicious launcher (PowerShell, cmd, wscript, etc.)."; }
            if (lowerData.Contains("-enc") || lowerData.Contains("-encodedcommand") || lowerData.Contains("-ep bypass"))
            { confidence += 0.40; reasoning += " Contains PowerShell obfuscation flags."; }
            if (lowerData.Contains("http://") || lowerData.Contains("https://"))
            { confidence += 0.30; reasoning += " References a remote resource."; }

            if (confidence >= 0.50)
            {
                var hive = isHklm ? "HKLM" : "HKCU";
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: Suspicious Autorun Entry",
                    Evidence = $"New autorun value '{valueName}' = '{valueData}' in {hive}\\{keyPath}",
                    Reasoning = reasoning,
                    Confidence = Math.Min(confidence, 0.95),
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        { "Hive", hive },
                        { "KeyPath", keyPath },
                        { "ValueName", valueName },
                        { "ValueData", valueData }
                    }
                };
                await _detectionEngine.EmitAsync(detection);
                _toastService.ShowToast("Sentinel Alert: Autorun Entry", $"'{valueName}' added to {hive}\\Run");
            }
            else
            {
                _logger.LogDebug("[RegistryMonitor] New autorun entry '{ValueName}' in {Hive}\\{Key} - confidence too low ({Confidence})",
                    valueName, isHklm ? "HKLM" : "HKCU", keyPath, confidence);
            }
        }

        private async Task EvaluateNewService(string serviceName, string imagePath)
        {
            var lowerPath = imagePath.ToLowerInvariant();
            var confidence = 0.0;
            var reasoning = "New Windows service registered.";

            if (lowerPath.Contains(@"\temp\") || lowerPath.Contains(@"\tmp\") || lowerPath.Contains(@"\appdata\"))
            { confidence += 0.50; reasoning += " Image path in a user-writable directory."; }
            if (lowerPath.Contains("powershell") || lowerPath.Contains("cmd.exe") || lowerPath.Contains("wscript"))
            { confidence += 0.35; reasoning += " Service image is a script interpreter."; }
            if (string.IsNullOrEmpty(imagePath))
            { confidence += 0.20; reasoning += " Service has no image path (kernel driver or system service)."; }

            if (confidence >= 0.50)
            {
                var detection = new DetectionEvent
                {
                    RuleName = "Registry: Suspicious Service Registration",
                    Evidence = $"New service '{serviceName}' registered with ImagePath: '{imagePath}'",
                    Reasoning = reasoning,
                    Confidence = Math.Min(confidence, 0.95),
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                    ProcessName = "unknown",
                    ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        { "Hive", "HKLM" },
                        { "KeyPath", @"System\CurrentControlSet\Services" },
                        { "SubKey", serviceName },
                        { "ImagePath", imagePath }
                    }
                };
                await _detectionEngine.EmitAsync(detection);
                _toastService.ShowToast("Sentinel Alert: New Service", $"'{serviceName}' registered");
            }
        }

        private async Task ScanClsidAsync()
        {
            try
            {
                var currentClsid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                using var clsidKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID", writable: false);
                if (clsidKey == null) return;

                foreach (var subKeyName in clsidKey.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = clsidKey.OpenSubKey(subKeyName + "\\InprocServer32", writable: false);
                        if (subKey == null) continue;
                        var defaultValue = subKey.GetValue(null)?.ToString() ?? "";
                        if (!string.IsNullOrEmpty(defaultValue))
                        {
                            currentClsid[subKeyName] = defaultValue;
                        }
                    }
                    catch { }
                }

                // Find new CLSIDs
                foreach (var kvp in currentClsid)
                {
                    if (_clsidBaseline.ContainsKey(kvp.Key)) continue;

                    var clsid = kvp.Key;
                    var dllPath = kvp.Value;
                    var lowerPath = dllPath.ToLowerInvariant();

                    // Evaluate suspiciousness
                    var confidence = 0.0;
                    var reasoning = "New COM CLSID registered with InprocServer32.";

                    if (lowerPath.Contains(@"\temp\") || lowerPath.Contains(@"\tmp\") || lowerPath.Contains(@"\appdata\"))
                    { confidence += 0.55; reasoning += " DLL path in a user-writable directory."; }
                    if (lowerPath.Contains(@"\downloads\") || lowerPath.Contains(@"\desktop\"))
                    { confidence += 0.45; reasoning += " DLL path in Downloads or Desktop."; }
                    if (!lowerPath.StartsWith(@"c:\windows\") && !lowerPath.StartsWith(@"c:\program files"))
                    { confidence += 0.20; reasoning += " DLL is not in a standard system or program directory."; }

                    if (confidence >= 0.50)
                    {
                        var detection = new DetectionEvent
                        {
                            RuleName = "Registry: Suspicious COM CLSID Registration",
                            Evidence = $"New CLSID {{{clsid}}} with InprocServer32 = '{dllPath}'",
                            Reasoning = reasoning,
                            Confidence = Math.Min(confidence, 0.95),
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.RemoveRegistryEntry,
                            ProcessName = "unknown",
                            ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Hive", "HKCR" },
                                { "KeyPath", $"CLSID\\{{{clsid}}}\\InprocServer32" },
                                { "CLSID", clsid },
                                { "DllPath", dllPath }
                            }
                        };
                        await _detectionEngine.EmitAsync(detection);
                        _toastService.ShowToast("Sentinel Alert: COM Hijack", $"CLSID {{{clsid}}} registered");
                    }
                }

                _clsidBaseline = currentClsid;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RegistryMonitor] CLSID scan error");
            }
        }

        private static readonly string[] ExtensionRegistryPaths = new[]
        {
            @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
            @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
        };

        private void BuildProxyBaseline()
        {
            _proxyBaseline.Clear();
            CaptureProxyKeys(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU");
            CaptureProxyKeys(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKLM");
        }

        private void CaptureProxyKeys(RegistryKey hive, string path, string prefix)
        {
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key == null) return;
                foreach (var valueName in new[] { "ProxyEnable", "ProxyServer", "AutoConfigURL" })
                {
                    var val = key.GetValue(valueName)?.ToString();
                    _proxyBaseline[$"{prefix}:{valueName}"] = val;
                }
            }
            catch { }
        }

        private void AuditProxySettings()
        {
            CheckProxyKeys(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKCU");
            CheckProxyKeys(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "HKLM");
        }

        private void CheckProxyKeys(RegistryKey hive, string path, string prefix)
        {
            try
            {
                using var key = hive.OpenSubKey(path, ResponsePolicy.MayPerformInlineHostMutation(_config));
                if (key == null) return;

                foreach (var valueName in new[] { "ProxyEnable", "ProxyServer", "AutoConfigURL" })
                {
                    var currentVal = key.GetValue(valueName)?.ToString();
                    var baselineKey = $"{prefix}:{valueName}";
                    _proxyBaseline.TryGetValue(baselineKey, out var baselineVal);

                    if (ProxyValuesEquivalent(valueName, baselineVal, currentVal))
                    {
                        // Adopt current representation so we do not re-fire on null<->"0"/"" noise
                        _proxyBaseline[baselineKey] = currentVal;
                        continue;
                    }

                    var evidence = $"Proxy setting '{valueName}' in {prefix} modified. Baseline: '{baselineVal}', Current: '{currentVal}'";
                    var reasoning = $"Proxy hijacking reroutes user traffic. Sentinel detected an unauthorized modification to system proxy settings.";

                    var detection = new DetectionEvent
                    {
                        RuleName = "Registry: Unauthorized Proxy Server Hijack",
                        Evidence = evidence,
                        Reasoning = reasoning,
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponsePolicy.MayPerformInlineHostMutation(_config) ? ResponseAction.RemoveRegistryEntry : ResponseAction.LogOnly,
                        ProcessName = "Unknown",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            { "Hive", prefix },
                            { "KeyPath", path },
                            { "ValueName", valueName },
                            { "BaselineValue", baselineVal ?? "" },
                            { "CurrentValue", currentVal ?? "" }
                        }
                    };

                    _ = _detectionEngine.EmitAsync(detection);
                    _toastService.ShowToast("Sentinel Alert: Proxy Hijack", $"Proxy '{valueName}' changed under {prefix}");

                    if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                    {
                        try
                        {
                            if (baselineVal == null)
                            {
                                key.DeleteValue(valueName, throwOnMissingValue: false);
                            }
                            else
                            {
                                if (valueName == "ProxyEnable" && int.TryParse(baselineVal, out int enableVal))
                                {
                                    key.SetValue(valueName, enableVal, RegistryValueKind.DWord);
                                }
                                else
                                {
                                    key.SetValue(valueName, baselineVal, RegistryValueKind.String);
                                }
                            }
                            _logger.LogWarning("[RegistryMonitor] Actively restored hijacked proxy '{ValueName}' to baseline value '{Baseline}'", valueName, baselineVal);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "[RegistryMonitor] Failed to restore proxy setting '{ValueName}'", valueName);
                        }
                    }
                    else
                    {
                        // LogOnly: adopt new value after one alert so we do not flood every 5s
                        _proxyBaseline[baselineKey] = currentVal;
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// ProxyEnable: missing / empty / "0" all mean "proxy disabled".
        /// ProxyServer / AutoConfigURL: null and empty are equivalent (no proxy URL).
        /// </summary>
        private static bool ProxyValuesEquivalent(string valueName, string? baseline, string? current)
        {
            if (string.Equals(baseline, current, StringComparison.OrdinalIgnoreCase))
                return true;

            if (string.Equals(valueName, "ProxyEnable", StringComparison.OrdinalIgnoreCase))
            {
                static bool IsProxyOff(string? v) =>
                    string.IsNullOrWhiteSpace(v) || v == "0" ||
                    string.Equals(v, "false", StringComparison.OrdinalIgnoreCase);

                if (IsProxyOff(baseline) && IsProxyOff(current))
                    return true;
            }
            else
            {
                // Empty string vs missing value for server/URL is not a hijack
                if (string.IsNullOrWhiteSpace(baseline) && string.IsNullOrWhiteSpace(current))
                    return true;
            }

            return false;
        }

        private void BuildExtensionBaseline()
        {
            _extensionBaseline.Clear();
            foreach (var path in ExtensionRegistryPaths)
            {
                CaptureExtensionValues(Registry.LocalMachine, path, "HKLM");
                CaptureExtensionValues(Registry.CurrentUser, path, "HKCU");
            }
        }

        private void CaptureExtensionValues(RegistryKey hive, string path, string prefix)
        {
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key == null) return;
                foreach (var valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName)?.ToString();
                    if (!string.IsNullOrEmpty(val))
                    {
                        _extensionBaseline.Add($"{prefix}:{path}:{val}");
                    }
                }
            }
            catch { }
        }

        private void AuditExtensionPolicies()
        {
            foreach (var path in ExtensionRegistryPaths)
            {
                CheckExtensionValues(Registry.LocalMachine, path, "HKLM");
                CheckExtensionValues(Registry.CurrentUser, path, "HKCU");
            }
        }

        private void CheckExtensionValues(RegistryKey hive, string path, string prefix)
        {
            try
            {
                using var key = hive.OpenSubKey(path, ResponsePolicy.MayPerformInlineHostMutation(_config));
                if (key == null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    var currentVal = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(currentVal)) continue;

                    var baselineKey = $"{prefix}:{path}:{currentVal}";
                    if (!_extensionBaseline.Contains(baselineKey))
                    {
                        var browserName = path.Contains("Chrome") ? "Chrome" : "Edge";
                        var evidence = $"Unauthorized force-installed extension policy detected in {prefix}\\{path}. Value: {currentVal}";
                        var reasoning = $"Malicious extensions can read passwords, hijack tabs, and steal sessions. Sentinel detected an unauthorized force-installed browser extension.";

                        var detection = new DetectionEvent
                        {
                            RuleName = $"Registry: Unauthorized {browserName} Extension Policy Injection",
                            Evidence = evidence,
                            Reasoning = reasoning,
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponsePolicy.MayPerformInlineHostMutation(_config) ? ResponseAction.RemoveRegistryEntry : ResponseAction.LogOnly,
                            ProcessName = "Unknown",
                            ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Hive", prefix },
                                { "KeyPath", path },
                                { "ValueName", valueName },
                                { "ExtensionConfig", currentVal! }
                            }
                        };

                        _ = _detectionEngine.EmitAsync(detection);
                        _toastService.ShowToast("Sentinel Alert: Browser Policy Hijack", $"New force-installed extension in {browserName}");

                        if (ResponsePolicy.MayPerformInlineHostMutation(_config))
                        {
                            try
                            {
                                key.DeleteValue(valueName);
                                _logger.LogWarning("[RegistryMonitor] Actively deleted unauthorized extension registry value '{ValueName}' ({Value})", valueName, currentVal);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "[RegistryMonitor] Failed to delete unauthorized extension policy value '{ValueName}'", valueName);
                            }
                        }
                    }
                }
            }
            catch { }
        }

        public override void Dispose()
        {
            try { _runHklmWatcher?.Stop(); _runHklmWatcher?.Dispose(); } catch { }
            try { _runHkcuWatcher?.Stop(); _runHkcuWatcher?.Dispose(); } catch { }
            try { _runOnceHklmWatcher?.Stop(); _runOnceHklmWatcher?.Dispose(); } catch { }
            try { _servicesWatcher?.Stop(); _servicesWatcher?.Dispose(); } catch { }
            try { _processWatcher?.Stop(); _processWatcher?.Dispose(); } catch { }
            base.Dispose();
        }
    }
}
