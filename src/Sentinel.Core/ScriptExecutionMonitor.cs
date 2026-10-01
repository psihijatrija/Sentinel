using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Comprehensive script-based attack detection covering:
    ///   1. PowerShell Script Block Logging (Event ID 4104) - catches deobfuscated content
    ///   2. Parent-child process anomaly detection - Office->shells, wmiprvse->shells, etc.
    ///   3. AMSI bypass detection - amsi.dll unload or integrity tampering
    ///   4. SAM hive extraction - reg.exe save targeting SAM/SECURITY/SYSTEM
    ///   5. Suspicious script file drops - .ps1/.vbs/.bat/.js created in user-writable paths
    ///   6. WMI provider abuse - wmiprvse.exe spawning child processes (T1047)
    ///   7. Scheduled task execution - schtasks.exe /run or taskeng spawning children
    ///
    /// v1.4.5: New monitor.
    /// </summary>
    public sealed class ScriptExecutionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScriptExecutionMonitor> _logger;

        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts = new(StringComparer.OrdinalIgnoreCase);
        private DateTime _lastScriptBlockQueryTime = DateTime.UtcNow;
        private readonly HashSet<string> _knownScriptFiles = new(StringComparer.OrdinalIgnoreCase);

        // Malicious patterns in PowerShell script blocks
        private static readonly string[] MaliciousPatterns = new[]
        {
            // AMSI bypass. Plaintext by design: C# folds "Amsi" + "ScanBuffer" back to the
            // full literal in the compiled PE, so splitting was cosmetic - and ML AV scores
            // the runtime-assembly PATTERN as evasion. A signed binary with plaintext
            // detection signatures reads as a security product, not malware.
            "AmsiInitFailed", "amsi.dll", "AmsiScanBuffer", "AmsiUtils",
            "Set-MpPreference -DisableRealtimeMonitoring",
            // Credential theft
            "Invoke-Mimikatz", "sekurlsa::logonpasswords", "Get-Credential",
            "System.Net.NetworkCredential", "ConvertFrom-SecureString",
            "dpapi::masterkey", "lsadump::sam", "kerberos::list",
            // Sentinel evasion
            "Sentinel", "Sentinel", "Stop-Service.*Sentinel",
            // Download cradles
            "Invoke-Expression", "IEX(", "iex(", "iex ",
            "DownloadString", "DownloadFile", "Net.WebClient",
            "Invoke-WebRequest", "Start-BitsTransfer",
            "New-Object Net.Sockets.TCPClient",
            // Execution
            "Invoke-Command", "-EncodedCommand", "FromBase64String",
            "Add-Type.*DllImport", "GetProcAddress", "VirtualAlloc",
            "OpenProcess",
            "WriteProcessMemory",
            "CreateRemoteThread",
            // Persistence
            "New-ScheduledTask", "Register-ScheduledTask",
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            // Webhook exfil (path visible in 4104; TLS on the wire is not)
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "api.telegram.org/bot",
            "hooks.slack.com",
            "webhook.site",
            "interact.sh",
        };

        // Parent-child anomaly pairs: parent -> suspicious children
        private static readonly Dictionary<string, HashSet<string>> AnomalousParentChild = new(StringComparer.OrdinalIgnoreCase)
        {
            // Office applications spawning shells
            ["winword"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "bash" },
            ["excel"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "bash" },
            ["outlook"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta" },
            ["powerpnt"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta" },
            // WMI provider spawning shells
            ["wmiprvse"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "cscript", "wscript", "mshta", "rundll32", "regsvr32" },
            ["wmiadap"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "cscript", "wscript" },
            // Task scheduler spawning LOLBins
            ["taskeng"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "mshta", "rundll32", "regsvr32", "cscript", "wscript" },
            ["taskhostw"] = new(StringComparer.OrdinalIgnoreCase) { "powershell", "pwsh", "cmd", "mshta", "rundll32", "regsvr32" },
            // Services spawning shells (legitimate svchost launches are filtered by path)
            ["services"] = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "cscript", "wscript" },
            // Explorer spawning LOLBins (user-initiated typically uses conhost)
            ["explorer"] = new(StringComparer.OrdinalIgnoreCase) { "mshta", "regsvr32", "rundll32", "cscript", "wscript", "certutil" },
        };

        // SAM hive extraction patterns
        private static readonly string[] SamHivePatterns = new[]
        {
            "reg save hklm\\sam", "reg.exe save hklm\\sam",
            "reg save hklm\\security", "reg.exe save hklm\\security",
            "reg save hklm\\system", "reg.exe save hklm\\system",
            "reg save \"hklm\\sam", "reg save \"hklm\\security", "reg save \"hklm\\system",
        };

        private static readonly HashSet<string> DangerousScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".inf", ".reg"
        };

        // Directories to watch for script drops
        private static readonly string[] ScriptDropWatchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        public ScriptExecutionMonitor(DetectionEngine de, ILogger<ScriptExecutionMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScriptExecutionMonitor] Started - monitoring script execution, parent-child anomalies, AMSI bypass, SAM extraction, script drops");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);

                    await CheckScriptBlockLogging(ct);
                    await CheckParentChildAnomalies(ct);
                    await CheckAmsiIntegrity(ct);
                    await CheckSamHiveExtraction(ct);
                    await CheckScriptFileDrops(ct);

                    // Expire old alerts (cooldown)
                    var cutoff = DateTime.UtcNow.AddMinutes(-2);
                    foreach (var key in _recentAlerts.Keys.ToArray())
                    {
                        if (_recentAlerts.TryGetValue(key, out var time) && time < cutoff)
                            _recentAlerts.TryRemove(key, out _);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] Error"); }
            }
        }

        /// <summary>
        /// Reads PowerShell Script Block Logging events (Event ID 4104) and scans
        /// deobfuscated script content for malicious patterns.
        /// </summary>
        private async Task CheckScriptBlockLogging(CancellationToken ct)
        {
            try
            {
                var queryTime = _lastScriptBlockQueryTime;
                _lastScriptBlockQueryTime = DateTime.UtcNow;

                var xpath = $"*[System[EventID=4104 and TimeCreated[@SystemTime >= '{queryTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
                var query = new EventLogQuery(
                    "Microsoft-Windows-PowerShell/Operational",
                    PathType.LogName,
                    xpath);

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        var scriptBlock = record.Properties?.Count > 2
                            ? record.Properties[2]?.Value?.ToString()
                            : null;

                        if (string.IsNullOrEmpty(scriptBlock)) continue;

                        var matchedPatterns = MaliciousPatterns
                            .Where(p => scriptBlock!.Contains(p))
                            .ToList();

                        if (matchedPatterns.Count == 0) continue;

                        var alertKey = $"ScriptBlock:{matchedPatterns[0]}";
                        if (_recentAlerts.ContainsKey(alertKey)) continue;
                        _recentAlerts[alertKey] = DateTime.UtcNow;

                        // Scale confidence with pattern count
                        double confidence = matchedPatterns.Count switch
                        {
                            1 => 0.55,
                            2 => 0.70,
                            3 => 0.80,
                            4 => 0.88,
                            _ => 0.95
                        };

                        // Tier1 kill for AMSI bypass, credential theft, or Sentinel targeting
                        bool isCritical = matchedPatterns.Any(p =>
                            p.Contains("Amsi") ||
                            p.Contains("Mimi") ||
                            p.Contains("sekurlsa") ||
                            p.Contains("Sentinel"));

                        int pid = 0;
                        string processName = "powershell";
                        try
                        {
                            pid = Convert.ToInt32(record.Properties?[0]?.Value ?? 0);
                            processName = GetProcessNameSafe(pid);
                        }
                        catch { }

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Script: Malicious PowerShell Script Block",
                            Evidence = $"Matched {matchedPatterns.Count} patterns: [{string.Join(", ", matchedPatterns.Take(5))}]. " +
                                       $"Script snippet: {scriptBlock![..Math.Min(200, scriptBlock!.Length)]}...",
                            Reasoning = "PowerShell Script Block Logging (Event 4104) captured deobfuscated script content " +
                                        "containing known attack tool signatures. This bypasses command-line obfuscation " +
                                        "since the AMSI/ScriptBlock layer sees the final decoded content.",
                            Confidence = confidence,
                            Tier = isCritical ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                            AuthorizedResponse = isCritical ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                            ProcessName = processName,
                            ProcessId = pid
                        });
                    }
                }
            }
            catch (EventLogNotFoundException) { } // Log doesn't exist on this system
            catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] ScriptBlockLogging check error"); }
        }

        /// <summary>
        /// Detects anomalous parent-child process relationships indicating exploitation
        /// (e.g., Office spawning cmd.exe, WMI spawning PowerShell).
        /// </summary>
        private async Task CheckParentChildAnomalies(CancellationToken ct)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var procName = proc.ProcessName.ToLowerInvariant();

                        // Check if this process is a suspicious child
                        foreach (var (parent, suspiciousChildren) in AnomalousParentChild)
                        {
                            if (!suspiciousChildren.Contains(procName)) continue;

                            // Get parent process
                            int parentPid = GetParentProcessId(proc.Id);
                            if (parentPid <= 0) continue;

                            string parentName;
                            try
                            {
                                using var parentProc = Process.GetProcessById(parentPid);
                                parentName = parentProc.ProcessName.ToLowerInvariant();
                            }
                            catch { continue; }

                            if (!parentName.Equals(parent)) continue;

                            // Confirmed anomaly
                            var alertKey = $"ParentChild:{parentPid}:{proc.Id}";
                            if (_recentAlerts.ContainsKey(alertKey)) continue;
                            _recentAlerts[alertKey] = DateTime.UtcNow;

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = $"Script: Anomalous Parent-Child ({parentName}->{procName})",
                                Evidence = $"Process '{procName}' (PID {proc.Id}) spawned by '{parentName}' (PID {parentPid}). " +
                                           "This parent should not spawn shell interpreters.",
                                Reasoning = $"The process {parentName}.exe spawned {procName}.exe which is a known " +
                                            "exploitation pattern. Office macros spawn cmd/powershell for payload execution. " +
                                            "WMI providers spawn shells during lateral movement (T1047).",
                                Confidence = 0.85,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = procName,
                                ProcessId = proc.Id
                            });
                        }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] ParentChild check error"); }
        }

        /// <summary>
        /// Detects AMSI bypass by checking if PowerShell processes have amsi.dll loaded.
        /// If amsi.dll is missing from a running PowerShell process, it was likely unloaded
        /// via FreeLibrary to disable script scanning.
        ///
        /// v1.6.3: Production FP - stock System32 powershell.exe without amsi.dll (CLR bootstrap /
        /// provider timing) triggered KillProcessTree + quarantine of the OS binary, removing
        /// C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe from the host.
        /// Guards: min process age, system-host demotion to LogOnly (never kill/quarantine path),
        /// kill only for non-system impostor paths.
        /// </summary>
        private async Task CheckAmsiIntegrity(CancellationToken ct)
        {
            try
            {
                var psProcesses = Process.GetProcessesByName("powershell")
                    .Concat(Process.GetProcessesByName("powershell_ise"))
                    .Concat(Process.GetProcessesByName("pwsh"))
                    .ToArray();

                foreach (var proc in psProcesses)
                {
                    try
                    {
                        // Skip young processes - amsi.dll often loads after CLR + SMA init
                        try
                        {
                            var age = DateTime.UtcNow - proc.StartTime.ToUniversalTime();
                            if (age.TotalSeconds < 15)
                                continue;
                        }
                        catch { continue; }

                        string? imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                        // PowerShell hosts are never games; still gate via CanInspect for consistency
                        if (!NativeProcessMemory.CanInspect(proc.Id, imagePath) &&
                            !SecurityValidation.IsSystemPowerShellPath(imagePath))
                            continue;

                        bool amsiLoaded = false;
                        int moduleCount = 0;
                        try
                        {
                            var mods = NativeProcessMemory.EnumModules(proc.Id);
                            moduleCount = mods.Count;
                            amsiLoaded = mods.Any(m =>
                                m.Name.Equals("amsi.dll"));
                        }
                        catch { continue; }

                        // Too few modules = still starting up even if StartTime is old (suspended)
                        if (!amsiLoaded && moduleCount < 20)
                            continue;

                        if (!amsiLoaded)
                        {
                            var alertKey = $"AmsiBypass:{proc.Id}";
                            if (_recentAlerts.ContainsKey(alertKey)) continue;
                            _recentAlerts[alertKey] = DateTime.UtcNow;

                            bool systemHost = SecurityValidation.IsSystemPowerShellPath(imagePath);
                            // Stock Windows PS without amsi: log for forensics, do NOT kill.
                            // Impostor powershell.exe outside system paths: kill tree (binary still
                            // protected from quarantine by QuarantineManager OS-critical gate if under Windows).
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = systemHost
                                    ? "Script: AMSI Not Loaded (System PowerShell)"
                                    : "Script: AMSI Bypass Detected (amsi.dll Unloaded)",
                                Evidence = systemHost
                                    ? $"System PowerShell (PID {proc.Id}, path '{imagePath}') has no amsi.dll " +
                                      $"after {Math.Max(0, (int)(DateTime.UtcNow - proc.StartTime.ToUniversalTime()).TotalSeconds)}s " +
                                      $"and {moduleCount} modules. Logging only - system hosts are never killed/quarantined for this signal."
                                    : $"Non-system PowerShell-named process (PID {proc.Id}, path '{imagePath ?? "unknown"}') " +
                                      "does not have amsi.dll loaded. Possible AMSI bypass or impostor binary.",
                                Reasoning = systemHost
                                    ? "Missing amsi.dll on the stock Windows PowerShell host is often a false positive " +
                                      "(provider load timing, constrained hosts, or AMSI provider failure). " +
                                      "v1.6.3 demotes this to LogOnly after a production incident where Kill+Quarantine " +
                                      "deleted powershell.exe from System32."
                                    : "Attackers unload amsi.dll via FreeLibrary or run a fake powershell.exe from a " +
                                      "user-writable path. Non-system hosts without AMSI are treated as hostile.",
                                Confidence = systemHost ? 0.45 : 0.90,
                                Tier = systemHost ? DetectionTier.Tier2Indicator : DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = systemHost ? ResponseAction.LogOnly : ResponseAction.KillProcessTree,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                SignalType = SignalType.AmsiTampering,
                                // Only the non-system "AMSI Bypass Detected" case is a terminal
                                // Evasion. The system-host "AMSI Not Loaded" case is observe-only
                                // and must stay non-terminal (matches current substring behavior).
                                Family = systemHost ? (TerminalFamily?)null : TerminalFamily.Evasion,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ImagePath"] = imagePath ?? "",
                                    ["ModuleCount"] = moduleCount.ToString(),
                                    ["SystemHost"] = systemHost.ToString()
                                }
                            });
                        }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] AMSI check error"); }
        }

        /// <summary>
        /// Detects SAM/SECURITY/SYSTEM hive extraction via reg.exe.
        /// </summary>
        private async Task CheckSamHiveExtraction(CancellationToken ct)
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("reg"))
                {
                    try
                    {
                        string cmdLine;
                        try
                        {
                            cmdLine = GetProcessCommandLine(proc.Id);
                        }
                        catch { continue; }

                        if (string.IsNullOrEmpty(cmdLine)) continue;

                        var cmdLower = cmdLine.ToLowerInvariant();
                        bool isSamExtraction = SamHivePatterns.Any(p => cmdLower.Contains(p));

                        if (!isSamExtraction) continue;

                        var alertKey = $"SamHive:{proc.Id}";
                        if (_recentAlerts.ContainsKey(alertKey)) continue;
                        _recentAlerts[alertKey] = DateTime.UtcNow;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Script: SAM Hive Extraction",
                            Evidence = $"Process reg.exe (PID {proc.Id}) executing: {cmdLine[..Math.Min(300, cmdLine.Length)]}",
                            Reasoning = "The reg.exe command is saving SAM/SECURITY/SYSTEM registry hives to disk. " +
                                        "These hives contain NTLM password hashes and LSA secrets that can be cracked " +
                                        "offline or used for pass-the-hash attacks.",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = "reg",
                            ProcessId = proc.Id
                        });
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] SAM hive check error"); }
        }

        /// <summary>
        /// Monitors user-writable directories for new script file creation.
        /// </summary>
        private async Task CheckScriptFileDrops(CancellationToken ct)
        {
            try
            {
                foreach (var watchPath in ScriptDropWatchPaths)
                {
                    if (string.IsNullOrEmpty(watchPath) || !Directory.Exists(watchPath)) continue;

                    try
                    {
                        var files = Directory.EnumerateFiles(watchPath, "*.*", SearchOption.TopDirectoryOnly)
                            .Where(f => DangerousScriptExtensions.Contains(Path.GetExtension(f)))
                            .Where(f =>
                            {
                                try { return File.GetCreationTimeUtc(f) > DateTime.UtcNow.AddSeconds(-15); }
                                catch { return false; }
                            })
                            .Take(10);

                        foreach (var file in files)
                        {
                            if (_knownScriptFiles.Contains(file)) continue;
                            _knownScriptFiles.Add(file);

                            // Keep the set bounded
                            if (_knownScriptFiles.Count > 5000)
                                _knownScriptFiles.Clear();

                            var alertKey = $"ScriptDrop:{file}";
                            if (_recentAlerts.ContainsKey(alertKey)) continue;
                            _recentAlerts[alertKey] = DateTime.UtcNow;

                            // Read first 2KB to check for malicious content
                            string content = "";
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                                    FileShare.ReadWrite | FileShare.Delete);
                                var buffer = new byte[2048];
                                int read = fs.Read(buffer, 0, buffer.Length);
                                content = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
                            }
                            catch { }

                            var contentPatterns = MaliciousPatterns
                                .Where(p => content.Contains(p))
                                .ToList();

                            if (contentPatterns.Count == 0) continue; // Benign script drop

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Script: Suspicious Script File Dropped",
                                Evidence = $"New script '{Path.GetFileName(file)}' created in '{Path.GetDirectoryName(file)}'. " +
                                           $"Content matches: [{string.Join(", ", contentPatterns.Take(3))}]",
                                Reasoning = "A script file with a dangerous extension was created in a user-writable directory " +
                                            "and its content contains known attack tool patterns. This is a common staging " +
                                            "technique where malware drops a script for deferred execution.",
                                Confidence = contentPatterns.Count >= 3 ? 0.85 : 0.65,
                                Tier = contentPatterns.Count >= 3 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                                AuthorizedResponse = contentPatterns.Count >= 3 ? ResponseAction.Quarantine : ResponseAction.LogOnly,
                                ProcessName = "SYSTEM",
                                ProcessId = 0,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["FilePath"] = file,
                                    ["Patterns"] = string.Join(";", contentPatterns)
                                }
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[ScriptExecutionMonitor] ScriptDrop check error"); }
        }

        // 
        // Helpers
        // 

        private static string GetProcessNameSafe(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.ProcessName;
            }
            catch { return "unknown"; }
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static int GetParentProcessId(int pid)
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
            return -1;
        }
    }
}
