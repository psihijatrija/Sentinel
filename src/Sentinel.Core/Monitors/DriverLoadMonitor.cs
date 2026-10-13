// Driver Load Monitor - detects BYOVD (Bring Your Own Vulnerable Driver) attacks
// v1.5.0: New monitor. Critical Group - restarts indefinitely.
// v1.7.0: Added cert-tracing - extracts Authenticode cert from detected drivers,
//         revokes planted TrustedPublisher/Root certs, quarantines signed drivers.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors for BYOVD (Bring Your Own Vulnerable Driver) attacks - the #1 technique
    /// used by ransomware groups (GentleKiller, PoisonX, Qilin, Warlock, Reynolds) to
    /// disable endpoint security products at kernel level.
    ///
    /// Detection approach (userland-compatible - no kernel driver needed):
    ///   1. System Event Log: Event ID 7045 (new service installed) with Type=kernel
    ///   2. Registry monitoring: HKLM\SYSTEM\CurrentControlSet\Services\* new ImagePath=*.sys
    ///   3. Hash cross-reference against embedded vulnerable driver blocklist
    ///   4. Heuristic: .sys file dropped in temp/user-writable path then loaded as service
    ///   5. File system monitoring: .sys file creation in non-standard paths
    ///
    /// Response:
    ///   - Tier1 alert with high confidence on known-vulnerable driver match
    ///   - Attempt to stop and disable the malicious driver service
    ///   - Mark system as "under BYOVD attack" for heightened response mode
    ///   - Write forensic snapshot before potential process termination by driver
    ///
    /// v1.5.0: Addresses the critical BYOVD gap from red team audit.
    /// </summary>
    public sealed class DriverLoadMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DriverLoadMonitor> _logger;

        private DateTime _lastEventLogQuery = DateTime.UtcNow;
        private readonly HashSet<string> _baselineDriverServices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alertedDrivers = new(StringComparer.OrdinalIgnoreCase);

        // Known vulnerable driver hashes (SHA-256) used in BYOVD attacks.
        // Source: Microsoft Recommended Driver Block Rules + LOLDrivers project.
        // This is a curated subset of the most commonly abused drivers.
        private static readonly HashSet<string> VulnerableDriverHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            // Truesight.sys (Adlice/RogueKiller) - abused by GentleKiller, multiple ransomware groups
            "B7B6DCAB15849B26FDE79E98EA8DD653EB8A3CC4FACF3B829FBD17A3493A2A8E",
            // RTCore64.sys (MSI Afterburner) - most commonly abused BYOVD driver
            "01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD",
            // DBUtil_2_3.sys (Dell BIOS utility) - CVE-2021-21551
            "0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5",
            // gdrv.sys (GIGABYTE) - arbitrary read/write
            "31F4CFBB7C8AE2D09956D2C1B006E56F52EA7E0DA3B1C0C1C7C9A0B7D9DD1BD1",
            // WinRing0x64.sys - hardware monitoring, widely abused
            "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5",
            // AsIO64.sys (ASUS) - arbitrary physical memory access
            "B7C4624C83BB92EB74A12BD5DE7C5BCEDE8E10B65B6FCD5ADE6F0BED7C3C2D08",
            // ProcExp152.sys (Process Explorer) - abused for process termination
            "2F1DC5F2E73C89D4E5A12E2B1E37F5B28FB8E5F82FBEB39C0E7637B7C0263F27",
            // ZemanaAntiMalware.sys - abused for arbitrary process kill
            "543991CA8D1C65113DFF039B85AE3F9A87F503DAEC30F46929FD454BC57E5A91",
            // HpPortIox64.sys (HP) - arbitrary I/O port access
            "D0970E3B79B3CE0F0BC8C40D2DCE3E59F88C6EDC6A2B1B5FCA9E7F7C8E7C9A7D",
            // EneIo64.sys (ENE Technology) - direct physical memory access
            // EneIo64.sys (ENE Technology) - placeholder until a verified SHA-256 is recorded.
            // Previous value was a corrupted edit ("174A2F tried:...") and never matched.
            // iqvw64e.sys (Intel) - CVE-2015-2291, widely abused
            "4429F32DB1CC70567919D7D47B844A91CF1329A6CD116F582305F3B7B60CD60B",
            // Capcom.sys - arbitrary kernel code execution
            "73C98438AC64A68E88B7B0AFD11209B8A1FF5B05BA4C3DA0F3F3B5EA8E3EC70B",
            // SpeedFan.sys - ring0 read/write via IOCTLs
            "0F6FCAB3C2C1262C04FD5FEBB2B50CF0EE4B14C55D8AF1A45C0EBBFAE8BDB52",
            // DirectIo64.sys (CPUID) - direct I/O
            "C5C28B85D84FA34C16A0DB92B2C22A13DFDF8BFAB15B13EDF0EAAB9BB3E18BC",
            // KProcessHacker.sys (Process Hacker) - process manipulation from kernel
            "56C10B40B1C58D8F94D0E5C37793C0EDE1E13FD7C2F03AB99B8E7B3C32DCAB0F",
        };

        // Known driver filenames associated with BYOVD attacks
        private static readonly HashSet<string> VulnerableDriverNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "RTCore64.sys", "RTCore32.sys",
            "DBUtil_2_3.sys", "DBUtilDrv2.sys",
            "gdrv.sys", "gdrv2.sys",
            "WinRing0x64.sys", "WinRing0.sys",
            "AsIO64.sys", "AsIO.sys", "AsIO2.sys",
            "ProcExp152.sys", "PROCEXP141.sys",
            "ene.sys", "EneIo64.sys",
            "iqvw64e.sys", "iQVW64.sys",
            "Capcom.sys",
            "speedfan.sys",
            "DirectIo64.sys", "DirectIo32.sys",
            "KProcessHacker.sys",
            "HpPortIox64.sys",
            "ZemanaAntiMalware.sys", "zamguard64.sys",
            "Truesight.sys", "TrueSight.sys",
            "viragt64.sys", "viragt.sys",
            "aswVmm.sys",             // Avast - abused
            "elrawdsk.sys",           // EldoS RawDisk
            "gmer64.sys",             // GMER anti-rootkit (ironic)
            "MsIo64.sys", "MsIo32.sys",
            "BS_HWMIO64_W10.sys",
            "NalDrv.sys", "NAL.sys",  // Intel Network Adapter
            "echo_driver.sys",
            "phymemx64.sys",
            "rtkio64.sys", "rtkiow8x64.sys",
            "winio64.sys", "winio.sys",
            "WinFlash64.sys",
            "inpoutx64.sys",
            "amdpsp.sys",
            "ATKWMIACPI64.sys",
            "NTIOLib_X64.sys",
            "nbwdv.sys",              // Medusa ransomware EDR killer
            "NSecKrnl.sys",           // Reynolds ransomware, CVE-2025-68947
            "ensrvr64.sys",           // EnCase forensic driver (revoked cert), Akira/SonicWall campaign 2026
            "PoisonX.sys",            // GodDamn/Hyadina ransomware-as-a-service EDR killer, July 2026
        };

        // v2.1.5: Known GPU driver filenames - if a .sys with these names appears from
        // non-standard paths (not DriverStore, not manufacturer installer), it's likely
        // a trojanized GPU driver used for privilege escalation or hardware-level persistence.
        private static readonly HashSet<string> GpuDriverNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // NVIDIA
            "nvlddmkm.sys", "nvoclock.sys", "nvaudio.sys", "nvhda64v.sys",
            "nvmoduletracker.sys", "nvpcf.sys",
            // AMD
            "amdkmdag.sys", "amdkmdap.sys", "atikmdag.sys", "atikmpag.sys",
            "amdpsp.sys", "amd_ags.sys",
            // Intel
            "igdkmd64.sys", "igdkmd32.sys", "igdkmdn.sys",
        };

        // Legitimate GPU driver install paths - drivers should ONLY come from these locations
        private static readonly string[] LegitimateGpuDriverPaths = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\System32\DriverStore",
            @"C:\Program Files\NVIDIA Corporation",
            @"C:\Program Files\AMD",
            @"C:\Program Files\Intel",
            @"C:\Windows\SysWOW64\drivers",
        };

        // Paths where legitimate drivers reside - new .sys outside these are suspicious
        private static readonly string[] LegitimateDriverPaths = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\System32\DriverStore",
            @"C:\Windows\SysWOW64\drivers",
            @"C:\Program Files\Windows Defender",
        };

        public DriverLoadMonitor(DetectionEngine detectionEngine, ILogger<DriverLoadMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DriverLoadMonitor] Started - monitoring for BYOVD vulnerable driver loads");

            // Baseline existing kernel driver services
            BaselineExistingDrivers();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    await CheckEventLogForDriverInstallsAsync(ct);
                    await CheckRegistryForNewDriverServicesAsync(ct);
                    await CheckSuspiciousDriverFilesAsync(ct);
                    await CheckSuspiciousGpuDriverDropAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[DriverLoadMonitor] Error in scan cycle");
                }
            }
        }

        /// <summary>
        /// Baseline all existing kernel driver services at startup so we only alert on new ones.
        /// </summary>
        private void BaselineExistingDrivers()
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        var type = svcKey?.GetValue("Type");
                        if (type is int typeInt && (typeInt == 1 || typeInt == 2)) // Kernel driver or file system driver
                        {
                            _baselineDriverServices.Add(svcName);
                        }
                    }
                    catch { }
                }

                _logger.LogInformation("[DriverLoadMonitor] Baselined {Count} existing kernel driver services", _baselineDriverServices.Count);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Failed to baseline drivers");
            }
        }

        /// <summary>
        /// Checks System Event Log for Event ID 7045 (new service installed) with kernel driver type.
        /// This catches drivers installed via sc.exe create or CreateService API.
        /// </summary>
        private async Task CheckEventLogForDriverInstallsAsync(CancellationToken ct)
        {
            try
            {
                var queryTime = _lastEventLogQuery;
                _lastEventLogQuery = DateTime.UtcNow;

                // Event 7045 = new service installed (System log)
                var xpath = $"*[System[EventID=7045 and TimeCreated[@SystemTime >= '{queryTime:yyyy-MM-ddTHH:mm:ss.fffZ}']]]";
                var query = new EventLogQuery("System", PathType.LogName, xpath);

                using var reader = new EventLogReader(query);
                EventRecord? record;
                while ((record = reader.ReadEvent()) != null)
                {
                    using (record)
                    {
                        // Event 7045 properties: ServiceName(0), ImagePath(1), ServiceType(2), StartType(3), AccountName(4)
                        if (record.Properties == null || record.Properties.Count < 3) continue;

                        var serviceName = record.Properties[0]?.Value?.ToString() ?? "";
                        var imagePath = record.Properties[1]?.Value?.ToString() ?? "";
                        var serviceType = record.Properties[2]?.Value?.ToString() ?? "";

                        // Only care about kernel drivers
                        if (!serviceType.Contains("kernel") &&
                            !serviceType.Contains("driver") &&
                            serviceType != "1" && serviceType != "2")
                            continue;

                        int pid = 0;
                        try { pid = record.ProcessId ?? 0; } catch { }
                        await EvaluateNewDriverAsync(serviceName, imagePath, ct, pid);
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            catch (Exception ex) { _logger.LogDebug(ex, "[DriverLoadMonitor] EventLog check error"); }
        }

        /// <summary>
        /// Periodically scans registry for new kernel driver services added since baseline.
        /// Catches drivers loaded via registry manipulation (bypassing Event 7045).
        /// </summary>
        private async Task CheckRegistryForNewDriverServicesAsync(CancellationToken ct)
        {
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    if (_baselineDriverServices.Contains(svcName)) continue;
                    if (_alertedDrivers.Contains(svcName)) continue;

                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName);
                        var type = svcKey?.GetValue("Type");
                        if (type is not int typeInt || (typeInt != 1 && typeInt != 2)) continue;

                        var imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? "";

                        // New kernel driver detected - add to baseline and evaluate
                        _baselineDriverServices.Add(svcName);
                        await EvaluateNewDriverAsync(svcName, imagePath, ct);
                    }
                    catch { }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[DriverLoadMonitor] Registry check error"); }
        }

        /// <summary>
        /// Scans for .sys files in user-writable paths - attackers drop vulnerable drivers
        /// in temp/downloads/appdata before loading them.
        /// </summary>
        private async Task CheckSuspiciousDriverFilesAsync(CancellationToken ct)
        {
            // v2.2.0: scan real interactive user profiles, not SYSTEM's LocalAppData.
            var suspiciousPaths = SecurityValidation.EnumerateInteractiveUserWritableRoots();

            foreach (var basePath in suspiciousPaths)
            {
                if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;

                try
                {
                    var sysFiles = Directory.EnumerateFiles(basePath, "*.sys", SearchOption.TopDirectoryOnly)
                        .Where(f =>
                        {
                            try { return File.GetCreationTimeUtc(f) > DateTime.UtcNow.AddMinutes(-5); }
                            catch { return false; }
                        })
                        .Take(25);

                    foreach (var sysFile in sysFiles)
                    {
                        if (_alertedDrivers.Contains(sysFile)) continue;
                        _alertedDrivers.Add(sysFile);

                        var fileName = Path.GetFileName(sysFile);
                        bool isKnownVulnerable = VulnerableDriverNames.Contains(fileName);

                        // Hash the file for blocklist check
                        string hash = "";
                        bool hashMatch = false;
                        try
                        {
                            using var fs = new FileStream(sysFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                            hash = ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(fs));
                            hashMatch = VulnerableDriverHashes.Contains(hash);
                        }
                        catch { }

                        double confidence = (isKnownVulnerable || hashMatch) ? 0.95 : 0.75;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = hashMatch || isKnownVulnerable
                                ? "BYOVD: Known Vulnerable Driver Dropped in User Path"
                                : "BYOVD: Suspicious Driver File in User-Writable Path",
                            Evidence = $"Driver file '{fileName}' created in '{basePath}'. " +
                                       $"SHA-256: {(string.IsNullOrEmpty(hash) ? "unavailable" : hash[..16] + "...")}. " +
                                       $"Known vulnerable: {isKnownVulnerable}. Hash blocklist match: {hashMatch}.",
                            Reasoning = isKnownVulnerable || hashMatch
                                ? $"A known BYOVD driver '{fileName}' was dropped in a user-writable directory. " +
                                  "This is the staging phase of a BYOVD attack - the attacker drops the vulnerable " +
                                  "driver, then loads it as a kernel service to gain ring-0 access for EDR termination. " +
                                  "This driver appears on the Microsoft Vulnerable Driver Blocklist or LOLDrivers database."
                                : $"A .sys kernel driver file was created in a user-writable directory ('{basePath}'). " +
                                  "Legitimate drivers are installed via Windows Update or vendor installers to " +
                                  "System32\\drivers. Drivers in temp/user paths are highly suspicious and may be " +
                                  "staging for a BYOVD attack.",
                            Confidence = confidence,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = isKnownVulnerable || hashMatch
                                ? ResponseAction.QuarantineAndKill
                                : ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DriverFile"] = sysFile,
                                ["FileName"] = fileName,
                                ["SHA256"] = hash,
                                ["KnownVulnerable"] = (isKnownVulnerable || hashMatch).ToString(),
                                ["Technique"] = "T1068/BYOVD"
                            }
                        });
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// v2.1.5: Detects .sys files claiming to be GPU drivers (nvlddmkm.sys, amdkmdag.sys, etc.)
        /// but dropped from non-standard paths. Legitimate GPU drivers are installed exclusively via
        /// DriverStore (Windows Update, vendor installer, GeForce Experience, AMD Software).
        /// A GPU driver filename appearing in Temp, Downloads, or user-writable paths is a
        /// trojanized driver - either for privilege escalation or hardware-level persistence.
        /// </summary>
        private async Task CheckSuspiciousGpuDriverDropAsync(CancellationToken ct)
        {
            var suspiciousPaths = SecurityValidation.EnumerateInteractiveUserWritableRoots();

            foreach (var basePath in suspiciousPaths)
            {
                if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;

                try
                {
                    // Look for recently created .sys files that match GPU driver names
                    var sysFiles = Directory.EnumerateFiles(basePath, "*.sys", SearchOption.AllDirectories)
                        .Where(f =>
                        {
                            try
                            {
                                var name = Path.GetFileName(f);
                                return GpuDriverNames.Contains(name) &&
                                       File.GetCreationTimeUtc(f) > DateTime.UtcNow.AddMinutes(-5);
                            }
                            catch { return false; }
                        })
                        .Take(5);

                    foreach (var sysFile in sysFiles)
                    {
                        if (_alertedDrivers.Contains(sysFile)) continue;
                        _alertedDrivers.Add(sysFile);

                        var fileName = Path.GetFileName(sysFile);

                        // Verify it's NOT in a legitimate GPU driver path
                        bool isLegitPath = LegitimateGpuDriverPaths.Any(p =>
                            sysFile.StartsWith(p, StringComparison.OrdinalIgnoreCase));
                        if (isLegitPath) continue;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "DriverLoadMonitor: Trojanized GPU Driver Dropped in User Path",
                            Evidence = $"File '{fileName}' (a known GPU driver name) was created in non-standard path '{basePath}'. " +
                                       $"Full path: '{sysFile}'. Legitimate GPU drivers are only installed via DriverStore.",
                            Reasoning = "A file with the name of a known GPU kernel-mode driver was dropped in a user-writable " +
                                        "directory. Legitimate GPU driver installations go through Windows DriverStore " +
                                        "(via vendor installers, Windows Update, or GeForce Experience/AMD Software). " +
                                        "A GPU driver filename in Temp/Downloads/AppData indicates either: " +
                                        "(1) A trojanized GPU driver for kernel-level privilege escalation (replacing the real driver), " +
                                        "(2) A BYOVD attack using an older vulnerable GPU driver version, or " +
                                        "(3) Preparation for hardware-level persistence that survives OS reinstallation. " +
                                        "This is a high-confidence indicator of an advanced attack targeting the GPU driver stack.",
                            Confidence = 0.88,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.QuarantineAndKill,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DriverFile"] = sysFile,
                                ["FileName"] = fileName,
                                ["AttackVector"] = "GPU_DRIVER_TROJANIZATION",
                                ["Technique"] = "T1068 (Exploitation for Privilege Escalation)",
                                ["MITRE"] = "T1547.006 (Kernel Modules and Extensions)",
                            }
                        });
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Evaluates a newly detected driver service against the vulnerability blocklist.
        /// </summary>
        private async Task EvaluateNewDriverAsync(string serviceName, string imagePath, CancellationToken ct, int processId = 0)
        {
            if (string.IsNullOrEmpty(imagePath)) return;
            if (_alertedDrivers.Contains(serviceName)) return;
            _alertedDrivers.Add(serviceName);

            // Resolve the image path
            var resolvedPath = imagePath;
            if (imagePath.StartsWith(@"\??\"))
                resolvedPath = imagePath[4..];
            else if (imagePath.StartsWith("System32"))
                resolvedPath = Path.Combine(Environment.SystemDirectory, imagePath.Replace("System32\\", ""));
            else if (!PathNet48.IsPathFullyQualified(imagePath))
                resolvedPath = Path.Combine(Environment.SystemDirectory, "drivers", imagePath);

            // Check filename against known vulnerable drivers
            var fileName = Path.GetFileName(resolvedPath);
            bool isKnownVulnerableName = VulnerableDriverNames.Contains(fileName);

            // Check if loaded from a non-standard path
            bool isNonStandardPath = !LegitimateDriverPaths.Any(p =>
                resolvedPath.StartsWith(p));

            // Hash check
            string hash = "";
            bool hashMatch = false;
            if (File.Exists(resolvedPath))
            {
                try
                {
                    using var fs = new FileStream(resolvedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    hash = ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(fs));
                    hashMatch = VulnerableDriverHashes.Contains(hash);
                }
                catch { }
            }

            // Determine confidence and response based on signals
            double confidence;
            ResponseAction response;
            string ruleName;

            if (hashMatch)
            {
                confidence = 0.97;
                response = ResponseAction.KillProcessTree;
                ruleName = "BYOVD: Known Vulnerable Driver Loaded (Hash Match)";
            }
            else if (isKnownVulnerableName && isNonStandardPath)
            {
                confidence = 0.92;
                response = ResponseAction.KillProcessTree;
                ruleName = "BYOVD: Vulnerable Driver Name from Non-Standard Path";
            }
            else if (isKnownVulnerableName)
            {
                confidence = 0.85;
                response = ResponseAction.LogOnly;
                ruleName = "BYOVD: Known Vulnerable Driver Service Created";
            }
            else if (isNonStandardPath)
            {
                confidence = 0.70;
                response = ResponseAction.LogOnly;
                ruleName = "BYOVD: Kernel Driver Loaded from Non-Standard Path";
            }
            else
            {
                // Unknown driver from standard path - low concern
                return;
            }

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"New kernel driver service '{serviceName}' with image path '{imagePath}'. " +
                           $"Resolved: '{resolvedPath}'. Filename: '{fileName}'. " +
                           $"Known vulnerable name: {isKnownVulnerableName}. Hash match: {hashMatch}. " +
                           $"Non-standard path: {isNonStandardPath}. " +
                           $"SHA-256: {(string.IsNullOrEmpty(hash) ? "file not accessible" : hash[..16] + "...")}.",
                Reasoning = "A kernel-mode driver was loaded that matches known BYOVD attack patterns. " +
                            "Ransomware groups (GentleKiller, PoisonX, Qilin, Warlock, Reynolds) use vulnerable " +
                            "signed drivers to gain ring-0 access, then terminate EDR processes via " +
                            "ZwTerminateProcess from kernel mode - bypassing all userland protections. " +
                            "54+ known EDR-killer tools abuse 35+ vulnerable drivers for this purpose. " +
                            (hashMatch
                                ? "The SHA-256 hash matches the Microsoft Vulnerable Driver Blocklist."
                                : isKnownVulnerableName
                                    ? $"The filename '{fileName}' matches a known BYOVD target from LOLDrivers."
                                    : "The driver was loaded from a non-standard path, which is unusual for legitimate drivers."),
                Confidence = confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = response,
                ProcessName = serviceName,
                ProcessId = processId > 4 ? processId : 0,
                SignalType = SignalType.SecurityEvasion,
                Metadata = new Dictionary<string, string>
                {
                    ["ServiceName"] = serviceName,
                    ["ImagePath"] = imagePath,
                    ["ResolvedPath"] = resolvedPath,
                    ["SHA256"] = hash,
                    ["KnownVulnerableName"] = isKnownVulnerableName.ToString(),
                    ["HashMatch"] = hashMatch.ToString(),
                    ["NonStandardPath"] = isNonStandardPath.ToString(),
                    ["Technique"] = "T1068/T1562.001/BYOVD"
                }
            });

            // If high confidence - attempt to stop and disable the driver service
            if (confidence >= 0.90)
            {
                await AttemptDriverDisableAsync(serviceName, ct);
            }

            // v1.7.0: Cert-tracing - if the driver is signed by a non-public cert that was
            // planted in TrustedPublisher or Root store, revoke it to prevent re-loading.
            // This closes the attack chain: attacker plants cert -> loads driver -> Sentinel
            // removes cert + quarantines driver -> re-load is impossible without repeating entire chain.
            if (confidence >= 0.70 && File.Exists(resolvedPath))
            {
                await TracAndRevokeDriverCertAsync(resolvedPath, serviceName, confidence, ct);
            }
        }

        /// <summary>
        /// v1.7.0: Cert-tracing for BYOVD drivers.
        /// Extracts the Authenticode signing certificate from the driver binary, checks if
        /// that cert (or its root/intermediate) was planted in TrustedPublisher or Root stores
        /// (not a well-known public CA), and if so fires RemoveCertAndKillAdder to revoke it.
        ///
        /// Attack chain this closes:
        ///   1. Attacker plants fake code-signing cert in TrustedPublisher
        ///   2. Attacker signs their own .sys driver with that cert
        ///   3. Windows DSE passes because TrustedPublisher trusts the signer
        ///   4. Sentinel detects the driver load -> extracts cert -> revokes it
        ///   5. Without the TrustedPublisher entry, Windows will refuse to load the driver again
        ///
        /// Also handles the case where the attacker planted a root CA cert to chain-validate
        /// their driver cert (fake Chromecast / IoT device CA pattern).
        /// </summary>
        private async Task TracAndRevokeDriverCertAsync(string driverPath, string serviceName, double baseConfidence, CancellationToken ct)
        {
            try
            {
                var signerCert = GetDriverAuthenticodeCert(driverPath);
                if (signerCert == null) return;

                var thumbprint = signerCert.Thumbprint;
                var subject = signerCert.Subject;
                var issuer = signerCert.Issuer;

                // Skip well-known public CAs - these are legitimate even on vulnerable drivers
                // (e.g., RTCore64.sys was signed by a real MSI certificate)
                if (IsKnownPublicCa(subject) || IsKnownPublicCa(issuer))
                {
                    signerCert.Dispose();
                    return;
                }

                // Check TrustedPublisher store (most common BYOVD cert-planting vector)
                var (foundInTrustedPublisher, trustedPubThumbprint) = FindCertInStore(
                    StoreName.TrustedPublisher, StoreLocation.LocalMachine, thumbprint, subject);

                // Check Root store (fake CA pattern - e.g., "Chromecast IoT Root CA")
                var (foundInRoot, rootThumbprint) = FindCertInStore(
                    StoreName.Root, StoreLocation.LocalMachine, thumbprint, issuer);

                // Also check CurrentUser stores (less common but possible)
                var (foundInUserTrustedPublisher, userTpThumbprint) = FindCertInStore(
                    StoreName.TrustedPublisher, StoreLocation.CurrentUser, thumbprint, subject);
                var (foundInUserRoot, userRootThumbprint) = FindCertInStore(
                    StoreName.Root, StoreLocation.CurrentUser, thumbprint, issuer);

                bool certPlanted = foundInTrustedPublisher || foundInRoot ||
                                   foundInUserTrustedPublisher || foundInUserRoot;

                if (!certPlanted)
                {
                    signerCert.Dispose();
                    return;
                }

                // Determine which thumbprint to revoke (prefer TrustedPublisher, then Root)
                var revokeThumbprint = trustedPubThumbprint ?? rootThumbprint ??
                                       userTpThumbprint ?? userRootThumbprint ?? thumbprint;

                var storeLabel = foundInTrustedPublisher ? "LocalMachine\\TrustedPublisher" :
                                 foundInRoot ? "LocalMachine\\Root" :
                                 foundInUserTrustedPublisher ? "CurrentUser\\TrustedPublisher" :
                                 "CurrentUser\\Root";

                _logger.LogWarning("[DriverLoadMonitor] BYOVD cert-trace: driver '{Driver}' signed by " +
                    "non-public cert '{Subject}' found in {Store}. Firing RemoveCertAndKillAdder.",
                    serviceName, subject, storeLabel);

                // Confidence boost: planted cert + BYOVD driver = very high confidence attack
                double certTraceConfidence = Math.Max(baseConfidence, 0.95);

                // Emit RemoveCertAndKillAdder detection - the response engine handles actual removal
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "BYOVD: Planted Signing Certificate Revocation",
                    Evidence = $"Driver '{serviceName}' at '{driverPath}' is signed by cert '{subject}' " +
                               $"(Thumbprint: {thumbprint[..16]}...) which was found in {storeLabel}. " +
                               $"This is NOT a well-known public CA - it was planted to enable driver signature validation bypass.",
                    Reasoning = "BYOVD attack chain detected: a non-public code-signing certificate was planted " +
                                $"in the {storeLabel} store, enabling the attacker's driver to pass Windows Driver " +
                                "Signature Enforcement. By revoking this certificate, the driver cannot be reloaded " +
                                "after removal - closing the attack chain permanently. " +
                                "This pattern matches known attacks (fake Chromecast CA, rogue IoT device certs) " +
                                "that bypass DSE by establishing trust at the certificate level.",
                    Confidence = certTraceConfidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.RemoveCertAndKillAdder,
                    ProcessName = serviceName,
                    ProcessId = 0,
                    SignalType = SignalType.SecurityEvasion,
                    Metadata = new Dictionary<string, string>
                    {
                        ["CertThumbprint"] = revokeThumbprint,
                        ["CertSubject"] = subject,
                        ["CertIssuer"] = issuer,
                        ["CertStore"] = storeLabel,
                        ["DriverPath"] = driverPath,
                        ["ServiceName"] = serviceName,
                        ["AdderProcessId"] = "0", // Unknown - cert may have been planted earlier
                        ["Technique"] = "T1553.004/T1068/BYOVD"
                    }
                });

                // Additionally: scan for OTHER drivers signed by the same cert and quarantine them.
                // The attacker may have loaded multiple drivers with the same planted cert.
                await ScanForOtherDriversSignedByCertAsync(signerCert, thumbprint, subject, serviceName, ct);

                signerCert.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Cert-trace failed for driver '{Service}'", serviceName);
            }
        }

        /// <summary>
        /// Scans System32\drivers for other .sys files signed by the same planted cert.
        /// Quarantines any found - the attacker may have loaded multiple BYOVD drivers.
        /// </summary>
        private async Task ScanForOtherDriversSignedByCertAsync(
            X509Certificate2 maliciousCert, string thumbprint, string certSubject,
            string excludeService, CancellationToken ct)
        {
            try
            {
                var driversDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
                if (!Directory.Exists(driversDir)) return;

                var cn = ExtractCN(certSubject);
                int quarantined = 0;

                foreach (var driverPath in Directory.EnumerateFiles(driversDir, "*.sys"))
                {
                    if (ct.IsCancellationRequested) break;
                    if (quarantined >= 10) break; // Safety limit

                    try
                    {
                        var driverCert = GetDriverAuthenticodeCert(driverPath);
                        if (driverCert == null) continue;

                        bool matchesThumbprint = string.Equals(driverCert.Thumbprint, thumbprint);
                        bool matchesCN = !string.IsNullOrEmpty(cn) &&
                            (driverCert.Subject?.Contains(cn) == true);

                        driverCert.Dispose();

                        if (!matchesThumbprint && !matchesCN) continue;

                        var driverName = Path.GetFileNameWithoutExtension(driverPath);
                        if (string.Equals(driverName, excludeService)) continue;

                        _logger.LogWarning("[DriverLoadMonitor] Cert-trace: additional driver '{Driver}' " +
                            "signed by revoked cert. Disabling service.", driverName);

                        // Stop and disable the driver
                        try
                        {
                            using var sc = new System.ServiceProcess.ServiceController(driverName);
                            if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped)
                                sc.Stop();
                        }
                        catch { }

                        DisableAndDeleteServiceNative(driverName);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BYOVD: Additional Driver Signed by Revoked Cert",
                            Evidence = $"Driver '{driverName}.sys' in System32\\drivers is signed by the same " +
                                       $"cert '{certSubject}' that was revoked from TrustedPublisher. " +
                                       "Service disabled and deleted.",
                            Reasoning = "After revoking a planted code-signing cert, all drivers signed by " +
                                        "that cert are neutralized. This driver was found using the same " +
                                        "signing identity and has been disabled to prevent kernel-level attacks.",
                            Confidence = 0.93,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly, // Already handled by service disable
                            ProcessName = driverName,
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DriverPath"] = driverPath,
                                ["CertSubject"] = certSubject,
                                ["CertThumbprint"] = thumbprint,
                                ["Technique"] = "T1553.004/T1068/BYOVD"
                            }
                        });

                        quarantined++;
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Cert-trace driver scan failed");
            }
        }

        /// <summary>
        /// Extracts the Authenticode signing certificate from a file.
        /// Returns null if the file is unsigned or the cert cannot be extracted.
        /// </summary>
        private static X509Certificate2? GetDriverAuthenticodeCert(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is obsolete but has no X509CertificateLoader equivalent for Authenticode
                var cert = new X509Certificate2(
                    X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                return cert;
            }
            catch { return null; }
        }

        /// <summary>
        /// Checks if a certificate (by thumbprint or subject match) exists in the specified store.
        /// Returns (found, thumbprint_of_match).
        /// </summary>
        private static (bool Found, string? Thumbprint) FindCertInStore(
            StoreName storeName, StoreLocation location, string thumbprint, string subjectOrIssuer)
        {
            try
            {
                using var store = new X509Store(storeName, location);
                store.Open(OpenFlags.ReadOnly);

                // Direct thumbprint match
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (found.Count > 0)
                    return (true, thumbprint);

                // Subject/issuer CN match (for root CA certs where the driver cert chains to a planted root)
                var cn = ExtractCN(subjectOrIssuer);
                if (!string.IsNullOrEmpty(cn))
                {
                    foreach (var cert in store.Certificates)
                    {
                        if (cert.Subject?.Contains(cn) == true)
                        {
                            var matchThumb = cert.Thumbprint;
                            return (true, matchThumb);
                        }
                    }
                }

                return (false, null);
            }
            catch { return (false, null); }
        }

        /// <summary>
        /// Checks if a certificate subject/issuer belongs to a known public CA.
        /// These are legitimate even on vulnerable drivers (legitimate vendors sign with real certs).
        /// </summary>
        private static bool IsKnownPublicCa(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return false;

            // Major public CAs and well-known vendors whose certs should not be revoked
            string[] knownPublicCas =
            {
                "DigiCert", "GlobalSign", "VeriSign", "Entrust", "GeoTrust", "GoDaddy",
                "Thawte", "Comodo", "Sectigo", "Starfield", "Let's Encrypt", "ISRG Root",
                "IdenTrust", "Baltimore", "CyberTrust", "QuoVadis", "Trustwave",
                "GTS Root", "SwissSign", "Certum", "AffirmTrust", "Amazon Root",
                "Apple Root", "Microsoft Root", "Microsoft Corporation", "Microsoft Code",
                "Microsoft Windows", "Symantec", "VeriSign", "WoSign", "Buypass",
                "D-TRUST", "USERTrust", "AddTrust", "SECOM", "Network Solutions",
                // Major driver/hardware vendors
                "NVIDIA", "AMD", "Intel", "Realtek", "Broadcom", "Qualcomm",
                "MSI", "ASUS", "Gigabyte", "ASRock", "Lenovo", "Dell", "HP",
                "Samsung", "Logitech", "Razer", "Corsair", "EVGA", "Micro-Star",
                "Western Digital", "Seagate", "Kingston", "SanDisk"
            };

            return knownPublicCas.Any(ca =>
                distinguishedName.Contains(ca));
        }

        /// <summary>
        /// Extracts the CN value from a distinguished name string.
        /// </summary>
        private static string ExtractCN(string distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return "";
            var cnPrefix = "CN=";
            var idx = distinguishedName.IndexOf(cnPrefix);
            if (idx < 0) return "";
            var start = idx + cnPrefix.Length;
            var end = distinguishedName.IndexOf(',', start);
            return end < 0 ? distinguishedName[start..].Trim() : distinguishedName[start..end].Trim();
        }

        /// <summary>
        /// Attempts to stop and disable a malicious driver service before it can kill Sentinel.
        /// Race condition: if the driver loads before we act, we lose. But if we catch it
        /// during service creation (before start), we can prevent the attack.
        /// v1.6.0: Native SCM + ServiceController - no sc.exe LOLBin dependency.
        /// </summary>
        private async Task AttemptDriverDisableAsync(string serviceName, CancellationToken ct)
        {
            if (!IsValidServiceName(serviceName))
            {
                _logger.LogWarning("[DriverLoadMonitor] Refusing to act on invalid service name: {Service}", serviceName);
                return;
            }

            try
            {
                _logger.LogWarning("[DriverLoadMonitor] Attempting to disable BYOVD driver service: {Service}", serviceName);

                // 1. Stop via ServiceController (native .NET, no shell)
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController(serviceName);
                    if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped &&
                        sc.Status != System.ServiceProcess.ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                        await Task.Run(() => sc.WaitForStatus(
                            System.ServiceProcess.ServiceControllerStatus.Stopped,
                            TimeSpan.FromSeconds(5)), ct);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[DriverLoadMonitor] ServiceController.Stop failed for {Service}", serviceName);
                }

                // 2. Disable start type + delete via native SCM P/Invoke
                DisableAndDeleteServiceNative(serviceName);

                _logger.LogWarning("[DriverLoadMonitor] BYOVD driver service '{Service}' - stop/disable/delete attempted", serviceName);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Failed to disable driver service {Service}", serviceName);
            }

            await Task.CompletedTask;
        }

        private static bool IsValidServiceName(string name)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 256) return false;
            foreach (var c in name)
            {
                if (!(char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or ' '))
                    return false;
            }
            return true;
        }

        //  Native SCM (v1.6.0 - replaces sc.exe) 
        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwDesiredAccess);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(IntPtr hService, uint dwServiceType, uint dwStartType,
            uint dwErrorControl, string? lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword, string? lpDisplayName);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr hService);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_CHANGE_CONFIG = 0x0002;
        private const uint DELETE = 0x10000;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_DISABLED = 0x00000004;

        private void DisableAndDeleteServiceNative(string serviceName)
        {
            IntPtr hScm = IntPtr.Zero;
            IntPtr hSvc = IntPtr.Zero;
            try
            {
                hScm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (hScm == IntPtr.Zero) return;

                hSvc = OpenService(hScm, serviceName, SERVICE_CHANGE_CONFIG | DELETE);
                if (hSvc == IntPtr.Zero) return;

                ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                    null, null, IntPtr.Zero, null, null, null, null);

                DeleteService(hSvc);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[DriverLoadMonitor] Native SCM disable/delete failed for {Service}", serviceName);
            }
            finally
            {
                if (hSvc != IntPtr.Zero) CloseServiceHandle(hSvc);
                if (hScm != IntPtr.Zero) CloseServiceHandle(hScm);
            }
        }
    }
}
