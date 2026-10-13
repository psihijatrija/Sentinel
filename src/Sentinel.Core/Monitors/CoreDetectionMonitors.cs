// Core Detection Monitor Group - DLL scanning, entropy analysis, load failure detection, and module integrity

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // DiskWideDllScanner - finds DLLs planted outside trusted directories
    // 
    public sealed class DiskWideDllScanner : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DiskWideDllScanner> _logger;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _alertedDlls = new(StringComparer.OrdinalIgnoreCase);

        public DiskWideDllScanner(DetectionEngine de, ILogger<DiskWideDllScanner> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DiskWideDllScanner] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(120000, ct);

                    var pruneCutoff = DateTime.UtcNow.AddMinutes(-10);
                    foreach (var kvp in _alertedDlls.Where(x => x.Value < pruneCutoff).ToList())
                    {
                        _alertedDlls.TryRemove(kvp.Key, out _);
                    }

                    var tempDir = Path.GetTempPath();
                    if (Directory.Exists(tempDir))
                    {
                        foreach (var dll in Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                var fi = new FileInfo(dll);
                                if (fi.Length > 0 && 
                                    fi.CreationTimeUtc > DateTime.UtcNow.AddSeconds(-125) &&
                                    !_alertedDlls.ContainsKey(dll))
                                {
                                    _alertedDlls.TryAdd(dll, DateTime.UtcNow);

                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Sideloading: DLL in Temp Directory",
                                        Evidence = $"Recently created DLL in temp: {dll} ({fi.Length} bytes)",
                                        Reasoning = "A DLL was recently dropped into a temporary directory, which is a common DLL sideloading or injection staging technique.",
                                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DiskWideDllScanner] Error"); }
            }
        }
    }


    // 
    // DLL Entropy Analyzer - detects packed/encrypted DLLs
    // 
    public sealed class DllEntropyAnalyzer : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllEntropyAnalyzer> _logger;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _scanned = new(StringComparer.OrdinalIgnoreCase);

        public DllEntropyAnalyzer(DetectionEngine de, ILogger<DllEntropyAnalyzer> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllEntropyAnalyzer] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(180000, ct);

                    foreach (var path in _scanned.Keys.ToList())
                    {
                        if (!File.Exists(path))
                        {
                            _scanned.TryRemove(path, out _);
                        }
                    }

                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly))
                        {
                            try
                            {
                                var fi = new FileInfo(file);
                                var currentWriteTime = fi.LastWriteTimeUtc;

                                if (_scanned.TryGetValue(file, out var prevWriteTime) && prevWriteTime == currentWriteTime)
                                    continue;

                                _scanned[file] = currentWriteTime;

                                var entropy = CalculateEntropy(file);
                                if (entropy > 7.2)
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "DLL Entropy: High Entropy DLL",
                                        Evidence = $"DLL '{file}' has entropy {entropy:F2} (threshold 7.2)",
                                        Reasoning = "A DLL with abnormally high entropy was found, suggesting it is packed or encrypted - common for malware payloads.",
                                        Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                        ProcessName = "SYSTEM", ProcessId = 0
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllEntropyAnalyzer] Error"); }
            }
        }

        private static double CalculateEntropy(string filePath)
        {
            var freq = new long[256];
            long total = 0;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var buf = new byte[8192];
                int read;
                while ((read = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < read; i++) freq[buf[i]]++;
                    total += read;
                    if (total > 1_000_000) break; 
                }
            }
            if (total == 0) return 0;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / total;
                entropy -= p * MathNet48.Log2(p);
            }
            return entropy;
        }
    }


    // 
    // DLL Load Failure Monitor - watches Windows event log for load failures
    // 
    public sealed class DllLoadFailureMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllLoadFailureMonitor> _logger;

        public DllLoadFailureMonitor(DetectionEngine de, ILogger<DllLoadFailureMonitor> l) { _detectionEngine = de; _logger = l; }

        // Tracks the most recent event RecordNumber we have processed to avoid re-scanning
        private long _lastProcessedRecordNumber = -1;

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllLoadFailureMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    // Use EventLogQuery with a time-bounded XPath filter instead of iterating
                    // all entries - avoids O(N) scan on large Application logs every 15s.
                    try
                    {
                        var cutoff = DateTime.UtcNow.AddSeconds(-20).ToUniversalTime()
                            .ToString("o", System.Globalization.CultureInfo.InvariantCulture);
                        // Query only SideBySide error events in the last 20 seconds
                        var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                            "Application",
                            System.Diagnostics.Eventing.Reader.PathType.LogName,
                            $"*[System[Provider[@Name='SideBySide'] and Level=2 and TimeCreated[@SystemTime>='{cutoff}']]]");

                        using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                        System.Diagnostics.Eventing.Reader.EventRecord? record;
                        while ((record = reader.ReadEvent()) != null)
                        {
                            using (record)
                            {
                                // Skip events we have already emitted
                                if (record.RecordId.HasValue && record.RecordId.Value <= _lastProcessedRecordNumber)
                                    continue;
                                if (record.RecordId.HasValue)
                                    _lastProcessedRecordNumber = record.RecordId.Value;

                                var desc = record.FormatDescription() ?? "";
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "DLL Load Failure: SideBySide Error",
                                    Evidence = $"SideBySide error at {record.TimeCreated}: {desc.Substring(0, Math.Min(200, desc.Length))}",
                                    Reasoning = "A DLL side-by-side loading failure was detected, which may indicate DLL hijacking or corruption.",
                                    Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = "SYSTEM", ProcessId = 0
                                });
                                break; // One per cycle
                            }
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DllLoadFailureMonitor] Error"); }
            }
        }
    }


    // 
    // Module Validation Monitor - checks loaded DLL integrity via hash
    // 
    public sealed class ModuleValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ModuleValidationMonitor> _logger;
        private readonly ConcurrentDictionary<string, string> _baselineHashes = new(StringComparer.OrdinalIgnoreCase);

        public ModuleValidationMonitor(DetectionEngine de, ILogger<ModuleValidationMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ModuleValidationMonitor] Started");
            // Baseline our own modules
            var selfDir = AppContext.BaseDirectory;
            foreach (var dll in Directory.EnumerateFiles(selfDir, "*.dll"))
            {
                try { _baselineHashes[dll] = HashFile(dll); } catch { }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    foreach (var (path, expectedHash) in _baselineHashes)
                    {
                        if (!File.Exists(path))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Deleted",
                                Evidence = $"Module was deleted: {path}",
                                Reasoning = "A Sentinel runtime module was removed from disk, indicating active tampering.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            continue;
                        }
                        var currentHash = HashFile(path);
                        if (currentHash != expectedHash)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Self-Protection: Sentinel Module Tampered",
                                Evidence = $"Module hash mismatch: {path} (expected {expectedHash}, got {currentHash})",
                                Reasoning = "A Sentinel runtime module was modified on disk, indicating active tampering or DLL replacement.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineHashes[path] = currentHash;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ModuleValidationMonitor] Error"); }
            }
        }

        private static string HashFile(string path)
        {
            using var fs = File.OpenRead(path);
            var hash = System.Security.Cryptography.Sha256Net48.HashData(fs);
            return ConvertHex.ToHexString(hash);
        }
    }


    // 
    // Runtime Module Integrity Monitor - checks loaded module paths
    // 
    public sealed class RuntimeModuleIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RuntimeModuleIntegrityMonitor> _logger;

        public RuntimeModuleIntegrityMonitor(DetectionEngine de, ILogger<RuntimeModuleIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RuntimeModuleIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    // Check that the Sentinel service's own loaded modules are from expected paths
                    var selfProc = Process.GetCurrentProcess();
                    foreach (ProcessModule mod in selfProc.Modules)
                    {
                        try
                        {
                            var modPath = mod.FileName ?? "";
                            // v2.9.3: case-insensitive path trust check. The previous
                            // ordinal Contains(@"\Windows\") missed the OS's own uppercased
                            // paths (C:\WINDOWS\System32\...), so every on-demand System32 DLL
                            // load (AppxPackaging, CRYPTXML, webservices, ...) was flagged as a
                            // possible injection - 8000+ benign entries flooding events.jsonl.
                            const StringComparison ic = StringComparison.OrdinalIgnoreCase;
                            if (modPath.IndexOf(@"\Windows\", ic) < 0 &&
                                modPath.IndexOf(AppContext.BaseDirectory, ic) < 0 &&
                                modPath.IndexOf(@"\dotnet\", ic) < 0 &&
                                modPath.IndexOf(@"\Program Files", ic) < 0 &&
                                modPath.IndexOf(@"\Microsoft\Windows Defender\", ic) < 0)
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Self-Protection: Unexpected Module Loaded",
                                    Evidence = $"Unexpected module loaded into Sentinel process: {modPath}",
                                    Reasoning = "A module from an untrusted path was loaded into the Sentinel service process, indicating possible DLL injection.",
                                    Confidence = 0.85, Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = "Sentinel.Service", ProcessId = System.Net48Environment.ProcessId
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[RuntimeModuleIntegrityMonitor] Error"); }
            }
        }
    }


    // 
    // ADS Data Staging Monitor - detects NTFS Alternate Data Streams abuse
    // 
    public sealed class AdsDataStagingMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AdsDataStagingMonitor> _logger;
        private readonly HashSet<string> _alertedFiles = new(StringComparer.OrdinalIgnoreCase);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, int dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr hFindFile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public AdsDataStagingMonitor(DetectionEngine de, ILogger<AdsDataStagingMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AdsDataStagingMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    // Scan temp + downloads for files with suspicious ADS streams
                    var tempDir = Path.GetTempPath();
                    var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

                    foreach (var dir in new[] { tempDir, downloadsDir })
                    {
                        if (!Directory.Exists(dir)) continue;
                        try
                        {
                            foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
                            {
                                if (_alertedFiles.Contains(file)) continue;
                                try
                                {
                                    var streams = GetAlternateDataStreams(file);
                                    // Zone.Identifier is normal (Mark of the Web). Others are suspicious.
                                    foreach (var stream in streams)
                                    {
                                        if (stream.Name.Contains("Zone.Identifier")) continue;
                                        if (stream.Name == "::$DATA") continue; // Primary data stream

                                        if (stream.Size > 1024) // Only flag ADS > 1KB (payload-sized)
                                        {
                                            _alertedFiles.Add(file);
                                            await _detectionEngine.EmitAsync(new DetectionEvent
                                            {
                                                RuleName = "ADS Staging: Hidden Data in Alternate Data Stream",
                                                Evidence = $"File '{file}' has a suspicious ADS '{stream.Name}' ({stream.Size} bytes)",
                                                Reasoning = "A file in a user-writable directory has a non-standard Alternate Data Stream larger than 1KB. ADS is used to hide payloads, exfiltration data, or persistence mechanisms from normal file listings.",
                                                Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                                                ProcessName = "SYSTEM", ProcessId = 0
                                            });
                                            break;
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }

                    // Limit alertedFiles growth
                    if (_alertedFiles.Count > 500) _alertedFiles.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AdsDataStagingMonitor] Error"); }
            }
        }

        private static List<(string Name, long Size)> GetAlternateDataStreams(string filePath)
        {
            var streams = new List<(string, long)>();
            var handle = FindFirstStreamW(filePath, 0, out var data, 0);
            if (handle == INVALID_HANDLE_VALUE) return streams;

            try
            {
                do
                {
                    streams.Add((data.cStreamName, data.StreamSize));
                } while (FindNextStreamW(handle, out data));
            }
            finally
            {
                FindClose(handle);
            }
            return streams;
        }
    }


    // 
    // DormantPayloadMonitor (v2.7.3) - process-centric "dropped but not phoning home" detector.
    //
    // Surfaces a RUNNING process whose image lives in a user-writable drop (Temp/Downloads/
    // AppData/Public), is UNSIGNED, and currently holds NO outbound/established TCP connection.
    // That is the shape of a staged payload that was dropped and is sitting idle waiting for its
    // trigger - it never phones home, so the network-centric chains would never see it.
    //
    // CONSTRAINT COMPLIANCE: this is a "what it IS / where it sits" signal, not "what it DOES",
    // so it is a weak Tier2 / LogOnly OBSERVE contributor only. It NEVER acts on its own. It
    // feeds the correlation engine (Provenance=dormant-dropped-payload) so that if the dormant
    // payload later does anything harmful (executes+injects, encrypts, accesses credentials,
    // tampers with defenses), a composite completes and it is handled gracefully (contain +
    // .senq vault quarantine, never a raw delete, no user panic). A truly inert file that never
    // acts stays observe-only forever.
    // 
    public sealed class DormantPayloadMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<DormantPayloadMonitor> _logger;

        // Dedup by image path so a persistent dormant payload is surfaced at most once per window.
        private readonly ConcurrentDictionary<string, DateTime> _flagged = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ReAlertWindow = TimeSpan.FromMinutes(30);

        // Only consider processes that have been alive at least this long, so a just-launched
        // installer/updater that has not opened its socket yet is not mistaken for dormant.
        private static readonly TimeSpan MinAgeBeforeDormant = TimeSpan.FromSeconds(45);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(60);

        public DormantPayloadMonitor(DetectionEngine de, SignerTrustService signerTrust, ILogger<DormantPayloadMonitor> l)
        {
            _detectionEngine = de;
            _signerTrust = signerTrust;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DormantPayloadMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    ScanOnce();

                    // Prune stale dedup entries.
                    var cutoff = DateTime.UtcNow - ReAlertWindow;
                    foreach (var kv in _flagged)
                        if (kv.Value < cutoff) _flagged.TryRemove(kv.Key, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DormantPayloadMonitor] Error"); }
            }
        }

        private void ScanOnce()
        {
            // PIDs with any established/outbound TCP connection right now.
            var connectedPids = GetConnectedPids();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    int pid = proc.Id;
                    if (pid <= 4) continue;

                    string? imagePath = SecurityValidation.GetProcessImagePath(pid);
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    // Only processes running from a user-writable drop are candidates.
                    if (!ModuleIdentity.IsUserWritableDrop(imagePath)) continue;

                    // Signed binaries from a drop are the normal installer/updater case - not dormant payloads.
                    if (_signerTrust.IsSignedFile(imagePath!)) continue;

                    // Skip obvious benign installer/extractor context (Inno/NSIS/redist unpack in Temp).
                    if (InstallerHeuristics.IsInstallerExtractor(proc.ProcessName, imagePath) ||
                        InstallerHeuristics.LooksLikeInstallerName(proc.ProcessName, imagePath) ||
                        InstallerHeuristics.IsDirectXOrRuntimeRedist(proc.ProcessName, imagePath))
                        continue;

                    // Must have been alive long enough that "no connection yet" is meaningful.
                    DateTime startUtc;
                    try { startUtc = proc.StartTime.ToUniversalTime(); }
                    catch { continue; } // access denied / exited - skip
                    if (DateTime.UtcNow - startUtc < MinAgeBeforeDormant) continue;

                    // The defining condition: unsigned drop-path process with NO active connection.
                    if (connectedPids.Contains(pid)) continue;

                    // Dedup per image path.
                    if (_flagged.TryGetValue(imagePath!, out var last) &&
                        (DateTime.UtcNow - last) < ReAlertWindow)
                        continue;
                    _flagged[imagePath!] = DateTime.UtcNow;

                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Dormant Payload: Unsigned Drop-Path Process Without Network",
                        Evidence = $"Process '{proc.ProcessName}' (PID {pid}) runs from user-writable drop '{imagePath}', " +
                                   $"is unsigned, and holds no outbound/established connection - a staged payload sitting idle.",
                        Reasoning = "An unsigned binary running from a Temp/Downloads/AppData drop with no network activity " +
                                    "matches a dropped-but-not-yet-active payload (staged implant awaiting its trigger). " +
                                    "On its own this is only weak observe-fuel - plenty of benign portable tools also run " +
                                    "unsigned from these paths - so it never acts alone. It contributes to the behavioral " +
                                    "chain and escalates to graceful containment only if this process later performs a " +
                                    "harmful act (injection, mass-encryption, credential/LSASS access, or defense tampering).",
                        Confidence = 0.45,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = proc.ProcessName,
                        ProcessId = pid,
                        SignalType = SignalType.SuspiciousProcess,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ImagePath"] = imagePath!,
                            ["Provenance"] = "dormant-dropped-payload",
                            ["NoActiveConnection"] = "true"
                        }
                    });
                }
                catch { /* per-process best effort */ }
                finally { try { proc.Dispose(); } catch { } }
            }
        }

        /// <summary>
        /// Returns the set of PIDs that currently own an established or connecting outbound TCP
        /// connection (IPv4 + IPv6), via GetExtendedTcpTable (userland iphlpapi, no elevation).
        /// A PID absent from this set has no active outbound channel.
        /// </summary>
        private static HashSet<int> GetConnectedPids()
        {
            var pids = new HashSet<int>();
            CollectConnectedPids(pids, AF_INET);
            CollectConnectedPids(pids, AF_INET6);
            return pids;
        }

        private static void CollectConnectedPids(HashSet<int> pids, int family)
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
            if (bufferSize <= 0) return;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                uint ret = GetExtendedTcpTable(buffer, ref bufferSize, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return;

                int numEntries = Marshal.ReadInt32(buffer);
                // IPv4 MIB_TCPROW_OWNER_PID = 24 bytes; IPv6 MIB_TCP6ROW_OWNER_PID = 56 bytes.
                int entrySize = family == AF_INET ? 24 : 56;
                int stateOffset = family == AF_INET ? 0 : 48;   // dwState offset within the row
                int pidOffset = family == AF_INET ? 20 : 52;    // dwOwningPid offset within the row
                int offset = 4;

                for (int i = 0; i < numEntries && i < 20000; i++)
                {
                    IntPtr entryPtr = buffer + offset + (i * entrySize);
                    int state = Marshal.ReadInt32(entryPtr, stateOffset);
                    // Count ESTABLISHED and SYN_SENT (actively connecting) as "has a connection".
                    if (state != MIB_TCP_STATE_ESTAB && state != MIB_TCP_STATE_SYN_SENT) continue;
                    int pid = Marshal.ReadInt32(entryPtr, pidOffset);
                    if (pid > 4) pids.Add(pid);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_SYN_SENT = 3;
        private const int MIB_TCP_STATE_ESTAB = 5;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);
    }
}
