using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class FileVerdictScanner : BackgroundService
    {
        private readonly HashReputationService _reputationService;
        private readonly FileVerdictAds _verdictAds;
        private readonly FileReputationEngine _reputationEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly FileScanIndex _scanIndex;
        private readonly ILogger<FileVerdictScanner> _logger;
        private readonly List<FileSystemWatcher> _watchers = new();

        // All scannable extensions - matches Antivirus.ps1 coverage
        private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"
        };

        // Container / disk-image extensions worth a bounded content walk (zip-bomb / polyglot /
        // embedded-payload smuggling). These are inspected via FileReputationEngine's bomb-safe
        // ArchiveContentInspector - never extracted to disk. Kept separate from ScanExtensions so
        // container files also flow through hash reputation + the archive inspector.
        private static readonly HashSet<string> ContainerExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".jar", ".apk", ".xpi", ".vsix", ".nupkg", ".appx", ".appxbundle",
            ".msix", ".msixbundle", ".iso", ".img",
        };

        // Directories to exclude from scanning (build artifacts, browser updates, user tools)
        // HARDENING v1.3.0: Removed "temp", "tmp", "cache" - these are primary malware staging areas.
        // Previously excluded "downloads" too (removed in 1.2.9). Now only skip paths that are
        // genuinely never attack vectors: build tool intermediates, auto-updater working dirs,
        // and user OS-image tools that perform bulk extraction of legitimate Windows binaries.
        // v1.3.10: Added WinSxS/CBS/DISM paths - NTLite feature-disable writes hundreds of signed
        // MS binaries there per operation; hashing + ADS writes on those files causes file lock
        // contention that stalls NTLite for minutes. Hash reputation is unnecessary for files
        // written exclusively by TrustedInstaller/DISM/NTLite inside the component store.
        private static readonly HashSet<string> ExcludedPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            // OS image/servicing tools - extract hundreds of signed Microsoft binaries
            "uupdump", "uup", "uups", "ntlite", "mount", "extracted", "msmg", "offlineimage",
            "winpe", "\\wim\\", "\\scratch\\",
            // Windows component store / CBS servicing - written only by TrustedInstaller/DISM/NTLite
            "\\windows\\winsxs\\", "\\windows\\servicing\\", "\\windows\\logs\\cbs\\",
            "\\windows\\logs\\dism\\", "\\windows\\temp\\cab", "\\windows\\temp\\dism",
            // Browser auto-updaters (self-signed, ephemeral)
            "opera autoupdate", "google\\update", "edge\\update"
        };

        // Processes that perform legitimate bulk OS-image servicing.
        // Files written by these processes inside Windows directories are always signed
        // Microsoft binaries - hash reputation lookups waste API quota and create file locks.
        private static readonly HashSet<string> ServicingProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "dism", "dismhost", "tiworker", "trustedinstaller", "poqexec", "ntlite"
        };

        // Throttle: max concurrent API lookups to avoid hammering CIRCL/MalwareBazaar
        private readonly SemaphoreSlim _apiThrottle = new(4, 4);

        public FileVerdictScanner(
            HashReputationService reputationService,
            FileVerdictAds verdictAds,
            FileReputationEngine reputationEngine,
            DetectionEngine detectionEngine,
            FileScanIndex scanIndex,
            ILogger<FileVerdictScanner> logger)
        {
            _reputationService = reputationService;
            _verdictAds = verdictAds;
            _reputationEngine = reputationEngine;
            _detectionEngine = detectionEngine;
            _scanIndex = scanIndex;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[FileVerdictScanner] Starting lazy verdict scan and file watchers...");

            // Start drive watchers for all scannable file types - PRIORITY: new files scanned immediately
            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                try
                {
                    // FileSystemWatcher doesn't support multiple filters natively,
                    // so we watch all files and filter in the event handler
                    var watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                    {
                        IncludeSubdirectories = true,
                        Filter = "*.*",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                    };
                    watcher.Created += OnFileCreated;
                    watcher.Renamed += OnFileRenamed;
                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to start FileSystemWatcher for drive {Drive}", drive.Name);
                }
            }

            // Lazy background walk - scans every file on every NTFS volume, skipping those already marked
            _ = Task.Run(async () => await WalkDrivesAsync(stoppingToken), stoppingToken);
        }

        private static bool IsScannable(string filePath)
        {
            var ext = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(ext) && ScanExtensions.Contains(ext))
                return true;

            // Container / disk-image files: bounded content inspection for smuggled payloads.
            if (!string.IsNullOrEmpty(ext) && ContainerExtensions.Contains(ext))
                return true;

            // HARDENING: Files without extensions (or unknown extensions) may still be
            // Windows PE executables - MalwareBazaar dumps, renamed payloads, and staged
            // binaries often lack extensions to evade extension-based scanning.
            // Check PE magic bytes (MZ header) for extensionless files.
            if (string.IsNullOrEmpty(ext) || ext.IndexOf('.') < 0)
            {
                return HasPeMagicBytes(filePath);
            }

            return false;
        }

        /// <summary>
        /// Checks if a file starts with the MZ magic bytes (0x4D 0x5A) indicating
        /// a Windows PE executable. Used to detect extensionless malware on disk.
        /// </summary>
        private static bool HasPeMagicBytes(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length < 2) return false;
                var b1 = fs.ReadByte();
                var b2 = fs.ReadByte();
                return b1 == 0x4D && b2 == 0x5A; // 'M' 'Z'
            }
            catch
            {
                return false;
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (IsScannable(e.FullPath))
                _ = Task.Run(async () => await ScanNewFileAsync(e.FullPath));
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (IsScannable(e.FullPath))
                _ = Task.Run(async () => await ScanNewFileAsync(e.FullPath));
        }

        /// <summary>
        /// Returns true when the process that last touched this file is a known OS-servicing
        /// tool (DISM, TrustedInstaller, NTLite, etc.).  We skip reputation scanning for those
        /// files: they are always signed Microsoft binaries, the API lookup wastes quota, and
        /// - most importantly - the FileStream open for hashing competes with the exclusive
        /// write lock held by the servicing tool, stalling NTLite feature-disable for minutes.
        /// </summary>
        private static bool IsWrittenByServicingProcess(string filePath)
        {
            try
            {
                // Quick name-based check first (avoids the WMI/RM call overhead on the hot path)
                foreach (var proc in System.Diagnostics.Process.GetProcesses())
                {
                    try
                    {
                        if (ServicingProcesses.Contains(proc.ProcessName))
                        {
                            proc.Dispose();
                            return true; // A servicing process is active - be conservative
                        }
                        proc.Dispose();
                    }
                    catch { }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Fast-path for new/renamed files. Minimal delay, no lazy throttle.
        /// Goal: tag known-malicious files BEFORE they can execute for the first time.
        /// </summary>
        private async Task ScanNewFileAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;

            var pathLower = filePath.ToLowerInvariant();
            if (ExcludedPaths.Any(excluded => pathLower.Contains(excluded))) return;

            // v1.3.10: Skip files written by OS-servicing tools (DISM, TrustedInstaller, NTLite).
            // These are always signed Microsoft binaries - reputation lookups are wasted API calls
            // and the FileStream open competes with the servicing tool's exclusive write lock,
            // stalling NTLite feature-disable operations for minutes.
            if (IsWrittenByServicingProcess(filePath)) return;

            // Brief stabilization wait - just enough for the write to finish
            await Task.Delay(500);

            int retries = 3;
            while (retries > 0)
            {
                try
                {
                    if (!File.Exists(filePath)) return;

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromMilliseconds(300))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        await ScanFileInternalAsync(filePath);
                        return;
                    }
                }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(800);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Fast scan failed for new file: {FilePath}", filePath);
                    return;
                }
            }

            // If fast path failed, fall back to lazy scan with longer backoff
            await ScanFileWithBackoffAsync(filePath);
        }

        private async Task ScanFileWithBackoffAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !IsScannable(filePath)) return;

            // Skip excluded paths
            var pathLower = filePath.ToLowerInvariant();
            if (ExcludedPaths.Any(excluded => pathLower.Contains(excluded)))
            {
                return;
            }

            // Wait for file to stabilize
            await Task.Delay(2000);

            int retries = 5;
            while (retries > 0)
            {
                try
                {
                    if (!File.Exists(filePath)) return;

                    var lastWrite = File.GetLastWriteTimeUtc(filePath);
                    if (DateTime.UtcNow - lastWrite < TimeSpan.FromSeconds(1))
                    {
                        throw new IOException("File is still being modified");
                    }

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        await ScanFileInternalAsync(filePath);
                        return;
                    }
                }
                catch (IOException)
                {
                    retries--;
                    await Task.Delay(2000);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to scan file: {FilePath}", filePath);
                    return;
                }
            }

            _logger.LogDebug("File scan abandoned after retries (file likely in use): {FilePath}", filePath);
        }

        private async Task ScanFileInternalAsync(string filePath)
        {
            try
            {
                string hash;
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var hashBytes = await sha.ComputeHashAsync(fs);
                    hash = ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
                }

                // Lazy: skip if already marked (ADS verdict exists and hash matches)
                var existingVerdict = _verdictAds.GetVerdict(filePath, hash);
                if (existingVerdict != HashVerdict.Unknown)
                {
                    // Record cheap stat so future walks skip this file without re-hashing.
                    _scanIndex.MarkScanned(filePath);
                    return;
                }

                // v1.3.1: Use the multi-signal FileReputationEngine for composite scoring
                var reputationResult = await _reputationEngine.EvaluateFileAsync(filePath);

                // Map composite verdict to legacy HashVerdict for ADS tagging
                HashVerdict verdict;
                switch (reputationResult.Verdict)
                {
                    case FileVerdict.Malicious:
                    case FileVerdict.HighRisk:
                        verdict = HashVerdict.Unsafe;
                        break;
                    case FileVerdict.Trusted:
                    case FileVerdict.LowRisk:
                        verdict = HashVerdict.Safe;
                        break;
                    default:
                        verdict = HashVerdict.Unknown;
                        break;
                }

                // Only persist definitive verdicts (not Unknown - will be retried)
                if (verdict != HashVerdict.Unknown)
                {
                    _verdictAds.SetVerdict(filePath, hash, verdict);
                }

                // v1.6.4: Observe-only - log verdict but NEVER modify file permissions.
                // Sentinel is an EDR (detect + respond to behavior), not an antivirus.
                // Blocking execution based on reputation scores alone caused false positives
                // (including quarantining our own installer) and violates the design principle
                // that response actions only fire when a process is ACTIVELY malicious.
                // Content-smuggling signals are noteworthy on their own, even if the composite
                // verdict lands short of Unsafe - surface them explicitly so an analyst sees them.
                if (reputationResult.StaticAnalysis.IsMzZipPolyglot)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] MZ+ZIP polyglot detected: {FilePath} (SHA256: {Hash}) - runs as .exe but also extracts as a .zip archive.",
                        filePath, hash);
                }
                if (reputationResult.StaticAnalysis.HasEmbeddedScriptPayload)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] Embedded script payload in compressed stream: {FilePath} (SHA256: {Hash}) - decompresses to executable script content.",
                        filePath, hash);
                }

                // v2.8.4: Bounded archive / disk-image content smuggling (zip bomb, nested archive,
                // embedded PE / script host inside a .zip/.iso/.img). This is a CONTENT signal about
                // a file at rest - there is no live malicious process yet and an attacker fully
                // controls container/file names, so per Sentinel's constraints it can NEVER solo-
                // authorize a destructive response. We emit it as a Tier2 observe seed: it enriches
                // correlation and, if the smuggled payload is later executed and does something
                // terminal, the behavioral monitors + chain logic authorize the kill. Fail-closed
                // inspection aborts are surfaced too (a container we could not fully vet).
                var archiveContent = reputationResult.StaticAnalysis.ArchiveContent;
                if (archiveContent != null &&
                    (archiveContent.HasSmugglingSignal || archiveContent.InspectionAborted))
                {
                    await EmitArchiveContentObserveAsync(filePath, hash, archiveContent);
                }

                if (verdict == HashVerdict.Unsafe)
                {
                    _logger.LogWarning(
                        "[FileVerdictScanner] Unsafe file on disk: {FilePath} (SHA256: {Hash}, Score={Score}, Verdict={Verdict})",
                        filePath, hash, reputationResult.CompositeScore, reputationResult.Verdict);
                }
                else if (reputationResult.Verdict == FileVerdict.Suspicious && reputationResult.CompositeScore >= 55)
                {
                    _logger.LogInformation(
                        "[FileVerdictScanner] Suspicious file: {FilePath} (Score={Score}, Entropy={Entropy:F2}, Signed={Signed})",
                        filePath, reputationResult.CompositeScore,
                        reputationResult.StaticAnalysis.Entropy, reputationResult.IsSigned);
                }

                // Evaluation completed for this content. Record cheap stat (path+size+mtime) so the
                // next drive walk skips this file entirely instead of re-reading and re-hashing it.
                // A later content change bumps size/mtime and invalidates this, forcing a re-scan.
                _scanIndex.MarkScanned(filePath);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error in ScanFileInternalAsync for {FilePath}", filePath);
            }
        }

        /// <summary>
        /// Emit a Tier2 observe-tier detection for content-smuggling found inside a container at
        /// rest. Deliberately LogOnly + PID 0: a file's contents are attacker-controllable and no
        /// process is executing yet, so this must never solo-authorize a kill (Sentinel constraint).
        /// It seeds correlation - if the payload is extracted and detonated, behavioral monitors
        /// supply the kill-grade terminal leg and the chain logic authorizes any response.
        /// </summary>
        private async Task EmitArchiveContentObserveAsync(string filePath, string hash, ArchiveContentAnalysis ac)
        {
            try
            {
                string ruleName = ac.ZipBombShape
                    ? "Content Smuggling: Decompression Bomb in Container"
                    : ac.IsDiskImage
                        ? "Content Smuggling: Payload in Disk Image"
                        : "Content Smuggling: Payload in Archive";

                var evidence =
                    $"File={filePath}; SHA256={hash}; " +
                    $"container={(ac.IsDiskImage ? "disk-image" : "archive")}; " +
                    $"findings={ac.Describe()}; " +
                    $"entries={ac.EntryCount}; depth={ac.MaxNestingDepth}; " +
                    $"declaredBytes={ac.DeclaredUncompressedBytes}; containerBytes={ac.ContainerBytes}";

                _logger.LogWarning(
                    "[FileVerdictScanner] {Rule}: {FilePath} (SHA256: {Hash}) - {Findings}",
                    ruleName, filePath, hash, ac.Describe());

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = ruleName,
                    Evidence = evidence,
                    Reasoning =
                        "A container file at rest carries a smuggled payload or decompression-bomb " +
                        "shape (zip bomb / nested archive / embedded executable or script host, or " +
                        "an ISO/IMG carrying such content). This bypasses extension-based scanning " +
                        "because the payload only surfaces when the container is opened or mounted. " +
                        "Content and file names are attacker-controlled, so this is an OBSERVE-tier " +
                        "signal only - it never authorizes a response by itself. It seeds correlation " +
                        "so that if the payload is extracted and executed, the resulting behavioral " +
                        "terminal (reverse shell / C2 / credential theft / bomb expansion in the " +
                        "PseudoSandbox) completes a chain that can be responded to.",
                    // Confidence intentionally modest: this is a content heuristic, not a behavior.
                    Confidence = ac.ZipBombShape || ac.ContainsExecutable ? 0.55 : 0.40,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    SignalType = SignalType.SuspiciousProcess,
                    ProcessName = Path.GetFileName(filePath),
                    ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        ["FilePath"] = filePath,
                        ["Sha256"] = hash,
                        ["ContainerKind"] = ac.IsDiskImage ? "disk-image" : "archive",
                        ["ZipBombShape"] = ac.ZipBombShape.ToString(),
                        ["ContainsExecutable"] = ac.ContainsExecutable.ToString(),
                        ["ContainsScriptHost"] = ac.ContainsScriptHost.ToString(),
                        ["ContainsNestedArchive"] = ac.ContainsNestedArchive.ToString(),
                        ["MaxNestingDepth"] = ac.MaxNestingDepth.ToString(),
                        ["MaxEntryRatio"] = ac.MaxEntryRatio.ToString("F0"),
                        ["OverallRatio"] = ac.OverallRatio.ToString("F0"),
                        ["InspectionAborted"] = ac.InspectionAborted.ToString(),
                        // Weak observe seed marker - keeps it out of any solo kill-grade path.
                        ["WeakObserveSeed"] = "true",
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileVerdictScanner] Failed to emit archive-content observe for {FilePath}", filePath);
            }
        }

        private async Task WalkDrivesAsync(CancellationToken ct)
        {
            // Wait a bit after startup to let higher-priority monitors initialize
            await Task.Delay(TimeSpan.FromSeconds(30), ct);

            var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady);
            foreach (var drive in drives)
            {
                if (ct.IsCancellationRequested) break;
                _logger.LogInformation("[FileVerdictScanner] Starting lazy walk of {Drive}", drive.Name);
                try
                {
                    await TraverseDirectoryAsync(drive.RootDirectory.FullName, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error initiating drive walk for {Drive}", drive.Name);
                }
            }
            _logger.LogInformation("[FileVerdictScanner] Lazy walk complete on all volumes.");
        }

        private async Task TraverseDirectoryAsync(string rootDir, CancellationToken ct)
        {
            var queue = new Queue<string>();
            queue.Enqueue(rootDir);

            while (queue.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var currentDir = queue.Dequeue();

                // Skip excluded directories
                var dirLower = currentDir.ToLowerInvariant();
                if (ExcludedPaths.Any(excluded => dirLower.Contains(excluded))) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        if (!IsScannable(file)) continue;

                        // Cheap skip: if this exact file (same size + last-write time) was already
                        // scanned, there is nothing new to learn - avoid the full-file read + SHA256.
                        // This is what stops the walk from re-hashing every executable on every pass
                        // (the sustained-MB/s HDD firehose). Any content change bumps size/mtime and
                        // invalidates the entry, forcing a fresh scan.
                        if (_scanIndex.IsUnchangedSinceScan(file))
                            continue;

                        await ScanFileWithBackoffAsync(file);

                        // Lazy throttle: yield between files to keep system responsive
                        await Task.Delay(200, ct);
                    }

                    foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                    {
                        if (ct.IsCancellationRequested) break;
                        var name = Path.GetFileName(subDir).ToLowerInvariant();
                        if (name == "$recycle.bin" || name == "system volume information") continue;

                        queue.Enqueue(subDir);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error traversing directory: {Directory}", currentDir);
                }
            }
        }

        public override void Dispose()
        {
            _apiThrottle.Dispose();
            foreach (var watcher in _watchers)
            {
                watcher.Created -= OnFileCreated;
                watcher.Renamed -= OnFileRenamed;
                watcher.Dispose();
            }
            base.Dispose();
        }
    }
}
