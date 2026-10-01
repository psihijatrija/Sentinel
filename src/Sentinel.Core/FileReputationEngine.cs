using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Ml;

namespace Sentinel.Core
{
    /// <summary>
    /// Multi-signal file reputation engine - produces a composite trust score (0-100)
    /// by aggregating independent signals:
    ///
    ///   1. Hash reputation (CIRCL, MalwareBazaar, VirusTotal) - weighted consensus
    ///   2. Static PE analysis (entropy, suspicious imports, packer indicators)
    ///   3. Offline PE ML model (FastTree) - soft prior when models are present
    ///   4. Signer trust (Authenticode verification + publisher reputation)
    ///   5. Contextual risk (file origin path, age on disk, prevalence)
    ///
    /// Scoring: 0 = maximally trusted, 100 = confirmed malicious.
    ///   0-20:  Trusted (signed, known-good hash, established)
    ///   21-40: Low risk (some trust signals missing but no red flags)
    ///   41-60: Suspicious (unknown hash, unusual characteristics)
    ///   61-80: High risk (flagged by 1+ sources, suspicious static properties)
    ///   81-100: Malicious (confirmed by multiple sources or critical indicators)
    ///
    /// Rate limiting: 4 req/s to CIRCL, 2 req/s to MalwareBazaar, 4 req/min to VT.
    /// Caching: Results persisted via SecureCacheStore with 7-day TTL for Safe,
    ///          24h TTL for Unknown (retry), permanent for Unsafe.
    /// </summary>
    public sealed class FileReputationEngine
    {
        private readonly HashReputationService _hashRepService;
        private readonly SignerTrustService _signerTrust;
        private readonly SecureCacheStore _cacheStore;
        private readonly ILogger<FileReputationEngine> _logger;
        private readonly ContextBus? _contextBus;
        private readonly ThreatReportingConfig? _reportingConfig;

        // SECURITY v1.4.4: Shared static HttpClient instances to prevent socket exhaustion.
        // Each has appropriate timeout for its target API. Thread-safe, reuses connections.
        // v2.3.8: CIRCL / MalwareBazaar use the same SPKI pin helper as VirusTotal/report.
        // Pin mismatch or TLS failure -> Error (never Safe).
        private static readonly HttpClient _circlHttpClient = ProxyAuthHelper.CreatePinnedHttpClient(4, ProxyAuthHelper.CirclHashlookupPins);
        private static readonly HttpClient _mbHttpClient = ProxyAuthHelper.CreatePinnedHttpClient(3, ProxyAuthHelper.MalwareBazaarPins);
        // v2.0.4 HIGH-3: VT proxy uses certificate-pinned HttpClient
        private static readonly HttpClient _vtProxyHttpClient = ProxyAuthHelper.CreatePinnedHttpClient(5);

        // v2.0.4 LOW-1: Proxy health monitoring - track consecutive failures to alert on degradation
#pragma warning disable CS0169
        private int _proxyConsecutiveFailures;
#pragma warning restore CS0169
        private DateTimeOffset _lastProxyHealthAlert = DateTimeOffset.MinValue;
        private const int ProxyHealthAlertThreshold = 10; // Alert after 10 consecutive failures

        // Composite score cache: SHA256 -> (score, timestamp)
        private readonly ConcurrentDictionary<string, (FileReputationResult Result, DateTimeOffset CachedAt)> _resultCache = new();

        // Prevalence tracking: SHA256 -> number of distinct paths seen
        private readonly ConcurrentDictionary<string, HashSet<string>> _prevalenceMap = new();

        // Rate limiters per API source
        private readonly SemaphoreSlim _circlThrottle = new(4, 4);      // 4 concurrent
        private readonly SemaphoreSlim _malwareBazaarThrottle = new(2, 2); // 2 concurrent

        // Deduplication: track in-flight lookups to avoid duplicate API calls
        private readonly ConcurrentDictionary<string, Task<FileReputationResult>> _inFlight = new();

        // Import names compared against target PE import tables (not invoked by Sentinel).
        // Plain literals - split-string Concat is an ML evasion heuristic (Kaspersky/Defender).
        private static readonly HashSet<string> SuspiciousImports = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtMapViewOfSection",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "NtUnmapViewOfSection",
            "VirtualProtectEx",
            "OpenProcess",
            "ReadProcessMemory",
            "NtQueryInformationProcess",
            "AdjustTokenPrivileges",
            "LookupPrivilegeValue",
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "InternetOpen",
            "HttpSendRequest",
            "URLDownloadToFile",
            "WinExec",
            "ShellExecute",
            "CreateProcess"
        };

        private static readonly HashSet<string> HighRiskPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\",
            @"\downloads\", @"\users\public\", @"\programdata\",
            @"\windows\temp\", @"\recycle"
        };

        public FileReputationEngine(
            HashReputationService hashRepService,
            SignerTrustService signerTrust,
            SecureCacheStore cacheStore,
            ILogger<FileReputationEngine> logger,
            ContextBus? contextBus = null,
            ThreatReportingConfig? reportingConfig = null)
        {
            _hashRepService = hashRepService;
            _signerTrust = signerTrust;
            _cacheStore = cacheStore;
            _logger = logger;
            _contextBus = contextBus;
            _reportingConfig = reportingConfig;
        }

        /// <summary>
        /// Evaluates a file and returns a composite reputation result.
        /// Uses deduplication to prevent redundant API calls for the same hash.
        /// </summary>
        public async Task<FileReputationResult> EvaluateFileAsync(string filePath, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return FileReputationResult.Unknown(filePath);

            // Compute SHA-256 - FileShare.Delete ensures we never block user file operations
            string hash;
            long fileSize;
            try
            {
                using var sha = SHA256.Create();
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                fileSize = fs.Length;
                var hashBytes = await sha.ComputeHashAsync(fs, ct);
                hash = ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] Failed to hash {Path}", filePath);
                return FileReputationResult.Unknown(filePath);
            }

            if (_resultCache.TryGetValue(hash, out var cached))
            {
                var age = DateTimeOffset.UtcNow - cached.CachedAt;
                bool expired = cached.Result.Verdict == FileVerdict.Unknown && age > TimeSpan.FromHours(24);
                expired = expired || (cached.Result.Verdict == FileVerdict.Trusted && age > TimeSpan.FromDays(7));

                if (!expired)
                {
                    TrackPrevalence(hash, filePath);
                    return cached.Result;
                }
            }

            var resultTask = _inFlight.GetOrAdd(hash, _ => EvaluateInternalAsync(filePath, hash, fileSize, ct));
            try
            {
                return await resultTask;
            }
            finally
            {
                _inFlight.TryRemove(hash, out _);
            }
        }

        private async Task<FileReputationResult> EvaluateInternalAsync(string filePath, string hash, long fileSize, CancellationToken ct)
        {
            var result = new FileReputationResult
            {
                FilePath = filePath,
                Sha256 = hash,
                FileSize = fileSize,
                EvaluatedAt = DateTimeOffset.UtcNow
            };

            var hashTask = QueryHashReputationAsync(hash, ct);
            var staticResult = AnalyzeStaticProperties(filePath, fileSize);
            result.StaticAnalysis = staticResult;

            bool isSigned = _signerTrust.IsSignedFile(filePath);
            string? signerName = isSigned ? _signerTrust.GetSignerName(filePath) : null;
            result.IsSigned = isSigned;
            result.SignerName = signerName;

            var contextRisk = CalculateContextualRisk(filePath, hash);
            result.ContextualRisk = contextRisk;

            var hashResult = await hashTask;
            result.HashReputation = hashResult;

            result.CompositeScore = CalculateCompositeScore(result);
            result.Verdict = DetermineVerdict(result.CompositeScore);

            _resultCache[hash] = (result, DateTimeOffset.UtcNow);
            TrackPrevalence(hash, filePath);
            PersistResult(hash, result);

            _logger.LogDebug(
                "[FileReputationEngine] {Path} -> Score={Score}, Verdict={Verdict}, Hash={Hash}, Signed={Signed}",
                filePath, result.CompositeScore, result.Verdict, hash[..12], isSigned);

            _contextBus?.Publish(new FileVerdictSignal
            {
                ProcessId = 0,
                ProcessName = System.IO.Path.GetFileName(filePath),
                SourceMonitor = "FileReputationEngine",
                FilePath = filePath,
                Sha256 = hash,
                CompositeScore = result.CompositeScore,
                Verdict = result.Verdict,
                IsSigned = isSigned,
                SignerName = signerName
            });

            return result;
        }

        private async Task<HashReputationResult> QueryHashReputationAsync(string hash, CancellationToken ct)
        {
            var result = new HashReputationResult();
            var circlTask = QueryCirclAsync(hash, ct);
            var mbTask = QueryMalwareBazaarAsync(hash, ct);
            var vtTask = QueryVirusTotalAsync(hash, ct);
            await Task.WhenAll(circlTask, mbTask, vtTask);
            result.CirclVerdict = circlTask.Result;
            result.MalwareBazaarVerdict = mbTask.Result;
            result.VirusTotalVerdict = vtTask.Result;
            result.ConsensusScore = CalculateHashConsensus(result);
            return result;
        }

        private async Task<ApiVerdict> QueryCirclAsync(string hash, CancellationToken ct)
        {
            await _circlThrottle.WaitAsync(ct);
            try
            {
                var response = await _circlHttpClient.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{hash}", ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var trustMatch = System.Text.RegularExpressions.Regex.Match(
                        json, @"""hashlookup:trust""\s*:\s*(\d+)");
                    if (trustMatch.Success && int.TryParse(trustMatch.Groups[1].Value, out int trust))
                    {
                        return new ApiVerdict { Source = "CIRCL", Status = trust > 60 ? VerdictStatus.Safe : VerdictStatus.Unknown, TrustScore = trust };
                    }
                    return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Unknown };
                }
                if ((int)response.StatusCode == 404)
                    return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.NotFound };

                return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Error };
            }
            catch
            {
                return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Error };
            }
            finally { _circlThrottle.Release(); }
        }

        private async Task<ApiVerdict> QueryMalwareBazaarAsync(string hash, CancellationToken ct)
        {
            await _malwareBazaarThrottle.WaitAsync(ct);
            try
            {
                using var client = _mbHttpClient;
                var values = new Dictionary<string, string> { { "query", "get_info" }, { "hash", hash } };
                var content = new FormUrlEncodedContent(values);
                var response = await _mbHttpClient.PostAsync("https://mb-api.abuse.ch/api/v1/", content, ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    if (json.Contains("\"query_status\":\"ok\"") || json.Contains("\"query_status\": \"ok\""))
                        return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Malicious };
                    if (json.Contains("\"query_status\":\"hash_not_found\"") || json.Contains("\"query_status\": \"hash_not_found\""))
                        return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.NotFound };
                }
                return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Error };
            }
            catch
            {
                return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Error };
            }
            finally { _malwareBazaarThrottle.Release(); }
        }

        private async Task<ApiVerdict> QueryVirusTotalAsync(string hash, CancellationToken ct)
        {
            if (_reportingConfig == null || string.IsNullOrWhiteSpace(_reportingConfig.ProxyEndpoint))
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
            }

            if (!ProxyAuthHelper.HasSharedSecret(_reportingConfig))
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
            }

            try
            {
                const string path = "/lookup/vt";
                var payload = System.Text.Json.JsonSerializer.Serialize(new { type = "hash", value = hash });
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _reportingConfig.ProxyEndpoint!, path, payload, _reportingConfig);
                if (request == null)
                {
                    _logger.LogDebug("[FileReputationEngine] VT proxy auth skipped: {Error}", error);
                    return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
                }

                using (request)
                {
                    var response = await _vtProxyHttpClient.SendAsync(request, ct);

                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogDebug("[FileReputationEngine] VT proxy returned {Status}", response.StatusCode);
                        return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
                    }

                    var json = await response.Content.ReadAsStringAsync();

                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
                    {
                        return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
                    }

                    var verdictStr = root.TryGetProperty("verdict", out var vProp) ? vProp.GetString() : "not_found";
                    int detections = root.TryGetProperty("detections", out var dProp) ? dProp.GetInt32() : 0;
                    int engines = root.TryGetProperty("engines", out var eProp) ? eProp.GetInt32() : 0;
                    double detectionRate = root.TryGetProperty("detectionRate", out var drProp) ? drProp.GetDouble() : 0;

                    var status = verdictStr switch
                    {
                        "malicious" => VerdictStatus.Malicious,
                        "suspicious" => VerdictStatus.Suspicious,
                        "safe" => VerdictStatus.Safe,
                        "not_found" => VerdictStatus.NotFound,
                        _ => VerdictStatus.Unknown
                    };

                    return new ApiVerdict
                    {
                        Source = "VirusTotal",
                        Status = status,
                        DetectionCount = detections,
                        EngineCount = engines,
                        DetectionRate = detectionRate
                    };
                }
            }
            catch (OperationCanceledException)
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] VT proxy lookup failed for {Hash}", hash[..12]);
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
        }

        private StaticAnalysisResult AnalyzeStaticProperties(string filePath, long fileSize)
        {
            var result = new StaticAnalysisResult();
            try
            {
                var extLower = System.IO.Path.GetExtension(filePath);
                bool winmdByName = extLower.Equals(".winmd", StringComparison.OrdinalIgnoreCase)
                    || filePath.IndexOf(@"\WinMetadata\", StringComparison.OrdinalIgnoreCase) >= 0;
                if (winmdByName) result.IsMetadataOnlyModule = true;

                // Bounded, bomb-safe archive / disk-image content inspection. Runs for container
                // extensions (.zip/.iso/.img/.jar/...) even when the file is not a PE, so a payload
                // smuggled inside an archive or ISO is surfaced without extracting to disk. All caps
                // are enforced inside ArchiveContentInspector (fail closed).
                if (IsInspectableContainer(extLower))
                {
                    try
                    {
                        var archive = ArchiveContentInspector.Inspect(filePath);
                        if (archive.Inspected || archive.InspectionAborted)
                            result.ArchiveContent = archive;
                    }
                    catch { }
                }

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new BinaryReader(fs);

                try { result.HasEmbeddedScriptPayload = HasEmbeddedScriptPayload(fs); }
                catch { }

                if (fs.Length < 64) { result.IsPe = false; return result; }
                fs.Seek(0, SeekOrigin.Begin);
                var dosSignature = reader.ReadUInt16();
                if (dosSignature != 0x5A4D) { result.IsPe = false; return result; }
                result.IsPe = true;

                try { result.IsMzZipPolyglot = HasZipEndOfCentralDirectory(fs); }
                catch { }

                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = reader.ReadInt32();
                if (peOffset <= 0 || peOffset >= fs.Length - 4) return result;

                fs.Seek(peOffset, SeekOrigin.Begin);
                uint peSignature = reader.ReadUInt32();
                if (peSignature != 0x00004550) return result;

                ushort machine = reader.ReadUInt16();
                ushort numberOfSections = reader.ReadUInt16();
                result.SectionCount = numberOfSections;
                uint timeDateStamp = reader.ReadUInt32();
                result.CompileTimestamp = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp);

                fs.Seek(peOffset + 24, SeekOrigin.Begin);
                ushort optionalMagic = reader.ReadUInt16();
                result.Is64Bit = optionalMagic == 0x20B;

                try
                {
                    fs.Seek(peOffset + 24 + 16, SeekOrigin.Begin);
                    uint addressOfEntryPoint = reader.ReadUInt32();
                    int dirBase = result.Is64Bit ? 0x70 : 0x60;
                    long clrDirPos = peOffset + 24 + dirBase + (14 * 8);
                    if (clrDirPos + 8 <= fs.Length)
                    {
                        fs.Seek(clrDirPos, SeekOrigin.Begin);
                        uint clrRva = reader.ReadUInt32();
                        uint clrSize = reader.ReadUInt32();
                        if (addressOfEntryPoint == 0 && clrRva != 0 && clrSize != 0)
                            result.IsMetadataOnlyModule = true;
                    }
                }
                catch { }

                fs.Seek(0, SeekOrigin.Begin);
                int sampleSize = (int)Math.Min(65536, fs.Length);
                var sample = reader.ReadBytes(sampleSize);
                result.Entropy = CalculateEntropy(sample);
                result.IsPacked = result.Entropy > 7.0;
                result.HasSuspiciousSections = CheckSuspiciousSections(fs, peOffset, numberOfSections);
                result.SuspiciousImportCount = CountSuspiciousImports(filePath);
                result.FileSize = fileSize;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] Static analysis failed for {Path}", filePath);
            }
            return result;
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var freq = new int[256];
            foreach (var b in data) freq[b]++;
            double entropy = 0;
            double len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                entropy -= p * MathNet48.Log2(p);
            }
            return entropy;
        }

        private static bool CheckSuspiciousSections(FileStream fs, int peOffset, int sectionCount)
        {
            try
            {
                fs.Seek(peOffset + 24, SeekOrigin.Begin);
                using var reader = new BinaryReader(fs, System.Text.Encoding.ASCII, leaveOpen: true);
                ushort optMagic = reader.ReadUInt16();
                int optHeaderSize = optMagic == 0x20B ? 240 : 224;
                fs.Seek(peOffset + 24 + optHeaderSize, SeekOrigin.Begin);
                var suspiciousNames = new HashSet<string> { ".ndata", "UPX0", "UPX1", ".themida", ".vmp0", ".vmp1", "MEW", ".aspack" };
                for (int i = 0; i < sectionCount && i < 20; i++)
                {
                    var nameBytes = reader.ReadBytes(8);
                    var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                    if (suspiciousNames.Contains(name)) return true;
                    reader.ReadBytes(32);
                }
            }
            catch { }
            return false;
        }

        private static int CountSuspiciousImports(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length > 10_000_000) return 0;
                const int ChunkSize = 65536;
                const int OverlapSize = 64;
                var buffer = new byte[ChunkSize + OverlapSize];
                var found = new HashSet<string>(StringComparer.Ordinal);
                int overlapCarry = 0;
                while (true)
                {
                    int bytesRead = fs.Read(buffer, overlapCarry, ChunkSize);
                    if (bytesRead == 0) break;
                    int totalBytes = overlapCarry + bytesRead;
                    var text = System.Text.Encoding.ASCII.GetString(buffer, 0, totalBytes);
                    foreach (var import in SuspiciousImports)
                    {
                        if (!found.Contains(import) && text.Contains(import))
                            found.Add(import);
                    }
                    if (found.Count >= SuspiciousImports.Count) break;
                    if (bytesRead >= OverlapSize)
                    {
                        Buffer.BlockCopy(buffer, overlapCarry + bytesRead - OverlapSize, buffer, 0, OverlapSize);
                        overlapCarry = OverlapSize;
                    }
                    else overlapCarry = 0;
                    if (bytesRead < ChunkSize) break;
                }
                return found.Count;
            }
            catch { return 0; }
        }

        // Container extensions worth a bounded content walk. ISO/IMG are shallow-scanned (not
        // mounted); the zip family is walked structurally with depth/size/ratio caps.
        private static readonly HashSet<string> InspectableContainerExtensions =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ".zip", ".jar", ".apk", ".xpi", ".vsix", ".nupkg", ".appx", ".appxbundle",
                ".msix", ".msixbundle", ".iso", ".img",
            };

        private static bool IsInspectableContainer(string ext)
            => !string.IsNullOrEmpty(ext) && InspectableContainerExtensions.Contains(ext);

        private static readonly byte[] ZipEocdSignature = { 0x50, 0x4B, 0x05, 0x06 };

        private static bool HasZipEndOfCentralDirectory(FileStream fs)
        {
            long len = fs.Length;
            if (len < 22) return false;
            const int MaxTail = 65536 + 22;
            int tailLen = (int)Math.Min(MaxTail, len);
            fs.Seek(len - tailLen, SeekOrigin.Begin);
            var tail = new byte[tailLen];
            ReadExactly(fs, tail, 0, tailLen);
            int eocd = LastIndexOf(tail, ZipEocdSignature);
            if (eocd < 0) return false;
            const int MaxScan = 4 * 1024 * 1024;
            int scanLen = (int)Math.Min(MaxScan, len);
            fs.Seek(0, SeekOrigin.Begin);
            var head = new byte[scanLen];
            ReadExactly(fs, head, 0, scanLen);
            byte[] lfh = { 0x50, 0x4B, 0x03, 0x04 };
            return IndexOf(head, lfh, 0) >= 0;
        }

        private static readonly byte[] GzipMagic = { 0x1F, 0x8B };

        private static bool HasEmbeddedScriptPayload(FileStream fs)
        {
            long len = fs.Length;
            if (len < 4 || len > 20_000_000) return false;
            const int MaxRead = 2 * 1024 * 1024;
            int readLen = (int)Math.Min(MaxRead, len);
            fs.Seek(0, SeekOrigin.Begin);
            var data = new byte[readLen];
            ReadExactly(fs, data, 0, readLen);
            for (int i = 0; i + 3 < data.Length; i++)
            {
                if (data[i] == GzipMagic[0] && data[i + 1] == GzipMagic[1] && data[i + 2] == 0x08)
                {
                    if (DecompressAndScan(data, i, isGzip: true)) return true;
                }
            }
            if (data.Length > 2 && data[0] == 0x78 &&
                (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA))
            {
                if (DecompressAndScan(data, 2, isGzip: false)) return true;
            }
            if (DecompressAndScan(data, 0, isGzip: false)) return true;
            return false;
        }

        private static bool DecompressAndScan(byte[] data, int offset, bool isGzip)
        {
            if (offset < 0 || offset >= data.Length) return false;
            try
            {
                using var ms = new MemoryStream(data, offset, data.Length - offset, writable: false);
                using System.IO.Stream decomp = isGzip
                    ? new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress)
                    : new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress);
                const int MaxOut = 1 * 1024 * 1024;
                var outBuf = new byte[MaxOut];
                int total = 0, n;
                while (total < MaxOut && (n = decomp.Read(outBuf, total, MaxOut - total)) > 0)
                    total += n;
                if (total < 8) return false;
                var text = System.Text.Encoding.ASCII.GetString(outBuf, 0, total);
                return ContainsScriptFragment(text);
            }
            catch { return false; }
        }

        private static readonly string[] ScriptFragments =
        {
            "<script", "</script>", "javascript:", "onerror=", "onload=",
            "eval(", "document.cookie", "document.write", "fromCharCode",
            "<iframe", "<svg onload", "<img src=x onerror"
        };

        private static bool ContainsScriptFragment(string text)
        {
            foreach (var frag in ScriptFragments)
                if (text.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            return false;
        }

        private static void ReadExactly(System.IO.Stream s, byte[] buf, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = s.Read(buf, offset + read, count - read);
                if (n <= 0) break;
                read += n;
            }
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int start)
        {
            int end = haystack.Length - needle.Length;
            for (int i = Math.Max(0, start); i <= end; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private static int LastIndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = haystack.Length - needle.Length; i >= 0; i--)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private ContextualRiskResult CalculateContextualRisk(string filePath, string hash)
        {
            var result = new ContextualRiskResult();
            var pathLower = filePath.ToLowerInvariant();
            result.IsHighRiskPath = HighRiskPaths.Any(p => pathLower.Contains(p));
            result.IsProtectedPath = pathLower.Contains(@"\program files") ||
                                     pathLower.Contains(@"\windows\system32") ||
                                     pathLower.Contains(@"\windows\syswow64");
            try
            {
                var created = File.GetCreationTimeUtc(filePath);
                result.AgeOnDisk = DateTimeOffset.UtcNow - created;
                result.IsNewFile = result.AgeOnDisk < TimeSpan.FromHours(1);
            }
            catch { result.IsNewFile = true; }
            if (_prevalenceMap.TryGetValue(hash, out var paths))
                result.Prevalence = paths.Count;
            else
                result.Prevalence = 1;
            return result;
        }

        private void TrackPrevalence(string hash, string filePath)
        {
            var paths = _prevalenceMap.GetOrAdd(hash, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            lock (paths)
            {
                if (paths.Count < 100)
                    paths.Add(filePath);
            }
        }

        private static int CalculateHashConsensus(HashReputationResult hr)
        {
            int score = 50;
            if (hr.CirclVerdict.Status == VerdictStatus.Safe) score -= 25;
            else if (hr.CirclVerdict.Status == VerdictStatus.NotFound) score += 5;
            if (hr.MalwareBazaarVerdict.Status == VerdictStatus.Malicious) score += 40;
            else if (hr.MalwareBazaarVerdict.Status == VerdictStatus.NotFound) score -= 10;
            if (hr.VirusTotalVerdict.Status == VerdictStatus.Malicious) score += 35;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Suspicious) score += 20;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Safe) score -= 25;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.NotFound) score += 0;
            return MathNet48.Clamp(score, 0, 100);
        }

        private static int CalculateCompositeScore(FileReputationResult r)
        {
            double score = 0;
            score += r.HashReputation.ConsensusScore * 0.40;
            double staticScore = 30;
            if (r.StaticAnalysis.IsPe)
            {
                if (r.StaticAnalysis.IsPacked) staticScore += 25;
                if (r.StaticAnalysis.HasSuspiciousSections) staticScore += 15;
                if (r.StaticAnalysis.Entropy > 7.5) staticScore += 20;
                else if (r.StaticAnalysis.Entropy > 7.0) staticScore += 10;
                if (r.StaticAnalysis.SuspiciousImportCount > 5) staticScore += 20;
                else if (r.StaticAnalysis.SuspiciousImportCount > 2) staticScore += 10;
            }
            else staticScore = 20;
            if (r.StaticAnalysis.IsMzZipPolyglot) staticScore += 40;
            if (r.StaticAnalysis.HasEmbeddedScriptPayload) staticScore += 30;

            // Bounded archive / disk-image content smuggling. A zip bomb or an executable/script
            // payload smuggled inside a container is a strong static red flag; nested archives and
            // fail-closed aborts are weaker (evasion-shaped) contributions. Still capped below.
            var ac = r.StaticAnalysis.ArchiveContent;
            if (ac != null)
            {
                if (ac.ZipBombShape) staticScore += 45;
                if (ac.ContainsExecutable) staticScore += 30;
                if (ac.ContainsScriptHost) staticScore += 20;
                if (ac.ContainsNestedArchive) staticScore += 10;
                if (ac.NestedDepthExceeded || ac.EntryCountExceeded || ac.InspectionAborted) staticScore += 10;
            }
            staticScore = Math.Min(100, staticScore);
            score += staticScore * 0.25;
            double signerScore = 50;
            if (r.IsSigned) signerScore = 10;
            else if (r.StaticAnalysis.IsMetadataOnlyModule) signerScore = 15;
            else signerScore = 60;
            score += signerScore * 0.20;
            double contextScore = 30;
            if (r.ContextualRisk.IsHighRiskPath) contextScore += 25;
            if (r.ContextualRisk.IsNewFile) contextScore += 15;
            if (r.ContextualRisk.IsProtectedPath) contextScore -= 20;
            if (r.ContextualRisk.Prevalence > 5) contextScore -= 15;
            contextScore = MathNet48.Clamp(contextScore, 0, 100);
            score += contextScore * 0.15;
            return (int)MathNet48.Clamp(score, 0, 100);
        }

        private static FileVerdict DetermineVerdict(int compositeScore) => compositeScore switch
        {
            <= 20 => FileVerdict.Trusted,
            <= 40 => FileVerdict.LowRisk,
            <= 60 => FileVerdict.Suspicious,
            <= 80 => FileVerdict.HighRisk,
            _ => FileVerdict.Malicious
        };

        private void PersistResult(string hash, FileReputationResult result)
        {
            try
            {
                var data = $"{result.CompositeScore}|{(int)result.Verdict}|{result.EvaluatedAt.Ticks}";
                _cacheStore.Save("filerepo", hash, data);
            }
            catch { }
        }

        public FileReputationResult? LoadCachedResult(string hash)
        {
            try
            {
                var data = _cacheStore.Load("filerepo", hash);
                if (string.IsNullOrEmpty(data)) return null;
                var parts = data!.Split('|');
                if (parts.Length != 3) return null;
                return new FileReputationResult
                {
                    Sha256 = hash,
                    CompositeScore = int.Parse(parts[0]),
                    Verdict = (FileVerdict)int.Parse(parts[1]),
                    EvaluatedAt = new DateTimeOffset(long.Parse(parts[2]), TimeSpan.Zero)
                };
            }
            catch { return null; }
        }

        public FileReputationStats GetStats() => new()
        {
            CachedResults = _resultCache.Count,
            TrackedFiles = _prevalenceMap.Count,
            InFlightLookups = _inFlight.Count
        };
    }

    public enum FileVerdict
    {
        Unknown,
        Trusted,
        LowRisk,
        Suspicious,
        HighRisk,
        Malicious
    }

    public enum VerdictStatus
    {
        Unknown,
        Safe,
        Suspicious,
        Malicious,
        NotFound,
        Error,
        RateLimited
    }

    public sealed class FileReputationResult
    {
        public string FilePath { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long FileSize { get; set; }
        public DateTimeOffset EvaluatedAt { get; set; }
        public int CompositeScore { get; set; }
        public FileVerdict Verdict { get; set; } = FileVerdict.Unknown;
        public bool IsSigned { get; set; }
        public string? SignerName { get; set; }
        public HashReputationResult HashReputation { get; set; } = new();
        public StaticAnalysisResult StaticAnalysis { get; set; } = new();
        public ContextualRiskResult ContextualRisk { get; set; } = new();

        public static FileReputationResult Unknown(string path) => new()
        {
            FilePath = path, Verdict = FileVerdict.Unknown, CompositeScore = 50
        };
    }

    public sealed class HashReputationResult
    {
        public ApiVerdict CirclVerdict { get; set; } = new();
        public ApiVerdict MalwareBazaarVerdict { get; set; } = new();
        public ApiVerdict VirusTotalVerdict { get; set; } = new();
        public int ConsensusScore { get; set; }
    }

    public sealed class ApiVerdict
    {
        public string Source { get; set; } = "";
        public VerdictStatus Status { get; set; } = VerdictStatus.Unknown;
        public int TrustScore { get; set; }
        public int DetectionCount { get; set; }
        public int EngineCount { get; set; }
        public double DetectionRate { get; set; }
    }

    public sealed class StaticAnalysisResult
    {
        public bool IsPe { get; set; }
        public bool Is64Bit { get; set; }
        public double Entropy { get; set; }
        public bool IsPacked { get; set; }
        public bool HasSuspiciousSections { get; set; }
        public int SuspiciousImportCount { get; set; }
        public int SectionCount { get; set; }
        public long FileSize { get; set; }
        public DateTimeOffset CompileTimestamp { get; set; }
        public bool IsMzZipPolyglot { get; set; }
        public bool HasEmbeddedScriptPayload { get; set; }
        public bool IsMetadataOnlyModule { get; set; }

        /// <summary>
        /// Bounded archive / disk-image content inspection findings (zip bomb, nested archive,
        /// embedded PE / script host inside a .zip/.iso/.img container). Null when the file was
        /// not a container we inspect. Content signal only - never solo kill authority.
        /// </summary>
        public ArchiveContentAnalysis? ArchiveContent { get; set; }
    }

    public sealed class ContextualRiskResult
    {
        public bool IsHighRiskPath { get; set; }
        public bool IsProtectedPath { get; set; }
        public bool IsNewFile { get; set; }
        public TimeSpan AgeOnDisk { get; set; }
        public int Prevalence { get; set; }
    }

    public sealed class FileReputationStats
    {
        public int CachedResults { get; set; }
        public int TrackedFiles { get; set; }
        public int InFlightLookups { get; set; }
    }
}
