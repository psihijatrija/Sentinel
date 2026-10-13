using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Authenticode signature verification service.
    /// 
    /// This service answers ONE question: "Is this binary validly signed?"
    /// 
    /// Being signed does NOT grant trust or exemption. It is a signal that lowers
    /// detection confidence. Behavioral detections still fire on signed binaries -
    /// if something acts malicious, it gets killed regardless of who signed it.
    /// 
    /// The signer name is extracted for logging/evidence purposes only.
    /// Caches results per file path (signature doesn't change at runtime).
    /// </summary>
    public sealed class SignerTrustService
    {
        private readonly ILogger<SignerTrustService> _logger;

        // Cache: file path -> (isSigned, signerName, lastWriteTime, cachedAt)
        // HARDENING v1.3.0: Added lastWriteTime tracking. If the file is modified after
        // caching (e.g., attacker replaces a signed binary with malware), the stale cache
        // entry is invalidated and re-verified. Previously the cache was permanent.
        // 3.1.1: Added CachedAt + an insert-time size cap (CachedEntry below). This cache is a
        // process-lifetime DI singleton keyed by distinct file path, fed per-file on the same
        // full-disk-walk hot path (FileVerdictScanner -> FileReputationEngine.EvaluateFileAsync,
        // plus FileActivityMonitor watcher events and ~25 other call sites). The 3.0.9 release
        // bounded FileReputationEngine's hash-keyed caches but left this path-keyed sibling
        // unbounded, so a multi-volume scan still grew it toward hundreds of thousands of
        // permanent entries. It now evicts oldest-first on insert, mirroring the 3.0.9/3.1.0
        // insert-time pattern. Advisory and fail-open: an evicted entry is simply re-verified.
        private readonly ConcurrentDictionary<string, CachedEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

        private readonly struct CachedEntry
        {
            public CachedEntry(bool isSigned, string signer, DateTime lastWrite, DateTimeOffset cachedAt)
            {
                IsSigned = isSigned;
                Signer = signer;
                LastWrite = lastWrite;
                CachedAt = cachedAt;
            }
            public bool IsSigned { get; }
            public string Signer { get; }
            public DateTime LastWrite { get; }
            public DateTimeOffset CachedAt { get; }
        }

        // Insert-time bound. 50k matches the FileReputationEngine result-cache ceiling set in
        // 3.0.9; on overflow we shed the oldest 20% (by CachedAt) under a single-thread CAS
        // guard so the hot path never blocks on the trim.
        private const int MaxCachedPaths = 50_000;
        private const int TrimTargetPaths = 40_000;
        private int _trimming; // 0 = idle, 1 = a trim is in progress

        /// <summary>
        /// Confidence reduction factor for signed binaries.
        /// Detection confidence is multiplied by this value when the process is signed.
        /// Example: 0.6 confidence * 0.5 factor = 0.3 effective confidence.
        /// </summary>
        public const double SignedConfidenceMultiplier = 0.5;

        public SignerTrustService(ILogger<SignerTrustService> logger)
        {
            _logger = logger;
        }

        // Stores a verdict and enforces the insert-time cap. Returns the stored value.
        private CachedEntry StoreVerdict(string filePath, bool isSigned, string signer, DateTime lastWrite)
        {
            var entry = new CachedEntry(isSigned, signer, lastWrite, DateTimeOffset.UtcNow);
            _cache[filePath] = entry;
            if (_cache.Count > MaxCachedPaths)
            {
                TrimOldest();
            }
            return entry;
        }

        // Sheds the oldest entries (by CachedAt) down to TrimTargetPaths. Single-flight: if a
        // trim is already running on another thread, callers skip it. O(n) sort only at the cap
        // boundary, off the common path.
        private void TrimOldest()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _trimming, 1, 0) != 0) return;
            try
            {
                int over = _cache.Count - TrimTargetPaths;
                if (over <= 0) return;
                var victims = _cache
                    .OrderBy(kv => kv.Value.CachedAt)
                    .Take(over)
                    .Select(kv => kv.Key)
                    .ToList();
                foreach (var key in victims) _cache.TryRemove(key, out _);
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _trimming, 0);
            }
        }

        // Sentinel's own install tree churns constantly (log/quarantine/diagnostic writes) and
        // surfaces as FileActivityMonitor watcher events that reach IsSignedFile before the
        // name-based writer filter. Never let that self-activity populate the cache - fail-open
        // (treat as unsigned for scoring; our own binaries are already response-excluded via
        // SelfPathGuard). Non-attacker-controllable: SelfPathGuard resolves the real path.
        private static bool IsSelfPath(string filePath)
        {
            try
            {
                return SelfPathGuard.IsUnderInstallDirectory(filePath)
                       || SelfPathGuard.IsSentinelSelfBinary(filePath);
            }
            catch { return false; }
        }

        /// <summary>
        /// Returns true if the process at the given PID has a valid Authenticode signature.
        /// This does NOT mean the process is trusted - only that it's signed.
        /// </summary>
        public bool IsSignedProcess(int pid)
        {
            try
            {
                var path = SecurityValidation.GetProcessImagePath(pid);
                if (string.IsNullOrEmpty(path)) return false;
                return IsSignedFile(path!);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if the file at the given path has a valid Authenticode signature.
        /// This does NOT mean the file is trusted - only that it's signed.
        /// </summary>
        public bool IsSignedFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;

            // 3.1.1: never cache Sentinel's own install-tree churn (see IsSelfPath).
            if (IsSelfPath(filePath))
            {
                var (selfSigned, _) = VerifyAndExtractSigner(filePath);
                return selfSigned;
            }

            if (_cache.TryGetValue(filePath, out var cached))
            {
                // HARDENING v1.3.0: Invalidate cache if file was modified since caching
                try
                {
                    var currentWrite = File.GetLastWriteTimeUtc(filePath);
                    if (currentWrite != cached.LastWrite)
                    {
                        _cache.TryRemove(filePath, out _);
                        // Fall through to re-verify
                    }
                    else
                    {
                        return cached.IsSigned;
                    }
                }
                catch { return cached.IsSigned; }
            }

            var (isSigned, signer) = VerifyAndExtractSigner(filePath);
            DateTime writeTime = DateTime.MinValue;
            try { writeTime = File.GetLastWriteTimeUtc(filePath); } catch { }
            StoreVerdict(filePath, isSigned, signer, writeTime);
            return isSigned;
        }

        /// <summary>
        /// Returns the signer name for a given file, or null if unsigned/invalid.
        /// Used for logging and evidence in detection events.
        /// </summary>
        public string? GetSignerName(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return null;

            // 3.1.1: never cache Sentinel's own install-tree churn (see IsSelfPath).
            if (IsSelfPath(filePath))
            {
                var (selfSigned, selfSigner) = VerifyAndExtractSigner(filePath);
                return selfSigned ? selfSigner : null;
            }

            if (_cache.TryGetValue(filePath, out var cached))
            {
                try
                {
                    var currentWrite = File.GetLastWriteTimeUtc(filePath);
                    if (currentWrite != cached.LastWrite)
                    {
                        _cache.TryRemove(filePath, out _);
                    }
                    else
                    {
                        return cached.IsSigned ? cached.Signer : null;
                    }
                }
                catch { return cached.IsSigned ? cached.Signer : null; }
            }

            var (isSigned, signer) = VerifyAndExtractSigner(filePath);
            DateTime writeTime = DateTime.MinValue;
            try { writeTime = File.GetLastWriteTimeUtc(filePath); } catch { }
            StoreVerdict(filePath, isSigned, signer, writeTime);
            return isSigned ? signer : null;
        }

        /// <summary>
        /// Returns true if the file is signed by Microsoft or Windows.
        /// </summary>
        public bool IsMicrosoftSigned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;
            if (!IsSignedFile(filePath)) return false;
            var signer = GetSignerName(filePath) ?? string.Empty;
            return signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0
                   || signer.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Adjusts a detection confidence value based on whether the process is signed.
        /// Signed processes get reduced confidence (less likely to be malicious),
        /// but NEVER zero - behavioral detections always have a chance to fire.
        /// </summary>
        public double AdjustConfidence(double baseConfidence, int pid)
        {
            if (pid <= 4) return baseConfidence;
            if (!IsSignedProcess(pid)) return baseConfidence;
            return baseConfidence * SignedConfidenceMultiplier;
        }

        /// <summary>
        /// Adjusts a detection confidence value based on whether the file is signed.
        /// </summary>
        public double AdjustConfidence(double baseConfidence, string? filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return baseConfidence;
            if (!IsSignedFile(filePath!)) return baseConfidence;
            return baseConfidence * SignedConfidenceMultiplier;
        }

        //  Legacy compatibility shims (to be removed once all callers migrate) 

        /// <summary>
        /// Legacy: returns true if signed. Callers should migrate to using
        /// AdjustConfidence() or IsSignedProcess() + confidence logic.
        /// </summary>
        [Obsolete("Use IsSignedProcess/IsSignedFile + AdjustConfidence instead of binary trust checks")]
        public bool IsTrustedProcess(int pid) => IsSignedProcess(pid);

        /// <summary>
        /// Legacy: returns true if signed.
        /// </summary>
        [Obsolete("Use IsSignedFile + AdjustConfidence instead of binary trust checks")]
        public bool IsTrustedFile(string filePath) => IsSignedFile(filePath);

        /// <summary>
        /// Legacy: returns true if signed.
        /// </summary>
        [Obsolete("Use IsSignedFile + AdjustConfidence instead of binary trust checks")]
        public bool IsTrustedProcessByPath(string? imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            return IsSignedFile(imagePath!);
        }

        //  End legacy shims 

        private (bool IsSigned, string Signer) VerifyAndExtractSigner(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return (false, string.Empty);

                if (!SecurityValidation.VerifyAuthenticodeSignature(filePath, _logger))
                    return (false, string.Empty);

                var signer = ExtractSignerCN(filePath);
                return (true, signer ?? string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SignerTrustService] Failed to verify {Path}", filePath);
                return (false, string.Empty);
            }
        }

        private static string? ExtractSignerCN(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                using var cert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                var subject = cert.Subject;
                var cnStart = subject.IndexOf("CN=");
                if (cnStart < 0) return subject;

                cnStart += 3;
                string cn;
                if (cnStart < subject.Length && subject[cnStart] == '"')
                {
                    var cnEnd = subject.IndexOf('"', cnStart + 1);
                    cn = cnEnd > cnStart ? subject[(cnStart + 1)..cnEnd] : subject[(cnStart + 1)..];
                }
                else
                {
                    var cnEnd = subject.IndexOf(',', cnStart);
                    cn = cnEnd > cnStart ? subject[cnStart..cnEnd] : subject[cnStart..];
                }

                return cn.Trim();
            }
            catch
            {
                return null;
            }
        }

        public void AddTestOverride(string filePath, bool isSigned, string signer)
        {
            DateTime writeTime = DateTime.MinValue;
            try { writeTime = File.GetLastWriteTimeUtc(filePath); } catch { }
            StoreVerdict(filePath, isSigned, signer, writeTime);
        }

        /// <summary>
        /// Prune cache entries for files that no longer exist (called periodically).
        /// </summary>
        public void PruneCache()
        {
            var stale = _cache.Keys.Where(k => !File.Exists(k)).ToList();
            foreach (var k in stale) _cache.TryRemove(k, out _);
        }

        /// <summary>Current number of cached path verdicts (diagnostics / cap verification).</summary>
        public int GetCachedCount() => _cache.Count;
    }
}
