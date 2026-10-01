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

        // Cache: file path -> (isSigned, signerName, lastWriteTime)
        // HARDENING v1.3.0: Added lastWriteTime tracking. If the file is modified after
        // caching (e.g., attacker replaces a signed binary with malware), the stale cache
        // entry is invalidated and re-verified. Previously the cache was permanent.
        private readonly ConcurrentDictionary<string, (bool IsSigned, string Signer, DateTime LastWrite)> _cache = new(StringComparer.OrdinalIgnoreCase);

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
            _cache[filePath] = (isSigned, signer, writeTime);
            return isSigned;
        }

        /// <summary>
        /// Returns the signer name for a given file, or null if unsigned/invalid.
        /// Used for logging and evidence in detection events.
        /// </summary>
        public string? GetSignerName(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return null;

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
            _cache[filePath] = (isSigned, signer, writeTime);
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
            _cache[filePath] = (isSigned, signer, writeTime);
        }

        /// <summary>
        /// Prune cache entries for files that no longer exist (called periodically).
        /// </summary>
        public void PruneCache()
        {
            var stale = _cache.Keys.Where(k => !File.Exists(k)).ToList();
            foreach (var k in stale) _cache.TryRemove(k, out _);
        }
    }
}
