using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Manages allowlisting for detection suppression and confidence reduction.
    /// Includes built-in trusted publishers, development tools, gaming processes,
    /// and a user-managed persistent allowlist stored in SecureCacheStore.
    /// President's Law rules (LSASS, AMSI, ETW, ransomware, self-protection) are
    /// NEVER suppressed regardless of allowlist status.
    /// </summary>
    public sealed class AllowlistService
    {
        private readonly SecureCacheStore _cacheStore;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<AllowlistService> _logger;
        private readonly ConcurrentDictionary<string, AllowlistEntry> _userAllowlist;

        public AllowlistService(SecureCacheStore cacheStore, ILogger<AllowlistService> logger, SignerTrustService? signerTrust = null)
        {
            _cacheStore = cacheStore;
            _signerTrust = signerTrust ?? new SignerTrustService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<SignerTrustService>());
            _logger = logger;
            _userAllowlist = new ConcurrentDictionary<string, AllowlistEntry>(StringComparer.OrdinalIgnoreCase);
            LoadUserAllowlist();
        }

        /// <summary>
        /// Checks if a process should be suppressed from detection entirely.
        ///
        /// ONLY the user-managed allowlist can suppress detections.
        /// No built-in name lists, no path guessing, no gaming exemptions.
        ///
        /// If a detection fires on a legitimate app, it means the behavioral
        /// detection is wrong and needs fixing - not that the app needs allowlisting.
        ///
        /// President's Law rules (LSASS, ransomware, injection, etc.) are NEVER
        /// suppressed regardless of allowlist status.
        /// </summary>
        public bool ShouldSuppress(string processName, string? imagePath, string? ruleName)
        {
            // President's Law rules are NEVER fully suppressed - even if user-allowlisted.
            // However, user-allowlisted processes get demoted in the response engine (LogOnly),
            // not suppressed at detection level. This ensures the detection is always logged.
            if (IsPresidentsLawRule(ruleName)) return false;
            if (IsUserAllowlisted(processName, imagePath)) return true;
            return false;
        }

        /// <summary>
        /// Gets a confidence reduction factor (0.0 to 0.3) based on trust signals.
        /// Only reduces confidence - never suppresses. And only for user-allowlisted processes.
        /// </summary>
        public double GetConfidenceReduction(string processName, string? imagePath, string? signerName, string? ruleName)
        {
            if (IsPresidentsLawRule(ruleName)) return 0.0;
            if (IsUserAllowlisted(processName, imagePath)) return 0.3;
            return 0.0;
        }

        /// <summary>
        /// Development process check - used only by ParentPidSpoofDetector to reduce
        /// PPID false positives on tools with complex spawn chains. Requires path verification
        /// at the call site - this method alone does NOT grant any suppression.
        /// </summary>
        public bool IsDevelopmentProcess(string processName)
        {
            return DevelopmentProcesses.Contains(processName);
        }

        private static readonly HashSet<string> DevelopmentProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "devenv", "code", "Windsurf", "cursor", "kiro", "positron", "Devin",
            "msbuild", "dotnet", "node", "npm", "python", "py",
            "git", "git-remote-https",
            "cargo", "rustc", "go", "java", "javac",
            "cl", "link", "cmake", "ninja",
            "docker", "docker-compose", "kubectl",
            "powershell", "pwsh", "cmd", "wt",
            "rider64", "phpstorm64", "idea64", "webstorm64", "goland64",
        };

        public void AddToUserAllowlist(string processName, string? imagePath, string reason)
        {
            _userAllowlist[processName.ToLowerInvariant()] = new AllowlistEntry
            {
                ProcessName = processName,
                ImagePath = imagePath ?? "",
                Reason = reason,
                AddedAt = DateTimeOffset.UtcNow,
                AddedBy = "User"
            };
            SaveUserAllowlist();
            _logger.LogInformation("Allowlist: Added '{Process}' - {Reason}", processName, reason);
        }

        public void RemoveFromUserAllowlist(string processName)
        {
            if (_userAllowlist.TryRemove(processName.ToLowerInvariant(), out _))
            {
                SaveUserAllowlist();
                _logger.LogInformation("Allowlist: Removed '{Process}'", processName);
            }
        }

        public IReadOnlyList<AllowlistEntry> GetUserAllowlist() => _userAllowlist.Values.ToList();

        private bool IsUserAllowlisted(string processName, string? imagePath)
        {
            // HARDENING v1.3.0: Never allowlist when imagePath is null/missing.
            // Previously fell back to name-only matching, letting any process claim
            // an allowlisted name without proving it's the actual binary.
            if (string.IsNullOrEmpty(imagePath) || !System.IO.File.Exists(imagePath))
            {
                return false;
            }

            // Exclude temp/downloads directories from any name-only baseline trust
            var lowerPath = imagePath!.ToLowerInvariant();
            if (lowerPath.Contains(@"\temp\") || 
                lowerPath.Contains(@"\downloads\") || 
                lowerPath.Contains(@"\appdata\local\temp\"))
            {
                return false;
            }

            // Verify strict path match on allowlisted entries (case-insensitive - Windows paths)
            bool matchesEntry = _userAllowlist.Values.Any(e =>
                !string.IsNullOrEmpty(e.ImagePath) &&
                string.Equals(imagePath, e.ImagePath, StringComparison.OrdinalIgnoreCase));

            if (matchesEntry)
            {
                // Only verify the binary is validly signed - no path-based trust
                if (_signerTrust.IsSignedFile(imagePath))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsPresidentsLawRule(string? ruleName)
        {
            return ScoringEngine.IsPresidentsLawRule(ruleName);
        }

        private void LoadUserAllowlist()
        {
            try
            {
                var json = _cacheStore.Load("allowlist", "user");
                if (string.IsNullOrWhiteSpace(json)) return;
                var entries = JsonSerializer.Deserialize<List<AllowlistEntry>>(json!);
                if (entries == null) return;
                foreach (var e in entries)
                    _userAllowlist[e.ProcessName.ToLowerInvariant()] = e;
                _logger.LogInformation("Allowlist: Loaded {Count} user entries", _userAllowlist.Count);
            }
            catch { }
        }

        private void SaveUserAllowlist()
        {
            try
            {
                var json = JsonSerializer.Serialize(_userAllowlist.Values.ToList());
                _cacheStore.Save("allowlist", "user", json);
            }
            catch { }
        }
    }

    public sealed class AllowlistEntry
    {
        public string ProcessName { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTimeOffset AddedAt { get; set; }
        public string AddedBy { get; set; } = "";
    }
}
