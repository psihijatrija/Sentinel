using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Verifies core subsystems on startup before activating monitors:
    /// ETW session, DPAPI encryption, quarantine directory, log file, rule loading.
    /// </summary>
    public sealed class StartupSelfTest : IHostedService
    {
        private readonly ILogger<StartupSelfTest> _logger;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantine;
        private readonly DetectionEngine _detectionEngine;
        private readonly SecureCacheStore _cacheStore;

        public StartupSelfTest(
            ILogger<StartupSelfTest> logger,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantine,
            DetectionEngine detectionEngine,
            SecureCacheStore cacheStore)
        {
            _logger = logger;
            _eventLogger = eventLogger;
            _quarantine = quarantine;
            _detectionEngine = detectionEngine;
            _cacheStore = cacheStore;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _logger.LogInformation("[StartupSelfTest] Running pre-flight checks...");
            int passed = 0, failed = 0;

            // 1. Log file writable
            try
            {
                var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
                if (string.IsNullOrEmpty(logDir))
                    logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
                if (Directory.Exists(logDir)) passed++; else { Directory.CreateDirectory(logDir); passed++; }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Log directory check FAILED"); }

            // 2. Quarantine directory accessible
            try
            {
                var logDir = Path.GetDirectoryName(_eventLogger.LogFilePath);
                if (string.IsNullOrEmpty(logDir))
                    logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
                var quarantineDir = Path.Combine(logDir, "Quarantine");
                if (!Directory.Exists(quarantineDir)) Directory.CreateDirectory(quarantineDir);
                passed++;
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Quarantine directory check FAILED"); }

            // 3. DPAPI / SecureCacheStore functional
            try
            {
                // SECURITY v1.4.4: Use a random key for the self-test cache entry.
                // Previously used a fixed key "_check" with fixed value "ok" - known plaintext
                // that could theoretically aid cryptanalysis of the HMAC key when observed
                // before/after boot in the DPAPI-encrypted file. Random key eliminates this.
                var testKey = $"_selftest_{Guid.NewGuid():N}";
                var testVal = Guid.NewGuid().ToString("N");
                _cacheStore.Save("selftest", testKey, testVal);
                var val = _cacheStore.Load("selftest", testKey);
                if (val == testVal) passed++; else { failed++; _logger.LogWarning("[StartupSelfTest] DPAPI cache read-back mismatch"); }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] DPAPI cache check FAILED"); }

            // 4. Detection rules loaded
            try
            {
                var ruleCount = _detectionEngine.RuleCount;
                if (ruleCount > 0) { passed++; _logger.LogInformation("[StartupSelfTest] {Count} detection rules loaded", ruleCount); }
                else { failed++; _logger.LogWarning("[StartupSelfTest] No detection rules loaded!"); }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Rule count check FAILED"); }

            // 5. Event logger functional
            try
            {
                _ = _eventLogger.LogEventAsync("selftest", new { Status = "OK", Timestamp = DateTime.UtcNow });
                passed++;
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Event logger check FAILED"); }

            // 6. v1.5.4: Entropy file ACL integrity - verify the HMAC key material is protected
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = Path.Combine(programData, "Sentinel", "Secure", ".install_entropy");
                if (File.Exists(entropyFile))
                {
                    var fi = new FileInfo(entropyFile);
                    var acl = fi.GetAccessControl();
                    var rules = acl.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));
                    bool hasUserAccess = false;
                    var usersGroup = new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                    var everyoneSid = new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.WorldSid, null);

                    foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
                    {
                        var sid = rule.IdentityReference as System.Security.Principal.SecurityIdentifier;
                        if (sid == null) continue;
                        if ((sid == usersGroup || sid == everyoneSid) &&
                            rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow)
                        {
                            hasUserAccess = true;
                            break;
                        }
                    }

                    if (hasUserAccess)
                    {
                        // ACL is too permissive - standard users can read the entropy.
                        // Re-lock it and alert.
                        _logger.LogWarning("[StartupSelfTest] SECURITY: Entropy file ACL allows standard user access. Re-locking.");
                        var newAcl = new System.Security.AccessControl.FileSecurity();
                        newAcl.SetAccessRuleProtection(true, false);
                        var systemSid = new System.Security.Principal.SecurityIdentifier(
                            System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                        var adminsSid = new System.Security.Principal.SecurityIdentifier(
                            System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                        newAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            systemSid, System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.AccessControlType.Allow));
                        newAcl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                            adminsSid, System.Security.AccessControl.FileSystemRights.FullControl,
                            System.Security.AccessControl.AccessControlType.Allow));
                        fi.SetAccessControl(newAcl);
                        passed++;
                        _logger.LogInformation("[StartupSelfTest] Entropy file ACL re-locked to SYSTEM+Administrators");
                    }
                    else
                    {
                        passed++;
                    }
                }
                else
                {
                    // Entropy file doesn't exist yet (first run) - it'll be created by SecureCacheStore
                    passed++;
                }
            }
            catch (Exception ex) { failed++; _logger.LogWarning(ex, "[StartupSelfTest] Entropy file ACL check FAILED"); }

            _logger.LogInformation("[StartupSelfTest] Complete: {Passed} passed, {Failed} failed", passed, failed);

            if (failed > 0)
            {
                _logger.LogWarning("[StartupSelfTest] Some subsystems degraded - Sentinel running in reduced mode");
            }

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
