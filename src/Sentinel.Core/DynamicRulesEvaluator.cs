using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    public class DynamicCondition
    {
        public string Field { get; set; } = string.Empty;
        public string Operator { get; set; } = "Equals"; // Equals, Contains, StartsWith, EndsWith, NotEquals, NotContains
        public string Value { get; set; } = string.Empty;

        /// <summary>
        /// v1.8.1 RT-CRIT-2: Only documented telemetry model properties may be resolved via
        /// reflection. Blocks arbitrary .NET property inspection if a signed rule is ever forged.
        /// </summary>
        private static readonly HashSet<string> AllowedPropertyNames = new(StringComparer.OrdinalIgnoreCase)
        {
            // TelemetryEvent
            "Type", "Timestamp", "ProcessId", "ProcessName",
            // ProcessTelemetry
            "ImagePath", "ParentProcessId", "ParentProcessName", "CommandLine",
            // NetworkTelemetry
            "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "Protocol", "State",
            // FileActivityTelemetry
            "FilePath", "OperationType", "TargetPath",
            // ThreatIntelTelemetry
            "TargetProcessId", "ApiName", "Protection"
        };

        internal static bool IsAllowedPropertyName(string? name) =>
            !string.IsNullOrWhiteSpace(name) && AllowedPropertyNames.Contains(name!);

        public bool Evaluate(object target)
        {
            if (target == null) return false;
            if (!IsAllowedPropertyName(Field))
                return false;

            var prop = target.GetType().GetProperty(Field, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            if (prop == null) return false;

            var rawValue = prop.GetValue(target);
            string strValue = rawValue?.ToString() ?? string.Empty;

            switch (Operator.ToLowerInvariant())
            {
                case "equals":
                    return strValue.Equals(Value);
                case "notequals":
                    return !strValue.Equals(Value);
                case "contains":
                    return strValue.Contains(Value);
                case "notcontains":
                    return !strValue.Contains(Value);
                case "startswith":
                    return strValue.StartsWith(Value);
                case "endswith":
                    return strValue.EndsWith(Value);
                default:
                    return false;
            }
        }
    }

    public class DynamicRuleDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty; // e.g. "ProcessTelemetry", "NetworkTelemetry", "FileActivityTelemetry"
        public List<DynamicCondition> Conditions { get; set; } = new();
        public double Confidence { get; set; } = 0.80;
        public string Tier { get; set; } = "Tier1Behavioral"; // Tier1Behavioral, Tier2Indicator
        public string ResponseAction { get; set; } = "LogOnly"; // LogOnly, KillProcessTree, QuarantineAndKill
        public string Evidence { get; set; } = string.Empty;
        public string Reasoning { get; set; } = string.Empty;
        public string SignalType { get; set; } = "SuspiciousProcess"; // LsassAccess, Ransomware, ReverseShell, ProcessInjection, SecurityEvasion, SuspiciousProcess, NetworkC2

        public DetectionEvent CreateEvent(object triggeringEvent, int processId, string processName)
        {
            var tierParsed = Enum.TryParse<DetectionTier>(Tier, true, out var t) ? t : DetectionTier.Tier1Behavioral;
            var responseParsed = Enum.TryParse<Core.ResponseAction>(ResponseAction, true, out var r) ? r : Core.ResponseAction.LogOnly;
            var signalParsed = Enum.TryParse<SignalType>(SignalType, true, out var s) ? s : Core.SignalType.SuspiciousProcess;

            // Simple token replacements in the description fields (allowlisted properties only)
            string finalEvidence = ReplaceTokens(Evidence, triggeringEvent);
            string finalReasoning = ReplaceTokens(Reasoning, triggeringEvent);

            return new DetectionEvent
            {
                RuleName = $"DynamicRule:{Name}",
                ProcessId = processId,
                ProcessName = processName,
                Confidence = Confidence,
                Tier = tierParsed,
                AuthorizedResponse = responseParsed,
                SignalType = signalParsed,
                Evidence = finalEvidence,
                Reasoning = finalReasoning,
                Metadata = new Dictionary<string, string> { { "DynamicRuleSource", Name } }
            };
        }

        private string ReplaceTokens(string template, object source)
        {
            if (string.IsNullOrEmpty(template) || source == null) return template;

            var result = template;
            foreach (var prop in source.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                // v1.8.1: only substitute documented telemetry fields (same allowlist as Evaluate)
                if (!DynamicCondition.IsAllowedPropertyName(prop.Name))
                    continue;
                var val = prop.GetValue(source)?.ToString() ?? string.Empty;
                result = Sentinel.Core.StringNet48.ReplaceIgnoreCase(result, "{" + prop.Name + "}", val);
            }
            return result;
        }
    }

    public class DynamicRulesEvaluator : IDetectionRule, IDisposable
    {
        public string Name => "DynamicRulesEvaluator";

        private readonly string _rulesDirectory;
        private readonly List<DynamicRuleDefinition> _rules = new();
        private readonly object _lock = new();
        private readonly FileSystemWatcher? _watcher;
        private readonly ILogger<DynamicRulesEvaluator> _logger;
        private readonly byte[]? _hmacKey;
        private readonly bool _isTestMode; // v1.5.9: bypasses fail-closed HMAC check in unit tests
        private int _reloadScheduled; // 0/1 debounce flag for FileSystemWatcher
        private CancellationTokenSource? _reloadCts;

        public DynamicRulesEvaluator(ILogger<DynamicRulesEvaluator> logger)
        {
            _logger = logger;
            _rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
            _hmacKey = DeriveRuleSigningKey();

            try
            {
                if (!Directory.Exists(_rulesDirectory))
                {
                    Directory.CreateDirectory(_rulesDirectory);
                }

                // v1.5.5: Secure the rules directory ACL (SYSTEM + Admins only can write)
                SecureRulesDirectory();

                LoadRules();

                // Watch directory for changes
                _watcher = new FileSystemWatcher(_rulesDirectory, "*.json")
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                _watcher.Changed += OnRulesChanged;
                _watcher.Created += OnRulesChanged;
                _watcher.Deleted += OnRulesChanged;
                _watcher.Renamed += OnRulesChanged;
                _watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DynamicRulesEvaluator] Initialization failed");
            }
        }

        // For unit testing overrides (bypasses HMAC validation)
        public DynamicRulesEvaluator(string testRulesPath, ILogger<DynamicRulesEvaluator> logger)
        {
            _logger = logger;
            _rulesDirectory = testRulesPath;
            _hmacKey = null; // Disable HMAC validation in test mode
            _isTestMode = true; // v1.5.9: Allows bypassing fail-closed HMAC check in tests only
            if (!Directory.Exists(_rulesDirectory))
            {
                Directory.CreateDirectory(_rulesDirectory);
            }
            LoadRules();
        }

        /// <summary>
        /// v1.5.5: Derives HMAC signing key from installation entropy.
        /// Rule files must include an "hmac" field containing HMAC-SHA256(rule_json_without_hmac_field).
        /// This prevents unauthorized rule injection even with admin file-write access
        /// (attacker would need SYSTEM access to read the entropy file).
        /// </summary>
        private static byte[]? DeriveRuleSigningKey()
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = Path.Combine(programData, "Sentinel", "Secure", ".install_entropy");
                if (File.Exists(entropyFile))
                {
                    var entropy = File.ReadAllBytes(entropyFile);
                    if (entropy.Length == 32)
                    {
                        using var hmac = new HMACSHA256(entropy);
                        return hmac.ComputeHash(Encoding.UTF8.GetBytes("sentinel-dynamic-rules-signing-v1"));
                    }
                }
            }
            catch { }
            return null;
        }

        /// <summary>
        /// v1.5.5 / v1.6.0: Locks down the rules directory.
        /// SYSTEM: full control (only principal that can also read .install_entropy to sign).
        /// Administrators: read-only (cannot drop new signed rules without SYSTEM).
        /// Users: read-only.
        /// Combined with SYSTEM-only entropy ACL this blocks admin rule forgery.
        /// </summary>
        private void SecureRulesDirectory()
        {
            try
            {
                var dirInfo = new DirectoryInfo(_rulesDirectory);
                if (!dirInfo.Exists) return;

                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                // Clear existing explicit rules
                var existing = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule rule in existing)
                    security.RemoveAccessRuleAll(rule);

                var systemSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    systemSid,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                // v1.6.0: Admins read-only - signing key is SYSTEM-only, so write without
                // signature is rejected by fail-closed HMAC verification.
                var adminsSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    adminsSid,
                    System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                var usersSid = new System.Security.Principal.SecurityIdentifier(
                    System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    usersSid,
                    System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DynamicRulesEvaluator] Failed to secure rules directory ACL");
            }
        }

        /// <summary>
        /// v1.5.5: Verifies HMAC signature of a rule file.
        /// The file must contain an "hmac" field at root level. The signature is computed
        /// over the JSON content with the "hmac" field removed.
        /// HARDENING v1.5.9: Fails CLOSED when HMAC key is unavailable - rules are rejected.
        /// Previously failed open (returned true), allowing an attacker who deleted the entropy
        /// file to inject arbitrary unsigned rules that could suppress real detections.
        /// Test mode (constructor with testRulesPath) still bypasses HMAC via null _hmacKey check
        /// handled separately in the test constructor path.
        /// </summary>
        private bool VerifyRuleSignature(string fileContent, string filePath)
        {
            // HARDENING v1.5.9: Fail-closed when no signing key is available.
            // If the entropy file is missing (deleted by attacker, or corrupted), reject all rules.
            // The entropy file is created at install time by the installer - its absence in
            // production is anomalous and should be treated as potential tampering.
            // NOTE: Test mode uses a separate constructor that sets _hmacKey = null and never
            // calls this method (rules are loaded directly without verification).
            if (_hmacKey == null)
            {
                // v1.5.9: Test mode bypass - only reachable from the test constructor
                if (_isTestMode)
                {
                    return true;
                }

                _logger.LogError("[DynamicRulesEvaluator] REJECTED rule {File} - HMAC signing key unavailable. " +
                    "The install entropy file may be missing or corrupted. Dynamic rules require " +
                    "integrity verification and will NOT load without a valid signing key.",
                    Path.GetFileName(filePath));
                return false;
            }

            try
            {
                using var doc = JsonDocument.Parse(fileContent);
                var root = doc.RootElement;

                if (!root.TryGetProperty("hmac", out var hmacElement))
                {
                    _logger.LogWarning("[DynamicRulesEvaluator] REJECTED rule {File} - missing 'hmac' signature field",
                        Path.GetFileName(filePath));
                    return false;
                }

                var providedHmac = hmacElement.GetString();
                if (string.IsNullOrEmpty(providedHmac))
                {
                    _logger.LogWarning("[DynamicRulesEvaluator] REJECTED rule {File} - empty 'hmac' signature",
                        Path.GetFileName(filePath));
                    return false;
                }

                // Compute expected HMAC over the JSON content without the hmac field
                // We reconstruct the JSON without the hmac property for signing
                var contentToSign = RemoveHmacField(fileContent);
                using var hmac = new HMACSHA256(_hmacKey);
                var expectedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(contentToSign));

                // v1.8.1: constant-time compare (reject odd-length / non-hex provided HMAC)
                byte[]? providedBytes;
                try
                {
                    providedBytes = ConvertHex.FromHexString(providedHmac!);
                }
                catch
                {
                    _logger.LogWarning("[DynamicRulesEvaluator] REJECTED rule {File} - HMAC signature not valid hex",
                        Path.GetFileName(filePath));
                    return false;
                }

                if (!SecurityValidation.SecureCompare(providedBytes, expectedHash))
                {
                    _logger.LogWarning("[DynamicRulesEvaluator] REJECTED rule {File} - HMAC signature INVALID. " +
                        "Rule file may have been tampered with.", Path.GetFileName(filePath));
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[DynamicRulesEvaluator] REJECTED rule {File} - signature validation error",
                    Path.GetFileName(filePath));
                return false;
            }
        }

        /// <summary>
        /// Removes the "hmac" field from JSON content for signature computation.
        /// Uses a simple approach: deserialize, remove field, re-serialize deterministically.
        /// </summary>
        private static string RemoveHmacField(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            using var ms = new MemoryStream();
            using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = false }))
            {
                writer.WriteStartObject();
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.Name.Equals("hmac"))
                        continue;
                    prop.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        private void OnRulesChanged(object sender, FileSystemEventArgs e)
        {
            // v1.8.1 RT-MED-2 / RT-HIGH-1: non-blocking debounce (no Thread.Sleep).
            // Coalesce burst of watcher events; single read+HMAC happens inside LoadRules.
            var cts = new CancellationTokenSource();
            var previous = Interlocked.Exchange(ref _reloadCts, cts);
            try { previous?.Cancel(); } catch { }
            previous?.Dispose();

            if (Interlocked.Exchange(ref _reloadScheduled, 1) == 1 && previous != null)
            {
                // A reload task is already scheduled; the exchanged CTS will cancel the old delay.
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(150, cts.Token).ConfigureAwait(false);
                    LoadRules();
                }
                catch (OperationCanceledException)
                {
                    // Superseded by a newer change event
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[DynamicRulesEvaluator] Debounced rule reload failed");
                }
                finally
                {
                    Interlocked.Exchange(ref _reloadScheduled, 0);
                }
            }, CancellationToken.None);
        }

        private void LoadRules()
        {
            lock (_lock)
            {
                _rules.Clear();
                _logger.LogInformation($"[DynamicRulesEvaluator] Loading rules from {_rulesDirectory}");

                if (!Directory.Exists(_rulesDirectory)) return;

                foreach (var file in Directory.GetFiles(_rulesDirectory, "*.json"))
                {
                    try
                    {
                        var content = File.ReadAllText(file);

                        // v1.5.5: Verify HMAC signature before loading
                        if (!VerifyRuleSignature(content, file))
                        {
                            continue; // Skip unsigned/tampered rules
                        }

                        var rule = JsonSerializer.Deserialize<DynamicRuleDefinition>(content, new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true,
                            Converters = { new JsonStringEnumConverter() }
                        });

                        if (rule != null && !string.IsNullOrEmpty(rule.Name))
                        {
                            _rules.Add(rule);
                            _logger.LogInformation($"[DynamicRulesEvaluator] Successfully loaded dynamic rule: {rule.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"[DynamicRulesEvaluator] Failed to load rule file {Path.GetFileName(file)}");
                    }
                }
            }
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context?.TriggeringEvent == null) return null;

            var triggeringEvent = context.TriggeringEvent;
            var eventTypeName = triggeringEvent.GetType().Name;

            lock (_lock)
            {
                foreach (var rule in _rules)
                {
                    if (!rule.EventType.Equals(eventTypeName))
                        continue;

                    bool matchesAll = true;
                    foreach (var condition in rule.Conditions)
                    {
                        if (!condition.Evaluate(triggeringEvent))
                        {
                            matchesAll = false;
                            break;
                        }
                    }

                    if (matchesAll)
                    {
                        int processId = 0;
                        string processName = "Unknown";

                        // Attempt to extract ProcessId and ProcessName via reflection from triggering event
                        var pidProp = triggeringEvent.GetType().GetProperty("ProcessId", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (pidProp != null)
                        {
                            processId = (int)(pidProp.GetValue(triggeringEvent) ?? 0);
                        }

                        var nameProp = triggeringEvent.GetType().GetProperty("ProcessName", BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (nameProp != null)
                        {
                            processName = nameProp.GetValue(triggeringEvent)?.ToString() ?? "Unknown";
                        }

                        _logger.LogWarning($"[DynamicRulesEvaluator] Dynamic rule match triggered: {rule.Name} on PID {processId} ({processName})");
                        return rule.CreateEvent(triggeringEvent, processId, processName);
                    }
                }
            }

            return null;
        }

        public void Dispose()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
            }
            try
            {
                var cts = Interlocked.Exchange(ref _reloadCts, null);
                cts?.Cancel();
                cts?.Dispose();
            }
            catch { }
            GC.SuppressFinalize(this);
        }
    }
}
